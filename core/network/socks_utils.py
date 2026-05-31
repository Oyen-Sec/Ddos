"""
SOCKS5 socket utility — single source of truth for proxied TCP connections.
All attack engines use this to ensure IP anonymity and prevent DNS leaks.
"""
from __future__ import annotations

import socket
import ssl
from typing import Optional, Tuple
from urllib.parse import urlparse


def create_proxied_socket(
    proxy_url: str = "",
    timeout: float = 10.0,
    nodelay: bool = True,
) -> socket.socket:
    """
    Create a TCP socket, optionally routed through a SOCKS5 proxy.

    Args:
        proxy_url: SOCKS5 URL (socks5h://host:port) or empty for direct.
        timeout: Socket timeout in seconds.
        nodelay: Enable TCP_NODELAY (default True).

    Returns:
        A connected (or connectable) socket object.
        If proxy_url is set, the socket is a socks.socksocket with
        rdns=True (DNS resolved through proxy — no DNS leak).
    """
    if proxy_url:
        import socks as _socks

        p = urlparse(proxy_url)
        proxy_host = p.hostname or "127.0.0.1"
        proxy_port = p.port or 9050

        sock = _socks.socksocket()
        # rdns=True: resolve hostnames through the proxy
        sock.set_proxy(_socks.SOCKS5, proxy_host, proxy_port, rdns=True)
        sock.settimeout(timeout)
        if nodelay:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return sock

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    if nodelay:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def proxied_connect(
    host: str,
    port: int,
    proxy_url: str = "",
    timeout: float = 10.0,
) -> socket.socket:
    """
    Create a socket and connect to (host, port), optionally through SOCKS5.

    Returns:
        Connected socket.
    Raises:
        socket.error on connection failure.
    """
    sock = create_proxied_socket(proxy_url, timeout)
    sock.connect((host, port))
    return sock


def proxied_ssl_wrap(
    sock: socket.socket,
    server_hostname: str,
    alpn_protocols: Optional[Tuple[str, ...]] = None,
) -> ssl.SSLSocket:
    """
    Wrap an existing socket (direct or proxied) with SSL/TLS.

    Args:
        sock: The connected socket.
        server_hostname: SNI hostname for the target.
        alpn_protocols: ALPN protocols to negotiate (default: h2, http/1.1).

    Returns:
        SSL-wrapped socket.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("HIGH:!aNULL:!MD5")

    if alpn_protocols:
        ctx.set_alpn_protocols(list(alpn_protocols))
    else:
        ctx.set_alpn_protocols(["h2", "http/1.1"])

    ssl_sock = ctx.wrap_socket(sock, server_hostname=server_hostname)
    return ssl_sock


def extract_socks5_proxies(proxy_pool) -> list:
    """
    Extract SOCKS5 proxy URLs from a ProxyPool or similar iterable.
    Returns:
        List of SOCKS5 proxy URLs (e.g., socks5h://127.0.0.1:9050).
    """
    urls = []
    if proxy_pool is None:
        return urls
    try:
        for plist in getattr(proxy_pool, "_pools", {}).values():
            for ps in plist:
                u = getattr(ps, "url", None)
                if u and ("socks5" in u or "socks4" in u):
                    urls.append(u)
        if not urls:
            for ps in getattr(proxy_pool, "_pending", []) or []:
                u = getattr(ps, "url", None) or (ps if isinstance(ps, str) else None)
                if u and ("socks5" in u or "socks4" in u):
                    urls.append(u)
    except Exception:
        pass
    return urls


def detect_local_tor() -> list:
    """
    Detect locally running Tor SOCKS5 proxies.
    Checks common ports: 9050, 9150, 9250-9260.
    Returns:
        List of socks5h:// URLs for running Tor instances.
    """
    urls = []
    for port in [9050, 9150]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect(("127.0.0.1", port))
            urls.append(f"socks5h://127.0.0.1:{port}")
        except Exception:
            pass
        finally:
            s.close()
    # Check Tor manager range
    for port in range(9250, 9260, 2):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        try:
            s.connect(("127.0.0.1", port))
            urls.append(f"socks5h://127.0.0.1:{port}")
        except Exception:
            pass
        finally:
            s.close()
    return urls
