"""Target detection module — auto-detect CDN, server type, HTTP/2 support."""
from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class TargetProfile:
    supports_http2: bool = False
    has_cdn: bool = False
    cdn_provider: Optional[str] = None
    server_header: str = ""
    ip: str = ""
    hostname: str = ""


async def auto_detect_target(url: str, verbose: bool = False) -> Optional[TargetProfile]:
    """Auto-detect target capabilities: CDN, HTTP/2 support, server type."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    profile = TargetProfile(hostname=hostname)

    try:
        loop = asyncio.get_event_loop()
        ip = await loop.run_in_executor(None, socket.gethostbyname, hostname)
        profile.ip = ip
    except Exception:
        return profile

    def _check_h2() -> bool:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            sock = socket.socket()
            sock.settimeout(5)
            sock.connect((ip, 443))
            ssl_sock = ctx.wrap_socket(sock, server_hostname=hostname)
            alpn = ssl_sock.selected_alpn_protocol()
            ssl_sock.close()
            return alpn == "h2"
        except Exception:
            return False

    def _check_cdn() -> tuple:
        try:
            import http.client
            conn = http.client.HTTPSConnection(ip, timeout=5)
            conn.request("GET", "/", headers={
                "User-Agent": "Mozilla/5.0",
                "Host": hostname,
            })
            resp = conn.getresponse()
            resp.read()
            headers = {k.lower(): v for k, v in resp.getheaders()}
            server = headers.get("server", "")
            cdn = None
            has_cdn = False
            if "cf-ray" in headers:
                has_cdn = True
                cdn = "Cloudflare"
            elif "cloudflare" in server.lower():
                has_cdn = True
                cdn = "Cloudflare"
            elif "akamai" in server.lower():
                has_cdn = True
                cdn = "Akamai"
            elif "cloudfront" in server.lower():
                has_cdn = True
                cdn = "CloudFront"
            elif "fastly" in server.lower():
                has_cdn = True
                cdn = "Fastly"
            conn.close()
            return has_cdn, cdn, server
        except Exception:
            return False, None, ""

    try:
        profile.supports_http2 = await loop.run_in_executor(None, _check_h2)
        has_cdn, cdn, server = await loop.run_in_executor(None, _check_cdn)
        profile.has_cdn = has_cdn
        profile.cdn_provider = cdn
        profile.server_header = server
    except Exception:
        pass

    if verbose:
        print(f"  [*] Target: {hostname} ({ip})")
        print(f"  [*] HTTP/2: {'Yes' if profile.supports_http2 else 'No'}")
        print(f"  [*] CDN: {cdn or 'None'}")
        print(f"  [*] Server: {server or 'Unknown'}")

    return profile
