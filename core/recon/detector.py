"""
Target Detector - Smart auto-detection untuk pilih attack method terbaik
"""
import asyncio
import socket
import ssl
import logging
from typing import Dict, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger("target_detector")


@dataclass
class TargetProfile:
    url: str
    host: str
    port: int
    is_https: bool = False
    supports_http2: bool = False
    supports_http3: bool = False
    cdn: str = "none"
    waf: str = "none"
    rate_limited: bool = False
    server: str = ""
    response_status: int = 0
    response_time_ms: float = 0
    is_alive: bool = False
    headers: Dict[str, str] = field(default_factory=dict)
    recommended_method: str = "http-flood"
    recommended_strategy: str = "direct"
    needs_proxy: bool = False
    needs_rapid_reset: bool = False


class TargetDetector:
    """Auto-detect target capabilities and recommend optimal attack strategy"""

    CDN_SIGNATURES = {
        "cloudflare": ["cf-ray", "cf-cache-status", "__cf_bm", "cf-request-id"],
        "akamai": ["akamai-", "x-akamai-", "akamai-cache"],
        "fastly": ["fastly-", "x-fastly-", "x-served-by"],
        "cloudfront": ["x-amz-cf-", "cloudfront"],
        "sucuri": ["x-sucuri-", "sucuri"],
        "incapsula": ["x-iinfo", "incap_ses_"],
        "stackpath": ["x-sp-", "stackpath"],
        "bunny": ["cdn-pullzone", "cdn-uid"],
    }

    WAF_SIGNATURES = {
        "cloudflare": ["cf-ray", "cf-mitigated"],
        "modsecurity": ["mod_security", "modsecurity"],
        "imperva": ["x-iinfo", "incap_ses"],
        "f5": ["x-wa-info", "bigipserver"],
        "barracuda": ["barra_counter_session"],
        "wordfence": ["x-wordfence-"],
        "sucuri": ["x-sucuri-id"],
        "akamai_kona": ["akamai-bot-manager"],
    }

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    @staticmethod
    def _is_bare_ip(host: str) -> bool:
        """Check if host is a bare IP address (no domain)"""
        if not host:
            return False
        parts = host.split(".")
        if len(parts) != 4:
            return False
        try:
            for p in parts:
                n = int(p)
                if n < 0 or n > 255:
                    return False
            return True
        except ValueError:
            return False

    async def probe(self, target_url: str) -> TargetProfile:
        """Full probe: detect HTTP/2, CDN, WAF, rate-limit"""
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        parsed = urlparse(target_url)
        host = parsed.hostname or parsed.netloc
        is_ip = self._is_bare_ip(host)

        profile = TargetProfile(
            url=target_url,
            host=host,
            port=parsed.port or (443 if parsed.scheme == "https" else 80),
            is_https=parsed.scheme == "https",
        )

        # For bare IPs, do dual-probe: HTTPS first, fallback to HTTP
        if is_ip:
            await self._probe_bare_ip(profile)
        else:
            await self._http_probe(profile)

        if profile.is_https and profile.is_alive:
            await self._http2_probe(profile)

        self._detect_cdn(profile)
        self._detect_waf(profile)
        self._detect_rate_limit(profile)

        await self._rate_limit_probe(profile)

        self._recommend_strategy(profile)

        return profile

    async def _http_probe(self, profile: TargetProfile):
        """Probe via HTTP request to gather server info"""
        try:
            from curl_cffi.requests import AsyncSession
            import time

            kwargs = {"impersonate": "chrome120", "timeout": self.timeout}
            async with AsyncSession(**kwargs) as sess:
                start = time.monotonic()
                try:
                    resp = await sess.get(profile.url, timeout=self.timeout, allow_redirects=False)
                    elapsed = (time.monotonic() - start) * 1000
                    profile.response_time_ms = round(elapsed, 1)
                    profile.response_status = resp.status_code
                    profile.is_alive = resp.status_code < 600
                    profile.headers = {k.lower(): v for k, v in dict(resp.headers).items()}
                    profile.server = profile.headers.get("server", "")

                    if "alt-svc" in profile.headers:
                        alt_svc = profile.headers["alt-svc"]
                        if "h3" in alt_svc:
                            profile.supports_http3 = True
                        if "h2" in alt_svc:
                            profile.supports_http2 = True
                except Exception as e:
                    logger.debug(f"HTTP probe failed: {e}")
        except ImportError:
            await self._fallback_socket_probe(profile)

    async def _probe_bare_ip(self, profile: TargetProfile):
        """Probe a bare IP address - try HTTPS, HTTP, with cert verify disabled"""
        # Try curl_cffi first
        try:
            from curl_cffi.requests import AsyncSession
            import time

            kwargs = {
                "impersonate": "chrome120",
                "timeout": self.timeout,
                "verify": False,
            }
            async with AsyncSession(**kwargs) as sess:
                for url_try in [profile.url, profile.url.replace("https://", "http://")]:
                    try:
                        start = time.monotonic()
                        resp = await sess.get(url_try, timeout=self.timeout, allow_redirects=False)
                        elapsed = (time.monotonic() - start) * 1000
                        profile.response_time_ms = round(elapsed, 1)
                        profile.response_status = resp.status_code
                        profile.is_alive = resp.status_code < 600
                        profile.headers = {k.lower(): v for k, v in dict(resp.headers).items()}
                        profile.server = profile.headers.get("server", "")
                        profile.url = url_try
                        if url_try.startswith("http://"):
                            profile.is_https = False

                        if "alt-svc" in profile.headers:
                            alt_svc = profile.headers["alt-svc"]
                            if "h3" in alt_svc:
                                profile.supports_http3 = True
                            if "h2" in alt_svc:
                                profile.supports_http2 = True
                        return
                    except Exception as e:
                        logger.debug(f"Bare IP probe ({url_try}) failed: {e}")
                        continue
        except ImportError:
            pass

        # Always fall back to raw socket if curl_cffi didn't return success
        if not profile.is_alive:
            await self._raw_socket_probe(profile)

    async def _raw_socket_probe(self, profile: TargetProfile):
        """Last-resort raw TCP/SSL probe for bare IP targets"""
        import time

        # Try common ports
        port_attempts = [(True, 443), (False, 80), (True, 8443), (False, 8080),
                         (True, 8443), (False, 8000)]

        for is_ssl, port in port_attempts:
            try:
                ssl_ctx = None
                if is_ssl:
                    ssl_ctx = ssl.create_default_context()
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = ssl.CERT_NONE
                    try:
                        ssl_ctx.set_alpn_protocols(["h2", "http/1.1"])
                    except Exception:
                        pass

                start = time.monotonic()
                # First check if TCP port is even reachable
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(
                            profile.host, port, ssl=ssl_ctx,
                            server_hostname=profile.host if is_ssl else None,
                        ),
                        timeout=self.timeout,
                    )
                except (asyncio.TimeoutError, OSError, ssl.SSLError) as conn_err:
                    logger.debug(f"TCP/SSL connect {profile.host}:{port} failed: {conn_err}")
                    continue

                # If we got here, TCP/SSL connection is established
                # That ALONE proves server is alive
                profile.is_alive = True
                profile.response_time_ms = round((time.monotonic() - start) * 1000, 1)
                profile.url = f"{'https' if is_ssl else 'http'}://{profile.host}"
                if not is_ssl:
                    profile.is_https = False
                profile.port = port

                # Try to get HTTP response, but don't require it
                try:
                    # Try multiple Host header variants
                    common_hosts = [profile.host]
                    req = (
                        f"GET / HTTP/1.1\r\n"
                        f"Host: {profile.host}\r\n"
                        f"User-Agent: Mozilla/5.0\r\n"
                        f"Accept: */*\r\n"
                        f"Connection: close\r\n"
                        f"\r\n"
                    )
                    writer.write(req.encode())
                    await asyncio.wait_for(writer.drain(), timeout=2)

                    response = b""
                    try:
                        while len(response) < 4096:
                            chunk = await asyncio.wait_for(reader.read(2048), timeout=2)
                            if not chunk:
                                break
                            response += chunk
                    except asyncio.TimeoutError:
                        pass

                    text = response.decode(errors="replace")
                    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")

                    if lines and "HTTP/" in lines[0]:
                        parts = lines[0].split()
                        if len(parts) >= 2:
                            try:
                                profile.response_status = int(parts[1])
                            except ValueError:
                                pass

                        for line in lines[1:]:
                            if ":" in line:
                                k, v = line.split(":", 1)
                                profile.headers[k.strip().lower()] = v.strip()

                        profile.server = profile.headers.get("server", "")
                    else:
                        # No HTTP response - server probably wants specific Host header
                        # but TCP/SSL works = server exists
                        profile.response_status = 0  # unknown but alive
                        profile.server = "unknown (host-header required)"

                    # Check ALPN for HTTP/2
                    if is_ssl:
                        try:
                            ssl_obj = writer.get_extra_info("ssl_object")
                            if ssl_obj:
                                alpn = ssl_obj.selected_alpn_protocol()
                                if alpn == "h2":
                                    profile.supports_http2 = True
                        except Exception:
                            pass

                except Exception as http_err:
                    logger.debug(f"HTTP probe on {profile.host}:{port} failed: {http_err}")
                    profile.response_status = 0
                    profile.server = "unknown (TCP open, HTTP no-response)"

                try:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), timeout=1)
                except Exception:
                    pass

                return  # Success - mark profile as alive and exit

            except Exception as e:
                logger.debug(f"Raw socket probe ({profile.host}:{port} ssl={is_ssl}) failed: {e}")
                continue

    async def _fallback_socket_probe(self, profile: TargetProfile):
        """Pure socket fallback if curl_cffi not available"""
        try:
            loop = asyncio.get_event_loop()
            ssl_ctx = None
            if profile.is_https:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
                ssl_ctx.set_alpn_protocols(["h2", "http/1.1"])

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(profile.host, profile.port, ssl=ssl_ctx,
                                        server_hostname=profile.host if profile.is_https else None),
                timeout=self.timeout
            )

            req = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {profile.host}\r\n"
                f"User-Agent: Mozilla/5.0\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            writer.write(req.encode())
            await writer.drain()

            response = b""
            try:
                while len(response) < 8192:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=3)
                    if not chunk:
                        break
                    response += chunk
            except asyncio.TimeoutError:
                pass

            text = response.decode(errors="replace")
            lines = text.split("\r\n")
            if lines and "HTTP/" in lines[0]:
                parts = lines[0].split()
                if len(parts) >= 2:
                    try:
                        profile.response_status = int(parts[1])
                        profile.is_alive = True
                    except ValueError:
                        pass

            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    profile.headers[k.strip().lower()] = v.strip()

            profile.server = profile.headers.get("server", "")

            try:
                if profile.is_https and writer.get_extra_info("ssl_object"):
                    alpn = writer.get_extra_info("ssl_object").selected_alpn_protocol()
                    if alpn == "h2":
                        profile.supports_http2 = True
            except Exception:
                pass

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        except Exception as e:
            logger.debug(f"Socket probe failed: {e}")

    async def _http2_probe(self, profile: TargetProfile):
        """Direct ALPN negotiation to confirm HTTP/2 support"""
        try:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            ssl_ctx.set_alpn_protocols(["h2", "http/1.1"])

            loop = asyncio.get_event_loop()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(profile.host, profile.port, ssl=ssl_ctx,
                                        server_hostname=profile.host),
                timeout=self.timeout
            )

            sock = writer.get_extra_info("ssl_object")
            if sock:
                alpn = sock.selected_alpn_protocol()
                if alpn == "h2":
                    profile.supports_http2 = True
                    logger.debug(f"{profile.host} supports HTTP/2 (ALPN=h2)")

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        except Exception as e:
            logger.debug(f"HTTP/2 ALPN probe failed: {e}")

    def _detect_cdn(self, profile: TargetProfile):
        """Detect CDN from response headers"""
        headers_lower = {k.lower(): v.lower() for k, v in profile.headers.items()}
        all_text = " ".join(headers_lower.keys()) + " " + " ".join(headers_lower.values())

        for cdn_name, signatures in self.CDN_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in all_text:
                    profile.cdn = cdn_name
                    return

        server = profile.server.lower()
        if "cloudflare" in server:
            profile.cdn = "cloudflare"
        elif "akamai" in server:
            profile.cdn = "akamai"
        elif "fastly" in server:
            profile.cdn = "fastly"
        elif "cloudfront" in server:
            profile.cdn = "cloudfront"

    def _detect_waf(self, profile: TargetProfile):
        """Detect WAF from response headers and status codes"""
        headers_lower = {k.lower(): v.lower() for k, v in profile.headers.items()}
        all_text = " ".join(headers_lower.keys()) + " " + " ".join(headers_lower.values())

        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in all_text:
                    profile.waf = waf_name
                    return

        if profile.cdn == "cloudflare" and profile.response_status in (403, 503, 429):
            profile.waf = "cloudflare"

    def _detect_rate_limit(self, profile: TargetProfile):
        """Detect rate limit headers"""
        headers_lower = {k.lower(): v for k, v in profile.headers.items()}
        rate_limit_headers = [
            "x-ratelimit-limit", "x-ratelimit-remaining", "x-rate-limit-limit",
            "ratelimit-limit", "x-ratelimit-reset", "retry-after",
        ]
        for h in rate_limit_headers:
            if h in headers_lower:
                profile.rate_limited = True
                return

        if profile.response_status == 429:
            profile.rate_limited = True

    async def _rate_limit_probe(self, profile: TargetProfile):
        """Send 10 quick requests to detect rate limiting"""
        try:
            from curl_cffi.requests import AsyncSession

            kwargs = {"impersonate": "chrome120", "timeout": 5}
            async with AsyncSession(**kwargs) as sess:
                tasks = []
                for _ in range(10):
                    tasks.append(self._safe_get(sess, profile.url))
                results = await asyncio.gather(*tasks, return_exceptions=True)

                status_counts = {}
                for r in results:
                    if isinstance(r, int):
                        status_counts[r] = status_counts.get(r, 0) + 1

                if status_counts.get(429, 0) > 0 or status_counts.get(403, 0) >= 3:
                    profile.rate_limited = True
                if status_counts.get(503, 0) >= 3:
                    profile.rate_limited = True
        except Exception:
            pass

    async def _safe_get(self, sess, url: str) -> int:
        try:
            resp = await sess.get(url, timeout=5)
            return resp.status_code
        except Exception:
            return 0

    def _recommend_strategy(self, profile: TargetProfile):
        """Choose optimal attack method based on target profile"""
        if profile.supports_http2:
            profile.needs_rapid_reset = True
            profile.recommended_method = "rapid-reset"
        else:
            profile.recommended_method = "http-flood"

        if profile.rate_limited or profile.waf in ("cloudflare", "akamai_kona", "imperva"):
            profile.needs_proxy = True
            if profile.supports_http2:
                profile.recommended_strategy = "rapid-reset+proxy"
            else:
                profile.recommended_strategy = "proxy-flood+adaptive"
        elif profile.cdn != "none":
            profile.recommended_strategy = "rapid-reset" if profile.supports_http2 else "mixed"
        else:
            profile.recommended_strategy = profile.recommended_method


def print_profile(profile: TargetProfile, color_func=None):
    """Pretty print target profile"""
    c = color_func if color_func else lambda t, s: s
    print(f"\n {c('c','='*70)}")
    print(f" {c('w','  TARGET INTELLIGENCE REPORT')}")
    print(f" {c('c','='*70)}")
    print(f"  Target:           {profile.url}")
    print(f"  Status:           {profile.response_status} ({c('g','ALIVE') if profile.is_alive else c('r','DEAD')})")
    print(f"  Response time:    {profile.response_time_ms}ms")
    print(f"  Server:           {profile.server or 'unknown'}")
    print(f" {c('d','-'*70)}")
    print(f"  HTTP/2 support:   {c('g','YES') if profile.supports_http2 else c('y','NO')}")
    print(f"  HTTP/3 support:   {c('g','YES') if profile.supports_http3 else c('y','NO')}")
    print(f"  CDN:              {c('y',profile.cdn) if profile.cdn != 'none' else c('g','none')}")
    print(f"  WAF:              {c('r',profile.waf) if profile.waf != 'none' else c('g','none')}")
    print(f"  Rate limited:     {c('r','YES') if profile.rate_limited else c('g','NO')}")
    print(f" {c('d','-'*70)}")
    print(f"  {c('y','RECOMMENDED METHOD:')}   {c('w',profile.recommended_method.upper())}")
    print(f"  {c('y','STRATEGY:')}             {c('w',profile.recommended_strategy.upper())}")
    print(f"  {c('y','NEEDS RAPID RESET:')}    {c('g','YES') if profile.needs_rapid_reset else c('d','no')}")
    print(f"  {c('y','NEEDS PROXY:')}          {c('g','YES') if profile.needs_proxy else c('d','no')}")
    print(f" {c('c','='*70)}\n")
