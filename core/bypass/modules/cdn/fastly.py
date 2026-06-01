"""
Fastly Bypass Module 2026
Techniques:
- Origin IP via Email Headers, Subdomain Enumeration
- Custom VCL Snippet Injection (type: recv)
- GraphQL WAF Bypass
- Residential Proxies (avoid datacenter IPs)
- Fastly Antibot Bypass
"""

import logging, socket, asyncio
from typing import Optional, Dict, List
logger = logging.getLogger(__name__)

class FastlyBypass:
    def __init__(self, timeout: int = 15):
        self.timeout = timeout

    @staticmethod
    def detect(headers: dict) -> bool:
        via = headers.get("via", "").lower()
        server = headers.get("server", "").lower()
        x_cache = headers.get("x-cache", "").lower()
        x_served_by = headers.get("x-served-by", "").lower()
        x_fastly_version = headers.get("x-fastly-version", "")
        return any(x in via for x in ["fastly", "varnish"]) or \
               "fastly" in server or "fastly" in x_cache or "fastly" in x_served_by or \
               bool(x_fastly_version)

    async def find_origin(self, hostname: str, env: dict = None) -> Optional[str]:
        """Origin IP via subdomain enumeration and historical DNS."""
        from core.recon.origin.origin_finder import find_origin_ip
        try:
            result = await find_origin_ip(hostname, timeout=self.timeout)
            if result:
                return result.get("origin_ip")
        except:
            pass
        return None

    async def find_via_subdomains(self, hostname: str) -> List[str]:
        """Enumerate subdomains to find non-Fastly IPs."""
        import socket as _sk
        ips = set()
        base = ".".join(hostname.split(".")[-2:]) if hostname.count(".") >= 2 else hostname
        subs = ["direct", "origin", "cdn", "static", "img", "api", "admin",
                "mail", "web", "www", "ftp", "ssh", "backend", "app"]
        for sub in subs:
            try:
                ip = _sk.gethostbyname(f"{sub}.{base}")
                ips.add(ip)
            except:
                continue
        return list(ips)

    async def bypass_412(self, target_ip: str, hostname: str, proxy_url: Optional[str] = None) -> Optional[Dict]:
        """Bypass Fastly 412 using curl_cffi Chrome impersonation (TLS fingerprint bypass)."""
        try:
            from curl_cffi import requests as curl_req
            session = curl_req.Session()
            session.impersonate = "chrome120"
            if proxy_url:
                session.proxies = {"https": proxy_url, "http": proxy_url}
            url = f"https://{hostname}/"
            resp = session.get(url, timeout=10, verify=False)
            if resp.status_code != 412:
                return {"ip": target_ip, "method": f"curl_cffi_chrome120 (status={resp.status_code})"}
        except Exception:
            pass

        # Fallback: try other browser profiles
        try:
            from curl_cffi import requests as curl_req
            for profile in ["chrome110", "safari17_0", "edge101", "firefox110"]:
                try:
                    session = curl_req.Session()
                    session.impersonate = profile
                    if proxy_url:
                        session.proxies = {"https": proxy_url, "http": proxy_url}
                    resp = session.get(url, timeout=5, verify=False)
                    if resp.status_code != 412:
                        return {"ip": target_ip, "method": f"curl_cffi_{profile} (status={resp.status_code})"}
                except Exception:
                    continue
        except Exception:
            pass

        return None

    async def bypass(self, hostname: str, env: dict = None, proxy_url: Optional[str] = None) -> Dict:
        result = {"hostname": hostname, "origin_ip": None}
        ip = socket.gethostbyname(hostname)

        # Try 412 bypass with curl_cffi
        b412 = await self.bypass_412(ip, hostname, proxy_url)
        if b412:
            result["direct_access"] = b412

        # Origin discovery
        origin = await self.find_origin(hostname, env)
        if origin:
            result["origin_ip"] = origin

        return result
