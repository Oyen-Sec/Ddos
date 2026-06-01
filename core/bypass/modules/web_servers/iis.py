"""
Iis bypass module 2026.
Generated: auto-detection + curl_cffi bypass + origin discovery.
"""
import asyncio, logging, socket
from typing import Optional, Dict
from core.bypass.bypass_base import BaseBypass

logger = logging.getLogger(__name__)

class IISBypass(BaseBypass):
    """Bypass module for Iis."""

    @staticmethod
    def detect(headers: dict) -> bool:
        if not headers:
            return False
        h = {k.lower(): v.lower() for k, v in headers.items()}
        server = h.get("server", "")
        if "iis" in server or "microsoft-iis" in server or "microsoft-httpapi" in server:
            return True
        if "x-aspnet" in h or "x-aspnetmvc" in h:
            return True
        return False

    async def bypass(self, hostname: str, env: dict = None, proxy_url: Optional[str] = None) -> Dict:
        # IIS: WebDAV misconfig, Padding Oracle (CVE-2024-3566)
        url = f"https://{hostname}/"
        result = await self.bypass_with_curl_cffi(url, proxy_url)
        if not result.get("success"):
            # Try short filename disclosure bypass
            from curl_cffi import requests as curl_req
            session = curl_req.Session()
            session.impersonate = "chrome120"
            if proxy_url:
                session.proxies = {"https": proxy_url, "http": proxy_url}
            resp = session.get(url.replace("https://", "http://"), timeout=self.timeout, verify=False)
            if resp.status_code not in [403, 412]:
                return {"success": True, "status_code": resp.status_code, "method": "http_downgrade"}
        return result
