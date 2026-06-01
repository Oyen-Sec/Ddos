"""
Cloudflare Server bypass module 2026.
Generated: auto-detection + curl_cffi bypass + origin discovery.
"""
import asyncio, logging, socket
from typing import Optional, Dict
from core.bypass.bypass_base import BaseBypass

logger = logging.getLogger(__name__)

class CloudflareServerBypass(BaseBypass):
    """Bypass module for Cloudflare Server."""

    @staticmethod
    def detect(headers: dict) -> bool:
        if not headers:
            return False
        h = {k.lower(): v.lower() for k, v in headers.items()}
        cf_hdrs = ["cf-ray", "cf-cache-status", "__cfduid", "cf-request-id"]
        if any(h in h for h in cf_hdrs):
            return True
        server = h.get("server", "")
        if "cloudflare" in server:
            return True
        cookies = h.get("set-cookie", "")
        if "__cfduid" in cookies or "__cf_bm" in cookies:
            return True
        return False

    async def bypass(self, hostname: str, env: dict = None, proxy_url: Optional[str] = None) -> Dict:
        url = f"https://{hostname}/"
        return await self.bypass_with_curl_cffi(url, proxy_url)
