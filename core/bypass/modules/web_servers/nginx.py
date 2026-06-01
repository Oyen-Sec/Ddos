"""
Nginx bypass module 2026.
Generated: auto-detection + curl_cffi bypass + origin discovery.
"""
import asyncio, logging, socket
from typing import Optional, Dict
from core.bypass.bypass_base import BaseBypass

logger = logging.getLogger(__name__)

class NginxBypass(BaseBypass):
    """Bypass module for Nginx."""

    @staticmethod
    def detect(headers: dict) -> bool:
        if not headers:
            return False
        h = {k.lower(): v.lower() for k, v in headers.items()}
        server = h.get("server", "")
        if "nginx" in server and "cloudflare" not in server:
            return True
        return False

    async def bypass(self, hostname: str, env: dict = None, proxy_url: Optional[str] = None) -> Dict:
        # Nginx: alias traversal, merge_slashes off, CRLF injection
        url = f"https://{hostname}/"
        result = await self.bypass_with_curl_cffi(url, proxy_url)
        if not result.get("success"):
            result = await self.bypass_with_oversized_payload(url, proxy_url=proxy_url)
        return result
