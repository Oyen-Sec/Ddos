"""
Citrix Netscaler bypass module 2026.
Generated: auto-detection + curl_cffi bypass + origin discovery.
"""
import asyncio, logging, socket
from typing import Optional, Dict
from core.bypass.bypass_base import BaseBypass

logger = logging.getLogger(__name__)

class CitrixNetscalerBypass(BaseBypass):
    """Bypass module for Citrix Netscaler."""

    @staticmethod
    def detect(headers: dict) -> bool:
        if not headers:
            return False
        h = {k.lower(): v.lower() for k, v in headers.items()}
        server = h.get("server", "")
        if "netscaler" in server or "citrix" in server:
            return True
        if "x-ns" in h or "x-citrix" in h:
            return True
        return False

    async def find_origin(self, hostname: str, env: dict = None) -> Optional[str]:
        return await super().find_origin(hostname, env)

    async def bypass(self, hostname: str, env: dict = None, proxy_url: Optional[str] = None) -> Dict:
        url = f"https://{hostname}/"
        result = await self.bypass_with_curl_cffi(url, proxy_url)
        if not result.get("success"):
            oversized = await self.bypass_with_oversized_payload(url, proxy_url=proxy_url)
            if oversized.get("success"):
                return oversized
        return result
