"""
Imperva bypass module 2026.
Generated: auto-detection + curl_cffi bypass + origin discovery.
"""
import asyncio, logging, socket
from typing import Optional, Dict
from core.bypass.bypass_base import BaseBypass

logger = logging.getLogger(__name__)

class ImpervaBypass(BaseBypass):
    """Bypass module for Imperva."""

    @staticmethod
    def detect(headers: dict) -> bool:
        if not headers:
            return False
        h = {k.lower(): v.lower() for k, v in headers.items()}
        if "x-cdn" in h or "x-iinfo" in h:
            return True
        server = h.get("server", "")
        if "incapsula" in server:
            return True
        cookies = h.get("set-cookie", "")
        if "incap_ses" in cookies or "visid_incap" in cookies:
            return True
        return False

    async def find_origin(self, hostname: str, env: dict = None) -> Optional[str]:
        return await super().find_origin(hostname, env)

    async def bypass(self, hostname: str, env: dict = None, proxy_url: Optional[str] = None) -> Dict:
        url = f"https://{hostname}/"
        # Imperva: use residential proxies + oversized payloads
        oversized = await self.bypass_with_oversized_payload(url, 16384, proxy_url)
        if oversized.get("success"):
            return oversized
        return await self.bypass_with_curl_cffi(url, proxy_url)
