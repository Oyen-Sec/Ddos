"""
Litespeed bypass module 2026.
Generated: auto-detection + curl_cffi bypass + origin discovery.
"""
import asyncio, logging, socket
from typing import Optional, Dict
from core.bypass.bypass_base import BaseBypass

logger = logging.getLogger(__name__)

class LitespeedBypass(BaseBypass):
    """Bypass module for Litespeed."""

    @staticmethod
    def detect(headers: dict) -> bool:
        if not headers:
            return False
        h = {k.lower(): v.lower() for k, v in headers.items()}
        server = h.get("server", "")
        if "litespeed" in server or "openlitespeed" in server:
            return True
        return False

    async def bypass(self, hostname: str, env: dict = None, proxy_url: Optional[str] = None) -> Dict:
        # LiteSpeed: CVE-2026-48172 (privilege escalation)
        url = f"https://{hostname}/"
        return await self.bypass_with_curl_cffi(url, proxy_url)
