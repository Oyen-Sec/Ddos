"""
F5 Asm bypass module 2026.
Generated: auto-detection + curl_cffi bypass + origin discovery.
"""
import asyncio, logging, socket
from typing import Optional, Dict
from core.bypass.bypass_base import BaseBypass

logger = logging.getLogger(__name__)

class F5AsmBypass(BaseBypass):
    """Bypass module for F5 Asm."""

    @staticmethod
    def detect(headers: dict) -> bool:
        if not headers:
            return False
        h = {k.lower(): v.lower() for k, v in headers.items()}
        if "x-asm-version" in h or "x-asm-policy" in h or "x-wa-ver" in h:
            return True
        server = h.get("server", "")
        if "bigip" in server or "f5" in server:
            return True
        cookies = h.get("set-cookie", "")
        if "bigipserver" in cookies.lower() or "mr" in cookies.lower():
            return True
        return False

    async def find_origin(self, hostname: str, env: dict = None) -> Optional[str]:
        return await super().find_origin(hostname, env)

    async def bypass(self, hostname: str, env: dict = None, proxy_url: Optional[str] = None) -> Dict:
        url = f"https://{hostname}/"
        # F5 BIG-IP: regex reversing + oversized payloads
        result = await self.bypass_with_curl_cffi(url, proxy_url)
        if not result.get("success"):
            result = await self.bypass_with_oversized_payload(url, 32768, proxy_url)
        return result
