"""
Io River bypass module 2026.
Generated: auto-detection + curl_cffi bypass + origin discovery.
"""
import asyncio, logging, socket
from typing import Optional, Dict
from core.bypass.bypass_base import BaseBypass

logger = logging.getLogger(__name__)

class IoRiverBypass(BaseBypass):
    """Bypass module for Io River."""

    @staticmethod
    def detect(headers: dict) -> bool:
        if not headers:
            return False
        h = {k.lower(): v.lower() for k, v in headers.items()}
        if "x-ioriver" in h:
            return True
        server = h.get("server", "")
        if "ioriver" in server:
            return True
        return False

    async def find_origin(self, hostname: str, env: dict = None) -> Optional[str]:
        return await super().find_origin(hostname, env)

    async def bypass(self, hostname: str, env: dict = None, proxy_url: Optional[str] = None) -> Dict:
        url = f"https://{hostname}/"
        # Try curl_cffi bypass
        result = await self.bypass_with_curl_cffi(url, proxy_url)
        # Try origin bypass if curl_cffi fails
        if not result.get("success"):
            origin = await self.find_origin(hostname, env)
            if origin:
                return {"success": True, "origin_ip": origin, "method": "origin_discovery"}
        return result
