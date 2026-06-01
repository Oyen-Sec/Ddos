"""
Securiwaf bypass module 2026.
Generated: auto-detection + curl_cffi bypass + origin discovery.
"""
import asyncio, logging, socket
from typing import Optional, Dict
from core.bypass.bypass_base import BaseBypass

logger = logging.getLogger(__name__)

class SecuriwafBypass(BaseBypass):
    """Bypass module for Securiwaf."""

    @staticmethod
    def detect(headers: dict) -> bool:
        if not headers:
            return False
        h = {k.lower(): v.lower() for k, v in headers.items()}
        # Generic WAF detection based on blocking behavior
        blocked_keywords = ["blocked", "denied", "forbidden", "waf", "rejected"]
        server = h.get("server", "")
        if any(w in server for w in blocked_keywords):
            return True
        if h.get("x-waf") or h.get("x-blocked-by") or h.get("x-filter"):
            return True
        return False
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
