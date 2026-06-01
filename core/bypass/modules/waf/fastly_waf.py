"""
Fastly WAF/CDN bypass module 2026.
Bypasses Fastly 412 Precondition Failed triggered by TLS fingerprint (JA3/JA4) detection.
Uses curl_cffi for browser TLS impersonation + proxy support.
"""
import asyncio
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from core.bypass.bypass_base import BaseBypass

logger = logging.getLogger("fastly_waf_bypass")

FASTLY_412_HEADERS = {
    "x-fastly-version", "x-timer", "x-served-by", "x-cache",
    "x-cache-hits", "x-s", "fastly-debug-digest",
}
FASTLY_412_STATUS = 412
FASTLY_412_BODY_EMPTY = True


@dataclass
class FastlyBypassResult:
    success: bool
    status_code: int
    method: str
    headers: Dict[str, str]
    body: str = ""


class FastlyWafBypass(BaseBypass):
    def __init__(self, timeout: int = 15):
        super().__init__(timeout)

    async def find_origin(self, hostname: str, env: dict = None) -> Optional[str]:
        return await super().find_origin(hostname, env)

    async def bypass(self, hostname: str, env: dict = None, proxy_url: Optional[str] = None) -> Dict:
        url = f"https://{hostname}/"
        result = await self.bypass_with_curl_cffi(url, proxy_url, self.timeout)
        if result.success:
            return {"success": True, "status_code": result.status_code, "method": result.method, "body_length": len(result.body)}
        rotated = await self.bypass_with_fingerprint_rotation(url, proxy_url, self.timeout)
        if rotated.success:
            return {"success": True, "status_code": rotated.status_code, "method": rotated.method, "body_length": len(rotated.body)}
        oversize = await self.bypass_with_oversized_payload(url, proxy_url=proxy_url)
        if oversize.get("success"):
            return oversize
        return {"success": False, "status_code": result.status_code, "method": "all_failed"}

    @staticmethod
    def detect(headers: dict) -> bool:
        if not headers:
            return False
        h = {k.lower(): v for k, v in headers.items()}
        if h.get("x-fastly-version"):
            return True
        server = h.get("server", "")
        if "fastly" in server.lower():
            return True
        via = h.get("via", "")
        if "fastly" in via.lower():
            return True
        return False

    @staticmethod
    def is_412_blocked(headers: dict, status_code: int) -> bool:
        return status_code == 412 and FastlyWafBypass.detect(headers)

    @staticmethod
    async def bypass_with_curl_cffi(
        url: str,
        proxy_url: Optional[str] = None,
        timeout: int = 15
    ) -> FastlyBypassResult:
        """Bypass Fastly 412 using curl_cffi Chrome impersonation."""
        try:
            from curl_cffi import requests as curl_req

            session = curl_req.Session()
            session.impersonate = "chrome120"

            if proxy_url:
                session.proxies = {"https": proxy_url, "http": proxy_url}

            resp = session.get(url, timeout=timeout, verify=False)
            success = resp.status_code != 412
            return FastlyBypassResult(
                success=success,
                status_code=resp.status_code,
                method="curl_cffi_chrome120",
                headers=dict(resp.headers),
                body=resp.text[:2000] if success else "",
            )
        except Exception as e:
            logger.warning(f"curl_cffi bypass failed: {e}")
            return FastlyBypassResult(False, 0, "curl_cffi_error", {}, str(e))

    @staticmethod
    async def bypass_with_fingerprint_rotation(
        url: str,
        proxy_url: Optional[str] = None,
        timeout: int = 15
    ) -> FastlyBypassResult:
        """Rotate through browser fingerprints to evade Fastly."""
        profiles = ["chrome120", "chrome110", "chrome116", "chrome99",
                     "chrome107", "chrome101", "safari15_3", "safari17_0",
                     "edge101", "firefox110"]
        try:
            from curl_cffi import requests as curl_req

            for profile in profiles:
                try:
                    session = curl_req.Session()
                    session.impersonate = profile
                    if proxy_url:
                        session.proxies = {"https": proxy_url, "http": proxy_url}

                    resp = session.get(url, timeout=timeout, verify=False)
                    if resp.status_code != 412:
                        return FastlyBypassResult(
                            success=True,
                            status_code=resp.status_code,
                            method=f"curl_cffi_{profile}",
                            headers=dict(resp.headers),
                            body=resp.text[:2000],
                        )
                except Exception:
                    continue
            return FastlyBypassResult(False, 412, "all_profiles_failed", {}, "")
        except Exception as e:
            logger.warning(f"fingerprint rotation bypass failed: {e}")
            return FastlyBypassResult(False, 0, "rotation_error", {}, str(e))

    @staticmethod
    async def bypass_all(
        url: str,
        proxy_url: Optional[str] = None,
        timeout: int = 15,
    ) -> List[FastlyBypassResult]:
        """Run all bypass methods and return results."""
        results = []
        results.append(await FastlyWafBypass.bypass_with_curl_cffi(url, proxy_url, timeout))
        for r in results:
            if r.success:
                return results
        results.append(await FastlyWafBypass.bypass_with_fingerprint_rotation(url, proxy_url, timeout))
        return results
