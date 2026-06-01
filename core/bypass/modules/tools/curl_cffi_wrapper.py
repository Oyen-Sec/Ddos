"""
curl_cffi wrapper - Chrome TLS fingerprint impersonation
Replicates Chrome's exact TLS fingerprint including HTTP/2 settings,
cipher suites, ALPN protocols for Akamai/Cloudflare bypass.
"""
import logging
from typing import Optional, Dict, Any
logger = logging.getLogger(__name__)

class CurlCffiWrapper:
    _instance = None
    _session = None

    @classmethod
    def get_session(cls, impersonate: str = "chrome120"):
        if cls._session is None:
            try:
                from curl_cffi.requests import AsyncSession
                cls._session = AsyncSession(impersonate=impersonate, timeout=30)
            except ImportError:
                logger.warning("curl_cffi not installed, falling back to requests")
                return None
        return cls._session

    @classmethod
    async def get(cls, url: str, **kwargs) -> Optional[Dict]:
        sess = cls.get_session()
        if sess is None:
            return None
        try:
            resp = await sess.get(url, **kwargs)
            return {"status": resp.status_code, "text": resp.text, "headers": dict(resp.headers)}
        except Exception as e:
            logger.debug(f"curl_cffi get failed: {e}")
            return None

    @classmethod
    async def close(cls):
        if cls._session:
            await cls._session.close()
            cls._session = None
