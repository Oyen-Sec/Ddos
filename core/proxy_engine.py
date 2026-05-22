import asyncio
import time
import random
import logging
import re
from dataclasses import dataclass
from typing import Optional, List, Dict, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("proxy_engine")

PROXY_TIERS = {
    "mobile": 1,    # CGNAT mobile - highest trust
    "residential": 2,
    "ipv6": 3,
    "datacenter": 4,
}


@dataclass
class ProxyStatus:
    url: str
    protocol: str
    host: str
    port: int
    alive: bool = False
    tier: str = "datacenter"
    connect_time_ms: float = 0.0
    external_ip: str = ""
    last_checked: float = 0.0
    fail_count: int = 0
    success_count: int = 0
    rtt_ema: float = 0.0


class ProxyValidator:
    def __init__(self, check_url: str = "https://httpbin.org/ip",
                 connect_timeout: int = 3, read_timeout: int = 3,
                 max_connect_time_ms: int = 3000):
        self.check_url = check_url
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.max_connect_time_ms = max_connect_time_ms

    def set_target(self, target_url: str):
        parsed = urlparse(target_url)
        self.check_url = f"{parsed.scheme}://{parsed.netloc}/cdn-cgi/trace"

    def _parse(self, url: str) -> Tuple[str, str, int]:
        p = urlparse(url)
        return p.scheme.lower(), p.hostname or "", p.port or 1080

    def _guess_tier(self, url: str) -> str:
        host = urlparse(url).hostname or ""
        cidr_4 = re.match(r'^10\.|^172\.(1[6-9]|2\d|3[01])\.|^192\.168\.', host)
        if cidr_4:
            return "datacenter"
        return "datacenter"

    def _detect_tier(self, proxy_url: str) -> str:
        return self._guess_tier(proxy_url)

    async def validate(self, proxy_url: str) -> Optional[ProxyStatus]:
        protocol, host, port = self._parse(proxy_url)
        st = ProxyStatus(url=proxy_url, protocol=protocol, host=host, port=port, tier=self._detect_tier(proxy_url))
        try:
            if protocol in ("http", "https"):
                from aiohttp import TCPConnector, ClientSession, ClientTimeout
                connector = TCPConnector(ssl=False)
                timeout = ClientTimeout(total=self.connect_timeout + self.read_timeout)
                async with ClientSession(connector=connector, timeout=timeout) as session:
                    start = time.monotonic()
                    async with session.get(self.check_url, timeout=timeout) as resp:
                        elapsed = (time.monotonic() - start) * 1000
                        st.connect_time_ms = round(elapsed, 2)
                        if resp.status != 200:
                            return None
                        try:
                            data = await resp.json()
                            st.external_ip = data.get("origin", "")
                        except Exception:
                            text = await resp.text()
                            m = re.search(r'\d+\.\d+\.\d+\.\d+', text)
                            if m:
                                st.external_ip = m.group(0)
                        st.alive = True
                        st.last_checked = time.time()
            elif protocol in ("socks4", "socks5"):
                try:
                    from aiohttp_socks import ProxyConnector
                    from aiohttp import ClientSession, ClientTimeout
                    connector = ProxyConnector.from_url(proxy_url)
                    timeout = ClientTimeout(total=self.connect_timeout + self.read_timeout)
                    async with ClientSession(connector=connector, timeout=timeout) as session:
                        start = time.monotonic()
                        async with session.get(self.check_url, timeout=timeout) as resp:
                            elapsed = (time.monotonic() - start) * 1000
                            st.connect_time_ms = round(elapsed, 2)
                            if resp.status != 200:
                                return None
                            st.alive = True
                            st.last_checked = time.time()
                except ImportError:
                    return None
            else:
                return None
            if st.alive and st.connect_time_ms > self.max_connect_time_ms:
                st.alive = False
                return None
            return st
        except (asyncio.TimeoutError, Exception):
            return None


class ProxyPool:
    def __init__(self, connect_timeout: int = 3, min_pool: int = 10,
                 health_check_interval: int = 60, max_fail: int = 3):
        self._pools: Dict[str, List[ProxyStatus]] = {"mobile": [], "residential": [], "ipv6": [], "datacenter": []}
        self._pending: List[ProxyStatus] = []
        self._dead: List[str] = []
        self._lock = asyncio.Lock()
        self._validator = ProxyValidator(connect_timeout=connect_timeout, read_timeout=connect_timeout)
        self._running = False
        self.min_pool = min_pool
        self.health_check_interval = health_check_interval
        self.max_fail = max_fail

    async def load(self, proxies: List[str]) -> int:
        count = 0
        for url in proxies:
            url = url.strip()
            if not url or url.startswith("#"):
                continue
            parsed = urlparse(url)
            if parsed.scheme in ("http", "https", "socks4", "socks5"):
                self._pending.append(ProxyStatus(url=url, protocol=parsed.scheme,
                                                  host=parsed.hostname or "",
                                                  port=parsed.port or 1080))
                count += 1
        return count

    async def load_file(self, path: str) -> int:
        try:
            with open(path, "r") as f:
                return await self.load(f.readlines())
        except FileNotFoundError:
            return 0

    async def quick_validate(self, count: int = 200, concurrency: int = 100) -> int:
        batch = self._pending[:count]
        if not batch:
            return 0
        sem = asyncio.Semaphore(concurrency)
        async def _v(ps):
            async with sem:
                return await self._validator.validate(ps.url)
        results = await asyncio.gather(*[_v(ps) for ps in batch], return_exceptions=True)
        alive = 0
        validated_urls = set()
        for i, r in enumerate(results):
            ps = batch[i]
            validated_urls.add(ps.url)
            if isinstance(r, ProxyStatus) and r.alive:
                tier = r.tier if r.tier in self._pools else "datacenter"
                self._pools[tier].append(r)
                alive += 1
            else:
                self._dead.append(ps.url)
        self._pending = [ps for ps in self._pending if ps.url not in validated_urls]
        return alive

    async def validate_background(self, concurrency: int = 100, batch_size: int = 500):
        while self._pending:
            batch = self._pending[:batch_size]
            sem = asyncio.Semaphore(concurrency)
            async def _v(ps):
                async with sem:
                    r = await self._validator.validate(ps.url)
                    if r and r.alive:
                        async with self._lock:
                            t = r.tier if r.tier in self._pools else "datacenter"
                            self._pools[t].append(r)
                    else:
                        async with self._lock:
                            self._dead.append(ps.url)
            await asyncio.gather(*[_v(ps) for ps in batch], return_exceptions=True)
            async with self._lock:
                for ps in batch:
                    if ps in self._pending:
                        self._pending.remove(ps)
            if not self._running:
                break

    async def health_loop(self):
        self._running = True
        while self._running:
            await asyncio.sleep(self.health_check_interval)
            if not self._running:
                break
            for tier in self._pools:
                alive = []
                for ps in self._pools[tier]:
                    r = await self._validator.validate(ps.url)
                    if r and r.alive:
                        alive.append(r)
                    else:
                        ps.fail_count += 1
                        if ps.fail_count >= self.max_fail:
                            self._dead.append(ps.url)
                        else:
                            alive.append(ps)
                self._pools[tier] = alive

    async def stop(self):
        self._running = False

    async def get_proxy(self, preferred_tier: str = "mobile") -> Optional[ProxyStatus]:
        tiers = [preferred_tier, "residential", "ipv6", "datacenter"]
        async with self._lock:
            for t in tiers:
                if t in self._pools and self._pools[t]:
                    ps = self._pools[t].pop(0)
                    self._pools[t].append(ps)
                    return ps
            all_proxies = []
            for pool in self._pools.values():
                all_proxies.extend(pool)
            if all_proxies:
                ps = all_proxies.pop(0)
                return ps
        return None

    async def get_proxy_weighted(self, preferred_tier: str = "mobile") -> Optional[ProxyStatus]:
        """
        Get proxy via weighted random selection.
        Higher weight = lower fail_count + lower rtt + higher success_count.
        """
        tiers = [preferred_tier, "residential", "ipv6", "datacenter"]
        async with self._lock:
            for t in tiers:
                if t in self._pools and self._pools[t]:
                    pool = self._pools[t]
                    weights = []
                    for ps in pool:
                        # Weight formula: success_count / (1 + fail_count + rtt_ema/1000)
                        w = (ps.success_count + 1) / (1 + ps.fail_count + ps.rtt_ema / 1000)
                        weights.append(w)
                    if sum(weights) == 0:
                        return random.choice(pool)
                    return random.choices(pool, weights=weights, k=1)[0]
        return None

    async def get_proxy_random(self, preferred_tier: str = "mobile") -> Optional[ProxyStatus]:
        """Pure random selection within preferred tier."""
        tiers = [preferred_tier, "residential", "ipv6", "datacenter"]
        async with self._lock:
            for t in tiers:
                if t in self._pools and self._pools[t]:
                    return random.choice(self._pools[t])
        return None

    async def get_proxy_sticky(self, worker_id: int, preferred_tier: str = "mobile") -> Optional[ProxyStatus]:
        """Sticky session: same worker_id gets same proxy via modulo."""
        tiers = [preferred_tier, "residential", "ipv6", "datacenter"]
        async with self._lock:
            for t in tiers:
                if t in self._pools and self._pools[t]:
                    pool = self._pools[t]
                    return pool[worker_id % len(pool)]
        return None

    async def report_success(self, ps: ProxyStatus, rtt_ms: float = 0.0):
        """Report successful use of proxy. Updates EMA and counter."""
        ps.success_count += 1
        if rtt_ms > 0:
            # EMA with alpha=0.3
            ps.rtt_ema = ps.rtt_ema * 0.7 + rtt_ms * 0.3 if ps.rtt_ema > 0 else rtt_ms

    async def report_failure(self, ps: ProxyStatus):
        """Report failed use. Auto-quarantine if exceeds max_fail."""
        ps.fail_count += 1
        if ps.fail_count >= self.max_fail:
            async with self._lock:
                for t in self._pools:
                    if ps in self._pools[t]:
                        self._pools[t].remove(ps)
                        self._dead.append(ps.url)
                        break

    async def detect_tiers(self, concurrency: int = 20):
        """
        Re-classify all alive proxies into proper tiers via ASN lookup.
        Run after quick_validate() to upgrade datacenter classifications.
        """
        try:
            from core.tier_detection import detect_proxy_tier
        except ImportError:
            logger.warning("tier_detection not available, skipping")
            return

        sem = asyncio.Semaphore(concurrency)

        async def reclassify(ps: ProxyStatus):
            async with sem:
                try:
                    new_tier = await detect_proxy_tier(ps.url, ps.external_ip)
                    if new_tier != ps.tier:
                        async with self._lock:
                            if ps.tier in self._pools and ps in self._pools[ps.tier]:
                                self._pools[ps.tier].remove(ps)
                            ps.tier = new_tier
                            if new_tier in self._pools:
                                self._pools[new_tier].append(ps)
                except Exception:
                    pass

        all_proxies = []
        async with self._lock:
            for pool in self._pools.values():
                all_proxies.extend(pool)

        await asyncio.gather(*[reclassify(ps) for ps in all_proxies], return_exceptions=True)

    def stats(self) -> dict:
        s = {}
        for t, pool in self._pools.items():
            s[t] = len(pool)
        s["dead"] = len(self._dead)
        s["pending"] = len(self._pending)
        s["total"] = sum(len(v) for v in self._pools.values())
        return s

    def get_alive_urls(self) -> List[str]:
        urls = []
        for pool in self._pools.values():
            for ps in pool:
                urls.append(ps.url)
        return urls

    def save_alive(self, path: str = "proxies/alive.txt"):
        urls = self.get_alive_urls()
        with open(path, "w") as f:
            f.write("\n".join(urls) + "\n")
        return len(urls)
