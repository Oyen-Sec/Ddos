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
    "mobile": 1,
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
    tls_handshake_ms: float = 0.0
    last_used: float = 0.0
    request_count: int = 0

class ProxyValidator:
    def __init__(self, check_url: str = "https://httpbin.org/ip",
                 connect_timeout: int = 3, read_timeout: int = 3,
                 max_connect_time_ms: int = 1200,  # STRICT: 1200ms threshold
                 max_tls_handshake_ms: int = 800,
                 target_url: str = ""):
        self.check_url = check_url
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.max_connect_time_ms = max_connect_time_ms
        self.max_tls_handshake_ms = max_tls_handshake_ms
        self.target_url = target_url
        # Target-specific validation: track WAF block patterns
        self._waf_block_patterns = [
            "cloudflare",
            "access denied",
            "forbidden",
            "blocked",
            "rate limit",
            "captcha",
            "akamai",
            "incapsula",
            "sucuri",
        ]

    def set_target(self, target_url: str):
        parsed = urlparse(target_url)
        self.check_url = f"{parsed.scheme}://{parsed.netloc}/cdn-cgi/trace"
        self.target_url = target_url
    
    async def validate_target_specific(self, proxy_url: str):
        """
        Target-Specific Validation Gate (FAST version)
        After TCP check passes (Stage 1), this does ONE HTTP HEAD to target
        No prior generic validation - we already know TCP works
        """
        if not self.target_url:
            return await self.validate(proxy_url)
        
        protocol, host, port = self._parse(proxy_url)
        st = ProxyStatus(
            url=proxy_url, protocol=protocol, host=host, port=port,
            tier=self._detect_tier(proxy_url),
        )
        
        try:
            try:
                from curl_cffi.requests import AsyncSession
                kwargs = {
                    "impersonate": "chrome124",
                    "timeout": 4,  # Aggressive timeout for fast filtering
                    "proxies": {"all": proxy_url},
                    "verify": False,
                }
                async with AsyncSession(**kwargs) as sess:
                    target_start = time.monotonic()
                    try:
                        resp = await sess.head(
                            self.target_url,
                            timeout=4,
                            allow_redirects=False,
                        )
                    except Exception:
                        # Fallback to GET with minimal range
                        try:
                            resp = await sess.get(
                                self.target_url,
                                timeout=4,
                                allow_redirects=False,
                                headers={"Range": "bytes=0-0"},
                            )
                        except Exception:
                            return None
                    
                    target_elapsed = (time.monotonic() - target_start) * 1000
                    st.connect_time_ms = round(target_elapsed, 2)
                    st.rtt_ema = target_elapsed
                    
                    # Eliminate if target routing too slow (relaxed: 4000ms)
                    if target_elapsed > 4000:
                        return None
                    
                    # Hard WAF block (Cloudflare 1020 etc)
                    if resp.status_code in (1020, 1010, 1015):
                        return None
                    
                    # Routing/upstream failures
                    if resp.status_code in (502, 504, 521, 522, 523, 525):
                        return None
                    
                    # Accept any reasonable response (200/30x/40x means we reached target)
                    # 403/429/503 = target reachable but WAF/rate limited - still useful
                    if 200 <= resp.status_code < 600:
                        st.alive = True
                        st.last_checked = time.time()
                        return st
                    
                    return None
                    
            except ImportError:
                # No curl_cffi - return basic alive (we know TCP works)
                st.alive = True
                st.last_checked = time.time()
                return st
        except Exception as e:
            logger.debug(f"Target validation error for {host}:{port}: {type(e).__name__}")
            return None

    def _parse(self, url: str) -> Tuple[str, str, int]:
        p = urlparse(url)
        return p.scheme.lower(), p.hostname or "", p.port or 1080

    def _guess_tier(self, url: str) -> str:
        return "datacenter"

    def _detect_tier(self, proxy_url: str) -> str:
        return self._guess_tier(proxy_url)

    async def validate(self, proxy_url: str) -> Optional[ProxyStatus]:
        protocol, host, port = self._parse(proxy_url)
        st = ProxyStatus(url=proxy_url, protocol=protocol, host=host, port=port, tier=self._detect_tier(proxy_url))
        try:
            if protocol in ("http", "https"):
                # Use curl_cffi which supports auth proxy URL natively
                try:
                    from curl_cffi.requests import AsyncSession
                    kwargs = {
                        "impersonate": "chrome120",
                        "timeout": self.connect_timeout + self.read_timeout,
                        "proxies": {"all": proxy_url},
                        "verify": False,
                    }
                    async with AsyncSession(**kwargs) as sess:
                        start = time.monotonic()
                        tls_start = time.monotonic()
                        resp = await sess.get(self.check_url,
                                              timeout=self.connect_timeout + self.read_timeout,
                                              allow_redirects=False)
                        elapsed = (time.monotonic() - start) * 1000
                        tls_elapsed = (time.monotonic() - tls_start) * 1000
                        st.connect_time_ms = round(elapsed, 2)
                        st.tls_handshake_ms = round(tls_elapsed, 2)
                        
                        # STRICT VALIDATION: Eliminate slow proxies immediately
                        if st.connect_time_ms > self.max_connect_time_ms:
                            logger.debug(f"Proxy {host}:{port} eliminated: RTT {st.connect_time_ms}ms > {self.max_connect_time_ms}ms")
                            return None
                        if st.tls_handshake_ms > self.max_tls_handshake_ms:
                            logger.debug(f"Proxy {host}:{port} eliminated: TLS handshake {st.tls_handshake_ms}ms > {self.max_tls_handshake_ms}ms")
                            return None
                        
                        # Accept any non-error response (200/204/301/302/403)
                        if resp.status_code in (200, 204, 301, 302, 403):
                            try:
                                text = resp.text
                                m = re.search(r'\d+\.\d+\.\d+\.\d+', text)
                                if m:
                                    st.external_ip = m.group(0)
                            except Exception:
                                pass
                            st.alive = True
                            st.last_checked = time.time()
                        else:
                            return None
                except ImportError:
                    # Fallback: aiohttp doesn't easily support proxy auth, skip auth proxies
                    from urllib.parse import urlparse
                    p = urlparse(proxy_url)
                    if p.username:
                        return None
                    from aiohttp import ClientSession, ClientTimeout
                    timeout = ClientTimeout(total=self.connect_timeout + self.read_timeout)
                    async with ClientSession(timeout=timeout) as session:
                        start = time.monotonic()
                        async with session.get(self.check_url, proxy=proxy_url,
                                                timeout=timeout, ssl=False) as resp:
                            elapsed = (time.monotonic() - start) * 1000
                            st.connect_time_ms = round(elapsed, 2)
                            
                            # STRICT VALIDATION
                            if st.connect_time_ms > self.max_connect_time_ms:
                                return None
                            
                            if resp.status not in (200, 204, 301, 302, 403):
                                return None
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
                        async with session.get(self.check_url, timeout=timeout, ssl=False) as resp:
                            elapsed = (time.monotonic() - start) * 1000
                            st.connect_time_ms = round(elapsed, 2)
                            
                            # STRICT VALIDATION
                            if st.connect_time_ms > self.max_connect_time_ms:
                                return None
                            
                            if resp.status not in (200, 204, 301, 302, 403):
                                return None
                            st.alive = True
                            st.last_checked = time.time()
                except ImportError:
                    return None
            else:
                return None
            
            return st if st.alive else None
        except (asyncio.TimeoutError, Exception) as e:
            logger.debug(f"Proxy {host}:{port} validation failed: {type(e).__name__}")
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
        from core.network.proxy_parser import parse_proxy
        count = 0
        seen = {ps.url for ps in self._pending}
        for line in proxies:
            url = parse_proxy(line)
            if not url:
                continue
            if url in seen:
                continue
            seen.add(url)
            parsed = urlparse(url)
            self._pending.append(ProxyStatus(
                url=url, protocol=parsed.scheme,
                host=parsed.hostname or "",
                port=parsed.port or 1080,
            ))
            count += 1
        return count

    async def load_file(self, path: str) -> int:
        try:
            with open(path, "r") as f:
                return await self.load(f.readlines())
        except FileNotFoundError:
            return 0

    async def _fast_tcp_check(self, ps: 'ProxyStatus', timeout: float = 1.5) -> bool:
        """
        Stage 1: Fast TCP connect check (no HTTP, no TLS)
        Eliminates 80%+ dead proxies in <1.5s per proxy
        """
        try:
            fut = asyncio.open_connection(ps.host, ps.port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
            except Exception:
                pass
            return True
        except Exception:
            return False

    async def quick_validate(self, count: int = 200, concurrency: int = 100,
                             target_specific: bool = True,
                             progress_cb=None,
                             max_alive: int = 0,
                             stage1_only: bool = False) -> int:
        """
        Two-stage proxy validation pipeline.
        
        Stage 1: Fast TCP connect check (1.5s timeout, eliminates dead proxies)
        Stage 2: Target-specific HTTP check (only on alive from Stage 1)
        
        Args:
            count: Max proxies to validate
            concurrency: Concurrent validation tasks (default 100, safe for most env)
            target_specific: Use HTTP HEAD to target on Stage 2
            progress_cb: Callback(stage, current, alive) for live progress
            max_alive: Early exit when N alive proxies found (0 = check all)
            stage1_only: Skip Stage 2 (target check) for max speed
        """
        batch = self._pending[:count]
        if not batch:
            return 0
        
        total_count = len(batch)
        sem = asyncio.Semaphore(concurrency)
        
        # ====================================================================
        # STAGE 1: Fast TCP connect check
        # ====================================================================
        stage1_alive: List['ProxyStatus'] = []
        stage1_done = [0]
        stage1_alive_count = [0]
        
        async def _stage1(ps):
            async with sem:
                try:
                    is_alive = await self._fast_tcp_check(ps, timeout=1.5)
                except (BlockingIOError, OSError) as e:
                    if hasattr(e, 'errno') and e.errno in (10035, 11, 35):
                        await asyncio.sleep(0.01)
                    is_alive = False
                except Exception:
                    is_alive = False
                
                stage1_done[0] += 1
                if is_alive:
                    stage1_alive_count[0] += 1
                
                # Progress callback every 50 checks
                if progress_cb and stage1_done[0] % 50 == 0:
                    try:
                        progress_cb("tcp_check", stage1_done[0], stage1_alive_count[0])
                    except Exception:
                        pass
                
                return ps if is_alive else None
        
        # Run Stage 1 with as_completed for progress streaming
        stage1_tasks = [asyncio.create_task(_stage1(ps)) for ps in batch]
        for coro in asyncio.as_completed(stage1_tasks):
            try:
                result = await coro
                if result:
                    stage1_alive.append(result)
                    # Early exit if we have enough alive proxies
                    if max_alive > 0 and len(stage1_alive) >= max_alive * 2 and stage1_only:
                        # Cancel remaining stage1 tasks
                        for t in stage1_tasks:
                            if not t.done():
                                t.cancel()
                        break
            except Exception:
                continue
        
        # Final stage1 progress
        if progress_cb:
            try:
                progress_cb("tcp_check", total_count, len(stage1_alive))
            except Exception:
                pass
        
        if stage1_only:
            # Skip Stage 2 - mark all stage1 alive as alive
            validated_urls = set()
            for ps in stage1_alive:
                ps.alive = True
                ps.last_checked = time.time()
                tier = ps.tier if ps.tier in self._pools else "datacenter"
                self._pools[tier].append(ps)
                validated_urls.add(ps.url)
            for ps in batch:
                if ps.url not in validated_urls:
                    self._dead.append(ps.url)
            self._pending = [ps for ps in self._pending if ps.url not in {p.url for p in batch}]
            return len(stage1_alive)
        
        # ====================================================================
        # STAGE 2: Target-specific HTTP check (only on stage1 alive)
        # ====================================================================
        use_target_gate = target_specific and bool(getattr(self._validator, 'target_url', ''))
        stage2_done = [0]
        stage2_alive_count = [0]
        stage2_alive: List['ProxyStatus'] = []
        
        async def _stage2(ps):
            async with sem:
                try:
                    if use_target_gate:
                        result = await self._validator.validate_target_specific(ps.url)
                    else:
                        result = await self._validator.validate(ps.url)
                except (BlockingIOError, OSError) as e:
                    if hasattr(e, 'errno') and e.errno in (10035, 11, 35):
                        await asyncio.sleep(0.01)
                    result = None
                except Exception:
                    result = None
                
                stage2_done[0] += 1
                if isinstance(result, ProxyStatus) and result.alive:
                    stage2_alive_count[0] += 1
                
                if progress_cb and stage2_done[0] % 25 == 0:
                    try:
                        progress_cb("target_check", stage2_done[0], stage2_alive_count[0])
                    except Exception:
                        pass
                
                return result
        
        if stage1_alive:
            stage2_tasks = [asyncio.create_task(_stage2(ps)) for ps in stage1_alive]
            for coro in asyncio.as_completed(stage2_tasks):
                try:
                    result = await coro
                    if isinstance(result, ProxyStatus) and result.alive:
                        stage2_alive.append(result)
                        # Early exit when we have enough alive proxies for the attack
                        if max_alive > 0 and len(stage2_alive) >= max_alive:
                            for t in stage2_tasks:
                                if not t.done():
                                    t.cancel()
                            break
                except Exception:
                    continue
        
        # Final stage2 progress
        if progress_cb:
            try:
                progress_cb("target_check", len(stage1_alive), len(stage2_alive))
            except Exception:
                pass
        
        # Commit results to pool
        validated_urls = {ps.url for ps in batch}
        for r in stage2_alive:
            tier = r.tier if r.tier in self._pools else "datacenter"
            self._pools[tier].append(r)
        
        # Mark non-alive as dead
        alive_urls = {r.url for r in stage2_alive}
        for ps in batch:
            if ps.url not in alive_urls:
                self._dead.append(ps.url)
        
        self._pending = [ps for ps in self._pending if ps.url not in validated_urls]
        return len(stage2_alive)

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
        """Get proxy with time-window rotation to avoid rate-limiting detection"""
        tiers = [preferred_tier, "residential", "ipv6", "datacenter"]
        current_time = time.time()
        async with self._lock:
            for t in tiers:
                if t in self._pools and self._pools[t]:
                    # Find proxy that hasn't been used in last 2 seconds (time-window isolation)
                    for ps in self._pools[t]:
                        if current_time - ps.last_used >= 2.0:
                            ps.last_used = current_time
                            ps.request_count += 1
                            # Move to end for round-robin
                            self._pools[t].remove(ps)
                            self._pools[t].append(ps)
                            return ps
                    # If all recently used, take least recently used
                    ps = min(self._pools[t], key=lambda x: x.last_used)
                    ps.last_used = current_time
                    ps.request_count += 1
                    return ps
            # Fallback to any available proxy
            all_proxies = []
            for pool in self._pools.values():
                all_proxies.extend(pool)
            if all_proxies:
                ps = min(all_proxies, key=lambda x: x.last_used)
                ps.last_used = current_time
                ps.request_count += 1
                return ps
        return None

    async def get_proxy_weighted(self, preferred_tier: str = "mobile") -> Optional[ProxyStatus]:
        tiers = [preferred_tier, "residential", "ipv6", "datacenter"]
        async with self._lock:
            for t in tiers:
                if t in self._pools and self._pools[t]:
                    pool = self._pools[t]
                    weights = []
                    for ps in pool:
                        w = (ps.success_count + 1) / (1 + ps.fail_count + ps.rtt_ema / 1000)
                        weights.append(w)
                    if sum(weights) == 0:
                        return random.choice(pool)
                    return random.choices(pool, weights=weights, k=1)[0]
        return None

    async def report_success(self, ps: ProxyStatus, rtt_ms: float = 0.0):
        ps.success_count += 1
        if rtt_ms > 0:
            ps.rtt_ema = ps.rtt_ema * 0.7 + rtt_ms * 0.3 if ps.rtt_ema > 0 else rtt_ms

    async def report_failure(self, ps: ProxyStatus):
        ps.fail_count += 1
        if ps.fail_count >= self.max_fail:
            async with self._lock:
                for t in self._pools:
                    if ps in self._pools[t]:
                        self._pools[t].remove(ps)
                        self._dead.append(ps.url)
                        break

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
