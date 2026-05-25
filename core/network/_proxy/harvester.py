"""
Auto Proxy Harvester v2.0
Scrapes 15+ public proxy sources in parallel, validates 1000+ proxies/sec
Uses async batching with smart timeout for speed
"""
import asyncio
import re
import logging
import time
from typing import List, Set, Optional, Dict
from urllib.parse import urlparse

logger = logging.getLogger("proxy_harvester")


class ProxyHarvester:
    """Scrape thousands of fresh proxies from public sources in parallel"""

    # Free proxy list sources - Updated 2026 (tahan banting, aktif)
    HTTP_SOURCES = [
        # GitHub sources (updated daily)
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/http.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
        "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
        "https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt",
        "https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http.txt",
        "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",
        "https://raw.githubusercontent.com/zloi-user/hideip.me/main/https.txt",
        "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
        "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
        "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt",
        "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/https/https.txt",
        
        # API sources (real-time)
        "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all",
        "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=http,https",
        "https://www.proxy-list.download/api/v1/get?type=http",
        "https://www.proxy-list.download/api/v1/get?type=https",
        "https://www.proxyscan.io/download?type=http",
        "https://openproxylist.xyz/http.txt",
        "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
    ]

    SOCKS5_SOURCES = [
        # GitHub sources (updated daily)
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/socks5.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
        "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
        "https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/socks5.txt",
        "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt",
        "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
        "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks5/socks5.txt",
        
        # API sources (real-time)
        "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks5&timeout=5000&country=all",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=5000&country=all",
        "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=socks5",
        "https://www.proxy-list.download/api/v1/get?type=socks5",
        "https://www.proxyscan.io/download?type=socks5",
        "https://openproxylist.xyz/socks5.txt",
    ]

    SOCKS4_SOURCES = [
        # GitHub sources (updated daily)
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/socks4.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
        "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",
        "https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/socks4.txt",
        "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks4.txt",
        "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks4.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
        "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks4/socks4.txt",
        
        # API sources (real-time)
        "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks4&timeout=5000&country=all",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=5000&country=all",
        "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=socks4",
        "https://www.proxy-list.download/api/v1/get?type=socks4",
        "https://www.proxyscan.io/download?type=socks4",
    ]

    def __init__(self, scrape_timeout: int = 15, validate_timeout: int = 4,
                 max_validate_concurrency: int = 500):
        self.scrape_timeout = scrape_timeout
        self.validate_timeout = validate_timeout
        self.max_validate_concurrency = max_validate_concurrency

    async def harvest(self, types: Optional[List[str]] = None) -> Dict[str, List[str]]:
        """Scrape all proxy sources in parallel"""
        types = types or ["http", "socks5", "socks4"]
        results = {"http": [], "socks5": [], "socks4": []}

        tasks = []
        labels = []
        for url in self.HTTP_SOURCES if "http" in types else []:
            tasks.append(self._fetch_proxy_list(url, "http"))
            labels.append(f"http:{url[:50]}")
        for url in self.SOCKS5_SOURCES if "socks5" in types else []:
            tasks.append(self._fetch_proxy_list(url, "socks5"))
            labels.append(f"socks5:{url[:50]}")
        for url in self.SOCKS4_SOURCES if "socks4" in types else []:
            tasks.append(self._fetch_proxy_list(url, "socks4"))
            labels.append(f"socks4:{url[:50]}")

        logger.info(f"Harvesting from {len(tasks)} sources in parallel...")
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        seen = set()
        for i, r in enumerate(responses):
            if isinstance(r, tuple):
                ptype, proxies = r
                for p in proxies:
                    if p not in seen:
                        seen.add(p)
                        results[ptype].append(p)
            elif isinstance(r, Exception):
                logger.debug(f"Source {i} failed: {r}")

        return results

    async def _fetch_proxy_list(self, url: str, ptype: str) -> tuple:
        """Fetch and parse proxy list from URL"""
        try:
            from curl_cffi.requests import AsyncSession
            from core.network.proxy_parser import parse_proxy
            kwargs = {"impersonate": "chrome120", "timeout": self.scrape_timeout}
            async with AsyncSession(**kwargs) as sess:
                resp = await sess.get(url, timeout=self.scrape_timeout)
                if resp.status_code != 200:
                    return (ptype, [])
                text = resp.text
                proxies = []
                seen = set()
                for line in text.split("\n"):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Use universal parser - handles all formats
                    parsed_url = parse_proxy(line)
                    if not parsed_url:
                        continue
                    # If line had no scheme, prepend the source ptype
                    if not re.match(r'^(https?|socks[45]h?)://', line, re.IGNORECASE):
                        # Replace default http:// with proper ptype
                        parsed_url = parsed_url.replace("http://", f"{ptype}://", 1)
                    if parsed_url in seen:
                        continue
                    seen.add(parsed_url)
                    proxies.append(parsed_url)
                return (ptype, proxies)
        except Exception as e:
            logger.debug(f"Fetch {url} failed: {e}")
            return (ptype, [])

    async def validate_batch(self, proxies: List[str], target_url: Optional[str] = None,
                             progress_cb=None) -> List[Dict]:
        """
        TIER PRO VALIDATION: Test REAL HTTP request to TARGET, not Google.
        Filter only FAST proxies (RTT <1000ms) that can actually reach target.
        """
        if not proxies:
            return []

        sem = asyncio.Semaphore(self.max_validate_concurrency)
        completed = [0]
        alive = []
        alive_lock = asyncio.Lock()

        # TIER PRO: Test against ACTUAL TARGET, not Google
        check_url = target_url if target_url else "http://www.google.com/generate_204"

        async def http_test_proxy(proxy_url: str) -> Optional[Dict]:
            """TIER PRO: Real HTTP request to TARGET through proxy"""
            from urllib.parse import urlparse as _urlparse
            p = _urlparse(proxy_url)
            scheme = p.scheme
            host = p.hostname
            port = p.port

            if not host or not port:
                return None

            start = time.monotonic()

            if scheme in ("http", "https"):
                try:
                    from curl_cffi.requests import AsyncSession
                    kwargs = {
                        "impersonate": "chrome120",
                        "timeout": self.validate_timeout,
                        "proxies": {"all": proxy_url},
                        "verify": False,
                    }
                    async with AsyncSession(**kwargs) as sess:
                        resp = await sess.get(check_url, timeout=self.validate_timeout,
                                               allow_redirects=False)
                        rtt = (time.monotonic() - start) * 1000
                        # TIER PRO: Accept any response (even 403/502) = proxy works
                        if resp.status_code in (200, 204, 301, 302, 403, 502, 503):
                            return {
                                "url": proxy_url,
                                "rtt_ms": round(rtt, 1),
                                "status": resp.status_code,
                                "type": scheme,
                                "auth": bool(p.username),
                            }
                except Exception as e:
                    logger.debug(f"HTTP test {proxy_url} failed: {e}")

            elif scheme in ("socks4", "socks5"):
                try:
                    from aiohttp_socks import ProxyConnector
                    from aiohttp import ClientSession, ClientTimeout
                    connector = ProxyConnector.from_url(proxy_url)
                    timeout = ClientTimeout(total=self.validate_timeout)
                    async with ClientSession(connector=connector, timeout=timeout) as session:
                        async with session.get(check_url, timeout=timeout, ssl=False) as resp:
                            rtt = (time.monotonic() - start) * 1000
                            if resp.status in (200, 204, 301, 302, 403, 502, 503):
                                return {
                                    "url": proxy_url,
                                    "rtt_ms": round(rtt, 1),
                                    "status": resp.status,
                                    "type": scheme,
                                    "auth": bool(p.username),
                                }
                except Exception as e:
                    logger.debug(f"SOCKS test {proxy_url} failed: {e}")

            return None

        async def validate_one(proxy_url: str):
            async with sem:
                try:
                    # TIER PRO: ALWAYS do FULL HTTP test to target
                    info = await http_test_proxy(proxy_url)

                    if info:
                        async with alive_lock:
                            alive.append(info)
                finally:
                    completed[0] += 1
                    if progress_cb and completed[0] % 200 == 0:
                        try:
                            progress_cb(completed[0], len(proxies), len(alive))
                        except Exception:
                            pass

        await asyncio.gather(*[validate_one(p) for p in proxies], return_exceptions=True)
        alive.sort(key=lambda x: x["rtt_ms"])
        return alive


async def auto_harvest_and_validate(target_url: Optional[str] = None,
                                     types: Optional[List[str]] = None,
                                     save_path: str = "proxies/alive.txt",
                                     min_rtt_ms: float = 1000.0,
                                     progress_cb=None) -> Dict:
    """TIER PRO: One-shot harvest + validate pipeline with STRICT filtering"""
    harvester = ProxyHarvester(max_validate_concurrency=500)

    print_cb = progress_cb or (lambda c, t, a: None)

    start = time.time()

    print_cb("scrape", 0, 0)
    harvested = await harvester.harvest(types or ["http", "socks5", "socks4"])
    all_proxies = harvested["http"] + harvested["socks5"] + harvested["socks4"]
    scraped_count = len(all_proxies)

    print_cb("validate", scraped_count, 0)
    alive = await harvester.validate_batch(all_proxies, target_url=target_url,
                                            progress_cb=lambda c, t, a: print_cb("validate", c, a))

    # TIER PRO: Filter by RTT <1000ms (only SUPER FAST proxies)
    fast_alive = [p for p in alive if p["rtt_ms"] <= min_rtt_ms]

    # Save to file
    if save_path and fast_alive:
        import os
        os.makedirs(os.path.dirname(save_path) or ".", exist_ok=True)
        with open(save_path, "w") as f:
            for p in fast_alive:
                f.write(p["url"] + "\n")

    return {
        "scraped": scraped_count,
        "alive": len(alive),
        "fast_alive": len(fast_alive),
        "elapsed": round(time.time() - start, 2),
        "proxies": fast_alive,
        "save_path": save_path,
        "by_type": {
            "http": len(harvested["http"]),
            "socks5": len(harvested["socks5"]),
            "socks4": len(harvested["socks4"]),
        },
    }
