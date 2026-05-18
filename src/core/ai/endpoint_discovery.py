import json
import re
import logging
import asyncio
import aiohttp
import os
from typing import List, Dict, Any
import urllib.parse
from src.utils.cdn_filter import is_cdn_or_static

DEFAULT_ENDPOINTS = [
    "/search", "/search?q=test", "/search?q=a&page=1",
    "/api/search", "/api/v1/search",
    "/filter", "/sort", "/category",
    "/products", "/product/1", "/item/1",
    "/cart", "/checkout", "/cart/add",
    "/login", "/register", "/auth", "/oauth",
    "/contact", "/form", "/submit",
    "/export", "/download", "/report", "/generate",
    "/api/graphql", "/graphql", "/gql",
    "/api/rest", "/api/v1/users", "/api/v1/data",
    "/wp-json/wp/v2/posts", "/wp-json/wp/v2/users",
    "/admin", "/panel", "/dashboard", "/backend",
    "/ajax", "/xhr", "/fetch", "/load",
    "/news", "/blog", "/article/1", "/post/1",
    "/page/1", "/category/tech", "/tag/test",
    "/", "/index.html", "/home", "/main"
]

class EndpointDiscovery:
    """
    Handles multi-source endpoint discovery for target reconnaissance.
    Ensures target selection even if crawling is blocked.
    """
    def __init__(self, domain: str, recon_json_path: str = None):
        self.domain = domain
        self.recon_json_path = recon_json_path or f"output/reports/recon_{domain}.json"
        self.logger = logging.getLogger("EndpointDiscovery")

    async def discover(self) -> List[Dict[str, Any]]:
        """Try multiple sources in order of preference."""
        endpoints = []
        
        # Source 1: Existing recon JSON
        self.logger.info("[*] Attempting discovery from Recon JSON...")
        recon_eps = self._from_recon_json()
        endpoints.extend(recon_eps)
        if len(endpoints) >= 10:
            return endpoints
            
        # Source 2: Sitemap / Robots (lightweight)
        self.logger.info("[-] Recon JSON insufficient. Attempting Sitemap/Robots...")
        sitemap_eps = await self._from_sitemap()
        endpoints.extend(sitemap_eps)
        if len(endpoints) >= 10:
            return endpoints
            
        # Source 3: Fallback wordlist (guaranteed)
        self.logger.info("[-] Sitemap blocked or empty. Falling back to wordlist (guaranteed).")
        wordlist_eps = self._from_wordlist()
        endpoints.extend(wordlist_eps)
        
        # Deduplicate
        seen = set()
        unique = []
        for ep in endpoints:
            url = ep.get("url", "")
            if url and url not in seen:
                seen.add(url)
                unique.append(ep)
                
        return unique

    def _from_recon_json(self) -> List[Dict[str, Any]]:
        try:
            if not os.path.exists(self.recon_json_path):
                return []
            with open(self.recon_json_path, 'r') as f:
                recon = json.load(f)
            
            endpoints = []
            # Extract from subdomain enumeration if found
            subs = recon.get("subdomain_enumeration", {}).get("found", [])
            for sub in subs:
                name = sub.get("name") if isinstance(sub, dict) else sub
                if name:
                    endpoints.append({"url": f"https://{name}", "source": "recon_subdomain", "score": 5.0})
            
            # Extract from tech stack hints
            tech = str(recon.get("technology_stack", {})).lower()
            if "wordpress" in tech:
                endpoints.append({"url": f"https://{self.domain}/wp-json/wp/v2/posts", "source": "recon_tech", "score": 8.0})
                
            return endpoints
        except Exception as e:
            self.logger.debug(f"Recon JSON parse failed: {e}")
            return []

    async def _from_sitemap(self) -> List[Dict[str, Any]]:
        urls = [f"https://{self.domain}/sitemap.xml", f"https://{self.domain}/robots.txt"]
        endpoints = []
        
        async with aiohttp.ClientSession(headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}) as session:
            for url in urls:
                try:
                    async with asyncio.timeout(5):
                        async with session.get(url) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                                found = re.findall(r'https?://[^\s<>\"\'\\)]+', text)
                                for u in found:
                                    blocked, reason = is_cdn_or_static(u, self.domain)
                                    if not blocked:
                                        endpoints.append({"url": u, "source": "sitemap", "score": 4.0})
                except: continue
        return endpoints

    def _from_wordlist(self) -> List[Dict[str, Any]]:
        return [{"url": f"https://{self.domain}{path}", "source": "fallback_wordlist", "score": 3.0} for path in DEFAULT_ENDPOINTS]

import os
