import logging
import random
import os
import asyncio
import aiohttp
from typing import List, Optional, Dict
import time

class ProxyManager:
    """
    Manages proxy pool: loading, health checking, and rotation.
    Supports HTTP, HTTPS, SOCKS4, SOCKS5.
    CRITICAL: Always validate proxies before attack.
    """
    def __init__(self, proxy_file: str = "config/proxies.json"):
        self.proxy_file = proxy_file
        self.logger = logging.getLogger("ProxyManager")
        self.proxies = self._load_proxies()
        self.working_proxies = []
        self.validated = False

    def _load_proxies(self) -> List[str]:
        if os.path.exists(self.proxy_file):
            try:
                import json
                with open(self.proxy_file, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        return data
                    return data.get("proxies", [])
            except Exception as e:
                self.logger.warning(f"Failed to load proxies: {e}")
        return []

    async def validate_proxy(self, proxy: str, test_url: str = "http://httpbin.org/ip", timeout: int = 5) -> bool:
        """
        Test if proxy works by making actual HTTP request.
        RETURNS: True if proxy is working, False otherwise
        """
        try:
            connector = aiohttp.TCPConnector()
            timeout_obj = aiohttp.ClientTimeout(total=timeout)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout_obj) as session:
                # Handle SOCKS proxies differently
                if proxy.startswith("socks"):
                    # For SOCKS, we can't use standard aiohttp without extra lib
                    # Skip SOCKS validation for now, log warning
                    self.logger.debug(f"[PROXY] SOCKS5 proxy: {proxy} (no validation)")
                    return False
                
                # HTTP/HTTPS proxy
                proxy_dict = self.get_proxy_dict(proxy)
                
                async with session.get(test_url, proxy=proxy_dict, ssl=False) as resp:
                    if resp.status == 200:
                        self.logger.debug(f"[PROXY] ✅ Working: {proxy}")
                        return True
        except asyncio.TimeoutError:
            self.logger.debug(f"[PROXY] ❌ Timeout: {proxy}")
            return False
        except Exception as e:
            self.logger.debug(f"[PROXY] ❌ Error: {proxy} - {type(e).__name__}")
            return False
        
        return False

    async def validate_all_proxies(self, test_url: str = "http://httpbin.org/ip", threads: int = 10, verbose: bool = True):
        """
        Validate all proxies concurrently.
        CRITICAL: Run this before any attack!
        """
        if not self.proxies:
            self.logger.error("[!] NO PROXIES LOADED! Attack may fail completely.")
            self.validated = False
            return []
        
        if verbose:
            self.logger.info(f"[*] Validating {len(self.proxies)} proxies (this may take 1-2 min)...")
        
        # Test in batches
        tasks = []
        for proxy in self.proxies:
            tasks.append(self.validate_proxy(proxy, test_url))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        self.working_proxies = [
            self.proxies[i] for i in range(len(self.proxies))
            if isinstance(results[i], bool) and results[i]
        ]
        
        if verbose:
            self.logger.info(f"[+] {len(self.working_proxies)}/{len(self.proxies)} proxies working")
        
        self.validated = True
        return self.working_proxies

    def sync_validate_all_proxies(self, threads: int = 10):
        """Synchronous wrapper for validation."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(self.validate_all_proxies(threads=threads))

    def refresh_proxies(self, sources: Optional[List[str]] = None):
        """
        Fetches fresh proxies from free providers.
        """
        self.logger.info("[*] Refreshing proxy pool from free sources...")
        import requests
        
        free_sources = [
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
            "https://www.proxy-list.download/api/v1/get?type=https"
        ]
        
        new_proxies = []
        for url in free_sources:
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200:
                    new_proxies.extend(resp.text.strip().split("\n"))
            except:
                continue
        
        self.proxies = list(set(self.proxies + new_proxies))
        self.logger.info(f"[+] Loaded {len(self.proxies)} proxies.")
        self._save_proxies()
        self.validated = False

    def _save_proxies(self):
        os.makedirs("config", exist_ok=True)
        import json
        with open(self.proxy_file, 'w') as f:
            json.dump(self.proxies, f, indent=4)

    def check_health(self, test_url: str = "http://httpbin.org/ip", threads: int = 20):
        """Legacy method - calls sync validation."""
        return self.sync_validate_all_proxies(threads=threads)

    def get_random_proxy(self) -> Optional[str]:
        """Get random working proxy. Returns None if no proxies available."""
        if not self.working_proxies:
            self.logger.warning("[!] No working proxies available. Attack may fail.")
            # Fallback to direct connection (no proxy)
            return None
        return random.choice(self.working_proxies)

    def get_proxy_dict(self, proxy_str: str) -> Dict[str, str]:
        """Converts 'ip:port' or 'proto://ip:port' to requests proxy dict."""
        if "://" not in proxy_str:
            proxy_str = f"http://{proxy_str}"
        return {
            "http": proxy_str,
            "https": proxy_str
        }

    def is_validated(self) -> bool:
        """Check if proxies have been validated."""
        return self.validated
    
    def has_working_proxies(self) -> bool:
        """Check if any working proxies available."""
        return len(self.working_proxies) > 0
