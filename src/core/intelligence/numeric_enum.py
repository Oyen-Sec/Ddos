import socket
import logging
import concurrent.futures
from typing import List, Tuple, Optional

class NumericSubdomainEnum:
    def __init__(self, domain: str):
        self.domain = domain
        self.logger = logging.getLogger("NumericSubdomainEnum")

    def check_subdomain(self, sub: str) -> Optional[Tuple[str, str]]:
        full_domain = f"{sub}.{self.domain}"
        try:
            ip = socket.gethostbyname(full_domain)
            return (full_domain, ip)
        except:
            return None

    def run(self, start: int = 1, end: int = 100, threads: int = 20) -> List[Tuple[str, str]]:
        self.logger.info(f"[*] Starting Numeric Subdomain Brute-Force (1-{end}) on {self.domain}...")
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            subs = [str(i) for i in range(start, end + 1)]
            future_to_sub = {executor.submit(self.check_subdomain, sub): sub for sub in subs}
            for future in concurrent.futures.as_completed(future_to_sub):
                res = future.result()
                if res:
                    self.logger.info(f"[+] Found: {res[0]} -> {res[1]}")
                    results.append(res)
        return results
