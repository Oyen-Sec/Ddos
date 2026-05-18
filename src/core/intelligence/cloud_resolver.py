import logging
from typing import List, Set
from .crt_sh_scanner import CrtShScanner
from .historical_dns import HistoricalDNS
from .subdomain_enum import SubdomainEnumerator
from .email_leak_finder import EmailLeakFinder
from .dork_scanner import DorkScanner

class CloudflareResolver:
    """
    Orchestrates multiple free methods to bypass Cloudflare and find the Origin IP.
    """
    def __init__(self, domain: str):
        self.domain = domain
        self.logger = logging.getLogger("CloudflareResolver")

    async def resolve(self, threads: int = 50):
        self.logger.info("\n[*] Starting Cloudflare resolution...")
        
        all_potential_ips: Set[str] = set()
        
        # 1. CRT.SH
        crt = CrtShScanner(self.domain)
        crt_subs = crt.scan()
        # Resolve CRT subdomains
        sub_enum = SubdomainEnumerator(self.domain)
        for sub in crt_subs:
            res = sub_enum.check_subdomain(sub.replace(f".{self.domain}", ""))
            if res: all_potential_ips.add(res[1])

        # 2. Historical DNS
        hist = HistoricalDNS(self.domain)
        hist_ips = hist.run_all()
        for ip in hist_ips: all_potential_ips.add(ip)

        # 3. Email/MX Leak
        email_leak = EmailLeakFinder(self.domain)
        mx_ips = email_leak.run()
        for ip in mx_ips: all_potential_ips.add(ip)

        # 4. Google Dorking (Information only)
        dorker = DorkScanner(self.domain)
        dorker.run()

        # 5. Targeted Subdomain Brute Force (Common origin subdomains)
        self.logger.info("[*] Enumerating subdomains via optimized wordlist...")
        sub_enum = SubdomainEnumerator(self.domain) # This now automatically uses subdomains_2026.txt
        results = sub_enum.run(threads=threads)
        for res in results:
            self.logger.info(f"    [+] Found unprotected subdomain: {res[0]} -> {res[1]}")
            all_potential_ips.add(res[1])

        self.logger.info(f"[+] Total potential Origin IPs gathered: {len(all_potential_ips)}")
        return list(all_potential_ips)
