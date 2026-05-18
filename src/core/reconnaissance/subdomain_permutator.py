import socket
import logging
import concurrent.futures
from typing import List, Tuple, Set

class SubdomainPermutator:
    """
    Subdomain Permutator v1.0.
    Generates and tests permutations of common subdomains to find unprotected origin IPs.
    """
    def __init__(self, domain: str):
        self.domain = domain
        self.logger = logging.getLogger("SubdomainPermutator")
        self.keywords = [
            'dev', 'staging', 'api', 'admin', 'panel', 'cpanel', 'whm', 'webmail',
            'mail', 'ftp', 'ssh', 'vpn', 'db', 'sql', 'backup', 'old', 'new',
            'app', 'mobile', 'm', 'v1', 'v2', 'v3', 'graphql', 'ws', 'cdn',
            'static', 'assets', 'img', 'internal', 'intranet', 'test', 'qa'
        ]

    def run(self, threads: int = 50) -> List[Tuple[str, str]]:
        self.logger.info(f"[*] Starting Professional Subdomain Permutation Scan for {self.domain}...")
        
        # Extended list for 10K+ like coverage (using a smarter permutation logic)
        self.keywords.extend([
            'vpn', 'remote', 'gateway', 'edge', 'origin', 'direct', 'backend',
            'mysql', 'db1', 'db2', 'api1', 'api2', 'dev-api', 'staging-api',
            'jenkins', 'git', 'gitlab', 'repo', 'ci', 'cd', 'deploy',
            'monitor', 'status', 'zabbix', 'grafana', 'prometheus', 'elk',
            'jira', 'confluence', 'wiki', 'help', 'support', 'billing'
        ])
        
        permutations = self._generate_permutations()
        self.logger.info(f"[*] Generated {len(permutations)} permutations for testing.")
        
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_sub = {executor.submit(self._check_subdomain, sub): sub for sub in permutations}
            for future in concurrent.futures.as_completed(future_to_sub):
                res = future.result()
                if res:
                    results.append(res)
        
        return results

    def _generate_permutations(self) -> Set[str]:
        perms = set()
        # Basic keywords
        for k in self.keywords:
            perms.add(k)
            
        # Combinations (k1-k2)
        for k1 in self.keywords[:10]: # Limit to top 10 for performance
            for k2 in self.keywords:
                if k1 != k2:
                    perms.add(f"{k1}-{k2}")
                    perms.add(f"{k1}{k2}")
                    
        # Numeric versions
        for k in ['api', 'v', 'app', 'srv']:
            for i in range(1, 11):
                perms.add(f"{k}{i}")
                perms.add(f"{k}-{i}")
                
        return perms

    def _check_subdomain(self, sub: str) -> Tuple[str, str]:
        full_domain = f"{sub}.{self.domain}"
        try:
            ip = socket.gethostbyname(full_domain)
            return (full_domain, ip)
        except:
            return None
