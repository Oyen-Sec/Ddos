import socket
import logging
import concurrent.futures
import requests
import os
from typing import List, Tuple, Optional

class SubdomainEnumerator:
    def __init__(self, domain: str, wordlist_path: str = None):
        self.domain = domain
        self.logger = logging.getLogger("SubdomainEnumerator")
        self.wordlist = self._load_wordlist(wordlist_path)
        self.found_subdomains = []

    def _load_wordlist(self, path: str) -> List[str]:
        if not path:
            # Default to comprehensive wordlist if it exists
            potential_path = os.path.join(os.getcwd(), 'wordlists', 'subdomains_2026.txt')
            if os.path.exists(potential_path):
                path = potential_path

        if path:
            try:
                with open(path, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.logger.error(f"[-] Error loading wordlist from {path}: {e}")
        
        # Fallback to hardcoded list if file not found
        base_words = [
            'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 'smtp', 'vpn', 
            'm', 'shop', 'ftp', 'dev', 'api', 'admin', 'test', 'portal', 'mysql', 'support',
            'static', 'staging', 'beta', 'demo', 'docs', 'img', 'cdn', 'cloud', 'apps',
            'secure', 'billing', 'git', 'gitlab', 'jenkins', 'jira', 'confluence', 'wiki',
            'news', 'forum', 'help', 'login', 'register', 'status', 'monitor', 'nagios',
            'cpanel', 'whm', 'webconf', 'autodiscover', 'pop', 'pop3', 'imap', 'direct', 
            'origin', 'backend', 'internal', 'private', 'ssh', 'db', 'database', 'sql', 
            'phpmyadmin', 'panel', 'cp', 'manage', 'host', 'web', 'client', 'customers', 
            'auth', 'oauth', 'sso', 'gateway', 'proxy', 'lb', 'loadbalancer', 'cluster', 
            'node', 'app', 'service', 'services', 'dev-api', 'api-dev', 'api-v1', 'api-v2',
            'staging-api', 'dev-db', 'db-dev', 'test-db', 'db-test', 'prod-db', 'db-prod',
            'direct-connect', 'direct-ip', 'real-ip', 'origin-ip', 'bypass', 'unfiltered',
            'hidden', 'secret', 'vpn-gw', 'rdp', 'vnc', 'backup', 'backups', 'storage',
            'media', 'images', 'files', 'assets', 'static-assets', 'content', 'api-docs',
            'dev-docs', 'sandbox', 'local', 'localhost', 'dev-local', 'm-api', 'mobile-api',
            'app-api', 'ws', 'websocket', 'streaming', 'stream', 'live', 'vod', 'video',
            'audio', 'cdn-origin', 'cdn-backend', 'origin-cdn', 'lb-origin', 'web-origin'
        ]
        return base_words

    def check_subdomain(self, sub: str) -> Optional[Tuple[str, str]]:
        full_domain = f"{sub}.{self.domain}"
        try:
            ip = socket.gethostbyname(full_domain)
            return (full_domain, ip)
        except:
            return None

    def run(self, threads: int = 50) -> List[Tuple[str, str]]:
        self.logger.info(f"[*] Starting Ultra-Deep Brute-Force on {self.domain}...")
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_sub = {executor.submit(self.check_subdomain, sub): sub for sub in self.wordlist}
            for future in concurrent.futures.as_completed(future_to_sub):
                res = future.result()
                if res:
                    self.logger.info(f"[+] Found: {res[0]} -> {res[1]}")
                    results.append(res)
        self.found_subdomains = results
        return self.found_subdomains
