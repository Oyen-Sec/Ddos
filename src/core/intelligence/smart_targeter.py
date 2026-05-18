import requests
import logging
import time
import urllib.parse
import re
from typing import List, Dict, Any
from bs4 import BeautifulSoup

class SmartTargeter:
    """
    Smart Targeter v1.0.
    Analyzes target website to find 'heavy' endpoints using static analysis and 
    dynamic response time measurements.
    """
    def __init__(self, domain: str):
        self.domain = domain
        self.url = f"https://{domain}" if not domain.startswith("http") else domain
        self.logger = logging.getLogger("SmartTargeter")
        self.endpoints_data: List[Dict[str, Any]] = []

    def run(self) -> List[Dict[str, Any]]:
        self.logger.info(f"[*] Starting Advanced Target Analysis for {self.domain}...")
        
        # 1. Crawl for potential endpoints
        found_urls = self._crawl_endpoints()
        
        # 2. Measure response times to identify heavy targets
        self.logger.info(f"[*] Measuring response times for {len(found_urls)} endpoints...")
        self.endpoints_data = self._analyze_latency(found_urls)
        
        # Sort by response time (heaviest first)
        self.endpoints_data = sorted(self.endpoints_data, key=lambda x: x['avg_latency'], reverse=True)
        
        for ep in self.endpoints_data[:5]:
            self.logger.info(f"    [+] High-Value Target Found: {ep['url']} ({ep['avg_latency']:.2f}ms)")
            
        return self.endpoints_data

    def _crawl_endpoints(self) -> List[str]:
        endpoints = [self.url]
        try:
            resp = requests.get(self.url, timeout=10, verify=False)
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Find forms
            for form in soup.find_all('form', attrs={'action': True}):
                action = form.get('action')
                full_url = urllib.parse.urljoin(self.url, action)
                if self.domain in full_url:
                    endpoints.append(full_url)

            # Find common API patterns
            api_patterns = [r'/api/v\d/\w+', r'/graphql', r'/wp-admin/admin-ajax.php', r'/login', r'/search', r'\.php\?']
            for pattern in api_patterns:
                matches = re.findall(pattern, resp.text)
                for match in matches:
                    full_url = urllib.parse.urljoin(self.url, match)
                    endpoints.append(full_url)
                    
            # Find heavy assets/scripts
            for script in soup.find_all('script', src=True):
                src = script.get('src')
                if self.domain in src or src.startswith('/'):
                    endpoints.append(urllib.parse.urljoin(self.url, src))

        except Exception as e:
            self.logger.error(f"[-] Crawling failed: {e}")
            
        return list(set(endpoints))

    def _analyze_latency(self, urls: List[str]) -> List[Dict[str, Any]]:
        results = []
        for url in urls:
            latencies = []
            try:
                # Test 3 times for average
                for _ in range(2):
                    start = time.perf_counter()
                    resp = requests.get(url, timeout=5, verify=False)
                    end = time.perf_counter()
                    latencies.append((end - start) * 1000)
                
                avg_latency = sum(latencies) / len(latencies)
                results.append({
                    "url": url,
                    "avg_latency": avg_latency,
                    "status_code": resp.status_code,
                    "content_length": len(resp.content),
                    "is_dynamic": "?" in url or resp.status_code == 200 and "no-cache" in str(resp.headers).lower()
                })
            except:
                continue
        return results
