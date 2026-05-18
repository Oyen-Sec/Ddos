import requests
import logging
import json
import mmh3
import base64
import re

class ShodanScanner:
    """
    Integrates Shodan for Origin IP discovery and tech fingerprinting.
    """
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.logger = logging.getLogger("ShodanScanner")

    def get_favicon_hash(self, url: str) -> int:
        try:
            response = requests.get(f"{url}/favicon.ico", timeout=10)
            favicon = base64.encodebytes(response.content)
            return mmh3.hash(favicon)
        except Exception as e:
            self.logger.error(f"[-] Error getting favicon: {e}")
            return None

    def search_by_favicon(self, favicon_hash: int) -> list:
        if not self.api_key:
            self.logger.warning("[-] Shodan API key missing. Cannot search.")
            return []
        
        self.logger.info(f"[*] Searching Shodan for favicon hash: {favicon_hash}...")
        url = f"https://api.shodan.io/shodan/host/search?key={self.api_key}&query=http.favicon.hash:{favicon_hash}"
        try:
            res = requests.get(url)
            if res.status_code == 200:
                data = res.json()
                ips = [item['ip_str'] for item in data.get('matches', [])]
                return ips
        except Exception as e:
            self.logger.error(f"[-] Shodan search error: {e}")
        return []

    def search_by_cert(self, domain: str) -> list:
        if not self.api_key: return []
        self.logger.info(f"[*] Searching Shodan for certificates of {domain}...")
        query = f'ssl:"{domain}"'
        url = f"https://api.shodan.io/shodan/host/search?key={self.api_key}&query={query}"
        try:
            res = requests.get(url)
            if res.status_code == 200:
                data = res.json()
                return [item['ip_str'] for item in data.get('matches', [])]
        except Exception:
            pass
        return []
