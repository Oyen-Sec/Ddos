import requests
import mmh3
import base64
import logging
from typing import Optional

class FaviconHunter:
    """
    Calculates favicon hash and searches for it in public databases.
    """
    def __init__(self, target_domain: str):
        self.target_domain = target_domain
        self.logger = logging.getLogger("FaviconHunter")

    def get_hash(self) -> Optional[int]:
        self.logger.info(f"[*] Calculating favicon hash for {self.target_domain}...")
        try:
            # Try multiple paths
            paths = ["/favicon.ico", "/favicon.png", "/assets/favicon.ico"]
            for path in paths:
                try:
                    res = requests.get(f"https://{self.target_domain}{path}", timeout=10, verify=False)
                    if res.status_code == 200:
                        favicon = base64.encodebytes(res.content)
                        f_hash = mmh3.hash(favicon)
                        self.logger.info(f"[+] Favicon Hash found ({path}): {f_hash}")
                        return f_hash
                except: continue
        except Exception as e:
            self.logger.error(f"[-] Error calculating favicon hash: {e}")
        return None

    def search_shodan_no_key(self, f_hash: int):
        """
        Since we don't have a key, we can't use the API, but we can provide the user
        with a direct Shodan search link.
        """
        search_url = f"https://www.shodan.io/search?query=http.favicon.hash:{f_hash}"
        self.logger.info(f"[!] Action Required: Search Shodan manually for this hash to find Origin IP:")
        self.logger.info(f"    -> {search_url}")
        return search_url
