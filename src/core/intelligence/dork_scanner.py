import logging
from typing import List
import urllib.parse

class DorkScanner:
    """
    Generates and suggests Google Dorks to find leaked Origin IPs or unprotected subdomains.
    """
    def __init__(self, domain: str):
        self.domain = domain
        self.logger = logging.getLogger("DorkScanner")

    def generate_dorks(self) -> List[str]:
        """
        Returns a list of Google Dorks for reconnaissance.
        """
        dorks = [
            f'site:{self.domain} -www -cloudflare',
            f'site:{self.domain} "index of" "config"',
            f'site:{self.domain} "index of" "admin"',
            f'site:{self.domain} "index of" "db"',
            f'site:*.{self.domain} -www',
            f'inurl:"{self.domain}" intitle:"index of"',
            f'"{self.domain}" "Real IP"',
            f'"{self.domain}" "Origin IP"',
            f'"{self.domain}" "X-Forwarded-For"',
            f'site:censys.io "{self.domain}"',
            f'site:shodan.io "{self.domain}"',
            f'site:zoomeye.org "{self.domain}"',
            f'site:fofa.info "{self.domain}"'
        ]
        return dorks

    def get_search_links(self) -> List[str]:
        dorks = self.generate_dorks()
        links = []
        for dork in dorks:
            encoded_dork = urllib.parse.quote(dork)
            links.append(f"https://www.google.com/search?q={encoded_dork}")
        return links

    def run(self):
        self.logger.info(f"[*] Generating Powerful Google Dorks for {self.domain}...")
        links = self.get_search_links()
        for i, link in enumerate(links):
            self.logger.info(f"    [DORK {i+1}] {self.generate_dorks()[i]}")
            self.logger.info(f"    -> {link}")
        return links
