import requests
import logging
import re
from bs4 import BeautifulSoup
from typing import List

class HistoricalDNS:
    def __init__(self, domain: str):
        self.domain = domain
        self.logger = logging.getLogger("HistoricalDNS")
        self.found_ips = set()
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
        }

    def from_viewdns(self):
        url = f"https://viewdns.info/iphistory/?domain={self.domain}"
        try:
            self.logger.info(f"[*] Querying ViewDNS for {self.domain}...")
            res = requests.get(url, headers=self.headers, timeout=15)
            if res.status_code == 200:
                soup = BeautifulSoup(res.text, 'html.parser')
                table = soup.find('table', {'border': '1'})
                if table:
                    for row in table.find_all('tr')[1:]:
                        cols = row.find_all('td')
                        if cols:
                            ip = cols[0].text.strip()
                            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                                self.found_ips.add(ip)
        except Exception: pass

    def from_hackertarget(self):
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        try:
            self.logger.info(f"[*] Querying HackerTarget for {self.domain}...")
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                lines = res.text.splitlines()
                for line in lines:
                    if "," in line:
                        _, ip = line.split(",", 1)
                        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                            self.found_ips.add(ip)
        except Exception: pass

    def from_rapiddns(self):
        url = f"https://rapiddns.io/subdomain/{self.domain}#result"
        try:
            self.logger.info(f"[*] Querying RapidDNS for {self.domain}...")
            res = requests.get(url, headers=self.headers, timeout=15)
            if res.status_code == 200:
                ips = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", res.text)
                for ip in ips:
                    self.found_ips.add(ip)
        except Exception: pass

    def run_all(self) -> List[str]:
        self.from_viewdns()
        self.from_hackertarget()
        self.from_rapiddns()
        return list(self.found_ips)
