import requests
import logging
import json
import re
from bs4 import BeautifulSoup

class CrtShScanner:
    def __init__(self, domain: str):
        self.domain = domain
        self.logger = logging.getLogger("CrtShScanner")
        # Try both JSON and HTML if needed
        self.json_url = f"https://crt.sh/?q=%25.{domain}&output=json"
        self.html_url = f"https://crt.sh/?q=%25.{domain}"

    def scan_json(self) -> set:
        subdomains = set()
        try:
            response = requests.get(self.json_url, timeout=25)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry['common_name']
                    if name.startswith('*.'): name = name[2:]
                    subdomains.add(name)
                    
                    alt_names = entry.get('name_value', '').split('\n')
                    for alt in alt_names:
                        alt = alt.strip()
                        if alt.startswith('*.'): alt = alt[2:]
                        if alt.endswith(self.domain): subdomains.add(alt)
            else:
                self.logger.warning(f"[-] crt.sh JSON returned status {response.status_code}")
        except Exception as e:
            self.logger.warning(f"[-] Error scanning crt.sh JSON: {e}")
        return subdomains

    def scan_html(self) -> set:
        subdomains = set()
        self.logger.info(f"[*] Fallback: Scanning crt.sh HTML for {self.domain}...")
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            response = requests.get(self.html_url, headers=headers, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                # Find all table cells (td) that contain subdomains
                for td in soup.find_all('td'):
                    text = td.text.strip()
                    if self.domain in text:
                        # Split by newline or comma if multiple names in one cell
                        parts = re.split(r'[\n,]', text)
                        for part in parts:
                            part = part.strip()
                            if part.startswith('*.'): part = part[2:]
                            if part.endswith(self.domain):
                                subdomains.add(part)
        except Exception as e:
            self.logger.error(f"[-] Error scanning crt.sh HTML: {e}")
        return subdomains

    def scan(self) -> list:
        self.logger.info(f"[*] Scanning crt.sh for subdomains of {self.domain}...")
        subdomains = self.scan_json()
        
        # If JSON failed or returned nothing, try HTML fallback
        if not subdomains:
            subdomains = self.scan_html()
            
        self.logger.info(f"[+] Found {len(subdomains)} subdomains from crt.sh")
        return sorted(list(subdomains))
