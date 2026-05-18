import requests
import logging
from typing import Dict

class HostingDetector:
    """
    Detects IP geolocation, ASN, and hosting provider.
    """
    def __init__(self, ip: str):
        self.ip = ip
        self.logger = logging.getLogger("HostingDetector")

    def lookup(self) -> Dict:
        try:
            # Use ip-api.com (free, no API key required)
            resp = requests.get(f"http://ip-api.com/json/{self.ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query", timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            self.logger.error(f"[-] Hosting lookup failed for {self.ip}: {e}")
        return {}

    def run(self):
        self.logger.info(f"[*] Detecting hosting/location for {self.ip}...")
        return self.lookup()
