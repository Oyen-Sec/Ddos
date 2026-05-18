import requests
import logging
import socket
from typing import Dict, Any, List, Optional

class ASNValidator:
    """
    Validates IP addresses against ASN records to identify Cloudflare and other proxies.
    """
    CLOUDFLARE_ASNS = ["AS13335", "AS13335", "AS13238", "AS209242"]
    
    def __init__(self):
        self.logger = logging.getLogger("ASNValidator")

    def get_asn_info(self, ip: str) -> Dict[str, Any]:
        """
        Fetches ASN info for a given IP.
        """
        try:
            # Using ip-api for free ASN lookup
            resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,isp,org,as,query", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    asn_raw = data.get("as", "")
                    asn_code = asn_raw.split(" ")[0] if asn_raw else "Unknown"
                    return {
                        "ip": ip,
                        "asn": asn_code,
                        "owner": data.get("isp", "Unknown"),
                        "is_cloudflare": asn_code in self.CLOUDFLARE_ASNS or "cloudflare" in data.get("isp", "").lower(),
                        "status": "success"
                    }
        except Exception as e:
            self.logger.error(f"[-] ASN lookup failed for {ip}: {e}")
        
        return {"ip": ip, "asn": "Unknown", "owner": "Unknown", "is_cloudflare": False, "status": "fail"}

    def is_origin_candidate(self, ip: str) -> bool:
        """
        Determines if an IP is a valid origin candidate (not Cloudflare).
        """
        info = self.get_asn_info(ip)
        return not info["is_cloudflare"] and info["asn"] != "Unknown"
