import socket
import logging
import re
from typing import Dict, List, Any
import dns.resolver
import dns.query
import dns.zone
import ipaddress
from .asn_validator import ASNValidator

class DNSAnalyzer:
    """
    DNS Analyzer v1.0.
    Comprehensive record enumeration, CDN detection, and vulnerability checking.
    """
    def __init__(self, domain: str):
        self.domain = domain
        self.logger = logging.getLogger("DNSAnalyzer")
        self.asn_validator = ASNValidator()
        self.cdn_ranges = {
            "Cloudflare": [
                "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13", 
                "104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18", 
                "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20", 
                "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17"
            ],
            "Akamai": ["23.32.0.0/11", "23.192.0.0/11", "184.24.0.0/13"],
            "AWS CloudFront": ["52.84.0.0/15", "54.182.0.0/16", "13.32.0.0/15"],
            "Fastly": ["151.101.0.0/16", "157.52.64.0/18", "199.232.0.0/16"],
            "Google Cloud CDN": ["130.211.0.0/22", "35.190.0.0/17"]
        }

    def analyze(self) -> Dict[str, Any]:
        results = {
            "records": {
                "A": [], "AAAA": [], "MX": [], "NS": [], 
                "TXT": [], "SOA": {}, "CNAME": [], "PTR": [], "SRV": [], "CAA": []
            },
            "dnssec": False,
            "axfr_vulnerable": False,
            "zone_transfer_attempted": True,
            "cdn_detected": "None",
            "cdn_confidence": 0,
            "name_servers": [],
            "wildcard_detected": False,
            "asn_validator": self.asn_validator
        }

        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'SRV', 'CAA']
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        for rtype in record_types:
            try:
                answers = resolver.resolve(self.domain, rtype)
                if rtype == 'SOA':
                    if answers:
                        soa = answers[0]
                        results["records"]["SOA"] = {
                            "primary_ns": str(soa.mname).rstrip('.'),
                            "admin_email": str(soa.rname).replace('.', '@', 1).rstrip('.'),
                            "serial": soa.serial,
                            "refresh": soa.refresh,
                            "retry": soa.retry,
                            "expire": soa.expire,
                            "minimum_ttl": soa.minimum
                        }
                elif rtype == 'MX':
                    results["records"][rtype] = [str(rdata.exchange).rstrip('.') for rdata in answers]
                elif rtype == 'NS':
                    results["records"][rtype] = [str(rdata.target).rstrip('.') for rdata in answers]
                    results["name_servers"] = [str(rdata.target).lower() for rdata in answers]
                else:
                    results["records"][rtype] = [str(rdata).rstrip('.') for rdata in answers]
            except Exception:
                continue

        # Check DNSSEC
        try:
            resolver.resolve(self.domain, 'DNSKEY')
            results["dnssec"] = True
        except Exception:
            pass

        # Detect CDN & Name Servers
        self._detect_cdn(results)
        
        # AXFR Attempt on each NS
        results["axfr_vulnerable"] = self._check_axfr(results["records"]["NS"])
        
        # Wildcard Detection
        results["wildcard_detected"] = self._check_wildcard()
        
        return results

    def _detect_cdn(self, results: Dict):
        # 1. Check A records against known IP ranges
        if results["records"]["A"]:
            for ip_str in results["records"]["A"]:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    for cdn_name, ranges in self.cdn_ranges.items():
                        for network in ranges:
                            if ip_obj in ipaddress.ip_network(network):
                                results["cdn_detected"] = cdn_name
                                results["cdn_confidence"] = 100
                                return
                except ValueError:
                    continue

        # 2. Fallback to NS keywords
        ns_data = " ".join(results["records"]["NS"]).lower()
        for cdn_name in self.cdn_ranges.keys():
            if cdn_name.lower().split()[0] in ns_data:
                results["cdn_detected"] = cdn_name
                results["cdn_confidence"] = 80
                return

    def _check_axfr(self, nameservers: List[str]) -> bool:
        for ns in nameservers:
            try:
                ns_ip = socket.gethostbyname(ns)
                z = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain, timeout=5))
                if z: 
                    self.logger.warning(f"[!] Vulnerable to AXFR on {ns} ({ns_ip})")
                    return True
            except Exception:
                continue
        return False

    def _check_wildcard(self) -> bool:
        try:
            random_sub = f"probe-{socket.gethostname()}.{self.domain}"
            socket.gethostbyname(random_sub)
            return True
        except Exception:
            return False

    def run(self):
        self.logger.info(f"[*] Executing Deep DNS Analysis for {self.domain}...")
        return self.analyze()
