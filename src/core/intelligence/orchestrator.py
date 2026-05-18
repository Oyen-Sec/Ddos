import asyncio
import logging
import json
import os
from typing import Dict, List, Set, Any
from . import (
    CrtShScanner, HistoricalDNS, ShodanScanner,
    FaviconHunter, DeepSubdomainEnumerator, EmailLeakFinder,
    DorkScanner
)
from ..reconnaissance.asn_validator import ASNValidator
from ..analysis.origin_validator import OriginValidator

class DeepIntelligence:
    """
    Phase 2: Origin IP Discovery - Zero-Knowledge Approach.
    Uses deep intelligence gathering to find potential origin IPs.
    """
    def __init__(self, target: str):
        self.target = target
        self.logger = logging.getLogger("DeepIntelligence")
        self.asn_validator = ASNValidator()
        self.origin_validator = OriginValidator(target)
        self.api_keys = self._load_api_keys()
        self.results = {
            "target": target,
            "found_ips": set(),
            "subdomains": set(),
            "origin_candidates": [],
            "confirmed_origin": None
        }

    def _load_api_keys(self) -> Dict:
        path = "config/api_keys.json"
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    return json.load(f)
            except: pass
        return {}

    async def run(self, threads: int = 50) -> Dict:
        self.logger.info(f"[*] Starting PHASE 2: DEEP INTELLIGENCE for {self.target}")
        
        # 1. Certificate Transparency (crt.sh)
        crt_scanner = CrtShScanner(self.target)
        self.logger.info("[*] Scanning Certificate Transparency Logs...")
        ct_subdomains = crt_scanner.scan()
        self.results["subdomains"].update(ct_subdomains)

        # 2. Historical DNS
        hist_dns = HistoricalDNS(self.target)
        self.logger.info("[*] Querying Historical DNS records...")
        hist_ips = hist_dns.run_all()
        self.results["found_ips"].update(hist_ips)

        # 3. Favicon Hashing & Shodan/Censys (Passive)
        fav_hunter = FaviconHunter(self.target)
        fav_hash = fav_hunter.get_hash()
        if fav_hash:
            self.logger.info(f"[+] Favicon Hash: {fav_hash}")
            if self.api_keys.get("shodan"):
                shodan = ShodanScanner(self.api_keys["shodan"])
                shodan_ips = shodan.search_by_favicon(fav_hash)
                self.results["found_ips"].update(shodan_ips)

        # 4. Deep Subdomain Enumeration
        deep_enum = DeepSubdomainEnumerator(self.target)
        found_subs = deep_enum.run(threads=threads)
        for sub, ip in found_subs:
            self.results["subdomains"].add(sub)
            self.results["found_ips"].add(ip)

        # 5. Email Leak Finder (Simplified check)
        email_finder = EmailLeakFinder(self.target)
        leak_ips = email_finder.run()
        self.results["found_ips"].update(leak_ips)

        # 6. Google Dorking
        dork_scanner = DorkScanner(self.target)
        self.results["dorks"] = dork_scanner.generate_dorks()

        # 7. Validate Found IPs
        self.logger.info(f"[*] Validating {len(self.results['found_ips'])} discovered IPs...")
        for ip in self.results["found_ips"]:
            asn_info = self.asn_validator.get_asn_info(ip)
            if not asn_info["is_cloudflare"]:
                # Potential origin!
                is_valid = await self.origin_validator.validate(ip)
                candidate = {
                    "ip": ip,
                    "asn": asn_info["asn"],
                    "owner": asn_info["owner"],
                    "is_origin": is_valid,
                    "confidence": "High" if is_valid else "Medium"
                }
                self.results["origin_candidates"].append(candidate)
                if is_valid and not self.results["confirmed_origin"]:
                    self.results["confirmed_origin"] = ip

        # Final Summary
        self.logger.info(f"[+] Deep Intelligence Complete. Found {len(self.results['origin_candidates'])} candidates.")
        if self.results["confirmed_origin"]:
            self.logger.info(f"CONFIRMED ORIGIN IP: {self.results['confirmed_origin']}")

        return self._prepare_report()

    def _prepare_report(self) -> Dict:
        report = {
            "target": self.target,
            "total_subdomains_found": len(self.results["subdomains"]),
            "total_ips_discovered": len(self.results["found_ips"]),
            "origin_candidates": self.results["origin_candidates"],
            "confirmed_origin": self.results["confirmed_origin"],
            "subdomains": sorted(list(self.results["subdomains"])),
            "suggested_dorks": self.results.get("dorks", [])
        }
        return report
