import asyncio
import logging
import json
import os
import uuid
from datetime import datetime
from typing import Dict
from .dns_analyzer import DNSAnalyzer
from .waf_detector import WAFDetector
from .origin_ip_finder import OriginIPFinder
from ..intelligence.ssl_analyzer import SSLAnalyzer
from .ip_intelligence import IPIntelligence
from .header_analyzer import HeaderAnalyzer
from .tech_stack import TechStack
from .attack_surface import AttackSurface
from .cloud_leak_finder import CloudLeakFinder
from .subdomain_permutator import SubdomainPermutator

class Reconnaissance:
    """
    Reconnaissance Orchestrator v1.0.
    Executes all sub-modules and aggregates data into a standardized JSON report.
    """
    def __init__(self, target: str):
        self.target = target
        self.logger = logging.getLogger("Reconnaissance")
        self.results = {
            "metadata": {
                "scan_id": str(uuid.uuid4()),
                "timestamp": datetime.now().isoformat(),
                "target": target,
                "scanner_version": "Recon-v1.0",
                "disclaimer": "For authorized penetration testing only"
            },
            "dns_analysis": {},
            "ip_intelligence": {},
            "ssl_tls_analysis": {},
            "http_headers_analysis": {},
            "waf_analysis": {},
            "technology_stack": {},
            "attack_surface_summary": {},
            "recommendations": {}
        }

    async def run_all(self, threads: int = 50) -> Dict:
        self.logger.info(f"[*] Starting Reconnaissance v1.0 for {self.target}...")
        
        # 1. DNS Analysis
        dns_an = DNSAnalyzer(self.target)
        self.results["dns_analysis"] = dns_an.run()
        
        # 2. IP Intelligence (on discovered A records)
        ips = self.results["dns_analysis"].get("records", {}).get("A", [])
        if ips:
            ip_intel = IPIntelligence(ips)
            self.results["ip_intelligence"]["ipv4"] = ip_intel.run()
        
        # 3. SSL/TLS Analysis
        ssl_an = SSLAnalyzer(self.target)
        self.results["ssl_tls_analysis"] = ssl_an.run()
        
        # 4. HTTP Headers Analysis
        header_an = HeaderAnalyzer(self.target)
        self.results["http_headers_analysis"] = header_an.run()
        
        # 5. WAF Detection & Bypass Assessment
        waf_an = WAFDetector(self.target)
        self.results["waf_analysis"] = waf_an.run()
        
        # 6. Technology Stack Fingerprinting
        tech_an = TechStack(self.target)
        self.results["technology_stack"] = tech_an.run()
        
        # 7. Origin IP Discovery
        origin_an = OriginIPFinder(self.target)
        self.results["ip_intelligence"]["origin_ip_discovery"] = await origin_an.run(threads=threads)
        
        # 8. Cloud Leak Discovery
        cloud_an = CloudLeakFinder(self.target)
        self.results["cloud_leaks"] = cloud_an.run()
        
        # 9. Subdomain Permutations with ASN Check
        perm_an = SubdomainPermutator(self.target)
        raw_perms = perm_an.run(threads=threads)
        validated_perms = []
        for sub, ip in raw_perms:
            asn_info = self.results["dns_analysis"]["asn_validator"].get_asn_info(ip) if "asn_validator" in self.results["dns_analysis"] else {"is_cloudflare": False, "asn": "Unknown"}
            validated_perms.append({
                "subdomain": sub,
                "ip": ip,
                "asn": asn_info.get("asn"),
                "is_cloudflare": asn_info.get("is_cloudflare"),
                "status": "Proxied" if asn_info.get("is_cloudflare") else "POTENTIAL ORIGIN"
            })
        self.results["subdomain_permutations"] = validated_perms
        
        # 10. Attack Surface Summary & Risk Scoring
        surface_an = AttackSurface(self.results)
        self.results["attack_surface_summary"] = surface_an.run()
        
        # 11. Recommendations (Based on findings)
        self.results["recommendations"] = self._generate_recommendations()
        
        self._save_report()
        return self.results

    def _generate_recommendations(self) -> Dict:
        return {
            "immediate_actions": [
                "Perform subdomain enumeration using standard wordlists",
                "Monitor certificate transparency logs for new entries",
                "Verify potential origin IPs via content matching"
            ],
            "attack_plan": [
                "Phase 1: Confirm Origin IP through historical DNS or leaks",
                "Phase 2: If origin found, bypass WAF and execute direct L3/L4 attack",
                "Phase 3: If origin remains hidden, use Core L7 Engine with JA3 spoofing"
            ]
        }

    def _save_report(self):
        os.makedirs("output/reports", exist_ok=True)
        filename = f"output/reports/recon_{self.target}.json"
        
        # Remove objects before saving to JSON
        save_results = self.results.copy()
        if "dns_analysis" in save_results and "asn_validator" in save_results["dns_analysis"]:
            del save_results["dns_analysis"]["asn_validator"]
            
        with open(filename, 'w') as f:
            json.dump(save_results, f, indent=4)
        self.logger.info(f"[+] Recon report saved to {filename}")
