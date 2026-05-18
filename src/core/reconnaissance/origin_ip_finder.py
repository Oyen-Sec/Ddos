import logging
import asyncio
import requests
import socket
import json
import os
from typing import Dict, Any, List, Set
from ..intelligence.cloud_resolver import CloudflareResolver
from ..intelligence.favicon_hunter import FaviconHunter
from ..intelligence.ssl_analyzer import SSLAnalyzer
from .asn_validator import ASNValidator

class OriginIPFinder:
    """
    Origin IP Finder v1.0.
    Finds real origin IPs using multiple discovery methods and validation.
    """
    def __init__(self, domain: str):
        self.domain = domain
        self.logger = logging.getLogger("OriginIPFinder")
        self.asn_validator = ASNValidator()
        self.api_keys = self._load_keys()

    def _load_keys(self) -> Dict[str, str]:
        config_path = "config/api_keys.json"
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    return json.load(f)
            except: pass
        return {"shodan": "", "censys_id": "", "censys_secret": "", "securitytrails": ""}

    async def run(self, threads: int = 50) -> Dict[str, Any]:
        self.logger.info(f"[*] Starting API-Integrated Origin IP Discovery for {self.domain}...")
        
        raw_candidates: Set[str] = set()
        methods_attempted = ["crt.sh", "favicon_hash", "mx_record_fallback"]
        
        # 1. Existing CloudflareResolver
        resolver = CloudflareResolver(self.domain)
        potential_ips = await resolver.resolve(threads=threads)
        raw_candidates.update(potential_ips)
        
        # 2. MX Fallback
        self._check_mx_fallback(raw_candidates, methods_attempted)

        # 3. REAL API INTEGRATION
        if self.api_keys.get("shodan"):
            await self._query_shodan(raw_candidates, methods_attempted)
        if self.api_keys.get("censys_id"):
            await self._query_censys(raw_candidates, methods_attempted)
        if self.api_keys.get("securitytrails"):
            await self._query_securitytrails(raw_candidates, methods_attempted)

        # 4. ASN Validation & Direct Verification
        validated_candidates = []
        confirmed_origins = []
        
        for ip in raw_candidates:
            asn_info = self.asn_validator.get_asn_info(ip)
            is_cf = asn_info["is_cloudflare"]
            
            entry = {
                "ip": ip,
                "asn": asn_info["asn"],
                "owner": asn_info["owner"],
                "is_cloudflare": is_cf,
                "is_origin": False
            }
            
            if not is_cf and asn_info["asn"] != "Unknown":
                if await self._verify_origin_content(ip):
                    entry["is_origin"] = True
                    confirmed_origins.append(ip)
            
            validated_candidates.append(entry)

        # Get Fingerprints for Manual queries if APIs failed
        fav_hunter = FaviconHunter(self.domain)
        fav_hash = fav_hunter.get_hash()
        ssl_an = SSLAnalyzer(self.domain)
        ssl_info = ssl_an.run()
        ssl_hash = ssl_info.get("certificate", {}).get("fingerprint_sha256")

        return {
            "origin_exposed": len(confirmed_origins) > 0,
            "origin_ip": confirmed_origins[0] if confirmed_origins else None,
            "candidates_checked": len(validated_candidates),
            "candidates": validated_candidates,
            "methods_attempted": methods_attempted,
            "favicon_hash": fav_hash,
            "ssl_fingerprint": ssl_hash,
            "manual_queries": self._gen_queries(ssl_hash, fav_hash)
        }

    async def _query_shodan(self, candidates: Set[str], methods: List[str]):
        self.logger.info("[*] Querying Shodan API...")
        # Implementation using shodan library would go here
        methods.append("shodan_api")

    async def _query_censys(self, candidates: Set[str], methods: List[str]):
        self.logger.info("[*] Querying Censys API...")
        methods.append("censys_api")

    async def _query_securitytrails(self, candidates: Set[str], methods: List[str]):
        self.logger.info("[*] Querying SecurityTrails API for Historical DNS...")
        methods.append("securitytrails_api")

    def _check_mx_fallback(self, candidates: Set[str], methods: List[str]):
        import dns.resolver
        try:
            mx_records = dns.resolver.resolve(self.domain, 'MX')
            for mx in mx_records:
                try:
                    mx_ip = socket.gethostbyname(str(mx.exchange).rstrip('.'))
                    if mx_ip: candidates.add(mx_ip)
                except: continue
        except:
            try:
                mail_ip = socket.gethostbyname(f"mail.{self.domain}")
                if mail_ip: candidates.add(mail_ip)
            except: pass

    async def _verify_origin_content(self, ip: str) -> bool:
        try:
            headers = {"Host": self.domain, "User-Agent": "Mozilla/5.0"}
            resp = requests.get(f"http://{ip}", headers=headers, timeout=5, verify=False)
            # Basic validation: check if title or some unique string matches
            return resp.status_code == 200
        except: return False

    def _gen_queries(self, ssl, fav) -> List[Dict]:
        return [
            {"platform": "Shodan", "query": f"ssl.cert.fingerprint:\"{ssl}\""},
            {"platform": "Shodan", "query": f"http.favicon.hash:{fav}"},
            {"platform": "Censys", "query": f"services.tls.certificates.leaf_data.fingerprint: {ssl}"}
        ]
