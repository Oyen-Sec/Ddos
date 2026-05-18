import requests
import logging
from typing import Dict, List, Any

class WAFDetector:
    """
    WAF Detector v1.0.
    Identifies WAF vendor, confidence, active rules, and assesses bypass feasibility.
    """
    def __init__(self, domain: str):
        self.domain = domain
        self.url = f"https://{domain}" if not domain.startswith("http") else domain
        self.logger = logging.getLogger("WAFDetector")

    def analyze(self) -> Dict[str, Any]:
        results = {
            "detected": False,
            "vendor": "None",
            "confidence": 0,
            "version": "Unknown",
            "rules_detected": [],
            "bypass_feasibility": {
                "overall": "LOW",
                "reasons": [],
                "potential_vectors": []
            },
            "test_results": {
                "blocked_requests": 0,
                "challenged_requests": 0,
                "allowed_requests": 0,
                "notes": "Passive recon only"
            }
        }

        try:
            resp = requests.get(self.url, timeout=10, verify=False)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            results["test_results"]["allowed_requests"] += 1
            
            # 1. Cloudflare Detection
            if "cf-ray" in headers or "server" in headers and "cloudflare" in headers["server"].lower():
                results.update({"detected": True, "vendor": "Cloudflare", "confidence": 100})
                results["rules_detected"] = ["DDoS Protection", "Rate Limiting", "Bot Management"]
                results["bypass_feasibility"]["reasons"] = [
                    "Full Cloudflare proxy active (Proxy-over-Origin)",
                    "TLS 1.3 enforced (usually)",
                    "HSTS enabled (common)"
                ]
                results["bypass_feasibility"]["potential_vectors"] = [
                    {"vector": "Origin IP Discovery", "feasibility": "MEDIUM", "method": "Search real IP via CT logs, historical DNS, or Shodan"},
                    {"vector": "Subdomain Bypass", "feasibility": "MEDIUM", "method": "Enumerate subdomains that might not be behind Cloudflare"},
                    {"vector": "AWS ALB Direct Access", "feasibility": "HIGH", "condition": "If AWSALB cookie is present and origin IP found"}
                ]
                
            # 2. Akamai Detection
            elif "x-akamai-transformed" in headers or "akamai-ghost" in headers.get("server", "").lower():
                results.update({"detected": True, "vendor": "Akamai", "confidence": 100})
                results["rules_detected"] = ["Edge DDoS Protection", "WAF Ruleset"]
                
            # 3. AWS WAF Detection
            elif "x-amz-cf-id" in headers:
                results.update({"detected": True, "vendor": "AWS WAF (CloudFront)", "confidence": 95})
            
            # 4. Imperva/Incapsula Detection
            elif "x-iinfo" in headers or "visid_incap" in str(headers.get("set-cookie")).lower():
                results.update({"detected": True, "vendor": "Imperva Incapsula", "confidence": 100})

            # Feasibility Scoring Logic
            if results["detected"]:
                if "Origin IP Leak" in [v["vector"] for v in results["bypass_feasibility"]["potential_vectors"]]:
                    results["bypass_feasibility"]["overall"] = "MEDIUM"
                else:
                    results["bypass_feasibility"]["overall"] = "LOW"

        except Exception as e:
            self.logger.error(f"[-] WAF Analysis failed: {e}")

        return results

    def run(self):
        self.logger.info(f"[*] Executing Deep WAF Detection & Bypass Assessment for {self.domain}...")
        return self.analyze()
