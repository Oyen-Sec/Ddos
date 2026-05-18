import logging
from typing import Dict, Any, List

class AttackSurface:
    """
    Attack Surface Summary v1.0.
    Aggregates all reconnaissance data, synchronizes findings with real intelligence,
    and ranks attack vectors with realistic scoring.
    """
    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.logger = logging.getLogger("AttackSurface")

    def summarize(self) -> Dict[str, Any]:
        self.logger.info("[*] Synchronizing Attack Surface Data & Ranking Vectors...")
        
        summary = {
            "total_open_ports": 0,
            "total_services": 0,
            "total_vulnerabilities": 0,
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "low_findings": 0,
            "informational": 0,
            "risk_score": 0.0,
            "risk_level": "LOW",
            "attack_vectors_ranked": [],
            "detailed_findings": []
        }

        # 1. Sync IP Intelligence (Ports & Services)
        ipv4_data = self.data.get("ip_intelligence", {}).get("ipv4", [])
        for ip_info in ipv4_data:
            summary["total_open_ports"] += len(ip_info.get("open_ports", []))
            summary["total_services"] += len(ip_info.get("services", []))
            
            # PTR check
            if not ip_info.get("reverse_dns"):
                summary["informational"] += 1
                summary["detailed_findings"].append({"issue": "Missing PTR record", "severity": "INFO", "target": ip_info.get("ip")})

        # 2. SSL/TLS Vulnerabilities & Grade
        ssl = self.data.get("ssl_tls_analysis", {})
        summary["total_vulnerabilities"] += len(ssl.get("vulnerabilities", []))
        if ssl.get("grade") == "F":
            summary["critical_findings"] += 1
            summary["risk_score"] += 5.0
            summary["detailed_findings"].append({"issue": "SSL Grade F", "severity": "CRITICAL"})
        elif ssl.get("grade") in ["A", "A+"]:
            summary["informational"] += 1

        # 3. HTTP Header & Cookie Security Flagging
        headers = self.data.get("http_headers_analysis", {})
        sec_headers = headers.get("security_headers", {})
        
        # CSP
        if not sec_headers.get("content_security_policy", {}).get("present"):
            summary["medium_findings"] += 1
            summary["risk_score"] += 1.0
            summary["detailed_findings"].append({"issue": "Missing Content-Security-Policy (CSP)", "severity": "MEDIUM"})
            
        # Cookies
        cookies = headers.get("cookie_analysis", {})
        for cname, cinfo in cookies.items():
            if not cinfo.get("httponly"):
                sev = "HIGH" if "session" in cname.lower() or "token" in cname.lower() else "MEDIUM"
                if sev == "HIGH": summary["high_findings"] += 1
                else: summary["medium_findings"] += 1
                summary["risk_score"] += (2.0 if sev == "HIGH" else 1.0)
                summary["detailed_findings"].append({"issue": f"Cookie {cname} missing HttpOnly flag", "severity": sev})
            
            if not cinfo.get("secure"):
                summary["medium_findings"] += 1
                summary["risk_score"] += 1.0
                summary["detailed_findings"].append({"issue": f"Cookie {cname} missing Secure flag", "severity": "MEDIUM"})
                
            if cinfo.get("samesite") == "None":
                summary["medium_findings"] += 1
                summary["risk_score"] += 1.0
                summary["detailed_findings"].append({"issue": f"Cookie {cname} SameSite=None (CSRF Risk)", "severity": "MEDIUM"})

        # 4. WAF & Bypass Opportunities
        bypass_ops = headers.get("bypass_opportunities", [])
        for op in bypass_ops:
            if op["severity"] == "HIGH":
                summary["high_findings"] += 1
                summary["risk_score"] += 2.5
                summary["detailed_findings"].append({"issue": op["technique"], "severity": "HIGH", "desc": op["description"]})
            elif op["severity"] == "MEDIUM":
                summary["medium_findings"] += 1
                summary["risk_score"] += 1.5

        # 5. Rank Attack Vectors (Realistic)
        origin_disc = self.data.get("ip_intelligence", {}).get("origin_ip_discovery", {})
        origin_found = origin_disc.get("origin_exposed", False)
        
        self._rank_vectors(summary, origin_found, origin_disc, bypass_ops)

        # 6. Final Risk Level Calculation
        if origin_found:
            summary["risk_score"] = max(summary["risk_score"], 9.0)
            summary["risk_level"] = "CRITICAL"
        elif summary["risk_score"] >= 7.0:
            summary["risk_level"] = "HIGH"
        elif summary["risk_score"] >= 3.0:
            summary["risk_level"] = "MEDIUM"
        else:
            summary["risk_level"] = "LOW"

        return summary

    def _rank_vectors(self, summary: Dict, origin_found: bool, origin_disc: Dict, bypass_ops: List[Dict]):
        vectors = []
        
        if origin_found:
            vectors.append({
                "rank": 1,
                "vector": "DIRECT_IP_VOLUMETRIC",
                "feasibility": "HIGH",
                "impact": "CRITICAL",
                "description": f"Origin IP {origin_disc.get('origin_ip')} exposed. Direct L3/L4 attack will bypass Cloudflare entirely."
            })
        
        # Always add L7 as it's always an option
        vectors.append({
            "rank": 2 if origin_found else 1,
            "vector": "L7_SMART_FLOOD",
            "feasibility": "MEDIUM",
            "impact": "HIGH",
            "description": "High-performance HTTP/2 flood with JA3 spoofing. Targeted at heaviest GET URLs found in Smart Targeting."
        })

        # AWS ALB Direct
        for op in bypass_ops:
            if "AWS ALB" in op["technique"]:
                vectors.append({
                    "rank": 3 if origin_found else 2,
                    "vector": "AWS_ALB_BYPASS",
                    "feasibility": "MEDIUM",
                    "impact": "CRITICAL",
                    "description": "Exploit AWS ALB sticky sessions to find origin ALB IP and bypass Cloudflare."
                })
                break

        # SEO Destruction
        vectors.append({
            "rank": 4,
            "vector": "SEO_DESTRUCTION",
            "feasibility": "HIGH",
            "impact": "MEDIUM",
            "description": "Execute negative SEO campaign via content scraping and backlink poisoning."
        })

        # Deep Origin Hunting
        if not origin_found:
            vectors.append({
                "rank": 5,
                "vector": "DEEP_ORIGIN_HUNTING",
                "feasibility": "HIGH",
                "impact": "CRITICAL",
                "description": "Continue discovery via Shodan/Censys API and SecurityTrails historical DNS data."
            })

        summary["attack_vectors_ranked"] = sorted(vectors, key=lambda x: x["rank"])

    def run(self):
        return self.summarize()
