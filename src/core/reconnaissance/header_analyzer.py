import requests
import logging
import re
from typing import Dict, Any, List

class HeaderAnalyzer:
    """
    HTTP Header Analyzer v1.0.
    Analyzes response headers, security flags, cookies, and identifies bypass opportunities.
    """
    def __init__(self, domain: str):
        self.domain = domain
        self.url = f"https://{domain}" if not domain.startswith("http") else domain
        self.logger = logging.getLogger("HeaderAnalyzer")

    def analyze(self) -> Dict[str, Any]:
        results = {
            "raw_headers": {},
            "security_headers": {},
            "bypass_opportunities": [],
            "cookie_analysis": {},
            "backend_leaks": []
        }

        try:
            # We use a real-looking UA to get actual production headers
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
            resp = requests.get(self.url, timeout=10, verify=False, headers=headers)
            results["raw_headers"] = dict(resp.headers)
            
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            
            # 1. Security Header Analysis
            security_checks = {
                "x-frame-options": {"msg": "MISSING — Clickjacking risk", "rec": "SAMEORIGIN"},
                "content-security-policy": {"msg": "MISSING — XSS risk", "rec": "Define a strict CSP"},
                "strict-transport-security": {"msg": "MISSING — MITM risk", "rec": "max-age=31536000; includeSubDomains"},
                "x-content-type-options": {"msg": "MISSING", "rec": "nosniff"},
                "referrer-policy": {"msg": "MISSING", "rec": "no-referrer-when-downgrade"},
                "permissions-policy": {"msg": "MISSING", "rec": "Define specific permissions"}
            }
            
            for h, data in security_checks.items():
                if h in resp_headers:
                    results["security_headers"][h.replace("-", "_")] = {
                        "present": True,
                        "value": resp_headers[h],
                        "recommendation": "OK"
                    }
                else:
                    results["security_headers"][h.replace("-", "_")] = {
                        "present": False,
                        "value": None,
                        "recommendation": data["msg"]
                    }

            # 2. Cookie Analysis
            for cookie in resp.cookies:
                results["cookie_analysis"][cookie.name] = {
                    "value_preview": cookie.value[:10] + "...",
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": cookie.secure,
                    "httponly": cookie.has_nonstandard_attr('httponly') or 'httponly' in str(cookie).lower(),
                    "samesite": cookie.get_nonstandard_attr('samesite', 'None'),
                    "risk": "Low"
                }
                
                # Identify Load Balancer / Framework Cookies
                cname = cookie.name.lower()
                if "awsalb" in cname:
                    results["cookie_analysis"][cookie.name]["type"] = "AWS ALB Sticky Session"
                    results["bypass_opportunities"].append({
                        "technique": "AWS ALB Direct Access",
                        "description": f"Target uses AWS ALB ({cookie.name}). If origin IP is found, Cloudflare can be bypassed.",
                        "severity": "HIGH"
                    })
                elif "asp.net_sessionid" in cname:
                    results["cookie_analysis"][cookie.name]["type"] = "ASP.NET Session"
                    results["cookie_analysis"][cookie.name]["risk"] = "Medium (Session Fixation potential)"
                elif "phpsessid" in cname:
                    results["cookie_analysis"][cookie.name]["type"] = "PHP Session"

            # 3. Backend Leaks & Server Info
            server = resp_headers.get("server", "").lower()
            if server:
                if "cloudflare" in server:
                    results["backend_leaks"].append("Server header points to Cloudflare proxy")
                else:
                    results["backend_leaks"].append(f"Origin server software leaked: {server}")
                    results["bypass_opportunities"].append({
                        "technique": "Direct Server Attack",
                        "description": f"Server header '{server}' is not a standard CDN header. Potential for direct attack.",
                        "severity": "MEDIUM"
                    })

            # Check for Server-Timing (can leak origin processing time)
            if "server-timing" in resp_headers:
                results["backend_leaks"].append("Server-Timing header present (leaks origin backend performance)")
                if "dur=" in resp_headers["server-timing"]:
                    results["bypass_opportunities"].append({
                        "technique": "Backend Timing Analysis",
                        "description": "Server-Timing header reveals origin response duration. Useful for identifying heavy endpoints.",
                        "severity": "LOW"
                    })

        except Exception as e:
            self.logger.error(f"[-] Header Analysis failed for {self.domain}: {e}")

        return results

    def run(self):
        self.logger.info(f"[*] Executing Deep HTTP Header Analysis for {self.domain}...")
        return self.analyze()
