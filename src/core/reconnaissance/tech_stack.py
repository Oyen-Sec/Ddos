import requests
import logging
import re
from typing import Dict, Any, List
from bs4 import BeautifulSoup

class TechStack:
    """
    Technology Stack Fingerprinter v1.0.
    Identifies Server, CDN, Load Balancer, Backend Frameworks, and Frontend Libraries.
    Uses multi-evidence detection (Headers, Cookies, Body, Scripts).
    """
    def __init__(self, domain: str):
        self.domain = domain
        self.url = f"https://{domain}" if not domain.startswith("http") else domain
        self.logger = logging.getLogger("TechStack")

    def fingerprint(self) -> Dict[str, Any]:
        results = {
            "server": {"detected": "Unknown", "version": None, "confidence": 0},
            "cdn": {"detected": "None", "version": None, "confidence": 0, "features": []},
            "load_balancer": {"detected": "None", "confidence": 0, "evidence": []},
            "backend": {"detected": "Unknown", "version": None, "confidence": 0, "evidence": []},
            "programming_language": "Unknown",
            "frontend_libraries": [],
            "additional_technologies": []
        }

        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            resp = requests.get(self.url, timeout=10, verify=False, headers=headers)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.text.lower()
            soup = BeautifulSoup(resp.text, 'html.parser')

            # 1. Server & CDN Detection
            server = resp_headers.get("server", "").lower()
            if server:
                results["server"] = {"detected": server, "version": None, "confidence": 100}
                if "cloudflare" in server:
                    results["cdn"] = {"detected": "Cloudflare", "confidence": 100, "features": ["Brotli", "WAF", "HSTS"]}
                    if "h3" in resp_headers.get("alt-svc", ""): results["cdn"]["features"].append("HTTP/3")
                elif "akamai" in server:
                    results["cdn"] = {"detected": "Akamai", "confidence": 100}

            # 2. Load Balancer Detection
            cookies = str(resp_headers.get("set-cookie", "")).lower()
            if "awsalb" in cookies:
                results["load_balancer"] = {"detected": "AWS ALB", "confidence": 100, "evidence": ["AWSALB cookie present"]}
            elif "nginx" in server:
                results["load_balancer"] = {"detected": "Nginx", "confidence": 70, "evidence": ["Server header"]}

            # 3. Backend Framework & Language
            x_powered = resp_headers.get("x-powered-by", "").lower()
            if x_powered:
                results["backend"] = {"detected": x_powered, "confidence": 100, "evidence": ["X-Powered-By header"]}
                if "php" in x_powered: results["programming_language"] = "PHP"
                elif "asp.net" in x_powered: results["programming_language"] = "C# / .NET"
            
            if "asp.net_sessionid" in cookies or "__requestverificationtoken" in cookies:
                results["backend"] = {"detected": "ASP.NET", "confidence": 95, "evidence": ["ASP.NET cookies"]}
                results["programming_language"] = "C# / .NET"
            elif "phpsessid" in cookies:
                results["backend"] = {"detected": "PHP", "confidence": 95, "evidence": ["PHPSESSID cookie"]}
                results["programming_language"] = "PHP"
            elif "django" in body or "csrftoken" in cookies:
                results["backend"] = {"detected": "Django", "confidence": 90, "evidence": ["Django patterns"]}
                results["programming_language"] = "Python"

            # 4. Frontend Libraries
            scripts = [s.get("src", "") for s in soup.find_all("script") if s.get("src")]
            lib_patterns = {
                "jQuery": r"jquery[.-](\d+\.\d+\.\d+)?",
                "React": r"react",
                "Vue": r"vue",
                "Angular": r"angular",
                "Bootstrap": r"bootstrap",
                "Tailwind": r"tailwind"
            }
            
            for lib, pattern in lib_patterns.items():
                for s in scripts:
                    match = re.search(pattern, s.lower())
                    if match:
                        version = match.group(1) if match.groups() else "Unknown"
                        results["frontend_libraries"].append({"name": lib, "version": version, "confidence": 90})
                        break

            # 5. Additional Technologies
            if "http/3" in results["cdn"]["features"]: results["additional_technologies"].append("HTTP/3 (QUIC)")
            if "br" in resp_headers.get("content-encoding", ""): results["additional_technologies"].append("Brotli compression")
            if "<!doctype html>" in body: results["additional_technologies"].append("HTML5")

        except Exception as e:
            self.logger.error(f"[-] TechStack fingerprinting failed: {e}")

        return results

    def run(self):
        self.logger.info(f"[*] Executing Deep Technology Stack Fingerprinting for {self.domain}...")
        return self.fingerprint()
