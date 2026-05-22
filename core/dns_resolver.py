import socket
import dns.resolver
import logging
from typing import Dict

logger = logging.getLogger("DNSResolver")

class DNSResolver:
    def __init__(self, domain: str):
        self.domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    def validate_ip_reachable(self, ip: str, port: int = 443, timeout: int = 5) -> Dict:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return {"reachable": True, "error": None}
            return {"reachable": False, "error": f"TCP connect failed: errno {result}"}
        except Exception as e:
            return {"reachable": False, "error": str(e)}

    def check_dns_consistency(self) -> Dict:
        results = {}
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8']
            answers = resolver.resolve(self.domain, 'A')
            results["dnspython_google"] = [str(r) for r in answers]
        except Exception:
            results["dnspython_google"] = []
        try:
            results["system"] = [socket.gethostbyname(self.domain)]
        except Exception:
            results["system"] = []
        all_ips = set()
        for res in results.values():
            if isinstance(res, list):
                all_ips.update(res)
        return {
            "consistent": len(all_ips) <= 1,
            "all_ips": list(all_ips),
            "results": results,
            "selected": results.get("system", [None])[0] if results.get("system") else (list(all_ips)[0] if all_ips else None)
        }

    def resolve(self) -> Dict:
        consistency = self.check_dns_consistency()
        if not consistency["all_ips"]:
            raise RuntimeError(f"CRITICAL: Cannot resolve {self.domain} by any method.")
        selected_ip = consistency["selected"]
        reach = self.validate_ip_reachable(selected_ip)
        return {
            "ip": selected_ip,
            "method": "consistent_check",
            "reachable": reach["reachable"],
            "reach_error": reach["error"],
            "all_ips": consistency["all_ips"]
        }

def pre_resolve_domain(domain: str) -> Dict:
    return DNSResolver(domain).resolve()
