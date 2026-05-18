import requests
import logging
import socket
import nmap
from typing import Dict, List, Any
import ipwhois

class IPIntelligence:
    """
    IP Intelligence v1.0.
    Analyzes IP addresses for Geolocation, ASN, Reputation, and Stealth Port Scanning.
    """
    def __init__(self, ips: List[str]):
        self.ips = ips
        self.logger = logging.getLogger("IPIntelligence")

    def analyze_batch(self) -> List[Dict[str, Any]]:
        results = []
        for ip in self.ips:
            results.append(self.analyze_ip(ip))
        return results

    def analyze_ip(self, ip: str) -> Dict[str, Any]:
        self.logger.info(f"[*] Analyzing IP: {ip}...")
        res = {
            "ip": ip,
            "version": 4 if ":" not in ip else 6,
            "asn": "Unknown",
            "asn_owner": "Unknown",
            "country": "Unknown",
            "city": "Unknown",
            "region": "Unknown",
            "latitude": 0.0,
            "longitude": 0.0,
            "hosting_provider": "Unknown",
            "is_datacenter": False,
            "is_cloudflare": False,
            "reverse_dns": [],
            "open_ports": [],
            "services": [],
            "reputation": "Unknown",
            "abuse_score": 0
        }

        # 1. Geolocation & ASN via ip-api (No key required)
        try:
            resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,lat,lon,query", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    res["country"] = data.get("country")
                    res["region"] = data.get("regionName")
                    res["city"] = data.get("city")
                    res["latitude"] = data.get("lat")
                    res["longitude"] = data.get("lon")
                    res["hosting_provider"] = data.get("isp")
                    res["asn"] = data.get("as", "").split(" ")[0]
                    res["asn_owner"] = " ".join(data.get("as", "").split(" ")[1:])
                    
                    # Explicit Cloudflare check
                    res["is_cloudflare"] = res["asn"] in ["AS13335", "AS13238"] or "cloudflare" in data.get("isp", "").lower()
                    
                    # Basic datacenter detection based on ISP keywords
                    dc_keywords = ['cloudflare', 'amazon', 'google', 'digitalocean', 'ovh', 'hetzner', 'akamai', 'microsoft']
                    if any(k in data.get("isp", "").lower() for k in dc_keywords):
                        res["is_datacenter"] = True
        except Exception:
            pass

        # 2. Advanced ASN Lookup via ipwhois
        if res["asn"] == "Unknown":
            try:
                obj = ipwhois.IPWhois(ip)
                results = obj.lookup_rdap()
                res["asn"] = results.get("asn")
                res["asn_owner"] = results.get("asn_description")
            except Exception:
                pass

        # 3. Reverse DNS
        try:
            rdns = socket.gethostbyaddr(ip)
            res["reverse_dns"] = [rdns[0]]
        except Exception:
            pass

        # 4. Port Scanning via Nmap (Passive/Top ports only)
        try:
            nm = nmap.PortScanner()
            # -F: Fast scan (top 100 ports), -sV: Version detection, -Pn: No ping
            nm.scan(ip, arguments='-F -sV -Pn')
            if ip in nm.all_hosts():
                for proto in nm[ip].all_protocols():
                    lport = nm[ip][proto].keys()
                    for port in lport:
                        res["open_ports"].append(port)
                        service = nm[ip][proto][port]
                        res["services"].append({
                            "port": port,
                            "name": service.get('name'),
                            "product": service.get('product'),
                            "version": service.get('version')
                        })
        except nmap.PortScannerError:
            self.logger.warning(f"[-] Nmap binary not found in path. Falling back to simple socket check for {ip}.")
            self._socket_port_scan(ip, res)
        except Exception as e:
            self.logger.warning(f"[-] Nmap scan failed for {ip}: {e}")
            self._socket_port_scan(ip, res)

        # 5. Reputation Check (Placeholder - AbuseIPDB etc usually require API keys)
        # We can implement a basic check or just leave it for now
        
        return res

    def _socket_port_scan(self, ip: str, res: Dict):
        common_ports = [80, 443, 21, 22, 25, 53, 3306, 8080, 8443]
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((ip, port)) == 0:
                res["open_ports"].append(port)
                # Basic service name mapping
                service_map = {80: "http", 443: "https", 21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 3306: "mysql", 8080: "http-proxy", 8443: "https-proxy"}
                res["services"].append({
                    "port": port,
                    "name": service_map.get(port, "unknown"),
                    "product": None,
                    "version": None
                })
            sock.close()

    def run(self):
        return self.analyze_batch()
