"""
Cloudflare CDN/WAF Bypass Module 2026
Comprehensive bypass techniques for Cloudflare protection.

Techniques:
1. Origin IP Discovery (crt.sh, Shodan, SecurityTrails, DNS history, subdomain enum)
2. FlareSolverr (browser automation bypass)
3. curl_cffi TLS fingerprint impersonation
4. Domain Fronting
5. SNI Spoofing
6. Residential proxy rotation
"""
import asyncio
import logging
import socket
import ssl
import json
from typing import Optional, Dict, List, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class CloudflareBypass:
    """Cloudflare bypass orchestrator."""
    
    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.cf_ip_ranges = [
            "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
            "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
            "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
            "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
            "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
        ]
    
    @staticmethod
    def detect(headers: dict) -> bool:
        """Detect if target is behind Cloudflare."""
        if not headers:
            return False
        h = {k.lower(): v.lower() for k, v in headers.items()}
        
        # Check CF headers
        cf_headers = ["cf-ray", "cf-cache-status", "cf-request-id", "__cfduid"]
        if any(hdr in h for hdr in cf_headers):
            return True
        
        # Check server header
        server = h.get("server", "")
        if "cloudflare" in server:
            return True
        
        # Check set-cookie for CF cookies
        cookies = h.get("set-cookie", "")
        if "__cfduid" in cookies or "__cf_bm" in cookies or "cf_clearance" in cookies:
            return True
        
        return False
    
    def is_cloudflare_ip(self, ip: str) -> bool:
        """Check if IP belongs to Cloudflare ranges."""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            for cidr in self.cf_ip_ranges:
                if ip_obj in ipaddress.ip_network(cidr):
                    return True
        except:
            pass
        return False
    
    async def find_origin_via_crtsh(self, domain: str) -> List[str]:
        """Find origin IPs via Certificate Transparency (crt.sh)."""
        ips = set()
        try:
            import aiohttp
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        # Extract unique domain names
                        domains = set()
                        for entry in data[:100]:  # Limit to first 100
                            name = entry.get("name_value", "")
                            if name and "*" not in name:
                                domains.add(name.strip())
                        
                        # Resolve each domain
                        for d in list(domains)[:20]:  # Limit to 20 domains
                            try:
                                ip = socket.gethostbyname(d)
                                if not self.is_cloudflare_ip(ip):
                                    ips.add(ip)
                            except:
                                continue
        except Exception as e:
            logger.debug(f"crt.sh error: {e}")
        
        return list(ips)
    
    async def find_origin_via_shodan(self, domain: str, api_key: str) -> List[str]:
        """Find origin IPs via Shodan API."""
        ips = set()
        if not api_key:
            return []
        
        try:
            import shodan
            api = shodan.Shodan(api_key)
            
            # Search by hostname
            results = api.search(f"hostname:{domain}", limit=10)
            for result in results.get("matches", []):
                ip = result.get("ip_str")
                if ip and not self.is_cloudflare_ip(ip):
                    ips.add(ip)
        except Exception as e:
            logger.debug(f"Shodan error: {e}")
        
        return list(ips)
    
    async def find_origin_via_subdomain_enum(self, domain: str) -> List[str]:
        """Find origin via subdomain enumeration."""
        ips = set()
        base = ".".join(domain.split(".")[-2:]) if domain.count(".") >= 1 else domain
        
        # Common subdomains that might not be behind CF
        subdomains = [
            "direct", "origin", "backend", "api", "admin", "cpanel", "mail",
            "ftp", "ssh", "webmail", "smtp", "pop", "imap", "ns1", "ns2",
            "dev", "staging", "test", "uat", "prod", "www2", "old", "new"
        ]
        
        for sub in subdomains:
            try:
                fqdn = f"{sub}.{base}"
                ip = socket.gethostbyname(fqdn)
                if not self.is_cloudflare_ip(ip):
                    ips.add(ip)
            except:
                continue
        
        return list(ips)
    
    async def find_origin_via_dns_history(self, domain: str, securitytrails_key: str) -> List[str]:
        """Find origin via DNS history (SecurityTrails API)."""
        ips = set()
        if not securitytrails_key:
            return []
        
        try:
            import aiohttp
            url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
            headers = {"APIKEY": securitytrails_key}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        records = data.get("records", [])
                        for record in records[:20]:
                            for value in record.get("values", []):
                                ip = value.get("ip")
                                if ip and not self.is_cloudflare_ip(ip):
                                    ips.add(ip)
        except Exception as e:
            logger.debug(f"SecurityTrails error: {e}")
        
        return list(ips)
    
    async def verify_origin(self, ip: str, hostname: str) -> bool:
        """Verify if IP is actual origin by making direct request."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, 443))
            
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            ssl_sock = ctx.wrap_socket(sock, server_hostname=hostname)
            request = f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
            ssl_sock.send(request.encode())
            
            response = ssl_sock.recv(4096)
            ssl_sock.close()
            
            # Check if response looks legitimate (not CF error page)
            resp_str = response.decode(errors="ignore")
            if "200 OK" in resp_str or "301" in resp_str or "302" in resp_str:
                # Make sure it's not CF
                if "cloudflare" not in resp_str.lower() and "cf-ray" not in resp_str.lower():
                    return True
        except:
            pass
        
        return False
    
    async def bypass_with_curl_cffi(self, url: str, proxy_url: Optional[str] = None) -> Dict:
        """Bypass Cloudflare using curl_cffi TLS fingerprint impersonation."""
        try:
            from curl_cffi import requests as curl_req
            
            session = curl_req.Session()
            session.impersonate = "chrome120"
            
            if proxy_url:
                session.proxies = {"https": proxy_url, "http": proxy_url}
            
            resp = session.get(url, timeout=15, verify=False)
            
            return {
                "success": resp.status_code in [200, 301, 302],
                "status_code": resp.status_code,
                "method": "curl_cffi_chrome120",
                "headers": dict(resp.headers),
                "body_length": len(resp.text)
            }
        except Exception as e:
            logger.debug(f"curl_cffi bypass error: {e}")
            return {"success": False, "error": str(e)}
    
    async def bypass_with_flaresolverr(self, url: str, flaresolverr_url: str = "http://localhost:8191") -> Dict:
        """Bypass Cloudflare using FlareSolverr."""
        try:
            import aiohttp
            
            payload = {
                "cmd": "request.get",
                "url": url,
                "maxTimeout": 60000
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{flaresolverr_url}/v1", json=payload, timeout=70) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        solution = data.get("solution", {})
                        
                        return {
                            "success": solution.get("status") in [200, 301, 302],
                            "status_code": solution.get("status"),
                            "method": "flaresolverr",
                            "cookies": solution.get("cookies", []),
                            "user_agent": solution.get("userAgent"),
                            "body_length": len(solution.get("response", ""))
                        }
        except Exception as e:
            logger.debug(f"FlareSolverr bypass error: {e}")
            return {"success": False, "error": str(e)}
    
    async def find_origin(self, hostname: str, env: dict = None) -> Optional[str]:
        """Comprehensive origin IP discovery."""
        env = env or {}
        all_ips = set()
        
        # Method 1: crt.sh (Certificate Transparency)
        logger.info(f"[CF] Searching crt.sh for {hostname}...")
        crtsh_ips = await self.find_origin_via_crtsh(hostname)
        all_ips.update(crtsh_ips)
        logger.info(f"[CF] crt.sh found {len(crtsh_ips)} IPs")
        
        # Method 2: Subdomain enumeration
        logger.info(f"[CF] Enumerating subdomains for {hostname}...")
        subdomain_ips = await self.find_origin_via_subdomain_enum(hostname)
        all_ips.update(subdomain_ips)
        logger.info(f"[CF] Subdomain enum found {len(subdomain_ips)} IPs")
        
        # Method 3: Shodan
        shodan_key = env.get("SHODAN_API_KEY")
        if shodan_key:
            logger.info(f"[CF] Searching Shodan for {hostname}...")
            shodan_ips = await self.find_origin_via_shodan(hostname, shodan_key)
            all_ips.update(shodan_ips)
            logger.info(f"[CF] Shodan found {len(shodan_ips)} IPs")
        
        # Method 4: SecurityTrails DNS history
        st_key = env.get("SECURITYTRAILS_API_KEY")
        if st_key:
            logger.info(f"[CF] Searching SecurityTrails DNS history for {hostname}...")
            st_ips = await self.find_origin_via_dns_history(hostname, st_key)
            all_ips.update(st_ips)
            logger.info(f"[CF] SecurityTrails found {len(st_ips)} IPs")
        
        # Verify each IP
        logger.info(f"[CF] Verifying {len(all_ips)} candidate IPs...")
        for ip in list(all_ips)[:10]:  # Verify max 10 IPs
            if await self.verify_origin(ip, hostname):
                logger.info(f"[CF] Verified origin IP: {ip}")
                return ip
        
        logger.warning(f"[CF] No verified origin IP found for {hostname}")
        return None
    
    async def bypass(self, hostname: str, env: dict = None, proxy_url: Optional[str] = None) -> Dict:
        """Execute comprehensive Cloudflare bypass."""
        result = {
            "hostname": hostname,
            "origin_ip": None,
            "bypass_methods": []
        }
        
        # Try origin IP discovery first
        origin_ip = await self.find_origin(hostname, env)
        if origin_ip:
            result["origin_ip"] = origin_ip
            result["bypass_methods"].append({"method": "origin_discovery", "success": True, "ip": origin_ip})
        
        # Try curl_cffi bypass
        url = f"https://{hostname}/"
        curl_result = await self.bypass_with_curl_cffi(url, proxy_url)
        if curl_result.get("success"):
            result["bypass_methods"].append(curl_result)
        
        # Try FlareSolverr if configured
        flaresolverr_url = (env or {}).get("FLARESOLVERR_URL", "http://localhost:8191")
        if flaresolverr_url:
            flare_result = await self.bypass_with_flaresolverr(url, flaresolverr_url)
            if flare_result.get("success"):
                result["bypass_methods"].append(flare_result)
        
        return result
