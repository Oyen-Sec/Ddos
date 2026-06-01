"""
AWS CloudFront CDN Bypass Module 2026
Comprehensive bypass for AWS CloudFront protection.

Techniques:
1. Origin IP Discovery (Reverse DNS, Certificate Transparency, Shodan)
2. Host Header Injection
3. Origin Access Identity (OAI) Misconfiguration
4. curl_cffi TLS fingerprint impersonation
"""
import asyncio
import logging
import socket
import ssl
from typing import Optional, Dict, List

logger = logging.getLogger(__name__)


class CloudFrontBypass:
    """AWS CloudFront bypass orchestrator."""
    
    def __init__(self, timeout: int = 15):
        self.timeout = timeout
    
    @staticmethod
    def detect(headers: dict) -> bool:
        """Detect if target is behind CloudFront."""
        if not headers:
            return False
        h = {k.lower(): v.lower() for k, v in headers.items()}
        
        # Check CloudFront headers
        cf_headers = ["x-amz-cf-id", "x-amz-cf-pop", "x-cache"]
        if any(hdr in h for hdr in cf_headers):
            return True
        
        # Check server header
        server = h.get("server", "")
        if "cloudfront" in server or "amazon" in server:
            return True
        
        # Check Via header
        via = h.get("via", "")
        if "cloudfront" in via:
            return True
        
        return False
    
    async def find_origin_via_reverse_dns(self, domain: str) -> List[str]:
        """Find origin via reverse DNS lookup."""
        ips = set()
        
        # Try common origin subdomain patterns
        patterns = [
            f"origin.{domain}",
            f"origin-{domain.replace('.', '-')}",
            f"s3-{domain}",
            f"elb-{domain}",
            f"ec2-{domain}"
        ]
        
        for pattern in patterns:
            try:
                ip = socket.gethostbyname(pattern)
                ips.add(ip)
            except:
                continue
        
        return list(ips)
    
    async def find_origin_via_crtsh(self, domain: str) -> List[str]:
        """Find origin IPs via Certificate Transparency."""
        ips = set()
        try:
            import aiohttp
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        domains = set()
                        for entry in data[:100]:
                            name = entry.get("name_value", "")
                            if name and "*" not in name and "cloudfront" not in name.lower():
                                domains.add(name.strip())
                        
                        for d in list(domains)[:20]:
                            try:
                                ip = socket.gethostbyname(d)
                                # Exclude CloudFront IPs (they typically resolve to multiple IPs)
                                if not ip.startswith("13.") and not ip.startswith("52."):
                                    ips.add(ip)
                            except:
                                continue
        except Exception as e:
            logger.debug(f"crt.sh error: {e}")
        
        return list(ips)
    
    async def find_origin_via_shodan(self, domain: str, api_key: str) -> List[str]:
        """Find origin IPs via Shodan."""
        ips = set()
        if not api_key:
            return []
        
        try:
            import shodan
            api = shodan.Shodan(api_key)
            results = api.search(f"hostname:{domain}", limit=10)
            for result in results.get("matches", []):
                ip = result.get("ip_str")
                if ip:
                    ips.add(ip)
        except Exception as e:
            logger.debug(f"Shodan error: {e}")
        
        return list(ips)
    
    async def test_host_header_injection(self, ip: str, hostname: str) -> bool:
        """Test if origin accepts requests with Host header injection."""
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
            
            resp_str = response.decode(errors="ignore")
            if "200 OK" in resp_str or "301" in resp_str or "302" in resp_str:
                return True
        except:
            pass
        
        return False
    
    async def bypass_with_curl_cffi(self, url: str, proxy_url: Optional[str] = None) -> Dict:
        """Bypass CloudFront using curl_cffi."""
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
    
    async def find_origin(self, hostname: str, env: dict = None) -> Optional[str]:
        """Find origin IP for CloudFront-protected target."""
        env = env or {}
        all_ips = set()
        
        # Method 1: Reverse DNS
        logger.info(f"[CloudFront] Trying reverse DNS for {hostname}...")
        rdns_ips = await self.find_origin_via_reverse_dns(hostname)
        all_ips.update(rdns_ips)
        logger.info(f"[CloudFront] Reverse DNS found {len(rdns_ips)} IPs")
        
        # Method 2: crt.sh
        logger.info(f"[CloudFront] Searching crt.sh for {hostname}...")
        crtsh_ips = await self.find_origin_via_crtsh(hostname)
        all_ips.update(crtsh_ips)
        logger.info(f"[CloudFront] crt.sh found {len(crtsh_ips)} IPs")
        
        # Method 3: Shodan
        shodan_key = env.get("SHODAN_API_KEY")
        if shodan_key:
            logger.info(f"[CloudFront] Searching Shodan for {hostname}...")
            shodan_ips = await self.find_origin_via_shodan(hostname, shodan_key)
            all_ips.update(shodan_ips)
            logger.info(f"[CloudFront] Shodan found {len(shodan_ips)} IPs")
        
        # Test each IP with Host header injection
        logger.info(f"[CloudFront] Testing {len(all_ips)} candidate IPs...")
        for ip in list(all_ips)[:10]:
            if await self.test_host_header_injection(ip, hostname):
                logger.info(f"[CloudFront] Verified origin IP: {ip}")
                return ip
        
        return None
    
    async def bypass(self, hostname: str, env: dict = None, proxy_url: Optional[str] = None) -> Dict:
        """Execute comprehensive CloudFront bypass."""
        result = {
            "hostname": hostname,
            "origin_ip": None,
            "bypass_methods": []
        }
        
        # Try origin IP discovery
        origin_ip = await self.find_origin(hostname, env)
        if origin_ip:
            result["origin_ip"] = origin_ip
            result["bypass_methods"].append({"method": "origin_discovery", "success": True, "ip": origin_ip})
        
        # Try curl_cffi bypass
        url = f"https://{hostname}/"
        curl_result = await self.bypass_with_curl_cffi(url, proxy_url)
        if curl_result.get("success"):
            result["bypass_methods"].append(curl_result)
        
        return result
