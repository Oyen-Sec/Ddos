"""
Bypass Module Base Class 2026
All bypass modules inherit from this to ensure consistent API.
"""
import asyncio, logging, socket, ssl, random
from typing import Optional, Dict, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class BaseBypass:
    """Base class for all bypass modules."""
    
    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.name = self.__class__.__name__.replace("Bypass", "")
    
    @staticmethod
    def detect(headers: dict) -> bool:
        """Override in subclass with specific detection logic."""
        return False
    
    async def find_origin(self, hostname: str, env: dict = None) -> Optional[str]:
        """Shared origin IP discovery (delegates to find_origin_ip)."""
        from core.recon.origin.origin_finder import find_origin_ip
        try:
            result = await find_origin_ip(hostname, timeout=min(self.timeout, 8))
            if result:
                return result.get("origin_ip")
        except:
            pass
        return None
    
    async def bypass_with_curl_cffi(self, url: str, proxy_url: Optional[str] = None) -> Dict:
        """Universal curl_cffi bypass with Chrome impersonation."""
        try:
            from curl_cffi import requests as curl_req
            session = curl_req.Session()
            session.impersonate = "chrome120"
            if proxy_url:
                session.proxies = {"https": proxy_url, "http": proxy_url}
            resp = session.get(url, timeout=self.timeout, verify=False)
            return {
                "success": resp.status_code not in [403, 412, 503],
                "status_code": resp.status_code,
                "method": "curl_cffi_chrome120",
                "body_length": len(resp.text)
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def bypass_with_raw_request(self, hostname: str, ip: str, headers_add: dict = None) -> Optional[int]:
        """Direct raw HTTPS request with Host header (bypass via origin IP)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, 443))
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ss = ctx.wrap_socket(sock, server_hostname=hostname)
            req = f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n"
            if headers_add:
                for k, v in headers_add.items():
                    req += f"{k}: {v}\r\n"
            req += "\r\n"
            ss.send(req.encode())
            resp = ss.recv(4096)
            ss.close()
            status = int(resp.split(b" ")[1]) if b" " in resp[:20] else 0
            return status if status not in [403, 412] else None
        except:
            return None
    
    async def bypass_with_oversized_payload(self, url: str, size: int = 32768, proxy_url: Optional[str] = None) -> Dict:
        """Send oversized payload to bypass WAFs with size limits."""
        try:
            from curl_cffi import requests as curl_req
            session = curl_req.Session()
            session.impersonate = "chrome120"
            if proxy_url:
                session.proxies = {"https": proxy_url, "http": proxy_url}
            payload = "A" * size
            resp = session.post(url, data=payload, timeout=self.timeout, verify=False)
            return {"success": resp.status_code != 403, "status_code": resp.status_code, "method": f"oversized_{size}b"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def bypass(self, hostname: str, env: dict = None, proxy_url: Optional[str] = None) -> Dict:
        """Override in subclass with specific bypass logic."""
        url = f"https://{hostname}/"
        return await self.bypass_with_curl_cffi(url, proxy_url)
