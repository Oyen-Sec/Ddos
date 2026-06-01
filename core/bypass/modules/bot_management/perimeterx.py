"""
PerimeterX (HUMAN Security) Bot Management Bypass Module 2026
Comprehensive bypass for PerimeterX protection.

Techniques:
1. Residential Proxies
2. Browser Impersonation (SeleniumBase UC Mode)
3. px-solver (Rust-built solver service for _px3 cookie generation)
4. Camoufox stealth browser
5. TLS fingerprint rotation
"""
import asyncio
import logging
from typing import Optional, Dict, List

logger = logging.getLogger(__name__)


class PerimeterXBypass:
    """PerimeterX bot management bypass orchestrator."""
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
    
    @staticmethod
    def detect(headers: dict) -> bool:
        """Detect if target uses PerimeterX."""
        if not headers:
            return False
        h = {k.lower(): v.lower() for k, v in headers.items()}
        
        # Check PerimeterX headers
        px_headers = ["x-px-block-score", "x-px-uuid"]
        if any(hdr in h for hdr in px_headers):
            return True
        
        # Check set-cookie for PerimeterX cookies
        cookies = h.get("set-cookie", "")
        if "_px3" in cookies or "_px2" in cookies or "_pxhd" in cookies:
            return True
        
        return False
    
    async def bypass_with_curl_cffi(self, url: str, proxy_url: Optional[str] = None) -> Dict:
        """Bypass PerimeterX using curl_cffi with residential proxy."""
        try:
            from curl_cffi import requests as curl_req
            
            profiles = ["chrome120", "chrome116", "safari17_0", "edge101"]
            
            for profile in profiles:
                try:
                    session = curl_req.Session()
                    session.impersonate = profile
                    
                    if proxy_url:
                        session.proxies = {"https": proxy_url, "http": proxy_url}
                    
                    headers = {
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.5",
                        "Accept-Encoding": "gzip, deflate, br",
                        "DNT": "1",
                        "Connection": "keep-alive",
                        "Upgrade-Insecure-Requests": "1"
                    }
                    
                    resp = session.get(url, headers=headers, timeout=20, verify=False)
                    
                    # Check if blocked by PerimeterX
                    blocked = "_pxCaptcha" in resp.text or "Access to This Page Has Been Blocked" in resp.text
                    
                    if not blocked and resp.status_code in [200, 301, 302]:
                        return {
                            "success": True,
                            "status_code": resp.status_code,
                            "method": f"curl_cffi_{profile}",
                            "headers": dict(resp.headers),
                            "body_length": len(resp.text)
                        }
                except Exception as e:
                    logger.debug(f"curl_cffi {profile} failed: {e}")
                    continue
            
            return {"success": False, "error": "All profiles blocked"}
        except Exception as e:
            logger.debug(f"curl_cffi bypass error: {e}")
            return {"success": False, "error": str(e)}
    
    async def bypass_with_px_solver(self, url: str, px_app_id: str, proxy_url: Optional[str] = None) -> Dict:
        """Bypass PerimeterX using px-solver service."""
        try:
            import aiohttp
            
            # px-solver is a Rust service that generates valid _px3 cookies
            # Assuming it's running on localhost:3000
            solver_url = "http://localhost:3000/solve"
            
            payload = {
                "url": url,
                "px_app_id": px_app_id,
                "proxy": proxy_url
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(solver_url, json=payload, timeout=30) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        
                        # Extract _px3 cookie
                        px3_cookie = data.get("px3_cookie")
                        user_agent = data.get("user_agent")
                        
                        if px3_cookie:
                            # Make request with solved cookie
                            from curl_cffi import requests as curl_req
                            
                            session = curl_req.Session()
                            session.impersonate = "chrome120"
                            
                            if proxy_url:
                                session.proxies = {"https": proxy_url, "http": proxy_url}
                            
                            cookies = {"_px3": px3_cookie}
                            headers = {"User-Agent": user_agent} if user_agent else {}
                            
                            resp = session.get(url, cookies=cookies, headers=headers, timeout=15, verify=False)
                            
                            blocked = "_pxCaptcha" in resp.text
                            
                            return {
                                "success": not blocked and resp.status_code in [200, 301, 302],
                                "status_code": resp.status_code,
                                "method": "px_solver",
                                "blocked": blocked
                            }
        except Exception as e:
            logger.debug(f"px-solver bypass error: {e}")
            return {"success": False, "error": str(e)}
    
    async def bypass_with_seleniumbase(self, url: str, proxy_url: Optional[str] = None) -> Dict:
        """Bypass PerimeterX using SeleniumBase UC Mode."""
        try:
            from seleniumbase import Driver
            
            driver_kwargs = {
                "uc": True,
                "headless": False,
                "incognito": True,
                "disable_csp": True
            }
            
            if proxy_url:
                driver_kwargs["proxy"] = proxy_url
            
            driver = Driver(**driver_kwargs)
            
            try:
                driver.get(url)
                
                # Wait for PerimeterX challenge to resolve
                await asyncio.sleep(8)
                
                page_source = driver.page_source
                blocked = "_pxCaptcha" in page_source or "Access to This Page Has Been Blocked" in page_source
                
                result = {
                    "success": not blocked,
                    "method": "seleniumbase_uc",
                    "blocked": blocked,
                    "page_length": len(page_source)
                }
                
                driver.quit()
                return result
            except Exception as e:
                driver.quit()
                raise e
        except Exception as e:
            logger.debug(f"SeleniumBase bypass error: {e}")
            return {"success": False, "error": str(e)}
    
    async def bypass_with_camoufox(self, url: str, proxy_url: Optional[str] = None) -> Dict:
        """Bypass PerimeterX using Camoufox stealth browser."""
        try:
            from camoufox.sync_api import Camoufox
            
            with Camoufox(
                headless=False,
                humanize=True,
                geoip=True
            ) as browser:
                page = browser.new_page()
                
                if proxy_url:
                    from urllib.parse import urlparse
                    parsed = urlparse(proxy_url)
                    proxy_config = {
                        "server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"
                    }
                    page.context.set_proxy(proxy_config)
                
                response = page.goto(url, wait_until="networkidle", timeout=30000)
                
                # Wait for PerimeterX challenge
                await asyncio.sleep(8)
                
                content = page.content()
                blocked = "_pxCaptcha" in content or "Access to This Page Has Been Blocked" in content
                
                return {
                    "success": not blocked and response.status in [200, 301, 302],
                    "status_code": response.status,
                    "method": "camoufox_stealth",
                    "blocked": blocked,
                    "page_length": len(content)
                }
        except Exception as e:
            logger.debug(f"Camoufox bypass error: {e}")
            return {"success": False, "error": str(e)}
    
    async def bypass(self, hostname: str, env: dict = None, proxy_url: Optional[str] = None) -> Dict:
        """Execute comprehensive PerimeterX bypass."""
        url = f"https://{hostname}/"
        
        result = {
            "hostname": hostname,
            "bypass_methods": []
        }
        
        # Method 1: curl_cffi (fastest)
        logger.info(f"[PerimeterX] Trying curl_cffi bypass...")
        curl_result = await self.bypass_with_curl_cffi(url, proxy_url)
        if curl_result.get("success"):
            result["bypass_methods"].append(curl_result)
            return result
        
        # Method 2: px-solver (if available)
        px_app_id = (env or {}).get("PX_APP_ID")
        if px_app_id:
            logger.info(f"[PerimeterX] Trying px-solver...")
            solver_result = await self.bypass_with_px_solver(url, px_app_id, proxy_url)
            if solver_result.get("success"):
                result["bypass_methods"].append(solver_result)
                return result
        
        # Method 3: SeleniumBase UC Mode
        logger.info(f"[PerimeterX] Trying SeleniumBase UC Mode...")
        selenium_result = await self.bypass_with_seleniumbase(url, proxy_url)
        if selenium_result.get("success"):
            result["bypass_methods"].append(selenium_result)
            return result
        
        # Method 4: Camoufox
        logger.info(f"[PerimeterX] Trying Camoufox stealth browser...")
        camoufox_result = await self.bypass_with_camoufox(url, proxy_url)
        if camoufox_result.get("success"):
            result["bypass_methods"].append(camoufox_result)
        
        return result
