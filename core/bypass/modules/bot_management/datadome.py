"""
DataDome Bot Management Bypass Module 2026
Comprehensive bypass for DataDome protection.

Techniques:
1. Residential Proxies (avoid datacenter IPs)
2. Canvas Fingerprinting Spoof
3. Browser Impersonation (SeleniumBase UC Mode)
4. Camoufox stealth browser
5. TLS fingerprint rotation
"""
import asyncio
import logging
from typing import Optional, Dict, List

logger = logging.getLogger(__name__)


class DataDomeBypass:
    """DataDome bot management bypass orchestrator."""
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
    
    @staticmethod
    def detect(headers: dict) -> bool:
        """Detect if target uses DataDome."""
        if not headers:
            return False
        h = {k.lower(): v.lower() for k, v in headers.items()}
        
        # Check DataDome headers
        dd_headers = ["x-datadome-cid", "x-dd-b", "x-dd-version"]
        if any(hdr in h for hdr in dd_headers):
            return True
        
        # Check server header
        server = h.get("server", "")
        if "datadome" in server:
            return True
        
        # Check set-cookie for DataDome cookies
        cookies = h.get("set-cookie", "")
        if "datadome" in cookies:
            return True
        
        return False
    
    async def bypass_with_curl_cffi(self, url: str, proxy_url: Optional[str] = None) -> Dict:
        """Bypass DataDome using curl_cffi with residential proxy."""
        try:
            from curl_cffi import requests as curl_req
            
            # Try multiple browser profiles
            profiles = ["chrome120", "chrome116", "safari17_0", "edge101"]
            
            for profile in profiles:
                try:
                    session = curl_req.Session()
                    session.impersonate = profile
                    
                    if proxy_url:
                        session.proxies = {"https": proxy_url, "http": proxy_url}
                    
                    # Add realistic headers
                    headers = {
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.5",
                        "Accept-Encoding": "gzip, deflate, br",
                        "DNT": "1",
                        "Connection": "keep-alive",
                        "Upgrade-Insecure-Requests": "1",
                        "Sec-Fetch-Dest": "document",
                        "Sec-Fetch-Mode": "navigate",
                        "Sec-Fetch-Site": "none",
                        "Sec-Fetch-User": "?1"
                    }
                    
                    resp = session.get(url, headers=headers, timeout=20, verify=False)
                    
                    # Check if blocked by DataDome
                    if "datadome" not in resp.text.lower() and resp.status_code in [200, 301, 302]:
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
    
    async def bypass_with_seleniumbase(self, url: str, proxy_url: Optional[str] = None) -> Dict:
        """Bypass DataDome using SeleniumBase UC Mode."""
        try:
            from seleniumbase import Driver
            
            # UC Mode - undetected chromedriver
            driver_kwargs = {
                "uc": True,
                "headless": False,  # DataDome detects headless
                "incognito": True,
                "disable_csp": True
            }
            
            if proxy_url:
                driver_kwargs["proxy"] = proxy_url
            
            driver = Driver(**driver_kwargs)
            
            try:
                driver.get(url)
                
                # Wait for page load
                await asyncio.sleep(5)
                
                # Check if blocked
                page_source = driver.page_source
                blocked = "datadome" in page_source.lower() and "blocked" in page_source.lower()
                
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
        """Bypass DataDome using Camoufox stealth browser."""
        try:
            from camoufox.sync_api import Camoufox
            
            # Camoufox with stealth settings
            with Camoufox(
                headless=False,
                humanize=True,  # Human-like behavior
                geoip=True,  # Use real geolocation
                exclude_addons=["ublock"]  # Don't use ad blockers (suspicious)
            ) as browser:
                page = browser.new_page()
                
                if proxy_url:
                    # Parse proxy URL
                    from urllib.parse import urlparse
                    parsed = urlparse(proxy_url)
                    proxy_config = {
                        "server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"
                    }
                    page.context.set_proxy(proxy_config)
                
                response = page.goto(url, wait_until="networkidle", timeout=30000)
                
                # Wait for DataDome challenge to resolve
                await asyncio.sleep(5)
                
                content = page.content()
                blocked = "datadome" in content.lower() and "blocked" in content.lower()
                
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
        """Execute comprehensive DataDome bypass."""
        url = f"https://{hostname}/"
        
        result = {
            "hostname": hostname,
            "bypass_methods": []
        }
        
        # Method 1: curl_cffi (fastest)
        logger.info(f"[DataDome] Trying curl_cffi bypass...")
        curl_result = await self.bypass_with_curl_cffi(url, proxy_url)
        if curl_result.get("success"):
            result["bypass_methods"].append(curl_result)
            return result  # Return early if successful
        
        # Method 2: SeleniumBase UC Mode
        logger.info(f"[DataDome] Trying SeleniumBase UC Mode...")
        selenium_result = await self.bypass_with_seleniumbase(url, proxy_url)
        if selenium_result.get("success"):
            result["bypass_methods"].append(selenium_result)
            return result
        
        # Method 3: Camoufox (most advanced)
        logger.info(f"[DataDome] Trying Camoufox stealth browser...")
        camoufox_result = await self.bypass_with_camoufox(url, proxy_url)
        if camoufox_result.get("success"):
            result["bypass_methods"].append(camoufox_result)
        
        return result
