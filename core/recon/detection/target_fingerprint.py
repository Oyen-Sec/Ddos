"""
WordPress Detection & Adaptive Targeting Module
Detects WordPress installations and provides optimized attack endpoints
"""
import asyncio
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

class WordPressDetector:
    """Detect WordPress and identify high-value endpoints"""
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.wp_signatures = [
            "/wp-includes/",
            "/wp-content/",
            "/wp-admin/",
            "wp-json",
            "xmlrpc.php",
        ]
        self.wp_headers = [
            "x-powered-by",
            "link",  # REST API link header
        ]
    
    async def detect(self, target_url: str) -> Dict:
        """
        Detect if target is WordPress and return profile
        Returns: {
            "is_wordpress": bool,
            "confidence": float,
            "version": str,
            "endpoints": list,
            "plugins": list,
            "theme": str
        }
        """
        result = {
            "is_wordpress": False,
            "confidence": 0.0,
            "version": "unknown",
            "endpoints": [],
            "plugins": [],
            "theme": "unknown",
            "target_type": "generic"
        }
        
        try:
            from curl_cffi.requests import AsyncSession
            
            async with AsyncSession(impersonate="chrome124", timeout=self.timeout) as sess:
                # Test 1: Check homepage for WP signatures
                try:
                    resp = await sess.get(target_url, timeout=self.timeout)
                    html = resp.text
                    
                    # Check for wp-content, wp-includes in HTML
                    if "/wp-content/" in html or "/wp-includes/" in html:
                        result["confidence"] += 0.4
                    
                    # Check for wp-json in HTML
                    if "wp-json" in html or "wp/v2" in html:
                        result["confidence"] += 0.2
                    
                    # Check headers
                    for header in self.wp_headers:
                        if header in resp.headers:
                            header_val = resp.headers[header].lower()
                            if "wordpress" in header_val or "wp-json" in header_val:
                                result["confidence"] += 0.2
                    
                    # Extract version from generator meta tag
                    version_match = re.search(r'content="WordPress\s+([\d.]+)"', html)
                    if version_match:
                        result["version"] = version_match.group(1)
                        result["confidence"] += 0.2
                    
                except Exception:
                    pass
                
                # Test 2: Check xmlrpc.php
                try:
                    xmlrpc_url = urljoin(target_url, "/xmlrpc.php")
                    resp = await sess.post(xmlrpc_url, data="", timeout=self.timeout)
                    if resp.status_code in (200, 405) and b"XML-RPC" in resp.content:
                        result["confidence"] += 0.3
                        result["endpoints"].append("/xmlrpc.php")
                except Exception:
                    pass
                
                # Test 3: Check wp-json REST API
                try:
                    api_url = urljoin(target_url, "/wp-json/")
                    resp = await sess.get(api_url, timeout=self.timeout)
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            if "namespaces" in data or "routes" in data:
                                result["confidence"] += 0.3
                                result["endpoints"].append("/wp-json/")
                                result["endpoints"].append("/wp-json/wp/v2/posts")
                                result["endpoints"].append("/wp-json/wp/v2/users")
                        except Exception:
                            pass
                except Exception:
                    pass
                
                # Test 4: Check wp-cron.php
                try:
                    cron_url = urljoin(target_url, "/wp-cron.php")
                    resp = await sess.get(cron_url, timeout=self.timeout)
                    if resp.status_code == 200:
                        result["endpoints"].append("/wp-cron.php")
                except Exception:
                    pass
                
                # Test 5: Check wp-admin/admin-ajax.php
                try:
                    ajax_url = urljoin(target_url, "/wp-admin/admin-ajax.php")
                    resp = await sess.post(ajax_url, data={"action": "test"}, timeout=self.timeout)
                    if resp.status_code in (200, 400):
                        result["endpoints"].append("/wp-admin/admin-ajax.php")
                except Exception:
                    pass
        
        except Exception as e:
            pass
        
        # Determine if WordPress
        if result["confidence"] >= 0.5:
            result["is_wordpress"] = True
            result["target_type"] = "wordpress"
        
        return result
    
    def get_high_value_endpoints(self, wp_profile: Dict, target_url: str) -> List[str]:
        """
        Get high-value WordPress endpoints for targeted attacks
        Prioritizes computationally expensive endpoints
        """
        endpoints = []
        base_url = target_url.rstrip("/")
        
        if wp_profile.get("is_wordpress"):
            # High-value endpoints (CPU intensive)
            if "/xmlrpc.php" in wp_profile.get("endpoints", []):
                endpoints.append(f"{base_url}/xmlrpc.php")
            
            if "/wp-cron.php" in wp_profile.get("endpoints", []):
                endpoints.append(f"{base_url}/wp-cron.php")
            
            if "/wp-admin/admin-ajax.php" in wp_profile.get("endpoints", []):
                endpoints.append(f"{base_url}/wp-admin/admin-ajax.php")
            
            # REST API endpoints
            if "/wp-json/" in wp_profile.get("endpoints", []):
                endpoints.append(f"{base_url}/wp-json/wp/v2/posts")
                endpoints.append(f"{base_url}/wp-json/wp/v2/users")
                endpoints.append(f"{base_url}/wp-json/wp/v2/comments")
            
            # Search endpoint (database intensive)
            endpoints.append(f"{base_url}/?s=test")
            
            # Login page (authentication overhead)
            endpoints.append(f"{base_url}/wp-login.php")
        
        return endpoints


class GenericWebDetector:
    """Detect non-WordPress web architectures"""
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
    
    async def detect(self, target_url: str) -> Dict:
        """
        Detect web architecture type
        Returns: {
            "target_type": str,  # "spa", "api_gateway", "microservices", "generic"
            "endpoints": list,
            "technologies": list
        }
        """
        result = {
            "target_type": "generic",
            "endpoints": [],
            "technologies": []
        }
        
        try:
            from curl_cffi.requests import AsyncSession
            
            async with AsyncSession(impersonate="chrome124", timeout=self.timeout) as sess:
                resp = await sess.get(target_url, timeout=self.timeout)
                html = resp.text
                headers = resp.headers
                
                # Detect SPA frameworks
                if any(x in html for x in ["react", "vue", "angular", "_next", "__NUXT__"]):
                    result["target_type"] = "spa"
                    result["endpoints"] = ["/", "/api", "/graphql"]
                
                # Detect API Gateway
                if "application/json" in headers.get("content-type", ""):
                    result["target_type"] = "api_gateway"
                    result["endpoints"] = ["/api", "/v1", "/v2", "/graphql"]
                
                # Detect GraphQL
                if "graphql" in html.lower() or "/graphql" in html:
                    result["technologies"].append("graphql")
                    result["endpoints"].append("/graphql")
                
                # Detect common API paths
                common_paths = ["/api", "/v1", "/v2", "/rest", "/graphql", "/login", "/auth"]
                for path in common_paths:
                    try:
                        test_url = urljoin(target_url, path)
                        resp = await sess.get(test_url, timeout=self.timeout)
                        if resp.status_code in (200, 401, 403):
                            result["endpoints"].append(path)
                    except Exception:
                        pass
        
        except Exception:
            pass
        
        return result


async def detect_target_architecture(target_url: str) -> Dict:
    """
    Main detection function - determines target architecture
    Returns comprehensive profile for adaptive targeting
    """
    # Try WordPress detection first
    wp_detector = WordPressDetector(timeout=5)
    wp_profile = await wp_detector.detect(target_url)
    
    if wp_profile["is_wordpress"]:
        return wp_profile
    
    # Fallback to generic detection
    generic_detector = GenericWebDetector(timeout=5)
    generic_profile = await generic_detector.detect(target_url)
    
    return generic_profile
