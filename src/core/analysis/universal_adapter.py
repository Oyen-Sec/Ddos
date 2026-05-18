import logging
import urllib.parse
from typing import List, Dict, Any
from src.utils.cms_patterns import CMS_PATTERNS

class UniversalTargetAdapter:
    """
    Handles target detection and adaptation for various platforms.
    Detects CMS type and provides appropriate endpoints and filters.
    """
    def __init__(self, domain: str, recon_data: Dict[str, Any] = None):
        self.domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0]
        self.recon = recon_data or {}
        self.logger = logging.getLogger("UniversalAdapter")
        self.cms = self._detect_cms()

    def _detect_cms(self) -> str:
        recon_str = str(self.recon).lower()
        tech = self.recon.get("technology_stack", {})
        
        # Check against patterns
        for cms_name, config in CMS_PATTERNS.items():
            if cms_name == "generic": continue
            for pattern in config["detect"]:
                if pattern in recon_str or pattern in self.domain:
                    self.logger.info(f"[AI] Detected CMS: {cms_name.upper()} (Pattern: {pattern})")
                    return cms_name
                    
        # Backend framework hint
        backend = str(tech.get("backend_framework", "")).lower()
        if "wordpress" in backend: return "wordpress"
        if "shopify" in backend: return "shopify"
        
        self.logger.info("[AI] Detected CMS: GENERIC")
        return "generic"

    def discover_endpoints(self) -> List[Dict[str, Any]]:
        """Provides specific endpoints based on detected CMS."""
        config = CMS_PATTERNS.get(self.cms, CMS_PATTERNS["generic"])
        endpoints = []
        
        for path in config["heavy"]:
            endpoints.append({
                "url": f"https://{self.domain}{path}",
                "weight": "heavy",
                "method": "POST" if any(x in path for x in ["ajax", "add", "update", "login", "submit"]) else "GET"
            })
            
        for path in config["medium"]:
            endpoints.append({
                "url": f"https://{self.domain}{path}",
                "weight": "medium",
                "method": "GET"
            })
            
        for path in config["light"]:
            endpoints.append({
                "url": f"https://{self.domain}{path}",
                "weight": "light",
                "method": "GET"
            })
            
        return self.filter_invalid(endpoints)

    def filter_invalid(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Applies CMS-specific path and extension filters."""
        config = CMS_PATTERNS.get(self.cms, CMS_PATTERNS["generic"])
        filters = config["filter"]
        filtered = []
        
        for ep in endpoints:
            url = ep["url"]
            path = urllib.parse.urlparse(url).path.lower()
            blocked = False
            
            for pattern in filters:
                if pattern.startswith("*."):
                    ext = pattern.split("*.")[1]
                    if path.endswith(f".{ext}"):
                        blocked = True; break
                elif "/*" in pattern:
                    prefix = pattern.replace("/*", "")
                    if prefix in path:
                        blocked = True; break
                elif pattern in path:
                    blocked = True; break
            
            if not blocked:
                filtered.append(ep)
            else:
                self.logger.debug(f"[FILTER] Blocked: {url} | Reason: {pattern}")
                
        return filtered
