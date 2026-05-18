import urllib.parse
from typing import Tuple
from src.core.universal_cms import UniversalCMSDatabase

def is_static_asset(url: str, cms_type: str = "generic") -> Tuple[bool, str]:
    """
    Hardened path-based CDN and static asset filter.
    Returns (is_blocked, reason).
    """
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.lower()
    
    db = UniversalCMSDatabase.CMS_SIGNATURES.get(cms_type, 
                                                 UniversalCMSDatabase.CMS_SIGNATURES["generic"])
    
    # 1. Check static extensions
    for ext in db["static_extensions"]:
        if path.endswith(ext):
            return True, f"extension:{ext}"
            
    # 2. Check filter paths
    for fp in db["filter_paths"]:
        if fp.endswith("/*"):
            prefix = fp.rstrip("/*")
            if prefix in path:
                return True, f"path_prefix:{prefix}"
        elif fp in path:
            return True, f"path_match:{fp}"
            
    # 3. Check common CDN/Static subdomains
    domain = parsed.netloc.lower()
    cdn_keywords = ["cdn.", "static.", "assets.", "images.", "img.", "wp-content"]
    for kw in cdn_keywords:
        if kw in domain:
            return True, f"subdomain:{kw}"
            
    return False, "valid"
