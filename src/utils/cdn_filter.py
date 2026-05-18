import urllib.parse
from typing import Tuple, Set

CDN_DOMAIN_PATTERNS: Set[str] = {
    "squarespace.com", "squarespace-cdn.com",
    "cloudflare.com", "cloudfront.net",
    "amazonaws.com", "s3.amazonaws.com", "s3-",
    "googleusercontent.com", "gstatic.com", "googleapis.com",
    "akamai.net", "akamaiedge.net", "akamaihd.net",
    "fastly.net", "fastlylb.net",
    "cdn77.org",
    "kxcdn.com",
    "netdna-cdn.com", "netdna-ssl.com",
    "azureedge.net", "azurewebsites.net", "windows.net",
    "shopify.com", "shopifycdn.com", "shopifysvc.com",
    "wordpress.com", "wp.com",
    "wix.com", "wixstatic.com",
    "github.io", "githubusercontent.com",
    "jsdelivr.net",
    "bootstrapcdn.com",
    "unpkg.com",
    "cdnjs.cloudflare.com",
}

STATIC_FILE_EXTENSIONS: Set[str] = {
    '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
    '.ico', '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp4', '.webm', '.mp3', '.wav', '.ogg',
    '.pdf', '.zip', '.tar', '.gz', '.rar',
    '.xml', '.json', '.txt', '.log',
}

STATIC_PATH_PATTERNS = [
    '/static/', '/assets/', '/cdn/', '/media/',
    '/images/', '/img/', '/css/', '/js/',
    '/fonts/', '/uploads/', '/wp-content/',
    '/wp-includes/'
]

def is_cdn_or_static(url: str, origin_domain: str) -> Tuple[bool, str]:
    """
    Standardized filter to identify CDN or static asset domains.
    Returns (is_blocked, reason).
    """
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    origin = origin_domain.lower().replace("https://", "").replace("http://", "").split("/")[0]

    # 1. Must be origin domain or subdomain
    if origin not in domain:
        return True, f"not_origin_domain: {domain}"

    # 2. Check CDN domain patterns
    for cdn in CDN_DOMAIN_PATTERNS:
        if cdn in domain:
            return True, f"cdn_domain: {cdn}"

    # 3. Check Static file extensions
    for ext in STATIC_FILE_EXTENSIONS:
        if path.endswith(ext):
            return True, f"static_file: {ext}"

    # 4. Check Common static path patterns
    for sp in STATIC_PATH_PATTERNS:
        if sp in path:
            return True, f"static_path: {sp}"

    return False, "valid_target"
