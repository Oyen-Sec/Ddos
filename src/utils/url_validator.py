import urllib.parse
from typing import Set

CDN_DOMAINS: Set[str] = {
    "cloudflare.com", "cloudfront.net", "akamai.net", 
    "fastly.net", "googleusercontent.com", "gstatic.com",
    "bootstrapcdn.com", "jsdelivr.net", "unpkg.com",
    "squarespace.com", "squarespace-cdn.com",
    "shopify.com", "shopifycdn.com",
    "wix.com", "wixstatic.com",
    "wordpress.com", "wp.com",
    "github.io", "githubusercontent.com",
    "amazonaws.com", "s3.amazonaws.com",
    "azureedge.net", "azurewebsites.net",
    "googleapis.com", "firebaseapp.com"
}

STATIC_EXTENSIONS: Set[str] = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", 
    ".svg", ".woff", ".woff2", ".ttf", ".eot", ".ico",
    ".mp4", ".mp3", ".pdf", ".zip"
}

def is_cdn_url(url: str) -> bool:
    """Checks if the URL belongs to a known CDN domain."""
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    return any(cdn in domain for cdn in CDN_DOMAINS)

def is_static_asset(url: str) -> bool:
    """Checks if the URL is a static file asset."""
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.lower()
    return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)

def get_base_domain(url: str) -> str:
    """Extracts the base domain from a URL."""
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc.lower()

def is_same_origin(url: str, target_domain: str) -> bool:
    """Checks if the URL belongs to the target domain."""
    url_domain = get_base_domain(url)
    target_clean = target_domain.replace("https://", "").replace("http://", "").split("/")[0].lower()
    return target_clean in url_domain
