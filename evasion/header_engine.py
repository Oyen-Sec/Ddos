"""
Multi-Protocol Concurrency Layer - Advanced Header Randomization Module
100+ UA x 50+ Referer x 20+ Accept-Language with case rotation and order randomization
"""
import random
import string
from typing import Dict, List, Optional
from evasion.ua_pool import get_random_ua, UA_POOLS
from urllib.parse import urlparse

# Extended Referer Pool (50+)
REFERERS = [
    "https://www.google.com/search?q={keyword}",
    "https://www.google.com/url?url={url}",
    "https://www.google.com/translate?u={url}",
    "https://www.google.com/maps?ll={lat},{lon}",
    "https://www.bing.com/search?q={keyword}",
    "https://www.yahoo.com/search?p={keyword}",
    "https://duckduckgo.com/?q={keyword}",
    "https://www.facebook.com/sharer/sharer.php?u={url}",
    "https://twitter.com/intent/tweet?url={url}",
    "https://www.reddit.com/submit?url={url}",
    "https://www.linkedin.com/shareArticle?url={url}",
    "https://pinterest.com/pin/create/button/?url={url}",
    "https://www.tumblr.com/share?v=3&u={url}",
    "https://www.tiktok.com/share?url={url}",
    "https://www.instagram.com/?url={url}",
    "https://www.youtube.com/watch?v={random}",
    "https://www.twitch.tv/{random}",
    "https://www.amazon.com/s?k={keyword}",
    "https://www.ebay.com/sch/i.html?_nkw={keyword}",
    "https://www.wikipedia.org/wiki/{keyword}",
    "https://www.github.com/search?q={keyword}",
    "https://www.stackoverflow.com/search?q={keyword}",
    "https://www.medium.com/search?q={keyword}",
    "https://news.ycombinator.com/item?id={random}",
    "https://www.quora.com/search?q={keyword}",
    "https://www.drive.google.com/viewerng/viewer?url={url}",
    "https://translate.google.com/translate?u={url}",
    "https://www.cloudflare.com/learning/cdn/{keyword}",
    "https://developer.mozilla.org/en-US/search?q={keyword}",
    "https://www.w3schools.com/search?q={keyword}",
    "https://www.npmjs.com/search?q={keyword}",
    "https://pypi.org/search/?q={keyword}",
    "https://hub.docker.com/search?q={keyword}",
    "https://stackoverflow.com/questions/{random}",
    "https://www.bbc.com/search?q={keyword}",
    "https://www.cnn.com/search?q={keyword}",
    "https://www.reuters.com/search?query={keyword}",
    "https://www.nytimes.com/search?query={keyword}",
    "https://www.theguardian.com/search?q={keyword}",
    "https://www.washingtonpost.com/search?query={keyword}",
    "https://www.bloomberg.com/search?query={keyword}",
    "https://www.forbes.com/search?q={keyword}",
    "https://www.techcrunch.com/search?s={keyword}",
    "https://www.wired.com/search?query={keyword}",
    "https://www.arstechnica.com/search?q={keyword}",
    "https://www.zdnet.com/search?q={keyword}",
    "https://www.cnet.com/search?q={keyword}",
    "https://www.engadget.com/search?q={keyword}",
    "https://www.theverge.com/search?q={keyword}",
    "https://www.mashable.com/search?q={keyword}",
]

# Extended Accept-Language Pool (20+)
ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.9,de;q=0.8",
    "en-US,en;q=0.9,es;q=0.8",
    "en-US,en;q=0.9,it;q=0.8",
    "en-US,en;q=0.9,pt;q=0.8",
    "en-US,en;q=0.9,nl;q=0.8",
    "en-US,en;q=0.9,sv;q=0.8",
    "en-US,en;q=0.9,no;q=0.8",
    "id-ID,id;q=0.9,en-US;q=0.8",
    "ms-MY,ms;q=0.9,en-US;q=0.8",
    "ja-JP,ja;q=0.9,en-US;q=0.8",
    "ko-KR,ko;q=0.9,en-US;q=0.8",
    "zh-CN,zh;q=0.9,en-US;q=0.8",
    "zh-TW,zh;q=0.9,en-US;q=0.8",
    "fr-FR,fr;q=0.9,en-US;q=0.8",
    "de-DE,de;q=0.9,en-US;q=0.8",
    "es-ES,es;q=0.9,en-US;q=0.8",
    "pt-BR,pt;q=0.9,en-US;q=0.8",
    "ru-RU,ru;q=0.9,en-US;q=0.8",
    "ar-SA,ar;q=0.9,en-US;q=0.8",
    "hi-IN,hi;q=0.9,en-US;q=0.8",
    "th-TH,th;q=0.9,en-US;q=0.8",
    "vi-VN,vi;q=0.9,en-US;q=0.8",
]

# Accept-Encoding variations
ACCEPT_ENCODINGS = [
    "gzip, deflate, br",
    "gzip, deflate, br, zstd",
    "gzip, deflate, br;q=0.9, zstd;q=0.8",
    "gzip, br",
    "br, gzip, deflate",
    "gzip, deflate",
    "gzip, deflate, br;q=1.0",
]

# Sec-CH-UA variations
SEC_CH_UA = [
    '"Chromium";v="136", "Google Chrome";v="136", "Not/A)Brand";v="99"',
    '"Chromium";v="135", "Google Chrome";v="135", "Not/A)Brand";v="99"',
    '"Chromium";v="134", "Google Chrome";v="134", "Not/A)Brand";v="99"',
    '"Chromium";v="136", "Microsoft Edge";v="136", "Not/A)Brand";v="99"',
    '"Not A)Brand";v="8", "Chromium";v="136"',
]

SEC_CH_UA_PLATFORMS = ['"Windows"', '"macOS"', '"Linux"', '"Android"', '"iOS"']
SEC_CH_UA_MODELS = ['""', '"X86"', '"ARM"', '"Pixel 9"', '"iPhone"', '"iPad"']

# Keywords for referer URLs
KEYWORDS = ["test", "search", "query", "page", "article", "news", "update", "login", "admin",
            "dashboard", "profile", "settings", "help", "support", "contact", "about", "service",
            "product", "review", "feedback", "tutorial", "guide", "documentation", "api", "docs"]


def buildblock(size: int = None) -> str:
    """Generate random alphanumeric string"""
    if size is None:
        size = random.randint(5, 15)
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(size))


def random_ip() -> str:
    """Generate random IP address"""
    return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"


def rotate_header_case(headers: Dict[str, str]) -> Dict[str, str]:
    """Randomly rotate header case to defeat pattern matching"""
    rotated = {}
    for key, value in headers.items():
        # Randomly choose case variation
        case_choice = random.random()
        if case_choice < 0.33:
            # Original case
            rotated[key] = value
        elif case_choice < 0.66:
            # Lowercase
            rotated[key.lower()] = value
        else:
            # Mixed case (random per character)
            new_key = ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in key)
            rotated[new_key] = value
    return rotated


def randomize_header_order(headers: Dict[str, str]) -> List[tuple]:
    """Return headers as list of tuples in random order"""
    items = list(headers.items())
    random.shuffle(items)
    return items


def build_advanced_headers(url: str, method: str = "GET", pool: str = "all") -> Dict[str, str]:
    """
    Build advanced randomized headers with:
    - 100+ UA x 50+ Referer x 20+ Accept-Language combinations
    - Case rotation
    - Random header order
    - Polymorphic cookies
    """
    parsed = urlparse(url)
    host = parsed.netloc

    ua = get_random_ua(pool)
    referer_template = random.choice(REFERERS)
    keyword = random.choice(KEYWORDS)
    referer = referer_template.format(
        keyword=keyword,
        url=f"https://{host}",
        random=buildblock(8),
        lat=random.uniform(-90, 90),
        lon=random.uniform(-180, 180),
    )

    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": random.choice(ACCEPT_LANGUAGES),
        "Accept-Encoding": random.choice(ACCEPT_ENCODINGS),
        "Referer": referer,
        "Connection": random.choice(["keep-alive", "keep-alive"]),
        "Upgrade-Insecure-Requests": random.choice(["1", "0"]),
        "Sec-Fetch-Dest": random.choice(["document", "empty"]),
        "Sec-Fetch-Mode": random.choice(["navigate", "no-cors", "same-origin"]),
        "Sec-Fetch-Site": random.choice(["none", "same-origin", "cross-site", "same-site"]),
        "Sec-Fetch-User": random.choice(["?1", "?0"]),
        "Cache-Control": random.choice(["max-age=0", "no-cache", "no-store"]),
        "Pragma": random.choice(["no-cache", ""]),
        "DNT": random.choice(["1", "0"]),
        "Sec-CH-UA": random.choice(SEC_CH_UA),
        "Sec-CH-UA-Mobile": random.choice(["?0", "?1"]),
        "Sec-CH-UA-Platform": random.choice(SEC_CH_UA_PLATFORMS),
    }

    # Add random cookies (polymorphic)
    cookie_parts = []
    num_cookies = random.randint(0, 4)
    for _ in range(num_cookies):
        cookie_name = buildblock(random.randint(4, 10))
        cookie_value = buildblock(random.randint(8, 24))
        cookie_parts.append(f"{cookie_name}={cookie_value}")
    if cookie_parts:
        headers["Cookie"] = "; ".join(cookie_parts)

    # Add Keep-Alive with random timeout
    headers["Keep-Alive"] = f"timeout={random.randint(60, 300)}"

    if method == "POST":
        headers["Content-Type"] = random.choice([
            "application/x-www-form-urlencoded",
            "application/json",
            "multipart/form-data; boundary=----WebKitFormBoundary" + buildblock(16),
        ])
        headers["Origin"] = f"https://{host}"

    # Apply case rotation (30% chance)
    if random.random() < 0.3:
        headers = rotate_header_case(headers)

    return headers


def build_minimal_headers(url: str) -> Dict[str, str]:
    """Build minimal headers for PPS-style attacks"""
    return {
        "User-Agent": get_random_ua(),
        "Accept": "*/*",
    }


def build_bot_headers(url: str) -> Dict[str, str]:
    """Build headers mimicking search engine bots"""
    parsed = urlparse(url)
    return {
        "User-Agent": random.choice(UA_POOLS["search_bots"]),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "From": "bot@example.com",
    }
