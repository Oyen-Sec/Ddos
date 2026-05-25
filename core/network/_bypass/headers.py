"""
HTTP Header Mutation Engine
Implements organic header variation with micro-jittering to eliminate static patterns
"""
import random
import asyncio
import time
from typing import Dict, List, Optional

# User-Agent pool (modern browsers, various OS) - UPDATED 2026
USER_AGENTS = [
    # Chrome on Windows (latest versions)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    # Firefox on Windows (latest versions)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    # Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0",
    # Safari on macOS (latest versions)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    # Edge on Windows (latest versions)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]

# Accept header variations
ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
]

# Accept-Language variations
ACCEPT_LANGUAGE = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,es;q=0.8",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.8",
    "en,en-US;q=0.9",
]

# Accept-Encoding
ACCEPT_ENCODING = [
    "gzip, deflate, br",
    "gzip, deflate, br, zstd",
    "gzip, deflate",
]

# Sec-CH-UA variations (Chrome/Edge) - UPDATED 2026
SEC_CH_UA = [
    '"Not_A Brand";v="8", "Chromium";v="124", "Google Chrome";v="124"',
    '"Not_A Brand";v="8", "Chromium";v="125", "Google Chrome";v="125"',
    '"Not_A Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
    '"Not A(Brand";v="99", "Microsoft Edge";v="124", "Chromium";v="124"',
    '"Not A(Brand";v="99", "Microsoft Edge";v="125", "Chromium";v="125"',
]

# Sec-CH-UA-Platform
SEC_CH_UA_PLATFORM = [
    '"Windows"',
    '"macOS"',
    '"Linux"',
]

# Referer patterns (optional)
REFERER_PATTERNS = [
    None,  # No referer
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
]


class HeaderMutationEngine:
    """Generate organic HTTP headers with entropy per request"""
    
    def __init__(self):
        self.last_mutation_time = 0.0
    
    async def generate_headers(self, target_url: str, method: str = "GET", tls_profile: str = None,
                              minimal: bool = True) -> Dict[str, str]:
        """
        Generate mutated headers for each request (ASYNC)
        MINIMAL MODE (default): Only essential headers (Host, User-Agent, Accept)
        Cross-validates with TLS profile to avoid mismatch detection
        
        NO micro-jitter in minimal mode (high-throughput optimization)
        Jitter only applied in full mode (when stealth > throughput)
        """
        headers = {}
        
        # User-Agent (randomized, aligned with TLS profile if provided)
        if tls_profile:
            if "chrome" in tls_profile.lower():
                ua_pool = [ua for ua in USER_AGENTS if "Chrome" in ua and "Edg" not in ua]
            elif "firefox" in tls_profile.lower():
                ua_pool = [ua for ua in USER_AGENTS if "Firefox" in ua]
            elif "safari" in tls_profile.lower():
                ua_pool = [ua for ua in USER_AGENTS if "Safari" in ua and "Chrome" not in ua]
            elif "edge" in tls_profile.lower():
                ua_pool = [ua for ua in USER_AGENTS if "Edg" in ua]
            else:
                ua_pool = USER_AGENTS
            headers["User-Agent"] = random.choice(ua_pool) if ua_pool else random.choice(USER_AGENTS)
        else:
            headers["User-Agent"] = random.choice(USER_AGENTS)
        
        # Accept (always - essential)
        headers["Accept"] = random.choice(ACCEPT_HEADERS)
        
        # MINIMAL MODE: Stop here - only 2 essential headers (Host added by client)
        if minimal:
            return headers
        
        # FULL MODE: Add micro-jitter for stealth (slower throughput)
        jitter_ms = random.uniform(0, 20)
        await asyncio.sleep(jitter_ms / 1000.0)
        
        # FULL MODE: Add all optional headers
        headers["Accept-Language"] = random.choice(ACCEPT_LANGUAGE)
        headers["Accept-Encoding"] = random.choice(ACCEPT_ENCODING)
        
        if random.random() < 0.5 and ("Chrome" in headers["User-Agent"] or "Edg" in headers["User-Agent"]):
            headers["Sec-CH-UA"] = random.choice(SEC_CH_UA)
            headers["Sec-CH-UA-Mobile"] = "?0"
            headers["Sec-CH-UA-Platform"] = random.choice(SEC_CH_UA_PLATFORM)
        
        if random.random() < 0.7:
            headers["Sec-Fetch-Dest"] = random.choice(["document", "empty"])
            headers["Sec-Fetch-Mode"] = random.choice(["navigate", "cors", "no-cors"])
            headers["Sec-Fetch-Site"] = random.choice(["none", "same-origin", "cross-site"])
            if method == "GET":
                headers["Sec-Fetch-User"] = "?1"
        
        if random.random() < 0.3:
            referer = random.choice(REFERER_PATTERNS)
            if referer:
                headers["Referer"] = referer
        
        headers["Connection"] = random.choice(["keep-alive", "close"])
        
        if random.random() < 0.4:
            headers["Cache-Control"] = random.choice(["no-cache", "max-age=0", "no-store"])
        
        if random.random() < 0.5:
            headers["Upgrade-Insecure-Requests"] = "1"
        
        if random.random() < 0.2:
            headers["DNT"] = "1"
        
        return headers
    
    def mutate_header_order(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Randomize header field order to avoid static patterns
        Some headers must stay in specific positions (Host, User-Agent first)
        """
        # Priority headers (always first)
        priority = ["Host", "User-Agent", "Accept"]
        
        # Separate priority and other headers
        priority_headers = {k: headers[k] for k in priority if k in headers}
        other_headers = {k: v for k, v in headers.items() if k not in priority}
        
        # Shuffle other headers
        other_items = list(other_headers.items())
        random.shuffle(other_items)
        
        # Reconstruct with priority first
        result = {}
        result.update(priority_headers)
        result.update(dict(other_items))
        
        return result
    
    def add_custom_entropy(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Add custom entropy headers to further diversify fingerprint
        """
        # Random X-Request-ID (UUID-like)
        if random.random() < 0.3:
            request_id = f"{random.randint(1000000, 9999999)}-{random.randint(1000, 9999)}"
            headers["X-Request-ID"] = request_id
        
        # Random timestamp variation
        if random.random() < 0.2:
            headers["X-Client-Time"] = str(int(time.time() * 1000))
        
        return headers


# Global instance
_header_engine = HeaderMutationEngine()


async def get_mutated_headers(target_url: str, method: str = "GET", tls_profile: str = None,
                              minimal: bool = True) -> Dict[str, str]:
    """
    Get mutated headers for request (ASYNC with TLS cross-validation)
    
    minimal=True (default): Only Host, User-Agent, Accept (essential only)
    minimal=False: Full header set with all optional fields
    
    HPACK-friendly: Static table indexed values for HTTP/2 compression
    """
    headers = await _header_engine.generate_headers(target_url, method, tls_profile, minimal=minimal)
    if not minimal:
        # Only mutate order/entropy in full mode
        headers = _header_engine.mutate_header_order(headers)
        headers = _header_engine.add_custom_entropy(headers)
    return headers


# HPACK Static Table indices (RFC 7541) for HTTP/2 compression
# Using these saves bytes - server uses index instead of full string
HPACK_STATIC_INDICES = {
    ":method": {"GET": 2, "POST": 3},
    ":path": {"/": 4, "/index.html": 5},
    ":scheme": {"http": 6, "https": 7},
    ":status": {"200": 8, "204": 9, "206": 10, "304": 11, "400": 12, "404": 13, "500": 14},
    "accept-charset": 15,
    "accept-encoding": 16,  # "gzip, deflate"
    "accept-language": 17,
    "accept-ranges": 18,
    "accept": 19,
    "user-agent": 58,
    "host": 38,
    "cookie": 32,
}


def get_hpack_minimal_headers(host: str, path: str = "/", method: str = "GET") -> bytes:
    """
    Generate HPACK-encoded minimal headers for HTTP/2
    Uses indexed representation (single byte) where possible
    Saves ~80% header size vs literal encoding
    """
    import struct
    parts = []
    
    # :method (indexed if GET/POST)
    if method == "GET":
        parts.append(b"\x82")  # Indexed: index 2
    elif method == "POST":
        parts.append(b"\x83")  # Indexed: index 3
    else:
        # Literal with incremental indexing
        m_bytes = method.encode()
        parts.append(b"\x42")
        parts.append(struct.pack("B", len(m_bytes)) + m_bytes)
    
    # :path
    if path == "/":
        parts.append(b"\x84")  # Indexed: index 4
    elif path == "/index.html":
        parts.append(b"\x85")  # Indexed: index 5
    else:
        p_bytes = path.encode()
        parts.append(b"\x44")  # :path literal
        parts.append(struct.pack("B", len(p_bytes)) + p_bytes)
    
    # :scheme https (indexed: 7)
    parts.append(b"\x87")
    
    # :authority (host) - literal with incremental indexing
    h_bytes = host.encode()
    parts.append(b"\x41")  # :authority
    parts.append(struct.pack("B", len(h_bytes)) + h_bytes)
    
    # accept */* - literal
    parts.append(b"\x53")  # accept indexed name (19)
    accept_val = b"*/*"
    parts.append(struct.pack("B", len(accept_val)) + accept_val)
    
    return b"".join(parts)
