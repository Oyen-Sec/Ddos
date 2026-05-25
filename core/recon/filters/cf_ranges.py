"""
Cloudflare IP Range Manager
Downloads and caches official Cloudflare IP ranges (v4/v6)
Also checks ASN (AS13335, AS209242)
"""
import os
import time
import logging
import ipaddress
from typing import Set, List
from pathlib import Path

logger = logging.getLogger("cf_ranges")

# Cloudflare ASNs
CLOUDFLARE_ASNS = {13335, 209242}

# Cache file paths
CACHE_DIR = Path("cache/cloudflare")
IPV4_CACHE = CACHE_DIR / "ips-v4.txt"
IPV6_CACHE = CACHE_DIR / "ips-v6.txt"
CACHE_TTL = 86400 * 7  # 7 days


class CloudflareRangeChecker:
    """Check if IP is in Cloudflare range."""
    
    def __init__(self):
        self.ipv4_ranges: List[ipaddress.IPv4Network] = []
        self.ipv6_ranges: List[ipaddress.IPv6Network] = []
        self._load_ranges()
    
    def _download_ranges(self) -> bool:
        """Download Cloudflare IP ranges from official source."""
        try:
            import requests
            
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            
            # Download IPv4
            resp_v4 = requests.get("https://www.cloudflare.com/ips-v4", timeout=10)
            if resp_v4.status_code == 200:
                IPV4_CACHE.write_text(resp_v4.text)
                logger.info(f"Downloaded Cloudflare IPv4 ranges: {len(resp_v4.text.splitlines())} CIDRs")
            
            # Download IPv6
            resp_v6 = requests.get("https://www.cloudflare.com/ips-v6", timeout=10)
            if resp_v6.status_code == 200:
                IPV6_CACHE.write_text(resp_v6.text)
                logger.info(f"Downloaded Cloudflare IPv6 ranges: {len(resp_v6.text.splitlines())} CIDRs")
            
            return True
        except Exception as e:
            logger.error(f"Failed to download Cloudflare ranges: {e}")
            return False
    
    def _load_ranges(self):
        """Load Cloudflare IP ranges from cache or download."""
        # Check if cache exists and is fresh
        need_download = False
        
        if not IPV4_CACHE.exists() or not IPV6_CACHE.exists():
            need_download = True
        else:
            # Check cache age
            cache_age = time.time() - IPV4_CACHE.stat().st_mtime
            if cache_age > CACHE_TTL:
                need_download = True
        
        if need_download:
            logger.info("Cloudflare IP ranges cache missing or stale, downloading...")
            self._download_ranges()
        
        # Load IPv4 ranges
        if IPV4_CACHE.exists():
            for line in IPV4_CACHE.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        self.ipv4_ranges.append(ipaddress.IPv4Network(line))
                    except Exception as e:
                        logger.debug(f"Invalid IPv4 CIDR {line}: {e}")
        
        # Load IPv6 ranges
        if IPV6_CACHE.exists():
            for line in IPV6_CACHE.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        self.ipv6_ranges.append(ipaddress.IPv6Network(line))
                    except Exception as e:
                        logger.debug(f"Invalid IPv6 CIDR {line}: {e}")
        
        logger.info(f"Loaded {len(self.ipv4_ranges)} IPv4 + {len(self.ipv6_ranges)} IPv6 Cloudflare ranges")
    
    def is_cloudflare_ip(self, ip: str) -> bool:
        """Check if IP is in Cloudflare range."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            if isinstance(ip_obj, ipaddress.IPv4Address):
                for network in self.ipv4_ranges:
                    if ip_obj in network:
                        return True
            elif isinstance(ip_obj, ipaddress.IPv6Address):
                for network in self.ipv6_ranges:
                    if ip_obj in network:
                        return True
            
            return False
        except Exception as e:
            logger.debug(f"Invalid IP {ip}: {e}")
            return False
    
    def is_cloudflare_asn(self, asn: int) -> bool:
        """Check if ASN belongs to Cloudflare."""
        return asn in CLOUDFLARE_ASNS
    
    def get_asn_for_ip(self, ip: str) -> int:
        """Get ASN for IP via ipinfo.io (cached)."""
        try:
            import requests
            resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            data = resp.json()
            org = data.get('org', '')
            # Parse ASN from org string like "AS13335 Cloudflare, Inc."
            if org.startswith('AS'):
                asn_str = org.split()[0][2:]  # Remove "AS" prefix
                return int(asn_str)
        except Exception as e:
            logger.debug(f"Failed to get ASN for {ip}: {e}")
        return 0


# Global singleton
_cf_checker = None

def get_cf_checker() -> CloudflareRangeChecker:
    """Get global Cloudflare range checker instance."""
    global _cf_checker
    if _cf_checker is None:
        _cf_checker = CloudflareRangeChecker()
    return _cf_checker


def is_cloudflare_ip(ip: str) -> bool:
    """Quick check if IP is Cloudflare."""
    return get_cf_checker().is_cloudflare_ip(ip)


def is_cloudflare_asn(asn: int) -> bool:
    """Quick check if ASN is Cloudflare."""
    return get_cf_checker().is_cloudflare_asn(asn)
