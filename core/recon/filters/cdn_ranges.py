"""
CDN IP Ranges Database v8.0
Enhanced filter for Cloudflare, Akamai, Fastly, Gcore, CDN77, Alibaba Cloud
Auto-update from official sources
"""
import ipaddress
import logging
import requests
from pathlib import Path
from typing import Set, List, Dict
from datetime import datetime, timedelta

logger = logging.getLogger("cdn_ranges")

# CDN Provider ASN numbers
CDN_ASNS = {
    'cloudflare': [13335, 209242],
    'akamai': [16625, 20446, 21342, 21357, 21399, 22207],
    'fastly': [54113],
    'gcore': [199524, 202422],
    'cdn77': [60068],
    'alibaba': [45102, 37963, 45090],
    'stackpath': [33438],
    'bunnycdn': [200325],
}

# CDN IP range sources
CDN_SOURCES = {
    'cloudflare_v4': 'https://www.cloudflare.com/ips-v4',
    'cloudflare_v6': 'https://www.cloudflare.com/ips-v6',
    'fastly_v4': 'https://api.fastly.com/public-ip-list',
    'gcore_v4': 'https://api.gcore.com/cdn/public-ip-list',
}

# Cache paths
CACHE_DIR = Path("cache/cdn_ranges")
CACHE_EXPIRY_HOURS = 24


class CDNRangeFilter:
    """Filter CDN IP ranges from multiple providers."""
    
    def __init__(self):
        self.ipv4_ranges: Set[ipaddress.IPv4Network] = set()
        self.ipv6_ranges: Set[ipaddress.IPv6Network] = set()
        self.asn_map: Dict[int, str] = {}
        self._setup_cache_dir()
        self._build_asn_map()
    
    def _setup_cache_dir(self):
        """Create cache directory."""
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
    
    def _build_asn_map(self):
        """Build ASN to provider mapping."""
        for provider, asns in CDN_ASNS.items():
            for asn in asns:
                self.asn_map[asn] = provider
    
    def _is_cache_valid(self, cache_file: Path) -> bool:
        """Check if cache file is still valid."""
        if not cache_file.exists():
            return False
        
        mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
        age = datetime.now() - mtime
        
        return age < timedelta(hours=CACHE_EXPIRY_HOURS)
    
    def _fetch_cloudflare_ranges(self) -> List[str]:
        """Fetch Cloudflare IP ranges."""
        ranges = []
        
        for key in ['cloudflare_v4', 'cloudflare_v6']:
            cache_file = CACHE_DIR / f"{key}.txt"
            
            # Use cache if valid
            if self._is_cache_valid(cache_file):
                logger.info(f"Using cached {key}")
                ranges.extend(cache_file.read_text().strip().split('\n'))
                continue
            
            # Fetch fresh data
            try:
                url = CDN_SOURCES[key]
                logger.info(f"Fetching {key} from {url}")
                resp = requests.get(url, timeout=10)
                resp.raise_for_status()
                
                data = resp.text.strip()
                cache_file.write_text(data)
                ranges.extend(data.split('\n'))
                
            except Exception as e:
                logger.warning(f"Failed to fetch {key}: {e}")
                # Try to use stale cache
                if cache_file.exists():
                    ranges.extend(cache_file.read_text().strip().split('\n'))
        
        return ranges
    
    def _fetch_fastly_ranges(self) -> List[str]:
        """Fetch Fastly IP ranges."""
        cache_file = CACHE_DIR / "fastly.txt"
        
        if self._is_cache_valid(cache_file):
            logger.info("Using cached Fastly ranges")
            return cache_file.read_text().strip().split('\n')
        
        try:
            url = CDN_SOURCES['fastly_v4']
            logger.info(f"Fetching Fastly ranges from {url}")
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            
            data = resp.json()
            ranges = data.get('addresses', []) + data.get('ipv6_addresses', [])
            
            cache_file.write_text('\n'.join(ranges))
            return ranges
            
        except Exception as e:
            logger.warning(f"Failed to fetch Fastly ranges: {e}")
            if cache_file.exists():
                return cache_file.read_text().strip().split('\n')
            return []
    
    def _fetch_akamai_ranges(self) -> List[str]:
        """Fetch Akamai IP ranges (known ranges)."""
        # Akamai doesn't publish official list, use known ranges
        known_ranges = [
            '23.0.0.0/8',
            '104.64.0.0/10',
            '184.24.0.0/13',
            '2.16.0.0/13',
            '23.32.0.0/11',
        ]
        return known_ranges
    
    def _fetch_gcore_ranges(self) -> List[str]:
        """Fetch Gcore IP ranges."""
        cache_file = CACHE_DIR / "gcore.txt"
        
        if self._is_cache_valid(cache_file):
            logger.info("Using cached Gcore ranges")
            return cache_file.read_text().strip().split('\n')
        
        try:
            url = CDN_SOURCES['gcore_v4']
            logger.info(f"Fetching Gcore ranges from {url}")
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            
            data = resp.json()
            ranges = data.get('addresses', [])
            
            cache_file.write_text('\n'.join(ranges))
            return ranges
            
        except Exception as e:
            logger.warning(f"Failed to fetch Gcore ranges: {e}")
            if cache_file.exists():
                return cache_file.read_text().strip().split('\n')
            return []
    
    def _fetch_cdn77_ranges(self) -> List[str]:
        """Fetch CDN77 IP ranges (known ranges)."""
        known_ranges = [
            '93.190.128.0/18',
            '185.93.228.0/22',
        ]
        return known_ranges
    
    def _fetch_alibaba_ranges(self) -> List[str]:
        """Fetch Alibaba Cloud CDN ranges (known ranges)."""
        known_ranges = [
            '47.246.0.0/16',
            '47.88.0.0/16',
            '47.254.0.0/16',
        ]
        return known_ranges
    
    def load_all_ranges(self) -> bool:
        """Load all CDN IP ranges from all providers."""
        logger.info("Loading CDN IP ranges from all providers...")
        
        all_ranges = []
        
        # Cloudflare
        all_ranges.extend(self._fetch_cloudflare_ranges())
        
        # Fastly
        all_ranges.extend(self._fetch_fastly_ranges())
        
        # Akamai
        all_ranges.extend(self._fetch_akamai_ranges())
        
        # Gcore
        all_ranges.extend(self._fetch_gcore_ranges())
        
        # CDN77
        all_ranges.extend(self._fetch_cdn77_ranges())
        
        # Alibaba
        all_ranges.extend(self._fetch_alibaba_ranges())
        
        # Parse into IP networks
        for cidr in all_ranges:
            cidr = cidr.strip()
            if not cidr:
                continue
            
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                if network.version == 4:
                    self.ipv4_ranges.add(network)
                else:
                    self.ipv6_ranges.add(network)
            except Exception as e:
                logger.debug(f"Invalid CIDR {cidr}: {e}")
        
        logger.info(f"Loaded {len(self.ipv4_ranges)} IPv4 ranges, {len(self.ipv6_ranges)} IPv6 ranges")
        return True
    
    def is_cdn_ip(self, ip: str) -> tuple[bool, str]:
        """
        Check if IP belongs to any CDN provider.
        
        Returns:
            (is_cdn, provider_name)
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            if ip_obj.version == 4:
                ranges = self.ipv4_ranges
            else:
                ranges = self.ipv6_ranges
            
            for network in ranges:
                if ip_obj in network:
                    # Try to identify provider from network
                    provider = self._identify_provider(network)
                    return True, provider
            
            return False, ""
            
        except Exception as e:
            logger.debug(f"Invalid IP {ip}: {e}")
            return False, ""
    
    def _identify_provider(self, network: ipaddress.IPv4Network) -> str:
        """Identify CDN provider from network range."""
        # Simple heuristic based on known ranges
        network_str = str(network)
        
        if network_str.startswith('104.') or network_str.startswith('172.'):
            return 'cloudflare'
        elif network_str.startswith('23.'):
            return 'akamai'
        elif network_str.startswith('151.'):
            return 'fastly'
        elif network_str.startswith('92.') or network_str.startswith('185.'):
            return 'gcore'
        elif network_str.startswith('93.190'):
            return 'cdn77'
        elif network_str.startswith('47.'):
            return 'alibaba'
        else:
            return 'unknown_cdn'
    
    def is_cdn_asn(self, asn: int) -> tuple[bool, str]:
        """
        Check if ASN belongs to CDN provider.
        
        Returns:
            (is_cdn, provider_name)
        """
        if asn in self.asn_map:
            return True, self.asn_map[asn]
        return False, ""


# Global instance
_cdn_filter = None

def get_cdn_filter() -> CDNRangeFilter:
    """Get global CDN filter instance."""
    global _cdn_filter
    if _cdn_filter is None:
        _cdn_filter = CDNRangeFilter()
        _cdn_filter.load_all_ranges()
    return _cdn_filter
