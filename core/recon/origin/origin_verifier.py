"""
Origin IP Verifier v8.0
Enhanced live verification pipeline untuk kandidat origin IP
- Multi-path probe (/, /robots.txt, /favicon.ico)
- Multi-point content hash comparison
- Server header fingerprint analysis
- Shared hosting detection (PTR/reverse DNS)
- CDN IP range filtering (Cloudflare, Akamai, Fastly, Gcore, CDN77, Alibaba)
- Anti false positive mechanisms
- Host header reflection test (CDN/proxy detection)
- STRICT: ANY Cloudflare header = REJECT (not a real origin)
"""
import asyncio
import hashlib
import logging
import ssl
import socket
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass
from urllib.parse import urlparse

logger = logging.getLogger("origin_verifier")

# Cloudflare indicators
CF_HEADERS = ['cf-ray', 'cf-cache-status', 'cf-request-id', 'server: cloudflare']
CF_CHALLENGE_KEYWORDS = [
    'just a moment', 'checking your browser', 'ddos protection by cloudflare',
    'attention required', 'cloudflare', 'ray id', 'cf-ray'
]
CLOUDFRONT_HEADERS = [
    'x-amz-cf-pop', 'x-amz-cf-id', 'x-amz-cf-protocol-violation',
    'cloudfront',
]


@dataclass
class VerificationResult:
    """Result of origin verification."""
    ip: str
    is_verified: bool = False
    reason: str = ""
    http_status: int = 0
    https_status: int = 0
    server_header: str = ""
    body_hash: str = ""
    body_hash_robots: str = ""
    body_hash_favicon: str = ""
    ssl_cn: str = ""
    has_cf_headers: bool = False
    is_redirect: bool = False
    is_challenge_page: bool = False
    is_cdn_ip: bool = False
    cdn_provider: str = ""
    is_shared_hosting: bool = False
    ptr_record: str = ""
    response_time_ms: float = 0.0
    verification_method: str = ""
    hash_match_count: int = 0


class OriginVerifier:
    """Verify if IP candidate is real origin server."""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self._cdn_filter = None
    
    def _get_cdn_filter(self):
        """Lazy load CDN filter."""
        if self._cdn_filter is None:
            try:
                from core.recon.filters.cdn_ranges import get_cdn_filter
                self._cdn_filter = get_cdn_filter()
            except Exception as e:
                logger.warning(f"CDN filter not available: {e}")
        return self._cdn_filter
    
    async def verify_candidate(
        self,
        ip: str,
        target_domain: str,
        baseline_hash: Optional[str] = None,
        baseline_hash_robots: Optional[str] = None,
        baseline_hash_favicon: Optional[str] = None
    ) -> VerificationResult:
        """
        Verify single IP candidate with enhanced multi-path verification.
        
        Args:
            ip: Candidate IP address
            target_domain: Target domain (for Host header)
            baseline_hash: Expected content hash from real domain (/)
            baseline_hash_robots: Expected hash for /robots.txt
            baseline_hash_favicon: Expected hash for /favicon.ico
        
        Returns:
            VerificationResult with verification status
        """
        result = VerificationResult(ip=ip)
        import time
        start_time = time.time()
        
        # Step 0: Check if IP is in CDN range
        cdn_filter = self._get_cdn_filter()
        if cdn_filter:
            is_cdn, provider = cdn_filter.is_cdn_ip(ip)
            if is_cdn:
                result.is_cdn_ip = True
                result.cdn_provider = provider
                result.reason = f"CDN IP detected ({provider.upper()} range)"
                return result
        
        # Step 0.5: Check PTR/reverse DNS for shared hosting
        ptr_record = await self._get_ptr_record(ip)
        result.ptr_record = ptr_record
        
        if ptr_record:
            is_shared = self._is_shared_hosting_ptr(ptr_record)
            result.is_shared_hosting = is_shared
            if is_shared:
                result.reason = f"Shared hosting detected (PTR: {ptr_record})"
                # Don't return yet, continue verification but flag it
        
        # Step 0.6: Host header reflection test
        # A REAL origin should ONLY respond to Host headers it hosts
        # A CDN/proxy will respond to ANY Host header
        is_reflection = await self._test_host_header_reflection(ip, target_domain)
        if is_reflection:
            result.reason = "Host header reflection detected (server responds to any Host header - CDN/proxy)"
            result.response_time_ms = (time.time() - start_time) * 1000
            return result
        
        # Step 0.7: Direct IP test - real origin should respond with valid content
        # when accessed via IP + Host header, AND should NOT have Cloudflare headers
        direct_ok = await self._test_direct_origin(ip, target_domain)
        if not direct_ok:
            result.reason = "Direct IP test failed (not a valid origin server)"
            result.response_time_ms = (time.time() - start_time) * 1000
            return result
        
        # Step 1: Multi-path HTTP probe
        paths = ['/', '/robots.txt', '/favicon.ico']
        http_results = {}
        
        for path in paths:
            http_ok, http_status, http_body, http_headers = await self._probe_http(
                ip, target_domain, path=path, use_https=False
            )
            http_results[path] = {
                'ok': http_ok,
                'status': http_status,
                'body': http_body,
                'headers': http_headers
            }
        
        result.http_status = http_results['/']['status']
        
        # Step 2: Multi-path HTTPS probe
        https_results = {}
        ssl_cn = ""
        
        for path in paths:
            https_ok, https_status, https_body, https_headers, cn = await self._probe_https(
                ip, target_domain, path=path
            )
            https_results[path] = {
                'ok': https_ok,
                'status': https_status,
                'body': https_body,
                'headers': https_headers
            }
            if cn and not ssl_cn:
                ssl_cn = cn
        
        result.https_status = https_results['/']['status']
        result.ssl_cn = ssl_cn
        
        # Use HTTPS response if available, fallback to HTTP
        if https_results['/']['ok'] and https_results['/']['body']:
            primary_result = https_results['/']
            protocol = "HTTPS"
        elif http_results['/']['ok'] and http_results['/']['body']:
            primary_result = http_results['/']
            protocol = "HTTP"
        else:
            result.reason = "No valid HTTP/HTTPS response"
            result.response_time_ms = (time.time() - start_time) * 1000
            return result
        
        status = primary_result['status']
        body = primary_result['body']
        headers = primary_result['headers']
        
        # Step 3: Check for CDN headers (Cloudflare + CloudFront)
        result.has_cf_headers = self._has_cloudflare_headers(headers)
        is_cloudfront = self._has_cloudfront_headers(headers)
        if result.has_cf_headers or is_cloudfront:
            cdn_name = "Cloudflare" if result.has_cf_headers else "CloudFront"
            result.reason = f"{cdn_name} headers detected - still behind CDN"
            result.response_time_ms = (time.time() - start_time) * 1000
            return result
        
        # Step 4: Check for redirect - but allow same-domain redirects (legitimate origin behavior)
        if status in (301, 302, 303, 307, 308):
            location = headers.get('location', '')
            location_lower = location.lower()
            
            # Check if redirect goes to same domain or www subdomain
            is_same_domain = (
                target_domain in location_lower or
                f'www.{target_domain}' in location_lower or
                location_lower.startswith('/') or  # relative redirect
                location_lower.startswith(f'http://{target_domain}') or
                location_lower.startswith(f'https://{target_domain}')
            )
            
            if is_same_domain:
                # Same-domain redirect = origin server behavior (e.g., non-www -> www)
                # Don't return yet - continue to mark as verified
                result.is_redirect = True
                logger.debug(f"Same-domain redirect {status} -> {location} - treating as valid origin")
            else:
                # Cross-domain redirect = suspicious (could be CDN or parked domain)
                result.is_redirect = True
                result.reason = f"Cross-domain redirect {status} to {location}"
                result.response_time_ms = (time.time() - start_time) * 1000
                return result
        
        # Step 5: Check for challenge page
        result.is_challenge_page = self._is_challenge_page(body)
        if result.is_challenge_page:
            result.reason = "Cloudflare challenge page detected"
            result.response_time_ms = (time.time() - start_time) * 1000
            return result
        
        # Step 6: Extract server header
        result.server_header = headers.get('server', 'unknown')
        
        # Step 7: Multi-point content hash verification
        hash_matches = 0
        
        # Hash homepage
        if body:
            result.body_hash = hashlib.sha256(body.encode('utf-8', errors='ignore')).hexdigest()[:16]
            if baseline_hash and result.body_hash == baseline_hash:
                hash_matches += 1
        
        # Hash robots.txt
        robots_body = https_results['/robots.txt']['body'] or http_results['/robots.txt']['body']
        if robots_body:
            result.body_hash_robots = hashlib.sha256(robots_body.encode('utf-8', errors='ignore')).hexdigest()[:16]
            if baseline_hash_robots and result.body_hash_robots == baseline_hash_robots:
                hash_matches += 1
        
        # Hash favicon.ico
        favicon_body = https_results['/favicon.ico']['body'] or http_results['/favicon.ico']['body']
        if favicon_body:
            result.body_hash_favicon = hashlib.sha256(favicon_body.encode('utf-8', errors='ignore')).hexdigest()[:16]
            if baseline_hash_favicon and result.body_hash_favicon == baseline_hash_favicon:
                hash_matches += 1
        
        result.hash_match_count = hash_matches
        
        # Step 7.5: STRICT check - even if hash matches, if server is cloudflare, REJECT
        server_lower = result.server_header.lower()
        if 'cloudflare' in server_lower or 'cloudfront' in server_lower:
            result.reason = f"Server is CDN ({result.server_header}) - not a real origin"
            result.response_time_ms = (time.time() - start_time) * 1000
            return result
        
        # Step 7.6: Check SSL certificate - if CN doesn't match target domain, it's suspicious
        if result.ssl_cn and target_domain not in result.ssl_cn and f"*.{target_domain.split('.', 1)[-1] if '.' in target_domain else target_domain}" != result.ssl_cn:
            # SSL CN doesn't match - could be shared hosting or load balancer
            if result.ssl_cn == ip:  # IP as CN = self-signed, likely origin
                pass
            elif not result.ssl_cn:
                pass
            else:
                # Different domain - flag as suspicious but don't auto-reject
                logger.debug(f"SSL CN mismatch for {ip}: expected {target_domain}, got {result.ssl_cn}")
        
        # Step 8: Verification decision
        if result.is_redirect:
            # Same-domain redirect = verified origin (e.g., tokyo88.mom -> www.tokyo88.mom)
            result.is_verified = True
            result.verification_method = f"Origin redirect ({status})"
            location = headers.get('location', '')
            result.reason = f"VERIFIED: Redirect {status} -> {location} | Server: {result.server_header}"
        elif hash_matches >= 2:
            # At least 2 out of 3 hashes match - VERIFIED
            result.is_verified = True
            result.verification_method = f"Multi-point hash match ({hash_matches}/3)"
            result.reason = f"VERIFIED: {hash_matches}/3 content hashes match | {protocol} {status} | {result.server_header}"
        elif hash_matches == 1:
            # Only 1 hash matches - SUSPICIOUS but possible
            result.is_verified = True
            result.verification_method = f"Single hash match ({hash_matches}/3)"
            result.reason = f"VERIFIED (partial): {hash_matches}/3 hash match | {protocol} {status} | {result.server_header}"
        elif baseline_hash or baseline_hash_robots or baseline_hash_favicon:
            # Baseline provided but no match
            result.reason = f"Content hash mismatch (0/3 matches) | Expected vs Got: {baseline_hash[:8] if baseline_hash else 'N/A'}... vs {result.body_hash[:8]}..."
        else:
            # No baseline to compare, but got valid response
            if status == 200:
                result.is_verified = True
                result.verification_method = "HTTP 200 OK (no baseline)"
                result.reason = f"HTTP {status} OK | {protocol} | {result.server_header}"
            else:
                result.reason = f"HTTP {status} | No baseline hash to verify"
        
        result.response_time_ms = (time.time() - start_time) * 1000
        return result
    
    async def _test_host_header_reflection(self, ip: str, target_domain: str) -> bool:
        """
        Test if server responds to ANY Host header (CDN/proxy behavior).
        Real origin should ONLY respond to Host headers it hosts.
        Sends request with fake Host header - if 200 OK with similar content, it's a CDN/proxy.
        """
        import random
        import string
        
        fake_host = ''.join(random.choices(string.ascii_lowercase, k=12)) + '.nonexistent.com'
        
        try:
            import aiohttp
            connector = aiohttp.TCPConnector(ssl=False, force_close=True)
            timeout = aiohttp.ClientTimeout(total=5)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                url = f"http://{ip}/"
                headers = {'Host': fake_host}
                async with session.get(url, headers=headers, allow_redirects=False) as resp:
                    status = resp.status
                    body = await resp.text()
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    
                    # If server returns 200 OK to ANY Host header, it's a CDN/proxy
                    if status == 200 and len(body) > 100:
                        # Check for CDN headers in reflection response
                        if self._has_cloudflare_headers(resp_headers):
                            logger.debug(f"Reflection test: {ip} responds with CF headers to fake host - CDN")
                            return True
                        
                        # If content is too similar to target, it's a proxy
                        # (A real origin would return default page or error)
                        logger.debug(f"Reflection test: {ip} returns 200 to fake host - likely CDN/proxy")
                        return True
                    
                    # 404/error = real origin (only responds to domains it knows)
                    logger.debug(f"Reflection test: {ip} returns {status} to fake host - likely origin")
                    return False
                    
        except Exception as e:
            logger.debug(f"Reflection test failed for {ip}: {e}")
            return False
    
    async def _test_direct_origin(self, ip: str, target_domain: str) -> bool:
        """
        Test if IP is a real origin by checking:
        1. Server responds with valid HTTP
        2. Response does NOT have Cloudflare/CDN headers
        3. Server header is NOT cloudflare
        """
        try:
            import aiohttp
            connector = aiohttp.TCPConnector(ssl=False, force_close=True)
            timeout = aiohttp.ClientTimeout(total=5)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                # HTTP test
                url = f"http://{ip}/"
                headers = {'Host': target_domain}
                async with session.get(url, headers=headers, allow_redirects=False) as resp:
                    status = resp.status
                    body = await resp.text()
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    
                    server = resp_headers.get('server', '')
                    
                    # Check for CDN indicators (Cloudflare + CloudFront)
                    has_cf = self._has_cloudflare_headers(resp_headers)
                    has_cfront = self._has_cloudfront_headers(resp_headers)
                    is_cf_server = 'cloudflare' in server.lower()
                    is_cfront_server = 'cloudfront' in server.lower()
                    
                    if has_cf or has_cfront or is_cf_server or is_cfront_server:
                        cdn_name = "Cloudflare" if (has_cf or is_cf_server) else "CloudFront"
                        logger.debug(f"Direct origin test FAILED: {ip} - still behind {cdn_name} (server={server})")
                        return False
                    
                    if status in (200, 301, 302, 403, 404) and len(body) > 0:
                        # Valid origin response (not blocked, not error page)
                        logger.debug(f"Direct origin test PASSED: {ip} - no CF headers, server={server}")
                        return True
                    
                    logger.debug(f"Direct origin test FAILED: {ip} - invalid response (status={status})")
                    return False
                    
        except Exception as e:
            logger.debug(f"Direct origin test failed for {ip}: {e}")
            return False
    
    async def _get_ptr_record(self, ip: str) -> str:
        """Get PTR (reverse DNS) record for IP."""
        try:
            loop = asyncio.get_event_loop()
            ptr = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
            return ptr[0] if ptr else ""
        except Exception as e:
            logger.debug(f"PTR lookup failed for {ip}: {e}")
            return ""
    
    def _is_shared_hosting_ptr(self, ptr: str) -> bool:
        """Check if PTR indicates shared hosting."""
        ptr_lower = ptr.lower()
        
        # Known shared hosting providers
        shared_indicators = [
            'hostinger', 'namecheap', 'bluehost', 'godaddy', 'dreamhost',
            'siteground', 'hostgator', 'a2hosting', 'inmotion',
            'shared', 'cpanel', 'plesk', 'whm',
            'webhosting', 'hosting', 'vps', 'cloud'
        ]
        
        for indicator in shared_indicators:
            if indicator in ptr_lower:
                return True
        
        return False
    
    async def _probe_http(
        self,
        ip: str,
        host: str,
        path: str = '/',
        use_https: bool = False
    ) -> Tuple[bool, int, str, Dict[str, str]]:
        """
        Probe IP with HTTP/HTTPS request using Host header.
        
        Args:
            ip: IP address to probe
            host: Host header value
            path: URL path to request
            use_https: Use HTTPS instead of HTTP
        
        Returns:
            (success, status_code, body, headers)
        """
        try:
            import aiohttp
            
            scheme = "https" if use_https else "http"
            url = f"{scheme}://{ip}{path}"
            
            # Use custom connector to bypass SSL verification
            connector = aiohttp.TCPConnector(ssl=False, force_close=True)
            
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                headers = {
                    'Host': host,
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                }
                
                async with session.get(url, headers=headers, allow_redirects=False) as resp:
                    status = resp.status
                    body = await resp.text()
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    
                    return True, status, body, resp_headers
        
        except asyncio.TimeoutError:
            logger.debug(f"Timeout probing {ip}{path}")
            return False, 0, "", {}
        except Exception as e:
            logger.debug(f"Error probing {ip}{path}: {e}")
            return False, 0, "", {}
    
    async def _probe_https(
        self,
        ip: str,
        host: str,
        path: str = '/'
    ) -> Tuple[bool, int, str, Dict[str, str], str]:
        """
        Probe IP with HTTPS and extract SSL CN.
        
        Args:
            ip: IP address to probe
            host: Host header value
            path: URL path to request
        
        Returns:
            (success, status_code, body, headers, ssl_cn)
        """
        # First get SSL certificate CN
        ssl_cn = await self._get_ssl_cn(ip, host)
        
        # Then do HTTP probe
        success, status, body, headers = await self._probe_http(ip, host, path=path, use_https=True)
        
        return success, status, body, headers, ssl_cn
    
    async def _get_ssl_cn(self, ip: str, host: str) -> str:
        """Get SSL certificate Common Name."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            loop = asyncio.get_event_loop()
            
            def _get_cert():
                with socket.create_connection((ip, 443), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
                        if cert:
                            subject = dict(x[0] for x in cert.get('subject', []))
                            return subject.get('commonName', '')
                return ''
            
            cn = await loop.run_in_executor(None, _get_cert)
            return cn
        except Exception as e:
            logger.debug(f"SSL cert check failed for {ip}: {e}")
            return ''
    
    def _has_cloudflare_headers(self, headers: Dict[str, str]) -> bool:
        """Check if response has Cloudflare headers."""
        for key, value in headers.items():
            for cf_indicator in CF_HEADERS:
                if cf_indicator in key.lower() or cf_indicator in value.lower():
                    return True
        return False
    
    def _has_cloudfront_headers(self, headers: Dict[str, str]) -> bool:
        """Check if response has AWS CloudFront headers (CDN/proxy)."""
        for key, value in headers.items():
            key_lower = key.lower()
            value_lower = value.lower()
            for cf_indicator in CLOUDFRONT_HEADERS:
                if cf_indicator in key_lower or cf_indicator in value_lower:
                    return True
        return False
    
    def _is_challenge_page(self, body: str) -> bool:
        """Check if response body is Cloudflare challenge page."""
        body_lower = body.lower()
        for keyword in CF_CHALLENGE_KEYWORDS:
            if keyword in body_lower:
                return True
        return False
    
    async def verify_batch(
        self,
        candidates: List[str],
        target_domain: str,
        baseline_hash: Optional[str] = None,
        baseline_hash_robots: Optional[str] = None,
        baseline_hash_favicon: Optional[str] = None,
        max_concurrent: int = 10
    ) -> List[VerificationResult]:
        """
        Verify multiple candidates in parallel.
        
        Args:
            candidates: List of IP addresses
            target_domain: Target domain
            baseline_hash: Expected content hash (/)
            baseline_hash_robots: Expected hash (/robots.txt)
            baseline_hash_favicon: Expected hash (/favicon.ico)
            max_concurrent: Max concurrent verifications
        
        Returns:
            List of VerificationResult
        """
        sem = asyncio.Semaphore(max_concurrent)
        
        async def verify_with_sem(ip: str):
            async with sem:
                return await self.verify_candidate(
                    ip, target_domain, baseline_hash, 
                    baseline_hash_robots, baseline_hash_favicon
                )
        
        tasks = [verify_with_sem(ip) for ip in candidates]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        valid_results = []
        for r in results:
            if isinstance(r, VerificationResult):
                valid_results.append(r)
            elif isinstance(r, Exception):
                logger.debug(f"Verification exception: {r}")
        
        return valid_results


async def get_baseline_hash(target_url: str, use_flaresolverr: bool = False) -> Optional[str]:
    """
    Get baseline content hash from target domain.
    Uses FlareSolverr if Cloudflare challenge is active.
    
    Args:
        target_url: Target URL
        use_flaresolverr: Use FlareSolverr for CF bypass
    
    Returns:
        SHA-256 hash of body content (first 16 chars)
    """
    try:
        if use_flaresolverr:
            # Try FlareSolverr first
            try:
                from core.network.flaresolverr_client import solve_and_fetch
                result = solve_and_fetch(target_url)
                body = result.get('response_body', '')
                if body:
                    return hashlib.sha256(body.encode('utf-8', errors='ignore')).hexdigest()[:16]
            except Exception as e:
                logger.debug(f"FlareSolverr failed: {e}")
        
        # Fallback to direct request
        import aiohttp
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            async with session.get(target_url, headers=headers) as resp:
                body = await resp.text()
                return hashlib.sha256(body.encode('utf-8', errors='ignore')).hexdigest()[:16]
    
    except Exception as e:
        logger.error(f"Failed to get baseline hash: {e}")
        return None


async def get_baseline_hashes(
    target_domain: str, 
    use_flaresolverr: bool = False
) -> Dict[str, Optional[str]]:
    """
    Get baseline content hashes for multiple paths.
    
    Args:
        target_domain: Target domain
        use_flaresolverr: Use FlareSolverr for CF bypass
    
    Returns:
        Dict with keys: 'homepage', 'robots', 'favicon'
    """
    paths = {
        'homepage': f'https://{target_domain}/',
        'robots': f'https://{target_domain}/robots.txt',
        'favicon': f'https://{target_domain}/favicon.ico'
    }
    
    hashes = {}
    
    for key, url in paths.items():
        try:
            hash_val = await get_baseline_hash(url, use_flaresolverr)
            hashes[key] = hash_val
        except Exception as e:
            logger.debug(f"Failed to get baseline hash for {key}: {e}")
            hashes[key] = None
    
    return hashes
