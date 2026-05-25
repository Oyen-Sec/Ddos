"""
Origin IP Verifier v7.0
Live verification pipeline untuk kandidat origin IP
- HTTP/HTTPS probe dengan Host header
- Response analysis (CF detection, redirect, challenge page)
- Content hash verification
- SSL certificate check
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
    ssl_cn: str = ""
    has_cf_headers: bool = False
    is_redirect: bool = False
    is_challenge_page: bool = False
    response_time_ms: float = 0.0


class OriginVerifier:
    """Verify if IP candidate is real origin server."""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    async def verify_candidate(
        self,
        ip: str,
        target_domain: str,
        baseline_hash: Optional[str] = None
    ) -> VerificationResult:
        """
        Verify single IP candidate.
        
        Args:
            ip: Candidate IP address
            target_domain: Target domain (for Host header)
            baseline_hash: Expected content hash from real domain
        
        Returns:
            VerificationResult with verification status
        """
        result = VerificationResult(ip=ip)
        
        # Step 1: HTTP probe
        http_ok, http_status, http_body, http_headers = await self._probe_http(
            ip, target_domain, use_https=False
        )
        result.http_status = http_status
        
        # Step 2: HTTPS probe
        https_ok, https_status, https_body, https_headers, ssl_cn = await self._probe_https(
            ip, target_domain
        )
        result.https_status = https_status
        result.ssl_cn = ssl_cn
        
        # Use HTTPS response if available, fallback to HTTP
        if https_ok and https_body:
            status = https_status
            body = https_body
            headers = https_headers
        elif http_ok and http_body:
            status = http_status
            body = http_body
            headers = http_headers
        else:
            result.reason = "No valid HTTP/HTTPS response"
            return result
        
        # Step 3: Check for Cloudflare headers
        result.has_cf_headers = self._has_cloudflare_headers(headers)
        if result.has_cf_headers:
            result.reason = "Cloudflare headers detected (cf-ray, cf-cache-status)"
            return result
        
        # Step 4: Check for redirect
        if status in (301, 302, 303, 307, 308):
            location = headers.get('location', '')
            result.is_redirect = True
            result.reason = f"Redirect {status} to {location}"
            return result
        
        # Step 5: Check for challenge page
        result.is_challenge_page = self._is_challenge_page(body)
        if result.is_challenge_page:
            result.reason = "Cloudflare challenge page detected"
            return result
        
        # Step 6: Extract server header
        result.server_header = headers.get('server', 'unknown')
        
        # Step 7: Content hash verification
        if body:
            result.body_hash = hashlib.sha256(body.encode('utf-8', errors='ignore')).hexdigest()[:16]
            
            if baseline_hash:
                if result.body_hash == baseline_hash:
                    result.is_verified = True
                    result.reason = f"VERIFIED: Content hash match ({result.server_header})"
                else:
                    result.reason = f"Content hash mismatch (expected {baseline_hash[:8]}..., got {result.body_hash[:8]}...)"
            else:
                # No baseline to compare, but got valid response
                if status == 200:
                    result.is_verified = True
                    result.reason = f"HTTP {status} OK, server: {result.server_header}"
                else:
                    result.reason = f"HTTP {status}, no baseline hash to verify"
        else:
            result.reason = "Empty response body"
        
        return result
    
    async def _probe_http(
        self,
        ip: str,
        host: str,
        use_https: bool = False
    ) -> Tuple[bool, int, str, Dict[str, str]]:
        """
        Probe IP with HTTP/HTTPS request using Host header.
        
        Returns:
            (success, status_code, body, headers)
        """
        try:
            import aiohttp
            
            scheme = "https" if use_https else "http"
            url = f"{scheme}://{ip}/"
            
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
            logger.debug(f"Timeout probing {ip}")
            return False, 0, "", {}
        except Exception as e:
            logger.debug(f"Error probing {ip}: {e}")
            return False, 0, "", {}
    
    async def _probe_https(
        self,
        ip: str,
        host: str
    ) -> Tuple[bool, int, str, Dict[str, str], str]:
        """
        Probe IP with HTTPS and extract SSL CN.
        
        Returns:
            (success, status_code, body, headers, ssl_cn)
        """
        # First get SSL certificate CN
        ssl_cn = await self._get_ssl_cn(ip, host)
        
        # Then do HTTP probe
        success, status, body, headers = await self._probe_http(ip, host, use_https=True)
        
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
        max_concurrent: int = 10
    ) -> List[VerificationResult]:
        """
        Verify multiple candidates in parallel.
        
        Args:
            candidates: List of IP addresses
            target_domain: Target domain
            baseline_hash: Expected content hash
            max_concurrent: Max concurrent verifications
        
        Returns:
            List of VerificationResult
        """
        sem = asyncio.Semaphore(max_concurrent)
        
        async def verify_with_sem(ip: str):
            async with sem:
                return await self.verify_candidate(ip, target_domain, baseline_hash)
        
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
