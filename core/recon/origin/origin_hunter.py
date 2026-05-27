"""
Aggressive Origin IP Hunter v3.0
Multi-source parallel hunting: 18+ sources simultaneously
WAF bypass techniques, passive DNS, certificate transparency
Validates by sending Host header check to each candidate
"""
import asyncio
import re
import hashlib
import socket
import ssl
import logging
import json
import os
import time
from typing import List, Set, Dict, Optional, Any
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime

import backoff

logger = logging.getLogger("origin_hunter")


@dataclass
class OriginCandidate:
    ip: str
    confidence: float = 0.0
    source: str = ""
    verified: bool = False
    response_match: bool = False
    response_status: int = 0
    server: str = ""
    body_hash: str = ""
    discovery_method: str = ""
    response_body_snippet: str = ""


@dataclass
class SourceResult:
    source_name: str
    ips_found: List[str]
    count: int
    candidates_count: int
    error: Optional[str] = None


@dataclass
class HuntReport:
    target: str
    candidates: List[OriginCandidate] = field(default_factory=list)
    verified_origins: List[str] = field(default_factory=list)
    sources_hit: List[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    target_baseline_hash: str = ""
    target_baseline_status: int = 0
    target_baseline_size: int = 0
    source_results: List[SourceResult] = field(default_factory=list)
    waf_bypass_results: List[OriginCandidate] = field(default_factory=list)


class OriginHunter:
    """Aggressive origin IP hunter using 18+ parallel sources"""

    CF_RANGES = [
        "103.21.244.", "103.22.200.", "103.31.4.", "104.16.", "104.17.",
        "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.",
        "104.24.", "104.25.", "104.26.", "104.27.", "104.28.", "108.162.192.",
        "131.0.72.", "141.101.64.", "162.158.", "172.64.", "172.65.", "172.66.",
        "172.67.", "172.68.", "172.69.", "173.245.48.", "188.114.96.",
        "190.93.240.", "197.234.240.", "198.41.128.",
    ]

    AKAMAI_RANGES = ["23.32.", "23.33.", "23.34.", "23.35.", "23.36.", "23.37.",
                      "23.38.", "23.39.", "104.64.", "104.65.", "104.66.",
                      "104.67.", "104.68.", "104.69.", "104.70.", "104.71."]

    def __init__(self, timeout: int = 8, max_concurrent: int = 100, output_dir: Optional[str] = None):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self._candidates: Dict[str, OriginCandidate] = {}
        self._source_results: List[SourceResult] = []
        self._output_dir = output_dir or os.path.join("output", "origins")

    async def hunt(self, target: str, env: Optional[Dict] = None) -> HuntReport:
        """Launch all hunting techniques in parallel"""
        start = time.time()

        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        parsed = urlparse(target)
        host = parsed.hostname or ""

        # Try to load cached results first
        cached = self.load_cached_origins(target)
        if cached:
            logger.info(f"Using cached origin hunt results for {host}")
            print(f" [*] Loaded cached origins: {len(cached.verified_origins)} verified")
            return cached

        report = HuntReport(target=target)

        baseline = await self._fetch_baseline(target)
        if baseline:
            report.target_baseline_hash = baseline["hash"]
            report.target_baseline_status = baseline["status"]
            report.target_baseline_size = baseline["size"]

        env = env or {}

        # Launch ALL hunters in parallel (existing + new + CloudFail + 2026 Advanced)
        tasks = [
            self._hunt_crtsh(host),
            self._hunt_hackertarget(host),
            self._hunt_threatcrowd(host),
            self._hunt_dnshistory(host),
            self._hunt_subdomain_resolve(host),
            self._hunt_mxrecords(host),
            self._hunt_favicon(target),
            self._hunt_censys(host, env.get("CENSYS_ID"), env.get("CENSYS_SECRET")),
            self._hunt_shodan(host, env.get("SHODAN_KEY")),
            self._hunt_securitytrails(host, env.get("SECURITYTRAILS_KEY")),
            self._hunt_zoomeye(host, env.get("ZOOMEYE_KEY")),
            # 2026 Advanced platforms
            self._hunt_fofa(host, env.get("FOFA_KEY")),
            self._hunt_hunter(host, env.get("HUNTER_KEY")),
            self._hunt_binaryedge(host, env.get("BINARYEDGE_KEY")),
            self._hunt_netlas(host, env.get("NETLAS_KEY")),
            # New passive DNS sources
            self._hunt_anubisdb(host),
            self._hunt_rapiddns(host),
            self._hunt_threatminer(host),
            self._hunt_urlscan(host),
            self._hunt_wayback(host),
            self._hunt_certspotter(host),
            self._hunt_virustotal(host, env.get("VT_API_KEY")),
            # WAF bypass methods
            self._hunt_health_endpoints(host),
            self._hunt_acme_validation(host),
            self._hunt_xforwarded_bypass(host),
            self._hunt_cdn_misconfig(host),
            # CloudFail methods
            self._hunt_dnsdumpster(host),
            self._hunt_crimeflare(host),
            self._hunt_subdomain_bruteforce(host),
            # NEW POWERFUL SOURCES
            self._hunt_ipinfo(host),
            self._hunt_bgpview(host),
            self._hunt_viewdns(host),
            self._hunt_netcraft(host),
        ]

        source_names = [
            "crt.sh", "hackertarget", "threatcrowd", "dnshistory",
            "subdomain", "mx", "favicon", "censys", "shodan",
            "securitytrails", "zoomeye",
            "fofa", "hunter", "binaryedge", "netlas",
            "anubisdb", "rapiddns", "threatminer", "urlscan",
            "wayback", "certspotter", "virustotal",
            "health_endpoints", "acme_validation", "xforwarded_bypass",
            "cdn_misconfig",
            "dnsdumpster", "crimeflare", "subdomain_bruteforce",
            "ipinfo", "bgpview", "viewdns", "netcraft",
        ]

        try:
            results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=45)
        except asyncio.TimeoutError:
            logger.warning(f"Origin hunt timed out for {host} after 45s")
            results = [None] * len(tasks)

        for i, r in enumerate(results):
            source_name = source_names[i] if i < len(source_names) else f"source_{i}"
            if isinstance(r, list):
                if r:
                    report.sources_hit.append(f"{source_name}:{len(r)}")
                candidates_from_source = 0
                for ip in r:
                    if ip and self._is_valid_ip(ip) and not self._is_cdn_ip(ip):
                        if ip not in self._candidates:
                            self._candidates[ip] = OriginCandidate(ip=ip, source=source_name, confidence=0.3, discovery_method=source_name)
                            candidates_from_source += 1
                        else:
                            self._candidates[ip].confidence += 0.15
                            if source_name not in self._candidates[ip].source:
                                self._candidates[ip].source += "+" + source_name

                source_result = SourceResult(
                    source_name=source_name,
                    ips_found=r,
                    count=len(r),
                    candidates_count=candidates_from_source,
                )
                self._source_results.append(source_result)
            elif isinstance(r, Exception):
                logger.debug(f"Hunter {source_name} failed: {r}")
                self._source_results.append(SourceResult(
                    source_name=source_name,
                    ips_found=[],
                    count=0,
                    candidates_count=0,
                    error=str(r),
                ))

        # Verify all candidates by sending Host header check
        if self._candidates and report.target_baseline_hash:
            await self._verify_candidates(host, report.target_baseline_hash,
                                          report.target_baseline_status,
                                          report.target_baseline_size)

        # FALLBACK 2026: If no candidates found, directly resolve DNS and verify
        if not self._candidates:
            logger.info(f"[Fallback] No candidates from sources, trying direct DNS resolution...")
            try:
                direct_ips = await self._resolve_batch([host])
                for ip in direct_ips:
                    if ip not in self._candidates:
                        self._candidates[ip] = OriginCandidate(
                            ip=ip,
                            confidence=0.5,
                            source="dns_fallback",
                            discovery_method="direct_dns_resolution"
                        )
                # Verify these direct IPs
                if self._candidates and report.target_baseline_hash:
                    await self._verify_candidates(host, report.target_baseline_hash,
                                                  report.target_baseline_status,
                                                  report.target_baseline_size)
            except Exception as e:
                logger.debug(f"DNS fallback failed: {e}")

        # Sort by confidence + verified
        candidates = list(self._candidates.values())
        candidates.sort(key=lambda c: (-int(c.verified), -int(c.response_match), -c.confidence))
        report.candidates = candidates[:50]
        report.verified_origins = [c.ip for c in candidates if c.verified][:10]
        report.source_results = self._source_results

        report.elapsed_seconds = round(time.time() - start, 2)

        # Save results
        await self._save_results(target, report)

        # Auto-save to origin store
        try:
            from core.recon.origin.origin_store import save_hunt
            cands_serializable = []
            for c in report.candidates:
                cands_serializable.append({
                    "ip": c.ip,
                    "confidence": c.confidence,
                    "source": c.source,
                    "verified": c.verified,
                    "response_match": c.response_match,
                    "response_status": c.response_status,
                    "server": c.server,
                })
            save_hunt(target, report.verified_origins, cands_serializable)
        except Exception as e:
            logger.debug(f"Failed to save hunt: {e}")

        return report

    async def _save_results(self, target: str, report: HuntReport) -> None:
        """Save hunt results to output/origins/{target}/"""
        parsed = urlparse(target)
        host = parsed.hostname or re.sub(r'[^a-z0-9.-]', '_', target.lower())
        safe_host = re.sub(r'[^a-z0-9.-]', '_', host)

        output_path = Path(self._output_dir) / safe_host
        try:
            output_path.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.debug(f"Failed to create output dir {output_path}: {e}")
            return

        # Report JSON
        try:
            report_json = {
                "target": report.target,
                "host": host,
                "hunt_timestamp": datetime.utcnow().isoformat(),
                "elapsed_seconds": report.elapsed_seconds,
                "baseline": {
                    "hash": report.target_baseline_hash,
                    "status": report.target_baseline_status,
                    "size": report.target_baseline_size,
                },
                "summary": {
                    "total_candidates": len(report.candidates),
                    "verified_origins_count": len(report.verified_origins),
                    "sources_hit": report.sources_hit,
                },
                "verified_origins": [
                    {
                        "ip": c.ip,
                        "confidence": c.confidence,
                        "source": c.source,
                        "response_status": c.response_status,
                        "server": c.server,
                        "body_hash": c.body_hash,
                        "discovery_method": c.discovery_method,
                    }
                    for c in report.candidates if c.verified
                ],
                "top_candidates": [
                    {
                        "ip": c.ip,
                        "confidence": c.confidence,
                        "source": c.source,
                        "verified": c.verified,
                        "response_match": c.response_match,
                        "response_status": c.response_status,
                        "server": c.server,
                        "body_hash": c.body_hash,
                        "discovery_method": c.discovery_method,
                    }
                    for c in report.candidates[:30]
                ],
            }
            with open(str(output_path / "report.json"), "w") as f:
                json.dump(report_json, f, indent=2)
        except Exception as e:
            logger.debug(f"Failed to save report.json: {e}")

        # Origins TXT
        try:
            with open(str(output_path / "origins.txt"), "w") as f:
                for ip in report.verified_origins:
                    f.write(f"{ip}\n")
                if not report.verified_origins:
                    for c in report.candidates[:10]:
                        if c.response_match:
                            f.write(f"{c.ip}\n")
        except Exception as e:
            logger.debug(f"Failed to save origins.txt: {e}")

        # Sources JSON
        try:
            sources_json = []
            for sr in self._source_results:
                sources_json.append({
                    "source": sr.source_name,
                    "ips_found": sr.ips_found,
                    "count": sr.count,
                    "candidates_added": sr.candidates_count,
                    "error": sr.error,
                })
            with open(str(output_path / "sources.json"), "w") as f:
                json.dump(sources_json, f, indent=2)
        except Exception as e:
            logger.debug(f"Failed to save sources.json: {e}")

    async def _fetch_baseline(self, target: str) -> Optional[Dict]:
        """Get baseline response of target through CDN for comparison"""
        try:
            from curl_cffi.requests import AsyncSession
            kwargs = {"impersonate": "chrome120", "timeout": self.timeout}
            async with AsyncSession(**kwargs) as sess:
                resp = await sess.get(target, timeout=self.timeout, allow_redirects=False)
                content = resp.content[:8192] if resp.content else b""
                return {
                    "hash": hashlib.md5(content).hexdigest(),
                    "status": resp.status_code,
                    "size": len(resp.content) if resp.content else 0,
                    "server": resp.headers.get("server", ""),
                }
        except Exception as e:
            logger.debug(f"Baseline fetch failed: {e}")
            return None

    # ── Existing Hunt Methods ────────────────────────────────────────

    async def _hunt_crtsh(self, host: str) -> List[str]:
        """Scrape Certificate Transparency logs - finds historical certs"""
        try:
            from curl_cffi.requests import AsyncSession
            kwargs = {"impersonate": "chrome120", "timeout": 15}
            async with AsyncSession(**kwargs) as sess:
                domain = ".".join(host.split(".")[-2:])
                url = f"https://crt.sh/?q=%25.{domain}&output=json"
                resp = await sess.get(url, timeout=15)
                if resp.status_code != 200:
                    return []
                data = resp.json()

                subdomains = set()
                for entry in data[:200]:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub and not sub.startswith("*") and domain in sub:
                            subdomains.add(sub)

                ips = await self._resolve_batch(list(subdomains)[:100])
                return ips
        except Exception as e:
            logger.debug(f"crt.sh failed: {e}")
            return []

    async def _hunt_hackertarget(self, host: str) -> List[str]:
        """HackerTarget DNS records - subdomain enum + IP records"""
        try:
            from curl_cffi.requests import AsyncSession
            kwargs = {"impersonate": "chrome120", "timeout": 10}
            async with AsyncSession(**kwargs) as sess:
                ips = []
                resp = await sess.get(f"https://api.hackertarget.com/hostsearch/?q={host}", timeout=10)
                if resp.status_code == 200 and resp.text:
                    for line in resp.text.split("\n"):
                        if "," in line:
                            parts = line.split(",")
                            if len(parts) >= 2:
                                ip = parts[1].strip()
                                if self._is_valid_ip(ip):
                                    ips.append(ip)

                resp = await sess.get(f"https://api.hackertarget.com/dnslookup/?q={host}", timeout=10)
                if resp.status_code == 200 and resp.text:
                    found = re.findall(r'\d+\.\d+\.\d+\.\d+', resp.text)
                    ips.extend(found)

                return list(set(ips))
        except Exception as e:
            logger.debug(f"hackertarget failed: {e}")
            return []

    async def _hunt_threatcrowd(self, host: str) -> List[str]:
        """ThreatCrowd resolutions history"""
        try:
            from curl_cffi.requests import AsyncSession
            kwargs = {"impersonate": "chrome120", "timeout": 10}
            async with AsyncSession(**kwargs) as sess:
                url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={host}"
                resp = await sess.get(url, timeout=10)
                if resp.status_code != 200:
                    return []
                data = resp.json()
                ips = []
                for r in data.get("resolutions", [])[:50]:
                    ip = r.get("ip_address", "")
                    if self._is_valid_ip(ip):
                        ips.append(ip)
                return ips
        except Exception as e:
            logger.debug(f"threatcrowd failed: {e}")
            return []

    async def _hunt_dnshistory(self, host: str) -> List[str]:
        """DNS history via viewdns.info / dnshistory.org scraping"""
        try:
            from curl_cffi.requests import AsyncSession
            kwargs = {"impersonate": "chrome120", "timeout": 10}
            async with AsyncSession(**kwargs) as sess:
                ips = set()
                resp = await sess.get(
                    f"https://viewdns.info/iphistory/?domain={host}",
                    timeout=10
                )
                if resp.status_code == 200 and resp.text:
                    found = re.findall(r'(\d+\.\d+\.\d+\.\d+)', resp.text)
                    ips.update(found)
                return list(ips)
        except Exception as e:
            logger.debug(f"dnshistory failed: {e}")
            return []

    async def _hunt_subdomain_resolve(self, host: str) -> List[str]:
        """Common subdomain bruteforce - finds non-CDN-protected subs"""
        common_subs = [
            "direct", "origin", "cpanel", "ftp", "mail", "webmail", "smtp",
            "ns1", "ns2", "dns", "mx", "mx1", "mx2", "vpn", "remote",
            "test", "staging", "dev", "stage", "beta", "alpha", "preview",
            "admin", "panel", "control", "manage", "cp", "whm",
            "old", "backup", "legacy", "archive", "store",
            "api", "api2", "api-staging", "api-dev", "api-prod",
            "internal", "intranet", "private", "secure",
            "server", "server1", "srv", "srv1", "host",
            "static", "img", "image", "images", "media", "files",
            "blog", "shop", "secure-shop",
        ]
        targets = [f"{sub}.{host}" for sub in common_subs]
        return await self._resolve_batch(targets)

    async def _hunt_mxrecords(self, host: str) -> List[str]:
        """MX records - mail servers often expose origin IP"""
        try:
            try:
                import dns.resolver
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 5
                answers = resolver.resolve(host, "MX")
                ips = []
                for rdata in answers:
                    mx_host = str(rdata.exchange).rstrip(".")
                    try:
                        ip = socket.gethostbyname(mx_host)
                        ips.append(ip)
                    except Exception:
                        pass
                return ips
            except ImportError:
                return []
        except Exception:
            return []

    async def _hunt_favicon(self, target: str) -> List[str]:
        """Favicon hash - search Shodan/ZoomEye-like indexes by hash"""
        try:
            import mmh3
            from curl_cffi.requests import AsyncSession

            parsed = urlparse(target)
            base = f"{parsed.scheme}://{parsed.netloc}"

            kwargs = {"impersonate": "chrome120", "timeout": 8}
            async with AsyncSession(**kwargs) as sess:
                resp = await sess.get(f"{base}/favicon.ico", timeout=8)
                if resp.status_code != 200 or not resp.content:
                    return []

                import codecs
                favicon_b64 = codecs.encode(resp.content, "base64")
                favicon_hash = mmh3.hash(favicon_b64)
                logger.debug(f"Favicon hash: {favicon_hash}")
                return []
        except Exception:
            return []

    async def _hunt_censys(self, host: str, cid: Optional[str], csec: Optional[str]) -> List[str]:
        """Censys API search by hostname/cert subject"""
        if not cid or not csec:
            return []
        try:
            from curl_cffi.requests import AsyncSession
            import base64
            auth = base64.b64encode(f"{cid}:{csec}".encode()).decode()
            kwargs = {"impersonate": "chrome120", "timeout": 15,
                      "headers": {"Authorization": f"Basic {auth}"}}
            async with AsyncSession(**kwargs) as sess:
                payload = {
                    "query": f"services.tls.certificates.leaf_data.subject.common_name: {host} OR names: {host}",
                    "per_page": 50,
                }
                resp = await sess.post(
                    "https://search.censys.io/api/v2/hosts/search",
                    json=payload, timeout=15
                )
                if resp.status_code != 200:
                    return []
                data = resp.json()
                ips = []
                for hit in data.get("result", {}).get("hits", []):
                    ip = hit.get("ip")
                    if ip and self._is_valid_ip(ip):
                        ips.append(ip)
                return ips
        except Exception as e:
            logger.debug(f"censys failed: {e}")
            return []

    async def _hunt_shodan(self, host: str, key: Optional[str]) -> List[str]:
        """Shodan API - Enhanced 2026 with SSL cert search"""
        if not key:
            return []
        ips = []
        try:
            from curl_cffi.requests import AsyncSession
            kwargs = {"impersonate": "chrome120", "timeout": 20}
            async with AsyncSession(**kwargs) as sess:
                # Method 1: Hostname search
                resp = await sess.get(
                    f"https://api.shodan.io/shodan/host/search?key={key}&query=hostname:{host}",
                    timeout=20
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for m in data.get("matches", [])[:50]:
                        ip = m.get("ip_str")
                        if ip and self._is_valid_ip(ip):
                            ips.append(ip)
                
                # Method 2: SSL certificate search (2026 enhancement)
                resp2 = await sess.get(
                    f"https://api.shodan.io/shodan/host/search?key={key}&query=ssl.cert.subject.cn:{host}",
                    timeout=20
                )
                if resp2.status_code == 200:
                    data2 = resp2.json()
                    for m in data2.get("matches", [])[:50]:
                        ip = m.get("ip_str")
                        if ip and self._is_valid_ip(ip) and ip not in ips:
                            ips.append(ip)
                
                # Method 3: HTTP title search
                resp3 = await sess.get(
                    f"https://api.shodan.io/shodan/host/search?key={key}&query=http.title:{host}",
                    timeout=20
                )
                if resp3.status_code == 200:
                    data3 = resp3.json()
                    for m in data3.get("matches", [])[:30]:
                        ip = m.get("ip_str")
                        if ip and self._is_valid_ip(ip) and ip not in ips:
                            ips.append(ip)
                
                logger.info(f"[Shodan] Found {len(ips)} IPs for {host}")
                return ips
        except Exception as e:
            logger.debug(f"shodan failed: {e}")
            return ips

    async def _hunt_securitytrails(self, host: str, key: Optional[str]) -> List[str]:
        """SecurityTrails API - Enhanced 2026 with multiple endpoints"""
        if not key:
            return []
        ips = []
        try:
            from curl_cffi.requests import AsyncSession
            headers = {"APIKEY": key, "Accept": "application/json"}
            kwargs = {"impersonate": "chrome120", "timeout": 20, "headers": headers}
            async with AsyncSession(**kwargs) as sess:
                # Method 1: DNS History A records
                resp = await sess.get(
                    f"https://api.securitytrails.com/v1/history/{host}/dns/a",
                    timeout=20
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for record in data.get("records", [])[:50]:
                        for v in record.get("values", []):
                            ip = v.get("ip", "")
                            if self._is_valid_ip(ip):
                                ips.append(ip)
                
                # Method 2: Current DNS records (2026 enhancement)
                resp2 = await sess.get(
                    f"https://api.securitytrails.com/v1/domain/{host}",
                    timeout=20
                )
                if resp2.status_code == 200:
                    data2 = resp2.json()
                    current_dns = data2.get("current_dns", {})
                    for a_record in current_dns.get("a", {}).get("values", []):
                        ip = a_record.get("ip", "")
                        if self._is_valid_ip(ip) and ip not in ips:
                            ips.append(ip)
                
                # Method 3: Subdomains with IPs
                resp3 = await sess.get(
                    f"https://api.securitytrails.com/v1/domain/{host}/subdomains",
                    timeout=20
                )
                if resp3.status_code == 200:
                    data3 = resp3.json()
                    subdomains = data3.get("subdomains", [])[:30]
                    for sub in subdomains:
                        subdomain = f"{sub}.{host}"
                        # Get DNS for each subdomain
                        resp_sub = await sess.get(
                            f"https://api.securitytrails.com/v1/domain/{subdomain}",
                            timeout=15
                        )
                        if resp_sub.status_code == 200:
                            sub_data = resp_sub.json()
                            sub_dns = sub_data.get("current_dns", {})
                            for a_rec in sub_dns.get("a", {}).get("values", []):
                                ip = a_rec.get("ip", "")
                                if self._is_valid_ip(ip) and ip not in ips:
                                    ips.append(ip)
                
                logger.info(f"[SecurityTrails] Found {len(ips)} IPs for {host}")
                return ips
        except Exception as e:
            logger.debug(f"securitytrails failed: {e}")
            return ips

    async def _hunt_zoomeye(self, host: str, key: Optional[str]) -> List[str]:
        if not key:
            return []
        try:
            from curl_cffi.requests import AsyncSession
            kwargs = {"impersonate": "chrome120", "timeout": 15,
                      "headers": {"API-KEY": key}}
            async with AsyncSession(**kwargs) as sess:
                resp = await sess.get(
                    f"https://api.zoomeye.org/host/search?query=hostname:{host}",
                    timeout=15
                )
                if resp.status_code != 200:
                    return []
                data = resp.json()
                ips = []
                for m in data.get("matches", [])[:50]:
                    ip = m.get("ip", "")
                    if self._is_valid_ip(ip):
                        ips.append(ip)
                return ips
        except Exception as e:
            logger.debug(f"zoomeye failed: {e}")
            return []

    # ── 2026 Advanced Hunting Methods ──────────────────────────────────────

    async def _hunt_fofa(self, host: str, key: Optional[str]) -> List[str]:
        """FOFA - Chinese threat intel platform (2026)"""
        if not key:
            return []
        ips = []
        try:
            import base64
            from curl_cffi.requests import AsyncSession
            # FOFA query: domain="target.com"
            query = f'domain="{host}"'
            query_b64 = base64.b64encode(query.encode()).decode()
            
            async with AsyncSession(impersonate="chrome120", timeout=20) as sess:
                resp = await sess.get(
                    f"https://fofa.info/api/v1/search/all?email={key.split(':')[0]}&key={key.split(':')[1]}&qbase64={query_b64}&size=100",
                    timeout=20
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for result in data.get("results", []):
                        if len(result) > 0:
                            ip = result[0]
                            if self._is_valid_ip(ip):
                                ips.append(ip)
                logger.info(f"[FOFA] Found {len(ips)} IPs for {host}")
        except Exception as e:
            logger.debug(f"fofa failed: {e}")
        return ips

    async def _hunt_hunter(self, host: str, key: Optional[str]) -> List[str]:
        """Hunter.io - Advanced domain intelligence (2026)"""
        if not key:
            return []
        ips = []
        try:
            from curl_cffi.requests import AsyncSession
            async with AsyncSession(impersonate="chrome120", timeout=20) as sess:
                resp = await sess.get(
                    f"https://api.hunter.how/search?api-key={key}&query=domain={host}&page=1&page_size=100",
                    timeout=20
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("data", {}).get("arr", []):
                        ip = item.get("ip", "")
                        if self._is_valid_ip(ip):
                            ips.append(ip)
                logger.info(f"[Hunter] Found {len(ips)} IPs for {host}")
        except Exception as e:
            logger.debug(f"hunter failed: {e}")
        return ips

    async def _hunt_binaryedge(self, host: str, key: Optional[str]) -> List[str]:
        """BinaryEdge - Internet scanning platform (2026)"""
        if not key:
            return []
        ips = []
        try:
            from curl_cffi.requests import AsyncSession
            headers = {"X-Key": key}
            async with AsyncSession(impersonate="chrome120", timeout=20, headers=headers) as sess:
                resp = await sess.get(
                    f"https://api.binaryedge.io/v2/query/domains/subdomain/{host}",
                    timeout=20
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for event in data.get("events", []):
                        for record in event.get("A", []):
                            if self._is_valid_ip(record):
                                ips.append(record)
                logger.info(f"[BinaryEdge] Found {len(ips)} IPs for {host}")
        except Exception as e:
            logger.debug(f"binaryedge failed: {e}")
        return ips

    async def _hunt_netlas(self, host: str, key: Optional[str]) -> List[str]:
        """Netlas.io - Internet asset discovery (2026)"""
        if not key:
            return []
        ips = []
        try:
            from curl_cffi.requests import AsyncSession
            headers = {"X-API-Key": key}
            async with AsyncSession(impersonate="chrome120", timeout=20, headers=headers) as sess:
                resp = await sess.get(
                    f"https://app.netlas.io/api/domains/?q=domain:{host}",
                    timeout=20
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("items", []):
                        for record in item.get("a", []):
                            if self._is_valid_ip(record):
                                ips.append(record)
                logger.info(f"[Netlas] Found {len(ips)} IPs for {host}")
        except Exception as e:
            logger.debug(f"netlas failed: {e}")
        return ips

    # ── New Passive DNS Sources ──────────────────────────────────────

    @backoff.on_exception(backoff.expo, Exception, max_tries=3)
    async def _hunt_anubisdb(self, host: str) -> List[str]:
        """AnubisDB subdomain enumeration"""
        try:
            from curl_cffi.requests import AsyncSession
            async with AsyncSession(impersonate="chrome120", timeout=15) as sess:
                resp = await sess.get(
                    f"https://jldc.me/anubis/subdomains/{host}",
                    timeout=15
                )
                if resp.status_code != 200:
                    return []
                data = resp.json()
                if not isinstance(data, list):
                    return []
                subdomains = [s for s in data if isinstance(s, str) and s.strip()]
                ips = await self._resolve_batch(subdomains[:100])
                return ips
        except Exception as e:
            logger.debug(f"anubisdb failed: {e}")
            return []

    @backoff.on_exception(backoff.expo, Exception, max_tries=3)
    async def _hunt_rapiddns(self, host: str) -> List[str]:
        """RapidDNS.io subdomain/history search"""
        try:
            from curl_cffi.requests import AsyncSession
            async with AsyncSession(impersonate="chrome120", timeout=15) as sess:
                resp = await sess.get(
                    f"https://rapiddns.io/subdomain/{host}?full=1",
                    timeout=15
                )
                if resp.status_code != 200 or not resp.text:
                    return []
                ips = set()
                found = re.findall(r'(\d+\.\d+\.\d+\.\d+)', resp.text)
                ips.update(found)
                return list(ips)
        except Exception as e:
            logger.debug(f"rapiddns failed: {e}")
            return []

    @backoff.on_exception(backoff.expo, Exception, max_tries=3)
    async def _hunt_threatminer(self, host: str) -> List[str]:
        """ThreatMiner domain report"""
        try:
            from curl_cffi.requests import AsyncSession
            async with AsyncSession(impersonate="chrome120", timeout=15) as sess:
                resp = await sess.get(
                    f"https://api.threatminer.org/v2/domain.php?q={host}&rt=5",
                    timeout=15
                )
                if resp.status_code != 200:
                    return []
                data = resp.json()
                ips = []
                for entry in data.get("results", []):
                    if isinstance(entry, str):
                        if self._is_valid_ip(entry):
                            ips.append(entry)
                return ips
        except Exception as e:
            logger.debug(f"threatminer failed: {e}")
            return []

    @backoff.on_exception(backoff.expo, Exception, max_tries=3)
    async def _hunt_urlscan(self, host: str) -> List[str]:
        """URLScan.io API search by domain"""
        try:
            from curl_cffi.requests import AsyncSession
            async with AsyncSession(impersonate="chrome120", timeout=15) as sess:
                resp = await sess.get(
                    f"https://urlscan.io/api/v1/search/?q=domain:{host}",
                    timeout=15
                )
                if resp.status_code != 200:
                    return []
                data = resp.json()
                ips = set()
                for result in data.get("results", [])[:50]:
                    page = result.get("page", {})
                    ip = page.get("ip", "")
                    if self._is_valid_ip(ip):
                        ips.add(ip)
                return list(ips)
        except Exception as e:
            logger.debug(f"urlscan failed: {e}")
            return []

    @backoff.on_exception(backoff.expo, Exception, max_tries=3)
    async def _hunt_wayback(self, host: str) -> List[str]:
        """Wayback Machine CDX API for historical DNS"""
        try:
            from curl_cffi.requests import AsyncSession
            domain = ".".join(host.split(".")[-2:])
            async with AsyncSession(impersonate="chrome120", timeout=20) as sess:
                resp = await sess.get(
                    f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey",
                    timeout=20
                )
                if resp.status_code != 200:
                    return []
                data = resp.json()
                subdomains = set()
                for row in data[1:]:
                    if row and len(row) > 0:
                        raw = row[0] if isinstance(row, list) else row
                        parsed = urlparse(raw if isinstance(raw, str) else "")
                        sub = parsed.hostname or ""
                        if sub and domain in sub:
                            subdomains.add(sub.lower())
                ips = await self._resolve_batch(list(subdomains)[:100])
                return ips
        except Exception as e:
            logger.debug(f"wayback failed: {e}")
            return []

    @backoff.on_exception(backoff.expo, Exception, max_tries=3)
    async def _hunt_certspotter(self, host: str) -> List[str]:
        """CertSpotter certificate transparency"""
        try:
            from curl_cffi.requests import AsyncSession
            async with AsyncSession(impersonate="chrome120", timeout=15) as sess:
                resp = await sess.get(
                    f"https://api.certspotter.com/v1/issuances?domain={host}&include_subdomains=true&expand=dns_names",
                    timeout=15
                )
                if resp.status_code != 200:
                    return []
                data = resp.json()
                subdomains = set()
                for entry in data:
                    dns_names = entry.get("dns_names", [])
                    for name in dns_names:
                        name = name.strip().lower()
                        if name and not name.startswith("*") and host in name:
                            subdomains.add(name)
                ips = await self._resolve_batch(list(subdomains)[:100])
                return ips
        except Exception as e:
            logger.debug(f"certspotter failed: {e}")
            return []

    @backoff.on_exception(backoff.expo, Exception, max_tries=3)
    async def _hunt_virustotal(self, host: str, api_key: Optional[str]) -> List[str]:
        """VirusTotal passive DNS (if API key available)"""
        if not api_key:
            return []
        try:
            from curl_cffi.requests import AsyncSession
            async with AsyncSession(impersonate="chrome120", timeout=15,
                                    headers={"x-apikey": api_key}) as sess:
                resp = await sess.get(
                    f"https://www.virustotal.com/api/v3/domains/{host}/resolutions",
                    timeout=15
                )
                if resp.status_code != 200:
                    return []
                data = resp.json()
                ips = []
                for item in data.get("data", [])[:50]:
                    attrs = item.get("attributes", {})
                    ip = attrs.get("ip_address", "")
                    if self._is_valid_ip(ip):
                        ips.append(ip)
                return ips
        except Exception as e:
            logger.debug(f"virustotal failed: {e}")
            return []

    # ── WAF Bypass Methods ──────────────────────────────────────────

    async def _hunt_health_endpoints(self, host: str) -> List[str]:
        """Probe common health check endpoints that might bypass CDN"""
        health_paths = [
            "/health", "/healthcheck", "/healthz", "/ready", "/live",
            "/status", "/ping", "/load-balancer-heartbeat",
            "/heartbeat", "/lb-heartbeat", "/.well-known/health",
        ]
        ips = set()
        try:
            from curl_cffi.requests import AsyncSession
            async with AsyncSession(impersonate="chrome120", timeout=8) as sess:
                # Resolve the host first
                try:
                    resolved = socket.gethostbyname(host)
                    ips.add(resolved)
                except Exception:
                    pass

                for path in health_paths:
                    for scheme in ("https", "http"):
                        try:
                            url = f"{scheme}://{host}{path}"
                            resp = await sess.get(url, timeout=self.timeout, allow_redirects=False)
                            if resp.status_code in (200, 401, 403):
                                logger.debug(f"Health endpoint {url} returned {resp.status_code}")
                                try:
                                    ip = socket.gethostbyname(host)
                                    ips.add(ip)
                                except Exception:
                                    pass
                        except Exception:
                            continue
            return list(ips)
        except Exception as e:
            logger.debug(f"health_endpoints failed: {e}")
            return []

    async def _hunt_acme_validation(self, host: str) -> List[str]:
        """Check ACME challenge paths which may route to origin directly"""
        ips = set()
        try:
            from curl_cffi.requests import AsyncSession
            async with AsyncSession(impersonate="chrome120", timeout=8) as sess:
                url = f"https://{host}/.well-known/acme-challenge/"
                resp = await sess.get(url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code in (200, 401, 403):
                    try:
                        ip = socket.gethostbyname(host)
                        ips.add(ip)
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"acme_validation failed: {e}")
            return []
        return list(ips)

    async def _hunt_xforwarded_bypass(self, host: str) -> List[str]:
        """Send requests with X-Forwarded-For and Host header manipulations to bypass CDN"""
        ips = set()
        try:
            from curl_cffi.requests import AsyncSession

            # Common origin IPs to try as X-Forwarded-For
            spoof_ips = [
                "127.0.0.1", "localhost",
                "10.0.0.1", "10.0.0.2", "172.16.0.1", "192.168.1.1",
            ]

            async with AsyncSession(impersonate="chrome120", timeout=8) as sess:
                for spoof in spoof_ips:
                    headers = {
                        "X-Forwarded-For": spoof,
                        "X-Real-IP": spoof,
                        "X-Originating-IP": spoof,
                        "X-Remote-IP": spoof,
                        "X-Remote-Addr": spoof,
                    }
                    for scheme in ("https", "http"):
                        try:
                            url = f"{scheme}://{host}/"
                            resp = await sess.get(url, timeout=self.timeout,
                                                  headers=headers, allow_redirects=False)
                            if resp.status_code in (200, 401, 403):
                                try:
                                    ip = socket.gethostbyname(host)
                                    ips.add(ip)
                                except Exception:
                                    pass
                        except Exception:
                            continue
            return list(ips)
        except Exception as e:
            logger.debug(f"xforwarded_bypass failed: {e}")
            return []

    async def _hunt_cdn_misconfig(self, host: str) -> List[str]:
        """Check for CDN misconfigurations - direct IP access, Cloudflare IPs with wrong certs"""
        ips = set()
        try:
            from curl_cffi.requests import AsyncSession

            resolved_ip = None
            try:
                resolved_ip = socket.gethostbyname(host)
            except Exception:
                pass

            async with AsyncSession(impersonate="chrome120", timeout=8,
                                    verify=False) as sess:
                # Try direct IP access with Host header
                if resolved_ip and self._is_valid_ip(resolved_ip):
                    for scheme in ("https", "http"):
                        try:
                            url = f"{scheme}://{resolved_ip}/"
                            resp = await sess.get(url, timeout=self.timeout,
                                                  headers={"Host": host},
                                                  allow_redirects=False)
                            if resp.status_code in (200, 301, 302, 403, 401):
                                ips.add(resolved_ip)
                        except Exception:
                            continue

                # Try common origin hostnames
                origin_hostnames = [
                    f"origin.{host}",
                    f"origin-{host}",
                    f"direct.{host}",
                    f"origin-{host.split('.')[0]}.{'.'.join(host.split('.')[-2:])}",
                ]
                for oh in origin_hostnames:
                    try:
                        ip = socket.gethostbyname(oh)
                        if self._is_valid_ip(ip) and not self._is_cdn_ip(ip):
                            ips.add(ip)
                    except Exception:
                        continue

            return list(ips)
        except Exception as e:
            logger.debug(f"cdn_misconfig failed: {e}")
            return []

    # ── Utility Methods ─────────────────────────────────────────────

    async def _resolve_batch(self, hostnames: List[str]) -> List[str]:
        """Resolve hostnames in parallel"""
        sem = asyncio.Semaphore(50)

        async def resolve_one(name):
            async with sem:
                try:
                    loop = asyncio.get_event_loop()
                    res = await loop.run_in_executor(None, socket.gethostbyname, name)
                    return res
                except Exception:
                    return None

        results = await asyncio.gather(*[resolve_one(h) for h in hostnames], return_exceptions=True)
        return [r for r in results if r and isinstance(r, str)]

    async def _verify_candidates(self, original_host: str, baseline_hash: str,
                                  baseline_status: int, baseline_size: int):
        """
        Verify candidates using new OriginVerifier v7.0.
        Uses HTTP/HTTPS probe with Host header, CF detection, content hash verification.
        """
        try:
            from core.recon.origin.origin_verifier import OriginVerifier
            
            verifier = OriginVerifier(timeout=self.timeout)
            
            # Get list of candidate IPs
            candidate_ips = list(self._candidates.keys())
            
            logger.info(f"Verifying {len(candidate_ips)} candidates with OriginVerifier v7.0...")
            
            # Verify all candidates in parallel
            results = await verifier.verify_batch(
                candidates=candidate_ips,
                target_domain=original_host,
                baseline_hash=baseline_hash,
                max_concurrent=min(self.max_concurrent, 20)
            )
            
            # Update candidates with verification results
            for result in results:
                if result.ip in self._candidates:
                    candidate = self._candidates[result.ip]
                    
                    # Update candidate with verification data
                    candidate.response_status = result.https_status or result.http_status
                    candidate.server = result.server_header
                    candidate.body_hash = result.body_hash
                    candidate.verified = result.is_verified
                    candidate.response_match = result.is_verified
                    
                    # Update confidence based on verification
                    if result.is_verified:
                        candidate.confidence = 1.0
                        logger.info(f"[PASS] VERIFIED: {result.ip} - {result.reason}")
                    elif result.has_cf_headers or result.is_challenge_page:
                        # Discard CF IPs
                        candidate.confidence = 0.0
                        logger.debug(f"[FAIL] DISCARDED: {result.ip} - {result.reason}")
                    elif result.is_redirect:
                        # Redirect might be edge server
                        candidate.confidence = max(0.1, candidate.confidence - 0.3)
                        logger.debug(f"[WARN] REDIRECT: {result.ip} - {result.reason}")
                    else:
                        # Other failures
                        logger.debug(f"[FAIL] DISCARDED: {result.ip} - {result.reason}")
            
            verified_count = sum(1 for c in self._candidates.values() if c.verified)
            logger.info(f"Verification complete: {verified_count}/{len(candidate_ips)} verified")
            
        except ImportError as e:
            logger.warning(f"OriginVerifier not available, falling back to legacy verification: {e}")
            # Fallback to old method
            await self._verify_candidates_legacy(original_host, baseline_hash, baseline_status, baseline_size)
        except Exception as e:
            logger.error(f"Verification failed: {e}")
    
    async def _verify_candidates_legacy(self, original_host: str, baseline_hash: str,
                                  baseline_status: int, baseline_size: int):
        """Legacy verification method (fallback)."""
        sem = asyncio.Semaphore(self.max_concurrent)

        async def verify(candidate: OriginCandidate):
            async with sem:
                try:
                    from curl_cffi.requests import AsyncSession
                    for scheme in ["https", "http"]:
                        try:
                            url = f"{scheme}://{candidate.ip}/"
                            kwargs = {
                                "impersonate": "chrome120",
                                "timeout": self.timeout,
                                "headers": {"Host": original_host},
                                "verify": False,
                            }
                            async with AsyncSession(**kwargs) as sess:
                                resp = await sess.get(url, timeout=self.timeout, allow_redirects=False)
                                candidate.response_status = resp.status_code
                                candidate.server = resp.headers.get("server", "")

                                if resp.content:
                                    body = resp.content[:8192]
                                    candidate.body_hash = hashlib.md5(body).hexdigest()

                                if candidate.body_hash == baseline_hash and baseline_hash:
                                    candidate.verified = True
                                    candidate.response_match = True
                                    candidate.confidence = min(1.0, candidate.confidence + 0.7)
                                    return

                                size_diff = abs((len(resp.content) if resp.content else 0) - baseline_size)
                                if (resp.status_code == baseline_status and
                                    baseline_size > 0 and size_diff < baseline_size * 0.2):
                                    candidate.response_match = True
                                    candidate.confidence = min(1.0, candidate.confidence + 0.4)
                                    return

                                if resp.status_code in (200, 301, 302, 403, 401):
                                    candidate.confidence = min(1.0, candidate.confidence + 0.2)
                                return
                        except Exception:
                            continue
                except Exception:
                    pass

        await asyncio.gather(*[verify(c) for c in self._candidates.values()],
                             return_exceptions=True)

    def _is_cdn_ip(self, ip: str) -> bool:
        """Check if IP belongs to CDN (Cloudflare, Akamai, etc) using official ranges."""
        # Use official Cloudflare IP range checker
        try:
            from core.recon.filters.cf_ranges import is_cloudflare_ip
            if is_cloudflare_ip(ip):
                return True
        except Exception as e:
            logger.debug(f"CF range check failed, falling back to prefix: {e}")
            # Fallback to old prefix-based check
            for cf in self.CF_RANGES:
                if ip.startswith(cf):
                    return True
        
        # Check Akamai
        for ak in self.AKAMAI_RANGES:
            if ip.startswith(ak):
                return True
        
        return False

    def _is_valid_ip(self, ip: str) -> bool:
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            for p in parts:
                n = int(p)
                if n < 0 or n > 255:
                    return False
            if ip.startswith(("10.", "192.168.", "127.", "0.", "169.254.", "224.", "255.")):
                return False
            if ip.startswith("172."):
                second = int(ip.split(".")[1])
                if 16 <= second <= 31:
                    return False
            return True
        except Exception:
            return False

    # =
    # CLOUDFAIL INTEGRATION - DNSDumpster, Crimeflare, Subdomain Scan
    # =
    
    async def _hunt_dnsdumpster(self, host: str) -> List[str]:
        """DNSDumpster.com - Find subdomains and IPs not behind Cloudflare."""
        ips = []
        try:
            import requests
            from bs4 import BeautifulSoup
            
            url = "https://dnsdumpster.com/"
            session = requests.Session()
            
            # Get CSRF token
            resp = session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(resp.content, 'html.parser')
            csrf = soup.find('input', {'name': 'csrfmiddlewaretoken'})
            if not csrf:
                return ips
            
            csrf_token = csrf.get('value')
            
            # Submit search
            headers = {
                'Referer': url,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            data = {'csrfmiddlewaretoken': csrf_token, 'targetip': host, 'user': 'free'}
            cookies = {'csrftoken': csrf_token}
            
            resp = session.post(url, cookies=cookies, data=data, headers=headers, timeout=self.timeout)
            soup = BeautifulSoup(resp.content, 'html.parser')
            
            # Parse tables for DNS/MX/Host records
            tables = soup.findAll('table')
            for table in tables:
                rows = table.findAll('tr')
                for row in rows:
                    cols = row.findAll('td')
                    if len(cols) >= 2:
                        # Extract IP from second column
                        ip_text = cols[1].get_text()
                        ip_match = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ip_text)
                        for ip in ip_match:
                            if not self._is_cdn_ip(ip):
                                ips.append(ip)
        except Exception as e:
            logger.debug(f"DNSDumpster failed: {e}")
        return list(set(ips))
    
    async def _hunt_crimeflare(self, host: str) -> List[str]:
        """Crimeflare.com database - Historical Cloudflare bypass IPs."""
        ips = []
        try:
            import requests
            
            # Crimeflare database mirror
            url = "http://www.crimeflare.org:82/cfs.html"
            resp = requests.get(url, timeout=self.timeout)
            
            # Parse the database (format: domain IP)
            for line in resp.text.split('\n'):
                if host in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[1].strip()
                        if self._is_valid_ip(ip) and not self._is_cdn_ip(ip):
                            ips.append(ip)
        except Exception as e:
            logger.debug(f"Crimeflare failed: {e}")
        return list(set(ips))
    
    async def _hunt_subdomain_bruteforce(self, host: str, wordlist: Optional[List[str]] = None) -> List[str]:
        """Bruteforce common subdomains and check if they're not behind Cloudflare."""
        ips = []
        
        if not wordlist:
            # Top 50 common subdomains (reduced for speed)
            wordlist = [
                "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
                "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
                "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
                "ns3", "mail2", "new", "mysql", "old", "lists", "support", "mobile",
                "static", "docs", "beta", "shop", "secure", "demo", "cp", "wiki",
                "web", "media", "email", "images", "img", "www1", "portal", "video",
                "api", "cdn", "staging", "server"
            ]
        
        try:
            import socket
            
            async def check_subdomain(sub: str) -> Optional[str]:
                subdomain = f"{sub}.{host}"
                try:
                    loop = asyncio.get_event_loop()
                    ip = await loop.run_in_executor(None, socket.gethostbyname, subdomain)
                    if ip and not self._is_cdn_ip(ip):
                        return ip
                except Exception:
                    pass
                return None
            
            sem = asyncio.Semaphore(30)
            
            async def check_with_sem(sub: str):
                async with sem:
                    return await check_subdomain(sub)
            
            results = await asyncio.gather(*[check_with_sem(s) for s in wordlist], return_exceptions=True)
            ips = [r for r in results if r and isinstance(r, str)]
            
        except Exception as e:
            logger.debug(f"Subdomain bruteforce failed: {e}")
        
        return list(set(ips))
    
    async def _hunt_ipinfo(self, host: str) -> List[str]:
        """Hunt via ipinfo.io ASN lookup."""
        ips = []
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, socket.gethostbyname, host)
            if not self._is_cdn_ip(ip):
                ips.append(ip)
            import requests
            resp = await loop.run_in_executor(None, lambda: requests.get(f"https://ipinfo.io/{ip}/json", timeout=self.timeout))
            data = resp.json()
            org = data.get('org', '')
            logger.debug(f"ipinfo.io: {host} -> {ip} (ASN: {org})")
        except Exception as e:
            logger.debug(f"ipinfo.io failed: {e}")
        return list(set(ips))
    
    async def _hunt_bgpview(self, host: str) -> List[str]:
        """Hunt via BGPView API."""
        ips = []
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, socket.gethostbyname, host)
            import requests
            resp = await loop.run_in_executor(None, lambda: requests.get(f"https://api.bgpview.io/ip/{ip}", timeout=self.timeout))
            data = resp.json()
            if data.get('status') == 'ok' and not self._is_cdn_ip(ip):
                ips.append(ip)
        except Exception as e:
            logger.debug(f"BGPView failed: {e}")
        return list(set(ips))
    
    async def _hunt_viewdns(self, host: str) -> List[str]:
        """Hunt via ViewDNS.info IP history."""
        ips = []
        try:
            import requests
            url = f"https://viewdns.info/iphistory/?domain={host}"
            headers = {'User-Agent': 'Mozilla/5.0'}
            resp = requests.get(url, headers=headers, timeout=self.timeout)
            import re
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            found_ips = re.findall(ip_pattern, resp.text)
            for ip in found_ips:
                if self._is_valid_ip(ip) and not self._is_cdn_ip(ip):
                    ips.append(ip)
        except Exception as e:
            logger.debug(f"ViewDNS failed: {e}")
        return list(set(ips))
    
    async def _hunt_netcraft(self, host: str) -> List[str]:
        """Hunt via Netcraft site report."""
        ips = []
        try:
            import requests
            url = f"https://sitereport.netcraft.com/?url={host}"
            headers = {'User-Agent': 'Mozilla/5.0'}
            resp = requests.get(url, headers=headers, timeout=self.timeout)
            import re
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            found_ips = re.findall(ip_pattern, resp.text)
            for ip in found_ips:
                if self._is_valid_ip(ip) and not self._is_cdn_ip(ip):
                    ips.append(ip)
        except Exception as e:
            logger.debug(f"Netcraft failed: {e}")
        return list(set(ips))
    
    def load_cached_origins(self, target: str) -> Optional[HuntReport]:
        """Load previously saved origin hunt results from output/origins/{target}/"""
        parsed = urlparse(target if target.startswith('http') else f'https://{target}')
        host = parsed.hostname or re.sub(r'[^a-z0-9.-]', '_', target.lower())
        safe_host = re.sub(r'[^a-z0-9.-]', '_', host)
        
        output_path = Path(self._output_dir) / safe_host / "report.json"
        
        if not output_path.exists():
            return None
        
        try:
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            report = HuntReport(target=data.get('target', target))
            report.elapsed_seconds = data.get('elapsed_seconds', 0)
            report.target_baseline_hash = data.get('baseline', {}).get('hash', '')
            report.target_baseline_status = data.get('baseline', {}).get('status', 0)
            report.target_baseline_size = data.get('baseline', {}).get('size', 0)
            report.sources_hit = data.get('summary', {}).get('sources_hit', [])
            
            for c_data in data.get('verified_origins', []) + data.get('top_candidates', []):
                candidate = OriginCandidate(
                    ip=c_data.get('ip', ''),
                    confidence=c_data.get('confidence', 0.0),
                    source=c_data.get('source', 'cached'),
                    verified=c_data.get('verified', False),
                    response_match=c_data.get('response_match', False),
                    response_status=c_data.get('response_status', 0),
                    server=c_data.get('server', ''),
                    body_hash=c_data.get('body_hash', ''),
                    discovery_method=c_data.get('discovery_method', 'cached'),
                )
                if candidate.ip not in [c.ip for c in report.candidates]:
                    report.candidates.append(candidate)
            
            report.verified_origins = [c.ip for c in report.candidates if c.verified]
            
            logger.info(f"Loaded cached origins for {host}: {len(report.verified_origins)} verified")
            return report
            
        except Exception as e:
            logger.debug(f"Failed to load cached origins: {e}")
            return None
    
    def is_cloudflare_ip(self, ip: str) -> bool:
        """Check if IP is in Cloudflare range (public method)."""
        return self._is_cdn_ip(ip)
    
    def validate_origin_ip(self, ip: str, target_host: str) -> Dict[str, Any]:
        """Validate if an IP is a real origin (not CDN)."""
        result = {
            'ip': ip,
            'is_cloudflare': any(ip.startswith(r) for r in self.CF_RANGES),
            'is_akamai': any(ip.startswith(r) for r in self.AKAMAI_RANGES),
            'is_cdn': False,
            'is_origin': False,
            'response_status': 0,
            'server': '',
            'error': None,
        }
        
        result['is_cdn'] = result['is_cloudflare'] or result['is_akamai']
        result['is_origin'] = not result['is_cdn']
        
        try:
            import requests
            url = f"https://{ip}"
            headers = {'Host': target_host, 'User-Agent': 'Mozilla/5.0'}
            resp = requests.get(url, headers=headers, timeout=5, verify=False)
            result['response_status'] = resp.status_code
            result['server'] = resp.headers.get('Server', '')
            
            if resp.status_code in (200, 301, 302, 403):
                result['is_origin'] = True
        except Exception as e:
            result['error'] = str(e)
        
        return result


class WafBypassHunter:
    """Specifically targets WAF-bypass discovery methods to find origin IP"""

    def __init__(self, timeout: int = 10, output_dir: Optional[str] = None):
        self.timeout = timeout
        self._output_dir = output_dir or os.path.join("output", "origins")
        self._candidates: List[OriginCandidate] = []

    async def hunt(self, target: str, env: Optional[Dict] = None) -> HuntReport:
        """Run WAF bypass techniques only"""
        start = time.time()

        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        parsed = urlparse(target)
        host = parsed.hostname or ""
        env = env or {}

        report = HuntReport(target=target)

        baseline = await self._fetch_baseline(target)
        if baseline:
            report.target_baseline_hash = baseline["hash"]
            report.target_baseline_status = baseline["status"]
            report.target_baseline_size = baseline["size"]

        bypass_hunter = OriginHunter(timeout=self.timeout)

        # Run only WAF bypass methods
        tasks = [
            bypass_hunter._hunt_health_endpoints(host),
            bypass_hunter._hunt_acme_validation(host),
            bypass_hunter._hunt_xforwarded_bypass(host),
            bypass_hunter._hunt_cdn_misconfig(host),
        ]
        source_names = [
            "health_endpoints",
            "acme_validation",
            "xforwarded_bypass",
            "cdn_misconfig",
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, r in enumerate(results):
            source_name = source_names[i]
            if isinstance(r, list) and r:
                report.sources_hit.append(f"{source_name}:{len(r)}")
                for ip in r:
                    if ip and bypass_hunter._is_valid_ip(ip) and not bypass_hunter._is_cdn_ip(ip):
                        cand = OriginCandidate(ip=ip, source=source_name, confidence=0.5,
                                                discovery_method=source_name)
                        if cand not in self._candidates:
                            self._candidates.append(cand)

        # Verify candidates
        if self._candidates and report.target_baseline_hash:
            self._candidates = await self._verify_candidates(
                host, report.target_baseline_hash,
                report.target_baseline_status, report.target_baseline_size,
                self._candidates
            )

        self._candidates.sort(key=lambda c: (-int(c.verified), -int(c.response_match), -c.confidence))
        report.candidates = self._candidates[:30]
        report.verified_origins = [c.ip for c in self._candidates if c.verified][:10]
        report.waf_bypass_results = report.candidates
        report.elapsed_seconds = round(time.time() - start, 2)

        return report

    async def _fetch_baseline(self, target: str) -> Optional[Dict]:
        try:
            from curl_cffi.requests import AsyncSession
            kwargs = {"impersonate": "chrome120", "timeout": self.timeout}
            async with AsyncSession(**kwargs) as sess:
                resp = await sess.get(target, timeout=self.timeout, allow_redirects=False)
                content = resp.content[:8192] if resp.content else b""
                return {
                    "hash": hashlib.md5(content).hexdigest(),
                    "status": resp.status_code,
                    "size": len(resp.content) if resp.content else 0,
                    "server": resp.headers.get("server", ""),
                }
        except Exception:
            return None

    async def _verify_candidates(self, original_host: str, baseline_hash: str,
                                  baseline_status: int, baseline_size: int,
                                  candidates: List[OriginCandidate]) -> List[OriginCandidate]:
        sem = asyncio.Semaphore(50)

        async def verify(candidate: OriginCandidate):
            async with sem:
                try:
                    from curl_cffi.requests import AsyncSession
                    for scheme in ["https", "http"]:
                        try:
                            url = f"{scheme}://{candidate.ip}/"
                            kwargs = {
                                "impersonate": "chrome120",
                                "timeout": self.timeout,
                                "headers": {"Host": original_host},
                                "verify": False,
                            }
                            async with AsyncSession(**kwargs) as sess:
                                resp = await sess.get(url, timeout=self.timeout, allow_redirects=False)
                                candidate.response_status = resp.status_code
                                candidate.server = resp.headers.get("server", "")
                                if resp.content:
                                    body = resp.content[:8192]
                                    candidate.body_hash = hashlib.md5(body).hexdigest()

                                if candidate.body_hash == baseline_hash and baseline_hash:
                                    candidate.verified = True
                                    candidate.response_match = True
                                    candidate.confidence = min(1.0, candidate.confidence + 0.7)
                                    return

                                size_diff = abs((len(resp.content) if resp.content else 0) - baseline_size)
                                if (resp.status_code == baseline_status and
                                    baseline_size > 0 and size_diff < baseline_size * 0.2):
                                    candidate.response_match = True
                                    candidate.confidence = min(1.0, candidate.confidence + 0.4)
                                    return

                                if resp.status_code in (200, 301, 302, 403, 401):
                                    candidate.confidence = min(1.0, candidate.confidence + 0.2)
                                return
                        except Exception:
                            continue
                except Exception:
                    pass

        await asyncio.gather(*[verify(c) for c in candidates], return_exceptions=True)
        return candidates

    # =
    # CLOUDFAIL INTEGRATION - DNSDumpster, Crimeflare, Subdomain Scan
    # =
    
    async def _hunt_dnsdumpster(self, host: str) -> List[str]:
        """DNSDumpster.com - Find subdomains and IPs not behind Cloudflare."""
        ips = []
        try:
            import requests
            from bs4 import BeautifulSoup
            
            url = "https://dnsdumpster.com/"
            session = requests.Session()
            
            # Get CSRF token
            resp = session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(resp.content, 'html.parser')
            csrf = soup.find('input', {'name': 'csrfmiddlewaretoken'})
            if not csrf:
                return ips
            
            csrf_token = csrf.get('value')
            
            # Submit search
            headers = {
                'Referer': url,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            data = {'csrfmiddlewaretoken': csrf_token, 'targetip': host, 'user': 'free'}
            cookies = {'csrftoken': csrf_token}
            
            resp = session.post(url, cookies=cookies, data=data, headers=headers, timeout=self.timeout)
            soup = BeautifulSoup(resp.content, 'html.parser')
            
            # Parse tables for DNS/MX/Host records
            tables = soup.findAll('table')
            for table in tables:
                rows = table.findAll('tr')
                for row in rows:
                    cols = row.findAll('td')
                    if len(cols) >= 2:
                        # Extract IP from second column
                        ip_text = cols[1].get_text()
                        ip_match = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ip_text)
                        for ip in ip_match:
                            if not self._is_cdn_ip(ip):
                                ips.append(ip)
        except Exception as e:
            logger.debug(f"DNSDumpster failed: {e}")
        return list(set(ips))
    
    async def _hunt_crimeflare(self, host: str) -> List[str]:
        """Crimeflare.com database - Historical Cloudflare bypass IPs."""
        ips = []
        try:
            import requests
            
            # Crimeflare database mirror
            url = "http://www.crimeflare.org:82/cfs.html"
            resp = requests.get(url, timeout=self.timeout)
            
            # Parse the database (format: domain IP)
            for line in resp.text.split('\n'):
                if host in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[1].strip()
                        if self._is_valid_ip(ip) and not self._is_cdn_ip(ip):
                            ips.append(ip)
        except Exception as e:
            logger.debug(f"Crimeflare failed: {e}")
        return list(set(ips))
    
    async def _hunt_subdomain_bruteforce(self, host: str, wordlist: Optional[List[str]] = None) -> List[str]:
        """Bruteforce common subdomains and check if they're not behind Cloudflare."""
        ips = []
        
        if not wordlist:
            # Top 100 common subdomains
            wordlist = [
                "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
                "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
                "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
                "ns3", "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx",
                "static", "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar",
                "wiki", "web", "media", "email", "images", "img", "www1", "intranet",
                "portal", "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4",
                "www3", "dns", "search", "staging", "server", "mx1", "chat", "wap", "my",
                "svn", "mail1", "sites", "proxy", "ads", "host", "crm", "cms", "backup",
                "mx2", "lyncdiscover", "info", "apps", "download", "remote", "db", "forums",
                "store", "relay", "files", "newsletter", "app", "live", "owa", "en", "start",
                "sms", "office", "exchange", "ipv4"
            ]
        
        try:
            import socket
            import asyncio
            
            async def check_subdomain(sub: str) -> Optional[str]:
                subdomain = f"{sub}.{host}"
                try:
                    # Resolve DNS
                    loop = asyncio.get_event_loop()
                    ip = await loop.run_in_executor(None, socket.gethostbyname, subdomain)
                    
                    # Check if not behind Cloudflare
                    if ip and not self._is_cdn_ip(ip):
                        return ip
                except Exception:
                    pass
                return None
            
            # Limit concurrent checks
            sem = asyncio.Semaphore(50)
            
            async def check_with_sem(sub: str):
                async with sem:
                    return await check_subdomain(sub)
            
            results = await asyncio.gather(*[check_with_sem(s) for s in wordlist], return_exceptions=True)
            ips = [r for r in results if r and isinstance(r, str)]
            
        except Exception as e:
            logger.debug(f"Subdomain bruteforce failed: {e}")
        
        return list(set(ips))
    
    def load_cached_origins(self, target: str) -> Optional[HuntReport]:
        """Load previously saved origin hunt results from output/origins/{target}/"""
        parsed = urlparse(target if target.startswith('http') else f'https://{target}')
        host = parsed.hostname or re.sub(r'[^a-z0-9.-]', '_', target.lower())
        safe_host = re.sub(r'[^a-z0-9.-]', '_', host)
        
        output_path = Path(self._output_dir) / safe_host / "report.json"
        
        if not output_path.exists():
            return None
        
        try:
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            # Reconstruct HuntReport
            report = HuntReport(target=data.get('target', target))
            report.elapsed_seconds = data.get('elapsed_seconds', 0)
            report.target_baseline_hash = data.get('baseline', {}).get('hash', '')
            report.target_baseline_status = data.get('baseline', {}).get('status', 0)
            report.target_baseline_size = data.get('baseline', {}).get('size', 0)
            report.sources_hit = data.get('summary', {}).get('sources_hit', [])
            
            # Reconstruct candidates
            for c_data in data.get('verified_origins', []) + data.get('top_candidates', []):
                candidate = OriginCandidate(
                    ip=c_data.get('ip', ''),
                    confidence=c_data.get('confidence', 0.0),
                    source=c_data.get('source', 'cached'),
                    verified=c_data.get('verified', False),
                    response_match=c_data.get('response_match', False),
                    response_status=c_data.get('response_status', 0),
                    server=c_data.get('server', ''),
                    body_hash=c_data.get('body_hash', ''),
                    discovery_method=c_data.get('discovery_method', 'cached'),
                )
                if candidate.ip not in [c.ip for c in report.candidates]:
                    report.candidates.append(candidate)
            
            report.verified_origins = [c.ip for c in report.candidates if c.verified]
            
            logger.info(f"Loaded cached origins for {host}: {len(report.verified_origins)} verified, {len(report.candidates)} candidates")
            return report
            
        except Exception as e:
            logger.debug(f"Failed to load cached origins: {e}")
            return None
    
    def is_cloudflare_ip(self, ip: str) -> bool:
        """Check if IP is in Cloudflare range (public method for external use)."""
        return self._is_cdn_ip(ip)
    
    def validate_origin_ip(self, ip: str, target_host: str) -> Dict[str, Any]:
        """
        Validate if an IP is a real origin (not CDN).
        Returns dict with: is_origin, is_cloudflare, is_akamai, response_status
        """
        result = {
            'ip': ip,
            'is_cloudflare': any(ip.startswith(r) for r in self.CF_RANGES),
            'is_akamai': any(ip.startswith(r) for r in self.AKAMAI_RANGES),
            'is_cdn': False,
            'is_origin': False,
            'response_status': 0,
            'server': '',
            'error': None,
        }
        
        result['is_cdn'] = result['is_cloudflare'] or result['is_akamai']
        result['is_origin'] = not result['is_cdn']
        
        # Try to connect and verify
        try:
            import requests
            url = f"https://{ip}"
            headers = {'Host': target_host, 'User-Agent': 'Mozilla/5.0'}
            resp = requests.get(url, headers=headers, timeout=5, verify=False)
            result['response_status'] = resp.status_code
            result['server'] = resp.headers.get('Server', '')
            
            if resp.status_code in (200, 301, 302, 403):
                result['is_origin'] = True
        except Exception as e:
            result['error'] = str(e)
        
        return result


def print_hunt_report(report: HuntReport, color_func=None):
    # Lazy import to avoid circular import
    try:
        from main import _RICH_CONSOLE
        from rich.panel import Panel
        from rich.table import Table
        from rich import box
    except (ImportError, AttributeError):
        # Fallback to plain text if Rich import fails
        c = color_func if color_func else lambda t, s: s
        print(f"\n {c('c','='*70)}")
        print(f" {c('w','  ORIGIN HUNTER REPORT')}")
        print(f" {c('c','='*70)}")
        print(f"  Target:           {report.target}")
        print(f"  Verified origins: {c('g',str(len(report.verified_origins)))}")
        print(f"  Total candidates: {len(report.candidates)}")
        print(f" {c('c','='*70)}\n")
        return

    _RICH_CONSOLE.print()
    _RICH_CONSOLE.print(Panel(
        f"[bold white]Target:[/]           {report.target}\n"
        f"[bold white]Baseline status:[/]  {report.target_baseline_status}\n"
        f"[bold white]Baseline size:[/]    {report.target_baseline_size} bytes\n"
        f"[bold white]Sources hit:[/]      {', '.join(report.sources_hit) or 'none'}\n"
        f"[bold white]Total candidates:[/] {len(report.candidates)}\n"
        f"[bold white]Verified origins:[/] [green]{len(report.verified_origins)}[/]\n"
        f"[bold white]Hunt duration:[/]    {report.elapsed_seconds}s",
        title="[bold cyan]ORIGIN HUNTER REPORT[/]",
        border_style="cyan", box=box.HEAVY
    ))

    if report.waf_bypass_results:
        waf_table = Table(box=box.SIMPLE, header_style="bold magenta")
        waf_table.add_column("IP", style="bold magenta", width=20)
        waf_table.add_column("Method")
        waf_table.add_column("Confidence", justify="right")
        waf_table.add_column("Status")
        for cand in report.waf_bypass_results[:10]:
            tag = "[green]VERIFIED[/]" if cand.verified else "[yellow]CANDIDATE[/]"
            waf_table.add_row(cand.ip, cand.discovery_method, f"{cand.confidence:.0%}", tag)
        _RICH_CONSOLE.print(Panel(waf_table, title="[bold magenta]WAF BYPASS RESULTS[/]", border_style="magenta"))

    _RICH_CONSOLE.rule(style="dim")

    if report.verified_origins:
        vo_table = Table(box=box.SIMPLE, header_style="bold green")
        vo_table.add_column("IP", style="bold green", width=20)
        vo_table.add_column("Status")
        vo_table.add_column("Server")
        vo_table.add_column("Source")
        for ip in report.verified_origins:
            cand = next((c for c in report.candidates if c.ip == ip), None)
            if cand:
                vo_table.add_row(ip, str(cand.response_status), cand.server, cand.source)
        _RICH_CONSOLE.print(Panel(vo_table, title="[bold green]VERIFIED ORIGINS[/]", border_style="green"))
        _RICH_CONSOLE.rule(style="dim")

    cand_table = Table(box=box.SIMPLE, header_style="bold yellow")
    cand_table.add_column("#", justify="right", width=3)
    cand_table.add_column("IP", style="bold white", width=20)
    cand_table.add_column("Confidence", justify="right")
    cand_table.add_column("Status")
    cand_table.add_column("Source")
    cand_table.add_column("Tag")
    for i, cand in enumerate(report.candidates[:15], 1):
        if cand.verified:
            tag = "[green]VERIFIED[/]"
        elif cand.response_match:
            tag = "[yellow]LIKELY[/]"
        else:
            tag = "[dim]candidate[/]"
        cand_table.add_row(str(i), cand.ip, f"{cand.confidence:.0%}",
                          str(cand.response_status), cand.source, tag)
    _RICH_CONSOLE.print(Panel(cand_table, title="[bold yellow]TOP CANDIDATES[/]", border_style="yellow"))
