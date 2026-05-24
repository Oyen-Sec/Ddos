"""
Aggressive Origin IP Hunter v2.0
Multi-source parallel hunting: scrapes 8+ sources simultaneously
Validates by sending Host header check to each candidate
"""
import asyncio
import re
import hashlib
import socket
import ssl
import logging
import json
from typing import List, Set, Dict, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse

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


class OriginHunter:
    """Aggressive origin IP hunter using 8+ parallel sources"""

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

    def __init__(self, timeout: int = 8, max_concurrent: int = 100):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self._candidates: Dict[str, OriginCandidate] = {}

    async def hunt(self, target: str, env: Optional[Dict] = None) -> HuntReport:
        """Launch all hunting techniques in parallel"""
        import time
        start = time.time()

        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        parsed = urlparse(target)
        host = parsed.hostname or ""

        report = HuntReport(target=target)

        baseline = await self._fetch_baseline(target)
        if baseline:
            report.target_baseline_hash = baseline["hash"]
            report.target_baseline_status = baseline["status"]
            report.target_baseline_size = baseline["size"]

        env = env or {}

        # Launch ALL hunters in parallel
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
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, r in enumerate(results):
            if isinstance(r, list):
                source_name = ["crt.sh", "hackertarget", "threatcrowd", "dnshistory",
                               "subdomain", "mx", "favicon", "censys", "shodan",
                               "securitytrails", "zoomeye"][i]
                if r:
                    report.sources_hit.append(f"{source_name}:{len(r)}")
                for ip in r:
                    if ip and self._is_valid_ip(ip) and not self._is_cdn_ip(ip):
                        if ip not in self._candidates:
                            self._candidates[ip] = OriginCandidate(ip=ip, source=source_name, confidence=0.3)
                        else:
                            self._candidates[ip].confidence += 0.15
                            if source_name not in self._candidates[ip].source:
                                self._candidates[ip].source += "+" + source_name
            elif isinstance(r, Exception):
                logger.debug(f"Hunter {i} failed: {r}")

        # Verify all candidates by sending Host header check
        if self._candidates and report.target_baseline_hash:
            await self._verify_candidates(host, report.target_baseline_hash,
                                          report.target_baseline_status,
                                          report.target_baseline_size)

        # Sort by confidence + verified
        candidates = list(self._candidates.values())
        candidates.sort(key=lambda c: (-int(c.verified), -int(c.response_match), -c.confidence))
        report.candidates = candidates[:50]
        report.verified_origins = [c.ip for c in candidates if c.verified][:10]

        report.elapsed_seconds = round(time.time() - start, 2)

        # Auto-save to origin store
        try:
            from core.recon.origin_store import save_hunt
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

    async def _hunt_crtsh(self, host: str) -> List[str]:
        """Scrape Certificate Transparency logs - finds historical certs"""
        try:
            from curl_cffi.requests import AsyncSession
            kwargs = {"impersonate": "chrome120", "timeout": 15}
            async with AsyncSession(**kwargs) as sess:
                # Get all subdomains from crt.sh
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

                # Resolve all subdomains in parallel
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
                # Subdomain search
                resp = await sess.get(f"https://api.hackertarget.com/hostsearch/?q={host}", timeout=10)
                if resp.status_code == 200 and resp.text:
                    for line in resp.text.split("\n"):
                        if "," in line:
                            parts = line.split(",")
                            if len(parts) >= 2:
                                ip = parts[1].strip()
                                if self._is_valid_ip(ip):
                                    ips.append(ip)

                # Reverse DNS
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
                # Try viewdns.info
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
                # Without API, we can't search by hash - log only
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
        if not key:
            return []
        try:
            from curl_cffi.requests import AsyncSession
            kwargs = {"impersonate": "chrome120", "timeout": 15}
            async with AsyncSession(**kwargs) as sess:
                # Search by hostname
                resp = await sess.get(
                    f"https://api.shodan.io/shodan/host/search?key={key}&query=hostname:{host}",
                    timeout=15
                )
                if resp.status_code != 200:
                    return []
                data = resp.json()
                ips = []
                for m in data.get("matches", [])[:50]:
                    ip = m.get("ip_str")
                    if ip and self._is_valid_ip(ip):
                        ips.append(ip)
                return ips
        except Exception as e:
            logger.debug(f"shodan failed: {e}")
            return []

    async def _hunt_securitytrails(self, host: str, key: Optional[str]) -> List[str]:
        if not key:
            return []
        try:
            from curl_cffi.requests import AsyncSession
            kwargs = {"impersonate": "chrome120", "timeout": 15,
                      "headers": {"APIKEY": key}}
            async with AsyncSession(**kwargs) as sess:
                resp = await sess.get(
                    f"https://api.securitytrails.com/v1/history/{host}/dns/a",
                    timeout=15
                )
                if resp.status_code != 200:
                    return []
                data = resp.json()
                ips = []
                for record in data.get("records", [])[:30]:
                    for v in record.get("values", []):
                        ip = v.get("ip", "")
                        if self._is_valid_ip(ip):
                            ips.append(ip)
                return ips
        except Exception as e:
            logger.debug(f"securitytrails failed: {e}")
            return []

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
        """Send Host header to each candidate, compare response with baseline"""
        sem = asyncio.Semaphore(self.max_concurrent)

        async def verify(candidate: OriginCandidate):
            async with sem:
                try:
                    from curl_cffi.requests import AsyncSession
                    # Try HTTPS first
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

                                # Match: same baseline = origin
                                if candidate.body_hash == baseline_hash and baseline_hash:
                                    candidate.verified = True
                                    candidate.response_match = True
                                    candidate.confidence = min(1.0, candidate.confidence + 0.7)
                                    return
                                # Partial match: status matches and size close
                                size_diff = abs((len(resp.content) if resp.content else 0) - baseline_size)
                                if (resp.status_code == baseline_status and
                                    baseline_size > 0 and size_diff < baseline_size * 0.2):
                                    candidate.response_match = True
                                    candidate.confidence = min(1.0, candidate.confidence + 0.4)
                                    return

                                # Got SOMETHING - 200/301/302/403 = real server (not just CF rejection)
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
        for cf in self.CF_RANGES:
            if ip.startswith(cf):
                return True
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
            # Skip private ranges
            if ip.startswith(("10.", "192.168.", "127.", "0.", "169.254.", "224.", "255.")):
                return False
            if ip.startswith("172."):
                second = int(ip.split(".")[1])
                if 16 <= second <= 31:
                    return False
            return True
        except Exception:
            return False


def print_hunt_report(report: HuntReport, color_func=None):
    c = color_func if color_func else lambda t, s: s
    print(f"\n {c('c','='*70)}")
    print(f" {c('w','  ORIGIN HUNTER REPORT')}")
    print(f" {c('c','='*70)}")
    print(f"  Target:           {report.target}")
    print(f"  Baseline status:  {report.target_baseline_status}")
    print(f"  Baseline size:    {report.target_baseline_size} bytes")
    print(f"  Sources hit:      {', '.join(report.sources_hit) or 'none'}")
    print(f"  Total candidates: {len(report.candidates)}")
    print(f"  Verified origins: {c('g',str(len(report.verified_origins)))}")
    print(f"  Hunt duration:    {report.elapsed_seconds}s")
    print(f" {c('d','-'*70)}")

    if report.verified_origins:
        print(f"  {c('g','VERIFIED ORIGINS (response matches CDN baseline):')}")
        for ip in report.verified_origins:
            cand = next((c for c in report.candidates if c.ip == ip), None)
            if cand:
                print(f"    {c('g',ip):20s}  status={cand.response_status} server={cand.server} src={cand.source}")
        print(f" {c('d','-'*70)}")

    print(f"  {c('y','TOP CANDIDATES (by confidence):')}")
    for i, cand in enumerate(report.candidates[:15], 1):
        tag = c('g','VERIFIED') if cand.verified else (c('y','LIKELY') if cand.response_match else c('d','candidate'))
        print(f"    {i:2}. {c('w',cand.ip):20s}  conf={cand.confidence:.0%}  status={cand.response_status}  src={cand.source}  [{tag}]")
    print(f" {c('c','='*70)}\n")
