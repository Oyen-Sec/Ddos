import asyncio
import logging
import socket
import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple
from urllib.parse import urlparse, urljoin

logger = logging.getLogger("intel_engine")

CMS_SIGS = {
    "WordPress": {"/wp-includes/wlwmanifest.xml", "/wp-json/wp/v2/", "/wp-content/plugins/", "/xmlrpc.php"},
    "Joomla": {"/administrator/", "/media/system/js/", "/templates/"},
    "Drupal": {"/misc/drupal.js", "/sites/default/", "/core/"},
    "Magento": {"/skin/frontend/", "/js/mage/", "/static/version/"},
    "Laravel": {"/api/", "/_debugbar/"},
}

WAF_SIGS = {
    "Cloudflare": {"headers": {"cf-ray", "server"}, "body": {"attention required", "cloudflare", "cf-browser-verification"}, "cookies": {"__cfduid", "__cf_bm", "cf_clearance"}},
    "Sucuri": {"headers": {"x-sucuri-id"}, "body": {"sucuri website firewall"}},
    "Akamai": {"headers": {"x-akamai-transformed"}, "body": {"akamai"}},
    "AWS_WAF": {"headers": {"x-amz-cf-id"}, "body": {"aws waf"}},
    "DDoS-Guard": {"headers": {"server: ddos-guard"}, "body": {"ddos-guard"}},
}

ENDPOINTS = ["/", "/login", "/admin", "/wp-admin", "/api/", "/xmlrpc.php", "/robots.txt",
             "/.env", "/sitemap.xml", "/wp-json/", "/phpmyadmin/", "/backup/"]

ENDPOINT_WEIGHTS = {"/admin": 10, "/wp-admin": 10, "/login": 9, "/api/": 7, "/.env": 9, "/phpmyadmin/": 9}


@dataclass
class TargetProfile:
    url: str
    cms: str = "Unknown"
    cms_conf: float = 0.0
    waf: str = "None"
    waf_conf: float = 0.0
    server: str = ""
    rtt_ms: float = 0.0
    is_alive: bool = False
    ip: str = ""
    origin_ips: List[str] = field(default_factory=list)
    is_behind_cdn: bool = False
    top_endpoints: List[tuple] = field(default_factory=list)


class TargetAnalyzer:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def _req(self, url: str, path: str) -> Tuple[int, float, Dict, str]:
        import time
        full = urljoin(url, path)
        try:
            from curl_cffi.requests import Session
            sess = Session(impersonate="chrome120", timeout=self.timeout)
            start = time.monotonic()
            resp = sess.get(full, timeout=self.timeout, allow_redirects=True)
            el = round((time.monotonic() - start) * 1000, 2)
            sess.close()
            return resp.status_code, el, dict(resp.headers), resp.text[:5000]
        except Exception:
            try:
                import requests as req
                start = time.monotonic()
                resp = req.get(full, timeout=self.timeout, verify=False, headers={"User-Agent": "Mozilla/5.0"})
                el = round((time.monotonic() - start) * 1000, 2)
                return resp.status_code, el, dict(resp.headers), resp.text[:5000]
            except Exception:
                return 0, 0, {}, ""

    def detect_cms(self, url: str) -> Tuple[str, float]:
        scores = {}
        for name, paths in CMS_SIGS.items():
            score = 0
            for p in paths:
                st, el, hd, body = self._req(url, p)
                if st in (200, 301, 302, 403):
                    score += 1
                    if st == 200:
                        score += 1
                    if name == "WordPress" and p == "/xmlrpc.php" and "XML-RPC" in body:
                        score += 2
            meta = body.lower() if body else ""
            if name.lower() in meta:
                score += 2
            for k, v in hd.items():
                if name.lower() in v.lower():
                    score += 2
            scores[name] = score / max(len(paths), 1) * 20
        if not scores:
            return "Unknown", 0
        best = max(scores, key=scores.get)
        best_s = scores[best]
        if best_s < 15:
            return "Generic", best_s
        return best, round(best_s, 1)

    def detect_waf(self, url: str) -> Tuple[str, float]:
        st, el, hd, body = self._req(url, "/")
        bl = body.lower()
        detected = {}
        for name, sig in WAF_SIGS.items():
            s = 0
            for h in sig["headers"]:
                for k in hd:
                    combined = f"{k.lower()}: {hd[k].lower()}"
                    if h in combined:
                        s += 2
            for b in sig["body"]:
                if b in bl:
                    s += 2
            for c in sig.get("cookies", set()):
                if c in str(hd).lower():
                    s += 2
            if s > 0:
                detected[name] = s
        if not detected:
            return "None", 0
        best = max(detected, key=detected.get)
        return best, round(detected[best] / 6 * 100, 1)

    def rank_endpoints(self, url: str) -> List[tuple]:
        eps = []
        for path in ENDPOINTS:
            st, el, _, _ = self._req(url, path)
            w = ENDPOINT_WEIGHTS.get(path, 1)
            score = (1.0 / max(el, 1)) * w * 10 if st > 0 else 0
            if st in (200, 301, 302):
                score *= 1.5
            eps.append((path, st, el, round(score, 2)))
        eps.sort(key=lambda e: e[3], reverse=True)
        return eps

    def discover_origin(self, url: str) -> Tuple[str, List[str], bool]:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        ips = []
        is_cdn = False
        try:
            ips = list(set(socket.gethostbyname_ex(host)[2]))
            if ips:
                try:
                    rev = socket.gethostbyaddr(ips[0])[0].lower()
                    if any(c in rev for c in ["cloudflare", "akamai", "fastly", "incapsula"]):
                        is_cdn = True
                except Exception:
                    pass
        except Exception:
            pass
        try:
            import subprocess
            r = subprocess.run(["nslookup", host], capture_output=True, text=True, timeout=5)
            for line in r.stdout.split("\n"):
                if "Address:" in line or "Addresses:" in line:
                    for p in line.split():
                        if re.match(r'^\d+\.\d+\.\d+\.\d+$', p):
                            ips.append(p)
        except Exception:
            pass
        ips = list(set(ips))
        return ips[0] if ips else "", ips, is_cdn

    def discover_origin_crtsh(self, domain: str) -> List[str]:
        ips = []
        try:
            import urllib.request
            import json
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                seen = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for n in name.split("\n"):
                        if n.endswith(domain) and "*" not in n:
                            try:
                                addrs = socket.gethostbyname_ex(n.strip())[2]
                                for a in addrs:
                                    if a not in seen:
                                        seen.add(a)
                                        ips.append(a)
                            except Exception:
                                pass
        except Exception:
            pass
        return ips

    def analyze(self, url: str) -> TargetProfile:
        profile = TargetProfile(url=url)
        parsed = urlparse(url)
        if not parsed.scheme:
            url = "https://" + url
            parsed = urlparse(url)
        st, el, hd, body = self._req(url, "/")
        if st > 0:
            profile.is_alive = True
            profile.rtt_ms = el
            profile.server = hd.get("Server", hd.get("server", ""))
        profile.cms, profile.cms_conf = self.detect_cms(url)
        profile.waf, profile.waf_conf = self.detect_waf(url)
        profile.top_endpoints = self.rank_endpoints(url)[:5]
        ip, ips, is_cdn = self.discover_origin(url)
        profile.ip = ip
        profile.origin_ips = ips
        profile.is_behind_cdn = is_cdn or profile.waf != "None"
        if profile.is_behind_cdn:
            extra = self.discover_origin_crtsh(parsed.hostname or "")
            for e in extra:
                if e not in profile.origin_ips:
                    profile.origin_ips.append(e)
        logger.info("Target: %s CMS=%s(%.0f%%) WAF=%s(%.0f%%) IP=%s CDN=%s",
                    url, profile.cms, profile.cms_conf, profile.waf, profile.waf_conf,
                    profile.ip, profile.is_behind_cdn)
        return profile
