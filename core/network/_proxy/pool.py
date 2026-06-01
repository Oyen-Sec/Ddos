import asyncio
import time
import random
import logging
import re
import sqlite3
import os
import threading
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Any
from urllib.parse import urlparse
from contextlib import contextmanager

from core.network.flaresolverr_client import flaresolverr_client, CookieStore, BrowserSessionPool, FlareSolverrClient
from core.network.flaresolverr_client import FlareSolverrError
from core.network._tls.fingerprint import TLSFingerprintGenerator
from core.network.http2_impersonator import get_random_profile

logger = logging.getLogger("proxy_engine")

PROXY_TIERS = {
    "mobile": 1,
    "residential": 2,
    "ipv6": 3,
    "datacenter": 4,
    "premium": 0,
}

@dataclass
class ProxyStatus:
    url: str
    protocol: str
    host: str
    port: int
    alive: bool = False
    tier: str = "datacenter"
    connect_time_ms: float = 0.0
    external_ip: str = ""
    last_checked: float = 0.0
    fail_count: int = 0
    success_count: int = 0
    rtt_ema: float = 0.0
    tls_handshake_ms: float = 0.0
    last_used: float = 0.0
    request_count: int = 0
    ja3_hash: str = ""
    tls_profile: str = ""
    cf_session_id: str = ""
    premium: bool = False

class ProxyValidator:
    def __init__(self, check_url: str = "https://httpbin.org/ip",
                 connect_timeout: int = 3, read_timeout: int = 3,
                 max_connect_time_ms: int = 1200,
                 max_tls_handshake_ms: int = 800,
                 target_url: str = ""):
        self.check_url = check_url
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.max_connect_time_ms = max_connect_time_ms
        self.max_tls_handshake_ms = max_tls_handshake_ms
        self.target_url = target_url
        self._waf_block_patterns = [
            "cloudflare",
            "access denied",
            "forbidden",
            "blocked",
            "rate limit",
            "captcha",
            "akamai",
            "incapsula",
            "sucuri",
        ]

    def set_target(self, target_url: str):
        parsed = urlparse(target_url)
        self.check_url = f"{parsed.scheme}://{parsed.netloc}/cdn-cgi/trace"
        self.target_url = target_url
    
    async def validate_target_specific(self, proxy_url: str):
        if not self.target_url:
            return await self.validate(proxy_url)
        
        protocol, host, port = self._parse(proxy_url)
        st = ProxyStatus(
            url=proxy_url, protocol=protocol, host=host, port=port,
            tier=self._detect_tier(proxy_url),
        )
        
        try:
            try:
                from curl_cffi.requests import AsyncSession
                kwargs = {
                    "impersonate": "chrome124",
                    "timeout": 4,
                    "proxies": {"all": proxy_url},
                    "verify": False,
                }
                async with AsyncSession(**kwargs) as sess:
                    target_start = time.monotonic()
                    try:
                        resp = await sess.head(
                            self.target_url,
                            timeout=4,
                            allow_redirects=False,
                        )
                    except Exception:
                        try:
                            resp = await sess.get(
                                self.target_url,
                                timeout=4,
                                allow_redirects=False,
                                headers={"Range": "bytes=0-0"},
                            )
                        except Exception:
                            return None
                    
                    target_elapsed = (time.monotonic() - target_start) * 1000
                    st.connect_time_ms = round(target_elapsed, 2)
                    st.rtt_ema = target_elapsed
                    
                    if target_elapsed > 4000:
                        return None
                    
                    if resp.status_code in (1020, 1010, 1015):
                        return None
                    
                    if resp.status_code in (502, 504, 521, 522, 523, 525):
                        return None
                    
                    if 200 <= resp.status_code < 600:
                        st.alive = True
                        st.last_checked = time.time()
                        return st
                    
                    return None
                    
            except ImportError:
                st.alive = True
                st.last_checked = time.time()
                return st
        except Exception as e:
            logger.debug(f"Target validation error for {host}:{port}: {type(e).__name__}")
            return None

    def _parse(self, url: str) -> Tuple[str, str, int]:
        p = urlparse(url)
        return p.scheme.lower(), p.hostname or "", p.port or 1080

    def _guess_tier(self, url: str) -> str:
        return "datacenter"

    def _detect_tier(self, proxy_url: str) -> str:
        return self._guess_tier(proxy_url)

    async def validate(self, proxy_url: str) -> Optional[ProxyStatus]:
        protocol, host, port = self._parse(proxy_url)
        st = ProxyStatus(url=proxy_url, protocol=protocol, host=host, port=port, tier=self._detect_tier(proxy_url))
        try:
            if protocol in ("http", "https"):
                try:
                    from curl_cffi.requests import AsyncSession
                    kwargs = {
                        "impersonate": "chrome120",
                        "timeout": self.connect_timeout + self.read_timeout,
                        "proxies": {"all": proxy_url},
                        "verify": False,
                    }
                    async with AsyncSession(**kwargs) as sess:
                        start = time.monotonic()
                        tls_start = time.monotonic()
                        resp = await sess.get(self.check_url,
                                              timeout=self.connect_timeout + self.read_timeout,
                                              allow_redirects=False)
                        elapsed = (time.monotonic() - start) * 1000
                        tls_elapsed = (time.monotonic() - tls_start) * 1000
                        st.connect_time_ms = round(elapsed, 2)
                        st.tls_handshake_ms = round(tls_elapsed, 2)
                        
                        if st.connect_time_ms > self.max_connect_time_ms:
                            logger.debug(f"Proxy {host}:{port} eliminated: RTT {st.connect_time_ms}ms > {self.max_connect_time_ms}ms")
                            return None
                        if st.tls_handshake_ms > self.max_tls_handshake_ms:
                            logger.debug(f"Proxy {host}:{port} eliminated: TLS handshake {st.tls_handshake_ms}ms > {self.max_tls_handshake_ms}ms")
                            return None
                        
                        if resp.status_code in (200, 204, 301, 302, 403):
                            try:
                                text = resp.text
                                m = re.search(r'\d+\.\d+\.\d+\.\d+', text)
                                if m:
                                    st.external_ip = m.group(0)
                            except Exception:
                                pass
                            st.alive = True
                            st.last_checked = time.time()
                        else:
                            return None
                except ImportError:
                    from urllib.parse import urlparse
                    p = urlparse(proxy_url)
                    if p.username:
                        return None
                    from aiohttp import ClientSession, ClientTimeout
                    timeout = ClientTimeout(total=self.connect_timeout + self.read_timeout)
                    async with ClientSession(timeout=timeout) as session:
                        start = time.monotonic()
                        async with session.get(self.check_url, proxy=proxy_url,
                                                timeout=timeout, ssl=False) as resp:
                            elapsed = (time.monotonic() - start) * 1000
                            st.connect_time_ms = round(elapsed, 2)
                            
                            if st.connect_time_ms > self.max_connect_time_ms:
                                return None
                            
                            if resp.status not in (200, 204, 301, 302, 403):
                                return None
                            st.alive = True
                            st.last_checked = time.time()
            elif protocol in ("socks4", "socks5"):
                try:
                    from aiohttp_socks import ProxyConnector
                    from aiohttp import ClientSession, ClientTimeout
                    connector = ProxyConnector.from_url(proxy_url)
                    timeout = ClientTimeout(total=self.connect_timeout + self.read_timeout)
                    async with ClientSession(connector=connector, timeout=timeout) as session:
                        start = time.monotonic()
                        async with session.get(self.check_url, timeout=timeout, ssl=False) as resp:
                            elapsed = (time.monotonic() - start) * 1000
                            st.connect_time_ms = round(elapsed, 2)
                            
                            if st.connect_time_ms > self.max_connect_time_ms:
                                return None
                            
                            if resp.status not in (200, 204, 301, 302, 403):
                                return None
                            st.alive = True
                            st.last_checked = time.time()
                except ImportError:
                    return None
            else:
                return None
            
            return st if st.alive else None
        except (asyncio.TimeoutError, Exception) as e:
            logger.debug(f"Proxy {host}:{port} validation failed: {type(e).__name__}")
            return None


class FlareSolverrProxyValidator:
    def __init__(self, flaresolverr: Optional[FlareSolverrClient] = None,
                 connect_timeout: int = 10, read_timeout: int = 15):
        self._flaresolverr = flaresolverr or flaresolverr_client
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self._challenge_cache: Dict[str, Dict[str, Any]] = {}
        self._cache_lock = threading.Lock()

    async def validate(self, proxy_url: str) -> Optional[ProxyStatus]:
        protocol, host, port = self._parse(proxy_url)
        st = ProxyStatus(
            url=proxy_url, protocol=protocol, host=host, port=port,
            tier="premium",
        )
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._flaresolverr.solve_challenge(
                    "https://httpbin.org/ip",
                    proxy=proxy_url,
                )
            )
            if result and result.get("status_code", 0) in (200, 204, 301, 302):
                st.alive = True
                st.last_checked = time.time()
                st.premium = True
                st.tier = "premium"
                return st
            return None
        except (FlareSolverrError, Exception) as e:
            logger.debug(f"FlareSolverr validation failed for {host}:{port}: {e}")
            return None

    async def validate_target_specific(self, proxy_url: str, target_url: str) -> Optional[ProxyStatus]:
        protocol, host, port = self._parse(proxy_url)
        st = ProxyStatus(
            url=proxy_url, protocol=protocol, host=host, port=port,
            tier="premium",
        )
        cache_key = f"{proxy_url}::{target_url}"
        with self._cache_lock:
            cached = self._challenge_cache.get(cache_key)
            if cached and (time.time() - cached["timestamp"]) < 300:
                logger.debug(f"Using cached CF solution for {host}:{port}")
                st.alive = True
                st.last_checked = time.time()
                st.premium = True
                st.tier = "premium"
                st.cf_session_id = cached.get("session_id", "")
                return st
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._flaresolverr.solve_challenge(
                    target_url,
                    proxy=proxy_url,
                )
            )
            if result and result.get("status_code", 0) in (200, 204, 301, 302):
                st.alive = True
                st.last_checked = time.time()
                st.premium = True
                st.tier = "premium"
                session_id = result.get("session_id", "")
                st.cf_session_id = session_id
                with self._cache_lock:
                    self._challenge_cache[cache_key] = {
                        "timestamp": time.time(),
                        "session_id": session_id,
                        "cookies": result.get("cookies", {}),
                    }
                return st
            return None
        except (FlareSolverrError, Exception) as e:
            logger.debug(f"FlareSolverr target validation failed for {host}:{port}: {e}")
            return None

    def solve_via_proxy(self, proxy_url: str, target_url: str) -> Optional[Dict[str, Any]]:
        cache_key = f"{proxy_url}::{target_url}"
        with self._cache_lock:
            cached = self._challenge_cache.get(cache_key)
            if cached and (time.time() - cached["timestamp"]) < 300:
                logger.debug(f"Using cached solve for {proxy_url}")
                return cached
        try:
            result = self._flaresolverr.solve_challenge(target_url, proxy=proxy_url)
            if result and result.get("status_code", 0) in (200, 204, 301, 302):
                entry = {
                    "timestamp": time.time(),
                    "cookies": result.get("cookies", {}),
                    "user_agent": result.get("user_agent", ""),
                    "response_body": result.get("response_body", ""),
                }
                with self._cache_lock:
                    self._challenge_cache[cache_key] = entry
                return entry
            return None
        except (FlareSolverrError, Exception) as e:
            logger.debug(f"solve_via_proxy failed for {proxy_url}: {e}")
            return None

    def _parse(self, url: str) -> Tuple[str, str, int]:
        p = urlparse(url)
        return p.scheme.lower(), p.hostname or "", p.port or 1080


class FlareSolverrAwareProxyValidator(ProxyValidator):
    def __init__(self, flaresolverr: Optional[FlareSolverrClient] = None,
                 check_url: str = "https://httpbin.org/ip",
                 connect_timeout: int = 3, read_timeout: int = 3,
                 max_connect_time_ms: int = 1200,
                 max_tls_handshake_ms: int = 800,
                 target_url: str = "",
                 flaresolverr_fallback: bool = True):
        super().__init__(check_url, connect_timeout, read_timeout,
                         max_connect_time_ms, max_tls_handshake_ms, target_url)
        self._fs_validator = FlareSolverrProxyValidator(
            flaresolverr=flaresolverr,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
        )
        self.flaresolverr_fallback = flaresolverr_fallback

    async def validate(self, proxy_url: str) -> Optional[ProxyStatus]:
        result = await super().validate(proxy_url)
        if result and result.alive:
            return result
        if self.flaresolverr_fallback:
            fs_result = await self._fs_validator.validate(proxy_url)
            if fs_result and fs_result.alive:
                return fs_result
        return None

    async def validate_target_specific(self, proxy_url: str) -> Optional[ProxyStatus]:
        result = await super().validate_target_specific(proxy_url)
        if result and result.alive:
            return result
        if self.flaresolverr_fallback and self.target_url:
            fs_result = await self._fs_validator.validate_target_specific(proxy_url, self.target_url)
            if fs_result and fs_result.alive:
                return fs_result
        return None

    def solve_via_proxy(self, proxy_url: str, target_url: Optional[str] = None) -> Optional[Dict[str, Any]]:
        url = target_url or self.target_url
        if not url:
            return None
        return self._fs_validator.solve_via_proxy(proxy_url, url)


class SessionCookieManager:
    def __init__(self, db_path: str = "cookies/proxy_sessions.db"):
        self.db_path = db_path
        self._local = threading.local()
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn.execute("PRAGMA busy_timeout=5000")
        return self._local.conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS proxy_cookies (
                proxy_url TEXT NOT NULL,
                domain TEXT NOT NULL,
                name TEXT NOT NULL,
                value TEXT NOT NULL,
                path TEXT DEFAULT '/',
                expires REAL DEFAULT 0,
                secure INTEGER DEFAULT 0,
                http_only INTEGER DEFAULT 0,
                created_at REAL DEFAULT (julianday('now')),
                PRIMARY KEY (proxy_url, domain, name)
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_proxy_cookies_lookup
            ON proxy_cookies (proxy_url, domain)
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS proxy_sessions (
                proxy_url TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                domain TEXT NOT NULL,
                created_at REAL DEFAULT (julianday('now')),
                last_used REAL DEFAULT (julianday('now'))
            )
        """)
        conn.commit()

    def save_cookies(self, proxy_url: str, domain: str, cookies: Dict[str, str]) -> int:
        conn = self._get_conn()
        now = time.time()
        count = 0
        for name, value in cookies.items():
            conn.execute("""
                INSERT OR REPLACE INTO proxy_cookies
                (proxy_url, domain, name, value, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (proxy_url, domain, name, value, now))
            count += 1
        conn.commit()
        return count

    def load_cookies(self, proxy_url: str, domain: str) -> Dict[str, str]:
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT name, value FROM proxy_cookies WHERE proxy_url = ? AND domain = ?",
            (proxy_url, domain),
        )
        return {row["name"]: row["value"] for row in cursor.fetchall()}

    def delete_cookies(self, proxy_url: str, domain: Optional[str] = None) -> int:
        conn = self._get_conn()
        if domain:
            cursor = conn.execute(
                "DELETE FROM proxy_cookies WHERE proxy_url = ? AND domain = ?",
                (proxy_url, domain),
            )
        else:
            cursor = conn.execute(
                "DELETE FROM proxy_cookies WHERE proxy_url = ?",
                (proxy_url,),
            )
        conn.commit()
        return cursor.rowcount

    def save_session(self, proxy_url: str, session_id: str, domain: str) -> None:
        conn = self._get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO proxy_sessions
            (proxy_url, session_id, domain, last_used)
            VALUES (?, ?, ?, ?)
        """, (proxy_url, session_id, domain, time.time()))
        conn.commit()

    def get_session(self, proxy_url: str) -> Optional[Dict[str, Any]]:
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT * FROM proxy_sessions WHERE proxy_url = ?",
            (proxy_url,),
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

    def refresh_expired(self, max_age: int = 3600) -> int:
        conn = self._get_conn()
        cutoff = time.time() - max_age
        cursor = conn.execute(
            "DELETE FROM proxy_cookies WHERE created_at < ?",
            (cutoff,),
        )
        deleted = cursor.rowcount
        cursor = conn.execute(
            "DELETE FROM proxy_sessions WHERE last_used < ?",
            (cutoff,),
        )
        deleted += cursor.rowcount
        conn.commit()
        return deleted

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    def __enter__(self) -> "SessionCookieManager":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class ProxyPool:
    def __init__(self, connect_timeout: int = 3, min_pool: int = 10,
                 health_check_interval: int = 60, max_fail: int = 3):
        self._pools: Dict[str, List[ProxyStatus]] = {"mobile": [], "residential": [], "ipv6": [], "datacenter": [], "premium": []}
        self._pending: List[ProxyStatus] = []
        self._dead: List[str] = []
        self._lock = asyncio.Lock()
        self._validator = ProxyValidator(connect_timeout=connect_timeout, read_timeout=connect_timeout)
        self._running = False
        self.min_pool = min_pool
        self.health_check_interval = health_check_interval
        self.max_fail = max_fail
        self._tls_generator = TLSFingerprintGenerator()

    async def load(self, proxies: List[str]) -> int:
        from core.network._proxy.parser import parse_proxy
        count = 0
        seen = {ps.url for ps in self._pending}
        for line in proxies:
            url = parse_proxy(line)
            if not url:
                continue
            if url in seen:
                continue
            seen.add(url)
            parsed = urlparse(url)
            self._pending.append(ProxyStatus(
                url=url, protocol=parsed.scheme,
                host=parsed.hostname or "",
                port=parsed.port or 1080,
            ))
            count += 1
        return count

    async def load_file(self, path: str) -> int:
        try:
            with open(path, "r") as f:
                return await self.load(f.readlines())
        except FileNotFoundError:
            return 0

    async def _fast_tcp_check(self, ps: 'ProxyStatus', timeout: float = 1.5) -> bool:
        try:
            fut = asyncio.open_connection(ps.host, ps.port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
            except Exception:
                pass
            return True
        except Exception:
            return False

    def get_tls_profile_for_proxy(self, ps: ProxyStatus) -> Tuple[str, str]:
        tier = ps.tier
        if tier == "mobile":
            profile = "chrome124"
        elif tier == "residential":
            profile = "firefox125"
        elif tier == "premium":
            profile = "safari17"
        else:
            profiles = ["chrome124", "firefox125", "safari17", "edge124"]
            rotation_idx = ps.request_count % len(profiles)
            profile = profiles[rotation_idx]
        ja3 = self._tls_generator.get_ja3_string(profile)
        return profile, ja3

    async def quick_validate(self, count: int = 200, concurrency: int = 100,
                             target_specific: bool = True,
                             progress_cb=None,
                             max_alive: int = 0,
                             stage1_only: bool = False) -> int:
        batch = self._pending[:count]
        if not batch:
            return 0
        
        total_count = len(batch)
        sem = asyncio.Semaphore(concurrency)
        
        stage1_alive: List['ProxyStatus'] = []
        stage1_done = [0]
        stage1_alive_count = [0]
        
        async def _stage1(ps):
            async with sem:
                try:
                    is_alive = await self._fast_tcp_check(ps, timeout=1.5)
                except (BlockingIOError, OSError) as e:
                    if hasattr(e, 'errno') and e.errno in (10035, 11, 35):
                        await asyncio.sleep(0.01)
                    is_alive = False
                except Exception:
                    is_alive = False
                
                stage1_done[0] += 1
                if is_alive:
                    stage1_alive_count[0] += 1
                
                if progress_cb and stage1_done[0] % 50 == 0:
                    try:
                        progress_cb("tcp_check", stage1_done[0], stage1_alive_count[0])
                    except Exception:
                        pass
                
                return ps if is_alive else None
        
        stage1_tasks = [asyncio.create_task(_stage1(ps)) for ps in batch]
        for coro in asyncio.as_completed(stage1_tasks):
            try:
                result = await coro
                if result:
                    stage1_alive.append(result)
                    if max_alive > 0 and len(stage1_alive) >= max_alive * 2 and stage1_only:
                        for t in stage1_tasks:
                            if not t.done():
                                t.cancel()
                        break
            except Exception:
                continue
        
        if progress_cb:
            try:
                progress_cb("tcp_check", total_count, len(stage1_alive))
            except Exception:
                pass
        
        if stage1_only:
            validated_urls = set()
            for ps in stage1_alive:
                ps.alive = True
                ps.last_checked = time.time()
                tier = ps.tier if ps.tier in self._pools else "datacenter"
                profile, ja3 = self.get_tls_profile_for_proxy(ps)
                ps.tls_profile = profile
                ps.ja3_hash = ja3
                self._pools[tier].append(ps)
                validated_urls.add(ps.url)
            for ps in batch:
                if ps.url not in validated_urls:
                    self._dead.append(ps.url)
            self._pending = [ps for ps in self._pending if ps.url not in {p.url for p in batch}]
            return len(stage1_alive)
        
        use_target_gate = target_specific and bool(getattr(self._validator, 'target_url', ''))
        stage2_done = [0]
        stage2_alive_count = [0]
        stage2_alive: List['ProxyStatus'] = []
        
        async def _stage2(ps):
            async with sem:
                try:
                    if use_target_gate:
                        result = await self._validator.validate_target_specific(ps.url)
                    else:
                        result = await self._validator.validate(ps.url)
                except (BlockingIOError, OSError) as e:
                    if hasattr(e, 'errno') and e.errno in (10035, 11, 35):
                        await asyncio.sleep(0.01)
                    result = None
                except Exception:
                    result = None
                
                stage2_done[0] += 1
                if isinstance(result, ProxyStatus) and result.alive:
                    stage2_alive_count[0] += 1
                
                if progress_cb and stage2_done[0] % 25 == 0:
                    try:
                        progress_cb("target_check", stage2_done[0], stage2_alive_count[0])
                    except Exception:
                        pass
                
                return result
        
        if stage1_alive:
            stage2_tasks = [asyncio.create_task(_stage2(ps)) for ps in stage1_alive]
            for coro in asyncio.as_completed(stage2_tasks):
                try:
                    result = await coro
                    if isinstance(result, ProxyStatus) and result.alive:
                        stage2_alive.append(result)
                        if max_alive > 0 and len(stage2_alive) >= max_alive:
                            for t in stage2_tasks:
                                if not t.done():
                                    t.cancel()
                            break
                except Exception:
                    continue
        
        if progress_cb:
            try:
                progress_cb("target_check", len(stage1_alive), len(stage2_alive))
            except Exception:
                pass
        
        validated_urls = {ps.url for ps in batch}
        for r in stage2_alive:
            tier = r.tier if r.tier in self._pools else "datacenter"
            profile, ja3 = self.get_tls_profile_for_proxy(r)
            r.tls_profile = profile
            r.ja3_hash = ja3
            self._pools[tier].append(r)
        
        alive_urls = {r.url for r in stage2_alive}
        for ps in batch:
            if ps.url not in alive_urls:
                self._dead.append(ps.url)
        
        self._pending = [ps for ps in self._pending if ps.url not in validated_urls]
        return len(stage2_alive)

    async def health_loop(self):
        self._running = True
        while self._running:
            await asyncio.sleep(self.health_check_interval)
            if not self._running:
                break
            for tier in self._pools:
                alive = []
                for ps in self._pools[tier]:
                    r = await self._validator.validate(ps.url)
                    if r and r.alive:
                        alive.append(r)
                    else:
                        ps.fail_count += 1
                        if ps.fail_count >= self.max_fail:
                            self._dead.append(ps.url)
                        else:
                            alive.append(ps)
                self._pools[tier] = alive

    async def stop(self):
        self._running = False

    async def get_proxy(self, preferred_tier: str = "mobile") -> Optional[ProxyStatus]:
        tiers = [preferred_tier, "premium", "residential", "ipv6", "datacenter"]
        current_time = time.time()
        async with self._lock:
            for t in tiers:
                if t in self._pools and self._pools[t]:
                    for ps in self._pools[t]:
                        if current_time - ps.last_used >= 2.0:
                            ps.last_used = current_time
                            ps.request_count += 1
                            self._pools[t].remove(ps)
                            self._pools[t].append(ps)
                            return ps
                    ps = min(self._pools[t], key=lambda x: x.last_used)
                    ps.last_used = current_time
                    ps.request_count += 1
                    return ps
            all_proxies = []
            for pool in self._pools.values():
                all_proxies.extend(pool)
            if all_proxies:
                ps = min(all_proxies, key=lambda x: x.last_used)
                ps.last_used = current_time
                ps.request_count += 1
                return ps
        return None

    async def get_proxy_weighted(self, preferred_tier: str = "mobile") -> Optional[ProxyStatus]:
        tiers = [preferred_tier, "premium", "residential", "ipv6", "datacenter"]
        async with self._lock:
            for t in tiers:
                if t in self._pools and self._pools[t]:
                    pool = self._pools[t]
                    weights = []
                    for ps in pool:
                        w = (ps.success_count + 1) / (1 + ps.fail_count + ps.rtt_ema / 1000)
                        weights.append(w)
                    if sum(weights) == 0:
                        return random.choice(pool)
                    return random.choices(pool, weights=weights, k=1)[0]
        return None

    async def report_success(self, ps: ProxyStatus, rtt_ms: float = 0.0):
        ps.success_count += 1
        if rtt_ms > 0:
            ps.rtt_ema = ps.rtt_ema * 0.7 + rtt_ms * 0.3 if ps.rtt_ema > 0 else rtt_ms

    async def report_failure(self, ps: ProxyStatus):
        ps.fail_count += 1
        if ps.fail_count >= self.max_fail:
            async with self._lock:
                for t in self._pools:
                    if ps in self._pools[t]:
                        self._pools[t].remove(ps)
                        self._dead.append(ps.url)
                        break

    def stats(self) -> dict:
        s = {}
        for t, pool in self._pools.items():
            s[t] = len(pool)
        s["dead"] = len(self._dead)
        s["pending"] = len(self._pending)
        s["total"] = sum(len(v) for v in self._pools.values())
        return s

    def get_alive_urls(self) -> List[str]:
        urls = []
        for pool in self._pools.values():
            for ps in pool:
                urls.append(ps.url)
        return urls

    def save_alive(self, path: str = "proxies/alive.txt"):
        urls = self.get_alive_urls()
        with open(path, "w") as f:
            f.write("\n".join(urls) + "\n")
        return len(urls)


class TlsAwareProxyPool(ProxyPool):
    def __init__(self, connect_timeout: int = 3, min_pool: int = 10,
                 health_check_interval: int = 60, max_fail: int = 3):
        super().__init__(connect_timeout, min_pool, health_check_interval, max_fail)
        self._tls_generator = TLSFingerprintGenerator()
        self._tls_rotation_counters: Dict[str, int] = {}
        self._datacenter_rotation_interval: int = 3

    def set_datacenter_rotation_interval(self, n: int) -> None:
        self._datacenter_rotation_interval = max(1, n)

    def get_tls_profile_for_proxy(self, ps: ProxyStatus) -> Tuple[str, str]:
        tier = ps.tier
        if tier == "mobile":
            profile = get_random_profile()
            while profile not in ("chrome126", "firefox130"):
                profile = get_random_profile()
        elif tier == "residential":
            profile = "chrome126"
        elif tier == "premium":
            profile = "firefox130"
        else:
            key = ps.url
            counter = self._tls_rotation_counters.get(key, 0)
            rotation_index = counter // self._datacenter_rotation_interval
            profiles = ["chrome126", "firefox130"]
            profile = profiles[rotation_index % len(profiles)]
            self._tls_rotation_counters[key] = counter + 1
        ja3 = self._tls_generator.get_ja3_string(profile)
        return profile, ja3

    async def get_proxy(self, preferred_tier: str = "mobile") -> Optional[ProxyStatus]:
        ps = await super().get_proxy(preferred_tier)
        if ps:
            profile, ja3 = self.get_tls_profile_for_proxy(ps)
            ps.tls_profile = profile
            ps.ja3_hash = ja3
        return ps

    async def get_proxy_weighted(self, preferred_tier: str = "mobile") -> Optional[ProxyStatus]:
        ps = await super().get_proxy_weighted(preferred_tier)
        if ps:
            profile, ja3 = self.get_tls_profile_for_proxy(ps)
            ps.tls_profile = profile
            ps.ja3_hash = ja3
        return ps
