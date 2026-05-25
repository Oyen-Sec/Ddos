"""
FlareSolverr Integration Module
Automates Cloudflare challenge solving via FlareSolverr API
with SQLite-based cookie persistence and residential proxy support
"""
import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger("flaresolverr")

FLARESOLVERR_DEFAULT_ENDPOINT = "http://localhost:8191"
FLARESOLVERR_API_PATH = "/v1"
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
BASE_BACKOFF = 2.0


def _parse_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.hostname or ""


def _format_flaresolverr_proxy(proxy_url: Optional[str]) -> Optional[Dict[str, str]]:
    if not proxy_url:
        return None
    parsed = urlparse(proxy_url)
    result: Dict[str, str] = {
        "url": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}",
    }
    if parsed.username:
        result["username"] = parsed.username
    if parsed.password:
        result["password"] = parsed.password
    return result


# ---------------------------------------------------------------------------
# CookieStore - SQLite-based cookie persistence
# ---------------------------------------------------------------------------

class CookieStore:
    """Thread-safe SQLite-backed cookie store for FlareSolverr sessions."""

    def __init__(self, db_path: str = "cookies/flaresolverr.db"):
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
        return self._local.conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cookies (
                session_id TEXT NOT NULL,
                domain TEXT NOT NULL,
                name TEXT NOT NULL,
                value TEXT NOT NULL,
                path TEXT DEFAULT '/',
                expires REAL DEFAULT 0,
                secure INTEGER DEFAULT 0,
                http_only INTEGER DEFAULT 0,
                created_at REAL DEFAULT (julianday('now')),
                PRIMARY KEY (session_id, domain, name)
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_cookies_session
            ON cookies (session_id)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_cookies_domain
            ON cookies (domain)
        """)
        conn.commit()

    def save_cookies(self, session_id: str, cookies_dict: Dict[str, str], domain: str) -> int:
        conn = self._get_conn()
        now = time.time()
        count = 0
        for name, value in cookies_dict.items():
            conn.execute("""
                INSERT OR REPLACE INTO cookies
                (session_id, domain, name, value, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (session_id, domain, name, value, now))
            count += 1
        conn.commit()
        return count

    def load_cookies(self, session_id: str, domain: str) -> Dict[str, str]:
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT name, value FROM cookies WHERE session_id = ? AND domain = ?",
            (session_id, domain),
        )
        return {row["name"]: row["value"] for row in cursor.fetchall()}

    def delete_session(self, session_id: str) -> int:
        conn = self._get_conn()
        cursor = conn.execute("DELETE FROM cookies WHERE session_id = ?", (session_id,))
        conn.commit()
        return cursor.rowcount

    def get_all_sessions(self) -> List[str]:
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT DISTINCT session_id FROM cookies ORDER BY created_at DESC"
        )
        return [row["session_id"] for row in cursor.fetchall()]

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    def __enter__(self) -> "CookieStore":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# FlareSolverrClient
# ---------------------------------------------------------------------------

class FlareSolverrError(Exception):
    """Raised when FlareSolverr returns an error response."""
    pass


class FlareSolverrClient:
    """Client for the FlareSolverr HTTP API."""

    def __init__(self, endpoint: str = FLARESOLVERR_DEFAULT_ENDPOINT, timeout: int = REQUEST_TIMEOUT):
        self._endpoint = endpoint.rstrip("/")
        self._api_url = f"{self._endpoint}{FLARESOLVERR_API_PATH}"
        self._timeout = timeout
        self._running = False

    def start(self) -> None:
        self._running = True
        logger.info("FlareSolverr client started (endpoint: %s)", self._endpoint)

    def stop(self) -> None:
        self._running = False
        logger.info("FlareSolverr client stopped")

    def _request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        req = Request(
            self._api_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read().decode("utf-8")
        except URLError as e:
            raise FlareSolverrError(f"FlareSolverr connection failed: {e.reason}") from e
        except OSError as e:
            raise FlareSolverrError(f"FlareSolverr connection error: {e}") from e

        data: Dict[str, Any] = json.loads(raw)
        if data.get("status") != "ok":
            msg = data.get("message", data.get("error", "unknown error"))
            raise FlareSolverrError(f"FlareSolverr error: {msg}")
        return data

    def solve_challenge(
        self,
        url: str,
        proxy: Optional[str] = None,
        session: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "cmd": "request.get",
            "url": url,
            "maxTime": self._timeout * 1000,
        }
        if session:
            payload["session"] = session
        proxy_cfg = _format_flaresolverr_proxy(proxy)
        if proxy_cfg:
            payload["proxy"] = proxy_cfg

        last_exc: Optional[Exception] = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                data = self._request(payload)
            except (FlareSolverrError, OSError) as e:
                last_exc = e
                if attempt < MAX_RETRIES:
                    backoff = BASE_BACKOFF * (2 ** (attempt - 1))
                    logger.warning(
                        "FlareSolverr attempt %d/%d failed: %s. Retrying in %.1fs...",
                        attempt, MAX_RETRIES, e, backoff,
                    )
                    time.sleep(backoff)
                continue

            solution = data.get("solution", {})
            cookies_raw = solution.get("cookies", [])
            cookies = {}
            for c in cookies_raw:
                if isinstance(c, dict):
                    cookies[c.get("name", "")] = c.get("value", "")
            return {
                "cookies": cookies,
                "user_agent": solution.get("userAgent", ""),
                "status_code": solution.get("status", 0),
                "response_body": solution.get("response", ""),
                "headers": solution.get("headers", {}),
            }

        raise FlareSolverrError(
            f"All {MAX_RETRIES} retries exhausted for {url}"
        ) from last_exc

    def create_session(
        self, session_id: Optional[str] = None, proxy: Optional[str] = None
    ) -> str:
        sid = session_id or str(uuid.uuid4())
        payload: Dict[str, Any] = {
            "cmd": "sessions.create",
            "session": sid,
        }
        proxy_cfg = _format_flaresolverr_proxy(proxy)
        if proxy_cfg:
            payload["proxy"] = proxy_cfg
        self._request(payload)
        logger.info("FlareSolverr session created: %s", sid)
        return sid

    def destroy_session(self, session_id: str) -> None:
        payload = {
            "cmd": "sessions.destroy",
            "session": session_id,
        }
        try:
            self._request(payload)
            logger.info("FlareSolverr session destroyed: %s", session_id)
        except FlareSolverrError as e:
            logger.warning("Failed to destroy session %s: %s", session_id, e)

    def check_health(self) -> bool:
        try:
            self._request({"cmd": "sessions.list"})
            return True
        except (FlareSolverrError, OSError):
            return False

    def get_cookies_for_url(self, url: str, session_id: str) -> Dict[str, str]:
        domain = _parse_domain(url)
        payload: Dict[str, Any] = {
            "cmd": "request.get",
            "url": url,
            "session": session_id,
            "maxTime": self._timeout * 1000,
        }
        try:
            data = self._request(payload)
        except FlareSolverrError:
            return {}
        solution = data.get("solution", {})
        cookies_raw = solution.get("cookies", [])
        return {
            c["name"]: c["value"]
            for c in cookies_raw
            if isinstance(c, dict) and c.get("name")
        }


# ---------------------------------------------------------------------------
# ResidentialProxyManager
# ---------------------------------------------------------------------------

@dataclass
class ProviderConfig:
    name: str
    template: str
    requires_country: bool = False


BUILTIN_PROVIDERS: Dict[str, ProviderConfig] = {
    "brightdata": ProviderConfig(
        name="brightdata",
        template="http://{username}:{password}@zproxy.lum-infinite.com:22225",
    ),
    "oxylabs": ProviderConfig(
        name="oxylabs",
        template="http://{username}:{password}@pr.oxylabs.io:7777",
    ),
    "iproyal": ProviderConfig(
        name="iproyal",
        template="http://{username}:{password}@residential.iproyal.com:12321",
    ),
}


class ResidentialProxyManager:
    """Manages residential proxy providers and per-session proxy assignment."""

    def __init__(self) -> None:
        self._providers: Dict[str, ProviderConfig] = dict(BUILTIN_PROVIDERS)
        self._session_map: Dict[str, str] = {}

    def add_provider(self, name: str, config: Dict[str, Any]) -> None:
        template = config.get("template", "")
        requires_country = config.get("requires_country", False)
        self._providers[name.lower()] = ProviderConfig(
            name=name, template=template, requires_country=requires_country,
        )
        logger.info("Proxy provider added: %s", name)

    def format_proxy_url(
        self, provider: str, username: str, password: str, country: Optional[str] = None
    ) -> str:
        prov = self._providers.get(provider.lower())
        if not prov:
            raise ValueError(f"Unknown provider: {provider}. Available: {list(self._providers.keys())}")

        parts = username.split("-country-")
        if country:
            base_user = parts[0]
            user = f"{base_user}-country-{country}"
        else:
            user = username

        return prov.template.format(username=user, password=password)

    def get_residential_proxy(self, session_id: str) -> Optional[str]:
        return self._session_map.get(session_id)

    def rotate_proxy(self, session_id: str) -> None:
        self._session_map.pop(session_id, None)
        logger.info("Proxy rotated for session: %s", session_id)

    def assign_proxy(self, session_id: str, proxy_url: str) -> None:
        self._session_map[session_id] = proxy_url
        logger.debug("Proxy assigned to session %s: %s", session_id, proxy_url)


# ---------------------------------------------------------------------------
# BrowserSessionPool
# ---------------------------------------------------------------------------

@dataclass
class PooledSession:
    session_id: str
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    user_agent: str = ""
    proxy: Optional[str] = None
    in_use: bool = False


class BrowserSessionPool:
    """Pool of reusable FlareSolverr browser sessions with cookie rotation."""

    def __init__(
        self,
        flaresolverr: "FlareSolverrClient",
        cookie_store: CookieStore,
        proxy_manager: Optional[ResidentialProxyManager] = None,
        max_sessions: int = 10,
        session_ttl: int = 600,
    ):
        self._flaresolverr = flaresolverr
        self._cookie_store = cookie_store
        self._proxy_manager = proxy_manager
        self._max_sessions = max_sessions
        self._session_ttl = session_ttl
        self._sessions: Dict[str, PooledSession] = {}
        self._lock = threading.Lock()

    def acquire_session(self) -> PooledSession:
        with self._lock:
            available = [s for s in self._sessions.values() if not s.in_use]
            for ps in available:
                if time.time() - ps.last_used < self._session_ttl:
                    ps.in_use = True
                    ps.last_used = time.time()
                    logger.debug("Acquired existing session: %s", ps.session_id)
                    return ps
            if len(self._sessions) >= self._max_sessions:
                oldest = min(self._sessions.values(), key=lambda s: s.last_used)
                self._destroy_locked(oldest.session_id)

            session_id = self._flaresolverr.create_session(proxy=None)
            ps = PooledSession(session_id=session_id)
            self._sessions[session_id] = ps
            ps.in_use = True
            logger.info("Created new pooled session: %s (pool size: %d)", session_id, len(self._sessions))
            return ps

    def release_session(self, session_id: str) -> None:
        with self._lock:
            ps = self._sessions.get(session_id)
            if ps:
                ps.in_use = False
                ps.last_used = time.time()
                logger.debug("Released session: %s", session_id)

    def get_session_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def cleanup(self) -> int:
        with self._lock:
            now = time.time()
            expired = [
                sid for sid, ps in self._sessions.items()
                if not ps.in_use and (now - ps.created_at) > self._session_ttl
            ]
            for sid in expired:
                self._destroy_locked(sid)
            logger.info("Cleanup: removed %d expired sessions", len(expired))
            return len(expired)

    def _destroy_locked(self, session_id: str) -> None:
        self._flaresolverr.destroy_session(session_id)
        self._cookie_store.delete_session(session_id)
        self._sessions.pop(session_id, None)

    def destroy_all(self) -> int:
        with self._lock:
            sids = list(self._sessions.keys())
            for sid in sids:
                self._destroy_locked(sid)
            return len(sids)


# ---------------------------------------------------------------------------
# Global singletons
# ---------------------------------------------------------------------------

flaresolverr_client = FlareSolverrClient()
cookie_store = CookieStore()
proxy_manager = ResidentialProxyManager()


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def solve_and_fetch(
    url: str,
    proxy: Optional[str] = None,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    return flaresolverr_client.solve_challenge(url, proxy=proxy, session=session_id)


def is_flaresolverr_available() -> bool:
    return flaresolverr_client.check_health()
