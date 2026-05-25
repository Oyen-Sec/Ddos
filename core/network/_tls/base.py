import logging
import random
from typing import Optional, Dict, List
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger("tls_engine")

BROWSER_PROFILES = [
    {"impersonate": "chrome124", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", "sec-ch-ua": '"Not/A)Brand";v="99", "Google Chrome";v="124", "Chromium";v="124"'},
    {"impersonate": "chrome120", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "sec-ch-ua": '"Not/A)Brand";v="99", "Google Chrome";v="120", "Chromium";v="120"'},
    {"impersonate": "safari17_0", "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15", "sec-ch-ua": '"Not/A)Brand";v="99", "Safari";v="17", "WebKit";v="605"'},
]

ACCEPT_LANGUAGES = ["en-US,en;q=0.9", "id-ID,id;q=0.9,en;q=0.8", "en-GB,en;q=0.9",
                    "de-DE,de;q=0.9,en;q=0.8", "ja-JP,ja;q=0.9,en;q=0.8",
                    "fr-FR,fr;q=0.9,en;q=0.8", "ko-KR,ko;q=0.9,en;q=0.8"]

ACCEPTS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
]

PLATFORMS = ['"Windows"', '"macOS"', '"Linux"']


def random_profile() -> dict:
    return random.choice(BROWSER_PROFILES)


def build_headers(url: str, profile: Optional[dict] = None) -> Dict[str, str]:
    p = profile or random_profile()
    parsed = urlparse(url)
    ua = p["ua"]
    sch = p["sec-ch-ua"]
    plat = random.choice(PLATFORMS)
    lang = random.choice(ACCEPT_LANGUAGES)
    accept = random.choice(ACCEPTS)
    return {
        ":method": "GET",
        ":authority": parsed.netloc,
        ":scheme": parsed.scheme,
        ":path": parsed.path if parsed.path else "/" + ("?" + parsed.query if parsed.query else ""),
        "cache-control": "max-age=0",
        "sec-ch-ua": sch,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": plat,
        "upgrade-insecure-requests": "1",
        "user-agent": ua,
        "accept": accept,
        "sec-fetch-site": random.choice(["same-origin", "none", "cross-site"]),
        "sec-fetch-mode": "navigate",
        "sec-fetch-user": "?1",
        "sec-fetch-dest": "document",
        "accept-encoding": "gzip, deflate, br",
        "accept-language": lang,
    }


def build_post_headers(url: str, profile: Optional[dict] = None) -> Dict[str, str]:
    p = profile or random_profile()
    parsed = urlparse(url)
    ua = p["ua"]
    sch = p["sec-ch-ua"]
    plat = random.choice(PLATFORMS)
    lang = random.choice(ACCEPT_LANGUAGES)
    return {
        ":method": "POST",
        ":authority": parsed.netloc,
        ":scheme": parsed.scheme,
        ":path": parsed.path if parsed.path else "/",
        "cache-control": "no-cache",
        "sec-ch-ua": sch,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": plat,
        "user-agent": ua,
        "accept": "application/json, text/plain, */*",
        "sec-fetch-site": random.choice(["same-origin", "cross-site"]),
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
        "accept-encoding": "gzip, deflate, br",
        "accept-language": lang,
        "content-type": "application/x-www-form-urlencoded",
    }


class TLSManager:
    def __init__(self):
        self._sessions: Dict[str, object] = {}
        self._cookies: Dict[str, str] = {}

    def _make_session(self, profile: dict):
        try:
            from curl_cffi.requests import Session
            sess = Session(impersonate=profile["impersonate"], timeout=10)
            if self._cookies:
                sess.cookies.update(self._cookies)
            return sess
        except ImportError:
            return None

    def get_session(self, key: str = "default") -> object:
        if key not in self._sessions:
            profile = random_profile()
            sess = self._make_session(profile)
            self._sessions[key] = (sess, profile)
        return self._sessions[key]

    def get_fresh_session(self, profile: Optional[dict] = None) -> object:
        p = profile or random_profile()
        sess = self._make_session(p)
        if sess:
            self._sessions[p["impersonate"]] = (sess, p)
        return sess

    def save_cookies(self, cookies: dict):
        self._cookies.update(cookies)

    def rotate_session(self, key: str = "default"):
        if key in self._sessions:
            try:
                self._sessions[key][0].close()
            except Exception:
                pass
            del self._sessions[key]

    def close_all(self):
        for sess, _ in self._sessions.values():
            try:
                sess.close()
            except Exception:
                pass
        self._sessions.clear()
