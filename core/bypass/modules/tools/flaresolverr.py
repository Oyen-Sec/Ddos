"""
FlareSolverr Client - Bypass Cloudflare/DDoS-Guard JS challenges
"""
import logging, json, requests
from typing import Optional, Dict, List
logger = logging.getLogger(__name__)

class FlareSolverrClient:
    def __init__(self, endpoint: str = "http://127.0.0.1:8191/v1"):
        self.endpoint = endpoint

    def request(self, url: str, max_timeout: int = 60000) -> Optional[Dict]:
        try:
            resp = requests.post(self.endpoint, json={
                "cmd": "request.get",
                "url": url,
                "maxTimeout": max_timeout,
            }, timeout=max_timeout // 1000 + 5)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("solution", {}).get("status") == 200:
                    return data["solution"]
        except Exception as e:
            logger.debug(f"FlareSolverr error: {e}")
        return None

    def session_create(self) -> Optional[str]:
        try:
            resp = requests.post(self.endpoint, json={"cmd": "sessions.create"}, timeout=10)
            if resp.status_code == 200:
                return resp.json().get("session", "")
        except:
            pass
        return None

    def session_destroy(self, session_id: str):
        try:
            requests.post(self.endpoint, json={"cmd": "sessions.destroy", "session": session_id}, timeout=5)
        except:
            pass
