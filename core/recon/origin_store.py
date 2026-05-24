"""
Origin Store - Persistent storage for origin IP hunting results
Auto-save on hunt, auto-load on attack
"""
import os
import json
import time
from typing import Optional, Dict, List
from urllib.parse import urlparse


STORE_DIR = "output/origins"
LAST_HUNT_FILE = os.path.join(STORE_DIR, "last_hunt.json")


def _ensure_dir():
    os.makedirs(STORE_DIR, exist_ok=True)


def _hostname_from_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    p = urlparse(url)
    return (p.hostname or url).lower()


def save_hunt(target_url: str, verified_origins: List[str], candidates: List[Dict]) -> str:
    """Save hunt results keyed by hostname"""
    _ensure_dir()
    host = _hostname_from_url(target_url)

    record = {
        "target": target_url,
        "host": host,
        "timestamp": time.time(),
        "timestamp_human": time.strftime("%Y-%m-%d %H:%M:%S"),
        "verified_origins": verified_origins,
        "candidates": candidates,
    }

    # Save per-host file
    host_file = os.path.join(STORE_DIR, f"{host.replace('/','_')}.json")
    with open(host_file, "w") as f:
        json.dump(record, f, indent=2)

    # Save as last hunt
    with open(LAST_HUNT_FILE, "w") as f:
        json.dump(record, f, indent=2)

    # Save candidates as plain text for proxy_file-style use
    txt_file = os.path.join(STORE_DIR, f"{host.replace('/','_')}.txt")
    with open(txt_file, "w") as f:
        f.write(f"# Origin candidates for {target_url}\n")
        f.write(f"# Saved at: {record['timestamp_human']}\n")
        for ip in verified_origins:
            f.write(f"{ip}\n")
        for cand in candidates:
            ip = cand.get("ip") if isinstance(cand, dict) else cand
            if ip and ip not in verified_origins:
                f.write(f"{ip}\n")

    return host_file


def load_hunt(target_url: str) -> Optional[Dict]:
    """Load hunt result for a hostname (if exists & not too old)"""
    host = _hostname_from_url(target_url)
    host_file = os.path.join(STORE_DIR, f"{host.replace('/','_')}.json")
    if not os.path.exists(host_file):
        return None
    try:
        with open(host_file, "r") as f:
            data = json.load(f)
        return data
    except Exception:
        return None


def get_best_origin(target_url: str) -> Optional[str]:
    """Quick helper: get the best verified origin for a target (or None)"""
    data = load_hunt(target_url)
    if not data:
        return None
    if data.get("verified_origins"):
        return data["verified_origins"][0]
    cands = data.get("candidates", [])
    if cands:
        first = cands[0]
        if isinstance(first, dict):
            return first.get("ip")
        return first
    return None


def list_saved() -> List[Dict]:
    """List all saved hunt records"""
    _ensure_dir()
    records = []
    for fname in os.listdir(STORE_DIR):
        if fname.endswith(".json") and fname != "last_hunt.json":
            try:
                with open(os.path.join(STORE_DIR, fname), "r") as f:
                    data = json.load(f)
                records.append(data)
            except Exception:
                pass
    records.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
    return records


def is_ip_address(s: str) -> bool:
    """Check if string is a bare IP address"""
    if not s:
        return False
    s = s.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        for p in parts:
            n = int(p)
            if n < 0 or n > 255:
                return False
        return True
    except ValueError:
        return False
