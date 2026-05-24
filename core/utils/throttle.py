"""
Self-Health Monitor & Gate Validation
====================================
Tracks event loop lag, OS backpressure (WSAEWOULDBLOCK), and adaptive RPS ladder.

Designed for Windows networking stack with kernel-level socket tuning awareness.
All operations are thread-safe and non-blocking.
"""
from __future__ import annotations

import asyncio
import errno
import logging
import os
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("self_health")

# Windows-specific error code: socket buffer is full
WSAEWOULDBLOCK = 10035


@dataclass
class HealthSnapshot:
    """Read-only snapshot of self-health state at a point in time."""
    timestamp: float
    loop_lag_ms: float
    wsa_block_count_1s: int
    wsa_block_total: int
    is_overloaded: bool
    is_saturated: bool
    current_rps_factor: float
    actual_rps: float
    local_drops: int
    network_rtt_ms: float
    state_label: str


class SelfHealthMonitor:
    """
    Internal self-health monitor for Auto Mode v2.

    Responsibilities:
    - Measure event loop lag every 2s (asyncio.sleep(0) duration)
    - Track WSAEWOULDBLOCK / EAGAIN occurrences
    - Maintain adaptive RPS ladder with phase-based factors
    - Provide thread-safe health gate to attack workers

    NOT a thread itself - runs as asyncio task and exposes thread-safe state.
    """

    def __init__(
        self,
        loop_lag_threshold_ms: float = 5000.0,
        wsa_block_threshold: int = 500,
        wsa_block_window_seconds: float = 10.0,
        throttle_factor: float = 0.99,
        check_interval_seconds: float = 10.0,
    ) -> None:
        self.loop_lag_threshold_ms = loop_lag_threshold_ms
        self.wsa_block_threshold = wsa_block_threshold
        self.wsa_block_window_seconds = wsa_block_window_seconds
        self.throttle_factor = throttle_factor
        self.check_interval_seconds = check_interval_seconds

        # Thread-safe state
        self._lock = threading.Lock()
        self._loop_lag_ms: float = 0.0
        self._wsa_block_events: deque = deque(maxlen=256)  # timestamps
        self._wsa_block_total: int = 0
        self._is_overloaded: bool = False
        self._is_saturated: bool = False
        self._current_rps_factor: float = 1.0
        self._actual_rps: float = 0.0
        self._local_drops: int = 0
        self._network_rtt_ms: float = 0.0
        self._state_label: str = "STARTING"

        # Async task
        self._task: Optional[asyncio.Task] = None
        self._stop_event: Optional[asyncio.Event] = None
        self._running: bool = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the health monitor as an asyncio task on the current loop."""
        if self._running:
            return
        self._running = True
        self._stop_event = asyncio.Event()
        self._task = asyncio.create_task(self._monitor_loop())

    async def stop(self) -> None:
        """Stop the monitor cleanly."""
        if not self._running:
            return
        self._running = False
        if self._stop_event is not None:
            self._stop_event.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=2.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Monitor loop
    # ------------------------------------------------------------------

    async def _monitor_loop(self) -> None:
        """Periodic loop that measures lag and updates health state."""
        try:
            while self._running:
                # Measure event loop lag
                lag_ms = await self._measure_loop_lag()

                # Compute WSA block rate in last window
                now = time.monotonic()
                window_start = now - self.wsa_block_window_seconds
                with self._lock:
                    while self._wsa_block_events and self._wsa_block_events[0] < window_start:
                        self._wsa_block_events.popleft()
                    block_count = len(self._wsa_block_events)
                    self._loop_lag_ms = lag_ms

                # Decide if system is overloaded
                lag_overload = lag_ms > self.loop_lag_threshold_ms
                block_overload = block_count >= self.wsa_block_threshold

                with self._lock:
                    self._is_overloaded = bool(lag_overload or block_overload)
                    if self._is_overloaded:
                        # Reduce RPS factor by throttle_factor (multiplicative)
                        new_factor = self._current_rps_factor * self.throttle_factor
                        # Floor at 5%
                        self._current_rps_factor = max(0.05, new_factor)
                        self._state_label = "THROTTLED"
                        logger.warning(
                            "[health] Overload detected lag=%.1fms wsa_blocks=%d -> RPS factor %.2f",
                            lag_ms, block_count, self._current_rps_factor,
                        )

                # Wait for next interval or stop
                try:
                    if self._stop_event is None:
                        await asyncio.sleep(self.check_interval_seconds)
                    else:
                        await asyncio.wait_for(
                            self._stop_event.wait(),
                            timeout=self.check_interval_seconds,
                        )
                except asyncio.TimeoutError:
                    continue
        except asyncio.CancelledError:
            return
        except Exception as e:
            logger.error("[health] monitor loop error: %s", e)

    async def _measure_loop_lag(self) -> float:
        """Measure asyncio.sleep(0) duration as lag indicator."""
        # Run 5 samples and take median to avoid jitter
        samples = []
        for _ in range(5):
            t0 = time.perf_counter()
            await asyncio.sleep(0)
            samples.append((time.perf_counter() - t0) * 1000.0)
        samples.sort()
        return samples[len(samples) // 2]

    # ------------------------------------------------------------------
    # Public API (thread-safe)
    # ------------------------------------------------------------------

    def report_wsa_block(self) -> None:
        """Called by attack worker when BlockingIOError or WSAEWOULDBLOCK occurs."""
        with self._lock:
            self._wsa_block_events.append(time.monotonic())
            self._wsa_block_total += 1

    def report_actual_rps(self, rps: float) -> None:
        """Called by attack worker each second with measured RPS."""
        with self._lock:
            self._actual_rps = float(rps)

    def report_local_drop(self, count: int = 1) -> None:
        """Called when socket.send returned less than payload length."""
        with self._lock:
            self._local_drops += int(count)

    def report_network_rtt(self, rtt_ms: float) -> None:
        """Called by phase 4.5 ping check or attack worker."""
        with self._lock:
            self._network_rtt_ms = float(rtt_ms)

    def set_state_label(self, label: str) -> None:
        """Update phase/state label for dashboard."""
        with self._lock:
            self._state_label = str(label)

    def set_rps_factor(self, factor: float) -> None:
        """Manual override of RPS factor (used by phase orchestrator)."""
        factor = max(0.05, min(1.0, float(factor)))
        with self._lock:
            self._current_rps_factor = factor

    def mark_saturated(self, saturated: bool = True) -> None:
        """Set network saturation flag (from phase 4.5 ping check)."""
        with self._lock:
            self._is_saturated = bool(saturated)
            if saturated:
                self._state_label = "NETWORK_SATURATED"

    def get_rps_factor(self) -> float:
        """Worker reads this to adjust spawn rate."""
        with self._lock:
            return self._current_rps_factor

    def is_overloaded(self) -> bool:
        with self._lock:
            return self._is_overloaded

    def is_saturated(self) -> bool:
        with self._lock:
            return self._is_saturated

    def snapshot(self) -> HealthSnapshot:
        """Atomic snapshot for dashboard rendering."""
        with self._lock:
            now = time.monotonic()
            window_start = now - self.wsa_block_window_seconds
            block_1s = sum(1 for t in self._wsa_block_events if t >= window_start)
            return HealthSnapshot(
                timestamp=time.time(),
                loop_lag_ms=self._loop_lag_ms,
                wsa_block_count_1s=block_1s,
                wsa_block_total=self._wsa_block_total,
                is_overloaded=self._is_overloaded,
                is_saturated=self._is_saturated,
                current_rps_factor=self._current_rps_factor,
                actual_rps=self._actual_rps,
                local_drops=self._local_drops,
                network_rtt_ms=self._network_rtt_ms,
                state_label=self._state_label,
            )


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def is_wsa_would_block(exc: BaseException) -> bool:
    """Detect Windows WSAEWOULDBLOCK or POSIX EAGAIN/EWOULDBLOCK."""
    if isinstance(exc, BlockingIOError):
        return True
    if isinstance(exc, OSError):
        err = getattr(exc, "errno", None)
        if err in (WSAEWOULDBLOCK, errno.EAGAIN, errno.EWOULDBLOCK):
            return True
        if err in (10054, 10053):  # WSAECONNRESET, WSAECONNABORTED
            return False
    return False


async def loop_lag_probe() -> float:
    """One-shot event loop lag probe (ms)."""
    samples = []
    for _ in range(3):
        t0 = time.perf_counter()
        await asyncio.sleep(0)
        samples.append((time.perf_counter() - t0) * 1000.0)
    samples.sort()
    return samples[len(samples) // 2]


# ----------------------------------------------------------------------
# Phase Configuration Loader
# ----------------------------------------------------------------------

@dataclass
class PhaseConfig:
    """Single phase definition for the adaptive ladder."""
    name: str
    label: str
    duration_seconds: float
    rps_factor: float
    is_warmup: bool = False
    is_validate: bool = False
    is_cooldown: bool = False


def load_phase_config(config_path: str = "config/auto_mode.json") -> dict:
    """Load auto_mode.json. Returns dict, never raises."""
    import json

    default_config = {
        "engine": {
            "default": "raw_http11",
            "fallback_threshold_pct": 10,
            "fallback_window_seconds": 5,
            "pipeline_depth": 6,
            "max_payload_bytes": 300,
            "connection_pool_per_worker": 50,
            "socket_send_chunk_bytes": 1024,
            "tcp_nodelay": True,
            "so_reuseaddr": True,
            "so_linger_zero": True,
            "keep_alive_seconds": 30,
        },
        "thread_isolation": {
            "stats_queue_maxsize": 1000,
            "drop_old_when_full": True,
            "monitor_thread_daemon": True,
            "executor_max_workers_multiplier": 2,
            "dashboard_fps": 20,
            "dashboard_refresh_ms": 50,
            "stalled_threshold_ms": 1500,
        },
        "phases": {
            "phase_0_recon": {"duration_seconds": 5, "rps_factor": 0.0, "label": "RECON"},
            "phase_1_warmup": {"duration_pct": 0.10, "rps_factor": 0.10, "label": "WARMUP"},
            "phase_2_ramp": {"duration_pct": 0.20, "rps_factor": 0.35, "label": "RAMP"},
            "phase_3_peak": {"duration_pct": 0.40, "rps_factor": 1.00, "label": "PEAK"},
            "phase_4_validate": {
                "duration_pct": 0.10, "rps_factor": 0.75, "label": "VALIDATE",
                "ping_check": True, "ping_rtt_threshold_ms": 3000,
                "saturated_rps_factor": 0.25,
            },
            "phase_5_cooldown": {"duration_pct": 0.20, "rps_factor": 0.50, "label": "COOLDOWN"},
        },
        "self_health": {
            "loop_lag_check_interval_seconds": 10.0,
            "loop_lag_threshold_ms": 5000,
            "wsa_would_block_window_seconds": 10.0,
            "wsa_would_block_threshold": 500,
            "throttle_factor_on_overload": 0.99,
        },
        "validation": {
            "buffer_validate_send_return": True,
        },
        "windows_optimization": {
            "process_priority": "BELOW_NORMAL",
            "affinity_even_cores_only": True,
            "minimum_concurrent_per_worker": 10,
            "maximum_concurrent_per_worker": 100,
        },
    }

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        # Shallow merge into default
        def _merge(base: dict, over: dict) -> dict:
            for k, v in over.items():
                if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                    _merge(base[k], v)
                else:
                    base[k] = v
            return base
        return _merge(default_config, loaded)
    except FileNotFoundError:
        logger.warning("[config] %s not found - using defaults", config_path)
        return default_config
    except Exception as e:
        logger.error("[config] %s parse error: %s - using defaults", config_path, e)
        return default_config


def build_phase_schedule(total_duration: int, config: dict) -> list:
    """Build ordered list of PhaseConfig from total duration and config."""
    phases_cfg = config.get("phases", {})
    schedule = []

    # Phase 0: fixed seconds (recon)
    p0 = phases_cfg.get("phase_0_recon", {})
    schedule.append(PhaseConfig(
        name="phase_0_recon",
        label=p0.get("label", "RECON"),
        duration_seconds=float(p0.get("duration_seconds", 5)),
        rps_factor=float(p0.get("rps_factor", 0.0)),
    ))

    # Phases 1-5: percentage of total_duration
    remaining = max(0.0, float(total_duration) - schedule[0].duration_seconds)
    for key in ("phase_1_warmup", "phase_2_ramp", "phase_3_peak",
                "phase_4_validate", "phase_5_cooldown"):
        p = phases_cfg.get(key, {})
        pct = float(p.get("duration_pct", 0.0))
        dur = max(1.0, remaining * pct)
        schedule.append(PhaseConfig(
            name=key,
            label=p.get("label", key.upper()),
            duration_seconds=dur,
            rps_factor=float(p.get("rps_factor", 0.5)),
            is_warmup=(key == "phase_1_warmup"),
            is_validate=(key == "phase_4_validate"),
            is_cooldown=(key == "phase_5_cooldown"),
        ))

    return schedule


# ----------------------------------------------------------------------
# Windows process tuning
# ----------------------------------------------------------------------

def apply_windows_optimization(below_normal_priority: bool = True,
                               even_cores_only: bool = True) -> dict:
    """
    Apply Windows-specific process tuning.
    Returns dict describing what was applied (for diagnostics).
    """
    result = {
        "platform": sys.platform,
        "priority_set": False,
        "affinity_set": False,
        "affinity_cores": [],
        "errors": [],
    }

    if sys.platform != "win32":
        return result

    try:
        import psutil
        proc = psutil.Process(os.getpid())

        if below_normal_priority:
            try:
                # BELOW_NORMAL_PRIORITY_CLASS = 0x4000
                proc.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
                result["priority_set"] = True
            except Exception as e:
                result["errors"].append(f"priority: {e}")

        if even_cores_only:
            try:
                cpu_count = psutil.cpu_count(logical=True) or 4
                even_cores = list(range(0, cpu_count, 2))
                if even_cores:
                    proc.cpu_affinity(even_cores)
                    result["affinity_set"] = True
                    result["affinity_cores"] = even_cores
            except Exception as e:
                result["errors"].append(f"affinity: {e}")
    except ImportError:
        result["errors"].append("psutil not installed")
    except Exception as e:
        result["errors"].append(str(e))

    return result
