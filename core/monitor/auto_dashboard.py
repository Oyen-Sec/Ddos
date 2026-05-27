"""
Thread-isolated Auto Mode Dashboard
====================================
Renders live attack metrics via rich.live in a DEDICATED thread.
The render thread NEVER does network I/O - it only reads from queue.Queue.

Architecture:
    [Attack Thread] -> stats_queue -> [Dashboard Thread] -> rich.Live render
    [SelfHealth]    -> health_snap -> [Dashboard Thread]

Refresh rate: 20 FPS guaranteed (50ms interval).
If no data in stats_queue for >1500ms, vector status switches to STALLED (red).

This module deliberately avoids:
- Any asyncio code in the render path
- Any blocking I/O on the main loop
- Any shared mutex with attack workers (uses queue.Queue thread-safe)

Console safety: forces UTF-8 output to avoid Windows cp1252 charmap errors.
"""
from __future__ import annotations

import logging
import os
import queue
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

# Force UTF-8 console on Windows to allow Unicode block chars in sparkline
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

logger = logging.getLogger("auto_dashboard")


# ----------------------------------------------------------------------
# Status states
# ----------------------------------------------------------------------

VECTOR_STATES = {
    "STARTING":  "yellow",
    "WARMUP":    "blue",
    "ACTIVE":    "green",
    "THROTTLED": "red",
    "COOLDOWN":  "cyan",
    "DONE":      "white",
    "STALLED":   "bright_red",
    "ERROR":     "bright_red",
}


@dataclass
class VectorRow:
    """Per-vector aggregated state shown in dashboard table."""
    name: str
    label: str
    status: str = "STARTING"
    sent: int = 0
    completed: int = 0
    failed: int = 0
    timeout: int = 0
    local_drops: int = 0
    wsa_blocks: int = 0
    bytes_sent: int = 0
    instant_rps: float = 0.0
    avg_rps: float = 0.0
    last_update_ts: float = 0.0
    elapsed: float = 0.0


@dataclass
class GlobalState:
    """Aggregated global counters & phase info shown in header panel."""
    target: str = ""
    duration: float = 0.0
    started_at: float = field(default_factory=time.time)
    phase_label: str = "INIT"
    phase_index: int = 0
    phase_total: int = 6
    phase_elapsed: float = 0.0
    phase_duration: float = 0.0
    target_rps: int = 0
    actual_rps_total: float = 0.0
    rps_factor: float = 1.0
    loop_lag_ms: float = 0.0
    wsa_blocks_1s: int = 0
    is_overloaded: bool = False
    is_saturated: bool = False
    network_rtt_ms: float = 0.0
    engine_label: str = "raw_http11"
    note: str = ""


# ----------------------------------------------------------------------
# Dashboard Renderer (runs in dedicated thread)
# ----------------------------------------------------------------------

class AutoDashboard:
    """
    Thread-isolated dashboard for [9] Auto Mode v2.

    Public API (thread-safe):
        start()
        stop()
        register_vector(name, label) - call BEFORE attack worker starts
        update_global(state_dict_or_kwargs) - update global state
        feed_stats_queue() returns the queue.Queue you pass to workers
    """

    STALLED_MS_DEFAULT = 5000
    REFRESH_MS_DEFAULT = 50

    def __init__(
        self,
        target: str,
        duration: float,
        target_rps: int,
        stalled_ms: int = STALLED_MS_DEFAULT,
        refresh_ms: int = REFRESH_MS_DEFAULT,
        console: Optional[Console] = None,
    ) -> None:
        self.global_state = GlobalState(
            target=target,
            duration=float(duration),
            target_rps=int(target_rps),
        )
        self.stalled_ms = int(stalled_ms)
        self.refresh_ms = int(refresh_ms)
        self.refresh_per_second = max(1, int(1000 / max(1, refresh_ms)))
        # Force UTF-8 console to avoid Windows cp1252 charmap errors on block chars
        if console is None:
            try:
                self.console = Console(force_terminal=True, legacy_windows=False, color_system="truecolor")
            except Exception:
                self.console = Console()
        else:
            self.console = console
        # Detect if console can render Unicode (block chars used in sparkline)
        try:
            enc = (getattr(self.console.file, "encoding", None) or "").lower()
            self._unicode_ok = ("utf" in enc) or os.environ.get("PYTHONUTF8") == "1"
        except Exception:
            self._unicode_ok = False

        # Thread-safe data
        self._lock = threading.Lock()
        self._vectors: Dict[str, VectorRow] = {}
        self._stats_queue: "queue.Queue" = queue.Queue(maxsize=2000)
        self._health_snapshot: Optional[dict] = None

        # Rolling per-second RPS history (last 60 samples)
        self._rps_history: deque = deque(maxlen=60)
        self._last_global_rps_ts: float = time.time()
        self._last_global_sent: int = 0

        # Per-worker last-seen values for delta-based aggregation
        self._worker_peek: Dict[str, Dict[str, int]] = {}

        # Lifecycle
        self._stop_event = threading.Event()
        self._render_thread: Optional[threading.Thread] = None
        self._consumer_thread: Optional[threading.Thread] = None
        self._live: Optional[Live] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_stats_queue(self) -> "queue.Queue":
        """Pass this queue to all attack workers."""
        return self._stats_queue

    def get_total_sent(self) -> int:
        """Thread-safe read of total sent across all vectors (for stall detection)."""
        with self._lock:
            return sum(v.sent for v in self._vectors.values())

    def register_vector(self, name: str, label: str) -> None:
        """Register a vector before workers start. Status = STARTING."""
        with self._lock:
            self._vectors[name] = VectorRow(
                name=name,
                label=label,
                status="STARTING",
                last_update_ts=time.time(),
            )

    def set_vector_status(self, name: str, status: str) -> None:
        """External status change (phase orchestrator)."""
        with self._lock:
            v = self._vectors.get(name)
            if v is None:
                return
            v.status = status
            v.last_update_ts = time.time()

    def set_global_phase(
        self,
        label: str,
        index: int,
        total: int,
        duration: float,
        elapsed: float = 0.0,
    ) -> None:
        with self._lock:
            self.global_state.phase_label = label
            self.global_state.phase_index = int(index)
            self.global_state.phase_total = int(total)
            self.global_state.phase_duration = float(duration)
            self.global_state.phase_elapsed = float(elapsed)

    def set_global_health(self, snapshot: dict) -> None:
        """Push HealthSnapshot.__dict__ here every monitor tick."""
        with self._lock:
            self._health_snapshot = dict(snapshot)
            self.global_state.rps_factor = float(snapshot.get("current_rps_factor", 1.0))
            self.global_state.loop_lag_ms = float(snapshot.get("loop_lag_ms", 0.0))
            self.global_state.wsa_blocks_1s = int(snapshot.get("wsa_block_count_1s", 0))
            self.global_state.is_overloaded = bool(snapshot.get("is_overloaded", False))
            self.global_state.is_saturated = bool(snapshot.get("is_saturated", False))
            self.global_state.network_rtt_ms = float(snapshot.get("network_rtt_ms", 0.0))

    def set_global_note(self, note: str) -> None:
        with self._lock:
            self.global_state.note = str(note)

    def set_engine_label(self, label: str) -> None:
        with self._lock:
            self.global_state.engine_label = str(label)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start render + consumer threads."""
        if self._render_thread is not None:
            return
        self._stop_event.clear()
        self._consumer_thread = threading.Thread(
            target=self._consumer_loop,
            name="dashboard_consumer",
            daemon=True,
        )
        self._render_thread = threading.Thread(
            target=self._render_loop,
            name="dashboard_render",
            daemon=True,
        )
        self._consumer_thread.start()
        self._render_thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        """Signal threads to stop and join."""
        self._stop_event.set()
        if self._consumer_thread is not None:
            try:
                self._consumer_thread.join(timeout=timeout)
            except Exception:
                pass
        if self._render_thread is not None:
            try:
                self._render_thread.join(timeout=timeout)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Consumer thread: drain stats_queue, update VectorRow
    # ------------------------------------------------------------------

    def _consumer_loop(self) -> None:
        """
        Reads from stats_queue continuously and updates per-vector state.
        Each stats item is dict with: worker_id, vector_name (optional), sent, etc.
        """
        while not self._stop_event.is_set():
            try:
                item = self._stats_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            except Exception:
                continue
            if not isinstance(item, dict):
                continue
            self._apply_stats(item)

    def _apply_stats(self, item: dict) -> None:
        """
        Apply stats dict to corresponding VectorRow.

        FIX: Use per-worker last-seen tracking and SUM across workers.
        Previously used max() which undercounted when multiple workers
        reported to the same vector (only the highest single worker showed).
        """
        vname = item.get("vector_name") or item.get("worker_label") or item.get("vector")
        if not vname:
            vname = "raw_http11"

        worker_id = item.get("worker_id", 0)
        wid_key = f"{vname}_{worker_id}"

        with self._lock:
            v = self._vectors.get(vname)
            if v is None:
                v = VectorRow(name=vname, label=vname, status="ACTIVE")
                self._vectors[vname] = v

            # Per-worker tracking: store the delta since last report
            prev = self._worker_peek.get(wid_key, {})
            delta_sent = int(item.get("sent", 0)) - prev.get("sent", 0)
            delta_completed = int(item.get("completed", 0)) - prev.get("completed", 0)
            delta_failed = int(item.get("failed", 0)) - prev.get("failed", 0)
            delta_timeout = int(item.get("timeout", 0)) - prev.get("timeout", 0)

            if delta_sent > 0:
                v.sent += delta_sent
            if delta_completed > 0:
                v.completed += delta_completed
            if delta_failed > 0:
                v.failed += delta_failed
            if delta_timeout > 0:
                v.timeout += delta_timeout

            # Non-cumulative fields: take latest
            v.local_drops = max(v.local_drops, int(item.get("local_drops", v.local_drops)))
            v.wsa_blocks = max(v.wsa_blocks, int(item.get("wsa_blocks", v.wsa_blocks)))
            v.bytes_sent = max(v.bytes_sent, int(item.get("bytes_sent", v.bytes_sent)))
            v.instant_rps = float(item.get("instant_rps", v.instant_rps))
            v.avg_rps = float(item.get("avg_rps", v.avg_rps))
            v.elapsed = float(item.get("elapsed", v.elapsed))
            v.last_update_ts = time.time()

            # Store current values for next delta calculation
            self._worker_peek[wid_key] = {
                "sent": int(item.get("sent", 0)),
                "completed": int(item.get("completed", 0)),
                "failed": int(item.get("failed", 0)),
                "timeout": int(item.get("timeout", 0)),
            }

            if v.status == "STARTING" and v.sent > 0:
                v.status = "ACTIVE"

    # ------------------------------------------------------------------
    # Render thread
    # ------------------------------------------------------------------

    def _render_loop(self) -> None:
        """Render at 20 FPS using rich.Live."""
        try:
            with Live(
                self._build_layout(),
                console=self.console,
                refresh_per_second=self.refresh_per_second,
                screen=False,
                transient=False,
                redirect_stdout=False,
                redirect_stderr=False,
            ) as live:
                self._live = live
                while not self._stop_event.is_set():
                    try:
                        live.update(self._build_layout())
                    except Exception as e:
                        logger.debug("[render] update error: %s", e)
                    time.sleep(self.refresh_ms / 1000.0)
        except Exception as e:
            logger.error("[render] fatal: %s", e)
        finally:
            self._live = None

    # ------------------------------------------------------------------
    # Layout builders
    # ------------------------------------------------------------------

    def _build_layout(self) -> Group:
        """Build the full dashboard layout. Returns Group of renderables."""
        with self._lock:
            gs_copy = GlobalState(
                target=self.global_state.target,
                duration=self.global_state.duration,
                started_at=self.global_state.started_at,
                phase_label=self.global_state.phase_label,
                phase_index=self.global_state.phase_index,
                phase_total=self.global_state.phase_total,
                phase_elapsed=self.global_state.phase_elapsed,
                phase_duration=self.global_state.phase_duration,
                target_rps=self.global_state.target_rps,
                actual_rps_total=self.global_state.actual_rps_total,
                rps_factor=self.global_state.rps_factor,
                loop_lag_ms=self.global_state.loop_lag_ms,
                wsa_blocks_1s=self.global_state.wsa_blocks_1s,
                is_overloaded=self.global_state.is_overloaded,
                is_saturated=self.global_state.is_saturated,
                network_rtt_ms=self.global_state.network_rtt_ms,
                engine_label=self.global_state.engine_label,
                note=self.global_state.note,
            )
            vectors_copy = list(self._vectors.values())

        # Compute global RPS from vector totals
        now = time.time()
        total_sent = sum(v.sent for v in vectors_copy)
        elapsed_global = max(1e-6, now - gs_copy.started_at)
        global_avg_rps = total_sent / elapsed_global

        delta_t = max(1e-6, now - self._last_global_rps_ts)
        global_instant_rps = (total_sent - self._last_global_sent) / delta_t
        if delta_t >= 1.0:
            self._last_global_rps_ts = now
            self._last_global_sent = total_sent
            self._rps_history.append(global_instant_rps)

        gs_copy.actual_rps_total = global_avg_rps

        # Detect STALLED vectors
        for v in vectors_copy:
            stale_ms = (now - v.last_update_ts) * 1000.0
            if v.status in ("ACTIVE", "WARMUP", "THROTTLED") and stale_ms > self.stalled_ms:
                # Stalled - keep displayed status as STALLED but don't mutate locked dict
                v.status = "STALLED"

        header = self._render_header(gs_copy)
        health = self._render_health(gs_copy)
        table = self._render_vector_table(vectors_copy, global_avg_rps, global_instant_rps)
        chart = self._render_rps_chart()
        footer = self._render_footer(gs_copy, total_sent, global_instant_rps)

        return Group(header, health, table, chart, footer)

    def _render_header(self, gs: GlobalState) -> Panel:
        elapsed = time.time() - gs.started_at
        pct = min(100.0, (elapsed / max(1.0, gs.duration)) * 100.0)

        line1 = (
            f"[bold cyan]Auto Mode v2[/]  "
            f"[white]target=[/][bold yellow]{gs.target}[/]  "
            f"[white]engine=[/][bold magenta]{gs.engine_label}[/]"
        )
        line2 = (
            f"[white]duration:[/] {elapsed:6.1f}s / {gs.duration:.0f}s ({pct:5.1f}%)  "
            f"[white]target_rps:[/] [bold]{gs.target_rps}[/]  "
            f"[white]rps_factor:[/] [bold {'red' if gs.rps_factor < 0.5 else 'green'}]{gs.rps_factor:.2f}[/]"
        )
        phase_color = "yellow"
        phase_pct = 0.0
        if gs.phase_duration > 0:
            phase_pct = min(100.0, (gs.phase_elapsed / gs.phase_duration) * 100.0)
        line3 = (
            f"[white]phase {gs.phase_index}/{gs.phase_total}:[/] "
            f"[bold {phase_color}]{gs.phase_label}[/]  "
            f"[white]elapsed:[/] {gs.phase_elapsed:.1f}s / {gs.phase_duration:.1f}s ({phase_pct:.0f}%)"
        )
        if gs.note:
            line3 += f"   [dim]note:[/] [italic]{gs.note}[/]"
        return Panel(
            f"{line1}\n{line2}\n{line3}",
            border_style="bright_black",
            title="[bold]MULTI-PROTOCOL CONCURRENCY LAYER v5.0[/]",
            title_align="left",
        )

    def _render_health(self, gs: GlobalState) -> Panel:
        lag_color = "green" if gs.loop_lag_ms < 50 else ("yellow" if gs.loop_lag_ms < 100 else "red")
        rtt_color = "green" if gs.network_rtt_ms < 500 else ("yellow" if gs.network_rtt_ms < 2000 else "red")
        wsa_color = "green" if gs.wsa_blocks_1s == 0 else ("yellow" if gs.wsa_blocks_1s < 3 else "red")
        overload_text = f"[bold red]OVERLOADED[/]" if gs.is_overloaded else f"[bold green]OK[/]"
        sat_text = f"[bold red]SATURATED[/]" if gs.is_saturated else f"[bold green]NORMAL[/]"

        line = (
            f"[white]event_loop_lag:[/] [{lag_color}]{gs.loop_lag_ms:6.1f}ms[/]   "
            f"[white]wsa_blocks/s:[/] [{wsa_color}]{gs.wsa_blocks_1s:3d}[/]   "
            f"[white]network_rtt:[/] [{rtt_color}]{gs.network_rtt_ms:7.1f}ms[/]   "
            f"[white]system:[/] {overload_text}   "
            f"[white]network:[/] {sat_text}"
        )
        return Panel(line, border_style="bright_black", title="[bold]SELF-HEALTH[/]", title_align="left")

    def _render_vector_table(
        self,
        vectors: List[VectorRow],
        global_avg_rps: float,
        global_instant_rps: float,
    ) -> Panel:
        tbl = Table(expand=True, show_header=True, header_style="bold white on grey15", border_style="bright_black")
        tbl.add_column("STATUS", justify="left", width=12)
        tbl.add_column("VECTOR", justify="left", ratio=2)
        tbl.add_column("SENT", justify="right", width=10)
        tbl.add_column("OK", justify="right", width=10)
        tbl.add_column("FAIL", justify="right", width=8)
        tbl.add_column("LDROP", justify="right", width=7)
        tbl.add_column("WSA", justify="right", width=6)
        tbl.add_column("RPS", justify="right", width=8)
        tbl.add_column("LOAD", justify="left", ratio=1)

        # Find max RPS for bar scaling
        max_rps = max((v.instant_rps for v in vectors), default=1.0)
        if max_rps < 1.0:
            max_rps = 1.0

        if not vectors:
            tbl.add_row("[dim]waiting[/]", "[dim]No vectors registered yet[/]",
                       "0", "0", "0", "0", "0", "0", "")
        else:
            for v in vectors:
                color = VECTOR_STATES.get(v.status, "white")
                spinner = "*" if v.status in ("ACTIVE", "THROTTLED", "WARMUP") else " "
                status_cell = f"[bold {color}]{spinner} {v.status}[/]"

                rps_cell = f"[bold]{v.instant_rps:6.0f}[/]"
                if v.instant_rps >= 200:
                    rps_cell = f"[bold green]{v.instant_rps:6.0f}[/]"
                elif v.instant_rps >= 50:
                    rps_cell = f"[bold yellow]{v.instant_rps:6.0f}[/]"
                else:
                    rps_cell = f"[bold red]{v.instant_rps:6.0f}[/]"

                load_pct = (v.instant_rps / max_rps) * 100.0 if max_rps > 0 else 0.0
                bar_w = 16
                filled = int(bar_w * load_pct / 100.0)
                bar_color = "green" if v.instant_rps >= 200 else ("yellow" if v.instant_rps >= 50 else "red")
                load_bar = (
                    f"[{bar_color}]{'#' * filled}[/]"
                    f"[bright_black]{'.' * (bar_w - filled)}[/]"
                )

                tbl.add_row(
                    status_cell,
                    v.label,
                    self._fmt_num(v.sent),
                    self._fmt_num(v.completed),
                    self._fmt_num(v.failed),
                    self._fmt_num(v.local_drops),
                    self._fmt_num(v.wsa_blocks),
                    rps_cell,
                    load_bar,
                )

        # Summary footer row
        total_sent = sum(v.sent for v in vectors)
        total_ok = sum(v.completed for v in vectors)
        total_fail = sum(v.failed for v in vectors)
        total_drop = sum(v.local_drops for v in vectors)
        total_wsa = sum(v.wsa_blocks for v in vectors)
        tbl.add_section()
        tbl.add_row(
            "[bold cyan]TOTAL[/]",
            "[bold]Aggregated[/]",
            f"[bold cyan]{self._fmt_num(total_sent)}[/]",
            f"[bold green]{self._fmt_num(total_ok)}[/]",
            f"[bold red]{self._fmt_num(total_fail)}[/]",
            f"[bold yellow]{self._fmt_num(total_drop)}[/]",
            f"[bold yellow]{self._fmt_num(total_wsa)}[/]",
            f"[bold cyan]{global_instant_rps:6.0f}[/]",
            "",
        )

        return Panel(tbl, border_style="bright_black", title="[bold]VECTORS[/]", title_align="left")

    def _render_rps_chart(self) -> Panel:
        """Sparkline chart of last 60 seconds of global RPS."""
        if not self._rps_history:
            content = Text("waiting for traffic...", style="dim italic")
        else:
            history = list(self._rps_history)
            max_v = max(history) if history else 1.0
            if max_v < 1.0:
                max_v = 1.0
            avg_v = sum(history) / len(history) if history else 0.0
            cur_v = history[-1] if history else 0.0
            # Always use Unicode block chars (main.py forces UTF-8 stdout)
            blocks = " \u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588"
            # Build colored chart: green=high, yellow=mid, red=low
            chart_parts: List[str] = []
            for v in history:
                ratio = (v / max_v) if max_v > 0 else 0.0
                idx = int(ratio * (len(blocks) - 1))
                idx = max(0, min(len(blocks) - 1, idx))
                ch = blocks[idx]
                if ratio >= 0.66:
                    color = "bright_green"
                elif ratio >= 0.33:
                    color = "bright_yellow"
                else:
                    color = "bright_red"
                chart_parts.append(f"[{color}]{ch}[/]")
            chart_str = "".join(chart_parts)
            stats_line = (
                f"[bold cyan]now:[/] [bold bright_green]{cur_v:7.0f}[/] rps   "
                f"[bold cyan]avg:[/] [bold bright_yellow]{avg_v:7.0f}[/] rps   "
                f"[bold cyan]max:[/] [bold bright_magenta]{max_v:7.0f}[/] rps"
            )
            from rich.console import Group
            content = Group(
                Text.from_markup(stats_line),
                Text.from_markup(chart_str),
            )
        return Panel(content, border_style="bright_cyan",
                     title="[bold cyan]RPS TIMELINE (60s)[/]", title_align="left")

    def _render_footer(self, gs: GlobalState, total_sent: int, instant_rps: float) -> Panel:
        elapsed = time.time() - gs.started_at
        if elapsed >= gs.duration:
            status = "[bold green]COMPLETED[/]"
        else:
            remaining = gs.duration - elapsed
            status = f"[bold yellow]RUNNING[/]  remaining: {remaining:5.1f}s"
        line = (
            f"{status}   "
            f"[white]total_sent:[/] [bold cyan]{self._fmt_num(total_sent)}[/]   "
            f"[white]global_rps:[/] [bold cyan]{instant_rps:.0f}[/]   "
            f"[white]avg_rps:[/] [bold cyan]{gs.actual_rps_total:.0f}[/]"
        )
        return Panel(line, border_style="bright_black",
                     title="[bold]GLOBAL[/]", title_align="left")

    @staticmethod
    def _fmt_num(n: int) -> str:
        if n >= 1_000_000:
            return f"{n/1_000_000:.1f}M"
        if n >= 1_000:
            return f"{n/1_000:.1f}k"
        return str(int(n))


# ----------------------------------------------------------------------
# Convenience: run dashboard standalone (for tests)
# ----------------------------------------------------------------------

def demo() -> None:
    """Quick demo: register 3 fake vectors and feed random stats."""
    import random as _r

    dash = AutoDashboard(
        target="https://example.com",
        duration=15,
        target_rps=2000,
    )
    dash.register_vector("http_flood", "HTTP Flood (raw_http11)")
    dash.register_vector("rapid_reset", "Rapid Reset (CVE-2023-44487)")
    dash.register_vector("cache_bypass", "Cache-Bypass POST")

    dash.set_global_phase("WARMUP", 1, 5, duration=3.0, elapsed=0.0)
    dash.start()
    q = dash.get_stats_queue()

    start = time.time()
    sent_counters = {"http_flood": 0, "rapid_reset": 0, "cache_bypass": 0}
    try:
        while time.time() - start < 15:
            for vname in sent_counters:
                sent_counters[vname] += _r.randint(20, 80)
                q.put({
                    "vector_name": vname,
                    "sent": sent_counters[vname],
                    "completed": int(sent_counters[vname] * 0.7),
                    "failed": int(sent_counters[vname] * 0.2),
                    "local_drops": _r.randint(0, 5),
                    "wsa_blocks": _r.randint(0, 2),
                    "instant_rps": _r.randint(50, 300),
                    "avg_rps": _r.randint(40, 250),
                })
            dash.set_global_health({
                "loop_lag_ms": _r.uniform(5, 80),
                "wsa_block_count_1s": _r.randint(0, 4),
                "current_rps_factor": 1.0,
                "is_overloaded": False,
                "is_saturated": False,
                "network_rtt_ms": _r.uniform(50, 500),
            })
            time.sleep(0.3)
    finally:
        dash.stop()


if __name__ == "__main__":
    demo()
