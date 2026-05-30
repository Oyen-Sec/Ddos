"""
Modern Rich-powered live dashboard.
Multi-panel layout with smooth refresh, no flicker, full-screen.
"""
import asyncio
import time
from datetime import datetime
from typing import Dict, List, Optional

from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
from rich.console import Console


def fmt_num(n: int) -> str:
    if n < 1000:
        return str(n)
    if n < 1_000_000:
        return f"{n/1000:.1f}k"
    if n < 1_000_000_000:
        return f"{n/1_000_000:.2f}M"
    return f"{n/1_000_000_000:.2f}B"


def fmt_time(secs: int) -> str:
    if secs < 0:
        secs = 0
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    if h > 0:
        return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


class LiveAttackDashboard:
    """Rich-based live dashboard with full-screen layout"""

    def __init__(self, target: str, vectors: List[Dict], proxy_pool=None,
                 duration: int = 0, color_func=None,
                 origin_ip: str = "", profile_info: Dict = None,
                 screen: bool = False):
        self.target = target
        self.origin_ip = origin_ip
        self.profile_info = profile_info or {}
        self.vectors = vectors
        self.proxy_pool = proxy_pool
        self.duration = duration if duration > 0 else 60
        self._screen = screen
        self.start_time = time.time()
        self._stop = False
        self._task: Optional[asyncio.Task] = None
        self._tick = 0
        self._peak_rps = 0
        self._max_vec_rps = 1

        self.console = Console()
        self.layout = self._build_layout()

        self.progress = Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[bold white]{task.description}"),
            BarColumn(bar_width=40, complete_style="green", finished_style="cyan"),
            TextColumn("[bold]{task.percentage:>3.1f}%"),
            TextColumn("[bright_black]({task.completed:.0f}/{task.total:.0f}s)"),
            expand=True,
        )
        self.task_id = self.progress.add_task("OVERALL PROGRESS", total=self.duration)

        self._live: Optional[Live] = None

    def _build_layout(self) -> Layout:
        layout = Layout()
        layout.split(
            Layout(name="header", size=4),
            Layout(name="info", size=4),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=4),
        )
        return layout

    def _generate_table(self) -> Table:
        elapsed = time.time() - self.start_time
        spinners = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        sp = spinners[self._tick % len(spinners)]

        # Find max RPS for relative bar scaling
        max_rps = 1
        for vec in self.vectors:
            stats = vec.get("stats", {})
            rps = stats.get("current_rps", 0)
            if rps == 0 and elapsed > 0:
                rps = stats.get("completed", 0) / elapsed
            if rps > max_rps:
                max_rps = rps
        if max_rps > self._max_vec_rps:
            self._max_vec_rps = max_rps

        tabel = Table(expand=True, border_style="bright_black",
                      show_header=True, header_style="bold white on grey15")
        tabel.add_column("STATUS", justify="left", width=14)
        tabel.add_column("VECTOR / TASK", justify="left", ratio=2)
        tabel.add_column("REQ", justify="right", width=9)
        tabel.add_column("OK", justify="right", width=9)
        tabel.add_column("FAIL", justify="right", width=7)
        tabel.add_column("RPS", justify="right", width=7)
        tabel.add_column("LOAD", justify="left", ratio=1)

        for vec in self.vectors:
            stats = vec.get("stats", {})
            status = vec.get("status", "pending")
            label = vec.get("label", "?")
            
            # Thread-safe stats read with lock (if available)
            stats_lock = vec.get("stats_lock")
            if stats_lock:
                with stats_lock:
                    req = stats.get("total_requests", 0)
                    ok = stats.get("completed", 0)
                    fail = stats.get("failed", 0)
            else:
                req = stats.get("total_requests", 0)
                ok = stats.get("completed", 0)
                fail = stats.get("failed", 0)
            
            rps = stats.get("current_rps", 0)
            if rps == 0 and elapsed > 0 and ok > 0:
                rps = ok / elapsed

            # Status cell
            if status == "running":
                status_cell = f"[bold green]{sp} ACTIVE[/]"
                if rps >= 800:
                    speed_cell = f"[bold green]{rps:.0f}[/]"
                elif rps >= 100:
                    speed_cell = f"[bold yellow]{rps:.0f}[/]"
                else:
                    speed_cell = f"[bold red]{rps:.0f}[/]"
                # Mini bar showing relative load
                load_pct = (rps / self._max_vec_rps) * 100 if self._max_vec_rps > 0 else 0
                bar_width = 16
                filled = int(bar_width * load_pct / 100)
                if rps >= 800:
                    load_bar = f"[green]{'█' * filled}[/][bright_black]{'░' * (bar_width - filled)}[/]"
                elif rps >= 100:
                    load_bar = f"[yellow]{'█' * filled}[/][bright_black]{'░' * (bar_width - filled)}[/]"
                else:
                    load_bar = f"[red]{'█' * filled}[/][bright_black]{'░' * (bar_width - filled)}[/]"
            elif status == "pending":
                status_cell = f"[bold yellow]• STARTING[/]"
                speed_cell = f"[bright_black]0[/]"
                load_bar = f"[bright_black]{'░' * 16}[/]"
            elif status == "done":
                status_cell = f"[bold cyan]+ DONE[/]"
                speed_cell = f"[bright_black]{rps:.0f}[/]"
                load_bar = f"[cyan]{'█' * 16}[/]"
            elif status == "error":
                status_cell = f"[bold red]! ERROR[/]"
                speed_cell = f"[bold red]0[/]"
                load_bar = f"[red]{'X' * 16}[/]"
            else:
                status_cell = f"[dim]{status}[/]"
                speed_cell = f"[bright_black]0[/]"
                load_bar = f"[bright_black]{'░' * 16}[/]"

            tabel.add_row(
                status_cell,
                label,
                f"[bright_blue]{fmt_num(req)}[/]",
                f"[green]{fmt_num(ok)}[/]",
                f"[red]{fmt_num(fail)}[/]",
                speed_cell,
                load_bar,
            )
        return tabel

    def _build_header(self) -> Panel:
        now = datetime.now().strftime("%H:%M:%S")
        active = sum(1 for v in self.vectors if v.get("status") == "running")
        total = len(self.vectors)
        elapsed = time.time() - self.start_time
        remaining = max(0, self.duration - int(elapsed))
        
        # Count vector types
        http_count = sum(1 for v in self.vectors if any(x in v.get("label", "").lower() for x in ["http", "rapid", "hpack", "continuation", "settings", "smuggling", "cache"]))
        quic_count = sum(1 for v in self.vectors if "quic" in v.get("label", "").lower() or "http/3" in v.get("label", "").lower())
        api_count = sum(1 for v in self.vectors if any(x in v.get("label", "").lower() for x in ["rest", "graphql", "grpc", "json", "xml"]))
        dow_count = sum(1 for v in self.vectors if any(x in v.get("label", "").lower() for x in ["cold", "cost"]))
        
        return Panel(
            f"[bold white]Multi-Protocol Concurrency Layer | Asynchronous Attack Vector Engine[/]  "
            f"[bright_black]|[/]  [bold cyan]{self.target[:50]}[/]\n"
            f"[bold]Vectors:[/] [green]{active}[/]/[bold]{total}[/]  "
            f"[bright_black]|[/]  HTTP/2: [cyan]{http_count}[/]  QUIC: [magenta]{quic_count}[/]  API: [yellow]{api_count}[/]  DoW: [red]{dow_count}[/]  "
            f"[bright_black]|[/]  Time: [yellow]{fmt_time(remaining)}[/]  [bright_black]{now}[/]",
            border_style="cyan",
            title="[bold magenta]◆ LIVE ATTACK MONITOR ◆[/]",
            title_align="center",
        )

    def _build_info_panel(self) -> Panel:
        """Target info: origin, profile, bandwidth, vector breakdown"""
        lines = []

        # Origin info
        if self.origin_ip:
            lines.append(f"[bold]Origin:[/] [green]{self.origin_ip}[/] [bright_black](CDN bypass active)[/]")
        else:
            lines.append(f"[bold]Origin:[/] [bright_black]direct target (no bypass)[/]")

        # Profile info
        if self.profile_info:
            http2 = "[green]YES[/]" if self.profile_info.get("http2") else "[red]NO[/]"
            cdn = self.profile_info.get("cdn", "none")
            cdn_str = f"[yellow]{cdn}[/]" if cdn != "none" else "[green]none[/]"
            waf = self.profile_info.get("waf", "none")
            waf_str = f"[red]{waf}[/]" if waf != "none" else "[green]none[/]"
            server = self.profile_info.get("server", "unknown")
            lines.append(
                f"[bold]Profile:[/] HTTP/2={http2}  CDN={cdn_str}  WAF={waf_str}  Server=[cyan]{server[:25]}[/]"
            )
        
        # Vector breakdown
        go_vecs = sum(1 for v in self.vectors if v.get("type") == "go")
        py_vecs = sum(1 for v in self.vectors if v.get("type") == "py")
        lines.append(f"[bold]Vectors:[/] Go=[cyan]{go_vecs}[/]  Python=[yellow]{py_vecs}[/]  Total=[bold]{len(self.vectors)}[/]")

        return Panel(
            "\n".join(lines),
            border_style="bright_black",
            title="[bold]◆ Target Intelligence ◆[/]",
            title_align="left",
        )

    def _build_footer(self) -> Panel:
        total_req = 0
        total_ok = 0
        total_fail = 0
        total_to = 0
        
        # Thread-safe stats aggregation
        for v in self.vectors:
            stats_lock = v.get("stats_lock")
            stats = v.get("stats", {})
            if stats_lock:
                with stats_lock:
                    total_req += stats.get("total_requests", 0)
                    total_ok += stats.get("completed", 0)
                    total_fail += stats.get("failed", 0)
                    total_to += stats.get("timeout", 0)
            else:
                total_req += stats.get("total_requests", 0)
                total_ok += stats.get("completed", 0)
                total_fail += stats.get("failed", 0)
                total_to += stats.get("timeout", 0)
        
        elapsed = time.time() - self.start_time
        rps = total_ok / max(elapsed, 1)
        if rps > self._peak_rps:
            self._peak_rps = rps
        success = (total_ok / max(total_req, 1)) * 100 if total_req else 0

        # Estimate bandwidth (rough: 1 req = ~2KB avg)
        est_bandwidth_mb = (total_ok * 2) / 1024
        
        proxy_info = ""
        if self.proxy_pool:
            try:
                stats = self.proxy_pool.stats()
                px = stats.get("total", 0)
                palive = stats.get("alive", px)
                pdead = stats.get("dead", 0)
                if px > 0:
                    proxy_info = f"  [bold]Proxy:[/] [green]{palive}[/]/[bright_black]{px}[/] alive [red]{pdead}[/] dead"
            except Exception:
                pass

        line1 = (
            f"[bold]TOTAL:[/] [bright_blue]{fmt_num(total_req)}[/] req  "
            f"[green]{fmt_num(total_ok)}[/] ok  [red]{fmt_num(total_fail)}[/] fail  "
            f"[yellow]{fmt_num(total_to)}[/] timeout  "
            f"[bold cyan]{success:.1f}%[/] success"
        )
        line2 = (
            f"[bold]RPS:[/] [yellow]{rps:.0f}[/] current  [bold yellow]{self._peak_rps:.0f}[/] peak  "
            f"[bold]Bandwidth:[/] [cyan]~{est_bandwidth_mb:.1f}MB[/] sent"
            f"{proxy_info}"
        )

        return Panel(
            line1 + "\n" + line2,
            border_style="bright_black",
            title="[bold]◆ Combined Stats ◆[/]",
            title_align="left",
        )

    def _render_main(self):
        elapsed = time.time() - self.start_time
        self.progress.update(self.task_id, completed=min(elapsed, self.duration))

        main_layout = Layout()
        main_layout.split(
            Layout(Panel(self.progress, border_style="bright_black",
                          title="[bold]Overall Progress[/]"), size=5),
            Layout(Panel(self._generate_table(), border_style="bright_black",
                          title="[bold]Vector Status[/]")),
        )
        return main_layout

    def _render(self):
        self.layout["header"].update(self._build_header())
        self.layout["info"].update(self._build_info_panel())
        self.layout["main"].update(self._render_main())
        self.layout["footer"].update(self._build_footer())
        return self.layout

    def start(self):
        """Start dashboard - non-blocking"""
        self._live = Live(
            self._render(),
            refresh_per_second=10,
            screen=self._screen,
            console=self.console,
        )
        self._live.start()
        self._task = asyncio.create_task(self._loop())

    async def stop(self):
        self._stop = True
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=2)
            except Exception:
                self._task.cancel()
        if self._live:
            self._live.stop()
            self._live = None
        self._print_final_summary()

    async def _loop(self):
        try:
            while not self._stop:
                self._tick += 1
                if self._live:
                    self._live.update(self._render())
                await asyncio.sleep(0.05)  # FASTER: 50ms instead of 100ms = 20 FPS
        except asyncio.CancelledError:
            pass
        except Exception as e:
            try:
                self.console.print(f"[red]Dashboard error: {e}[/]")
            except Exception:
                pass

    def _print_final_summary(self):
        """Print persistent final summary after live ends"""
        elapsed = time.time() - self.start_time
        total_req = sum(v.get("stats", {}).get("total_requests", 0) for v in self.vectors)
        total_ok = sum(v.get("stats", {}).get("completed", 0) for v in self.vectors)
        total_fail = sum(v.get("stats", {}).get("failed", 0) for v in self.vectors)
        rps = total_ok / max(elapsed, 1)
        success = (total_ok / max(total_req, 1)) * 100 if total_req else 0

        tabel = Table(title="[bold green]ATTACK COMPLETE[/]", border_style="green",
                       show_header=True, header_style="bold")
        tabel.add_column("STATUS", width=12)
        tabel.add_column("VECTOR", justify="left", ratio=2)
        tabel.add_column("REQ", justify="right", width=10)
        tabel.add_column("OK", justify="right", width=10)
        tabel.add_column("FAIL", justify="right", width=8)

        for vec in self.vectors:
            stats = vec.get("stats", {})
            status = vec.get("status", "?")
            label = vec.get("label", "?")
            req = stats.get("total_requests", 0)
            ok = stats.get("completed", 0)
            fail = stats.get("failed", 0)

            if status == "done":
                status_cell = "[bold green]+ DONE[/]"
            elif status == "error":
                status_cell = "[bold red]! FAIL[/]"
            else:
                status_cell = f"[yellow]{status}[/]"

            tabel.add_row(
                status_cell, label,
                f"[bright_blue]{fmt_num(req)}[/]",
                f"[green]{fmt_num(ok)}[/]",
                f"[red]{fmt_num(fail)}[/]",
            )

        self.console.print()
        self.console.print(tabel)
        self.console.print(
            f"[bold]TOTAL:[/] req=[bright_blue]{fmt_num(total_req)}[/] "
            f"[green]ok={fmt_num(total_ok)}[/] [red]fail={fmt_num(total_fail)}[/] "
            f"| Duration: [white]{fmt_time(int(elapsed))}[/] "
            f"| RPS: [yellow]{rps:.0f}[/] "
            f"| Success: [green]{success:.1f}%[/]"
        )
        self.console.print()
