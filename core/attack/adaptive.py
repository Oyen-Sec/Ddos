import time
import logging
from typing import Dict, Optional

logger = logging.getLogger("adaptive_controller")

class AdaptiveState:
    IDLE = "IDLE"
    RAMP_UP = "RAMP_UP"
    SUSTAIN = "SUSTAIN"
    BACKOFF = "BACKOFF"
    SWITCH_METHOD = "SWITCH_METHOD"

class AdaptiveController:
    def __init__(self, initial_rps: int = 100, max_rps: int = 10000,
                 min_rps: int = 10, target_error_pct: float = 30,
                 target_timeout_ms: float = 3000):
        self.current_rps = initial_rps
        self.max_rps = max_rps
        self.min_rps = min_rps
        self.target_error_pct = target_error_pct
        self.target_timeout_ms = target_timeout_ms
        self.state = AdaptiveState.IDLE
        self._total_requests = 0
        self._total_errors = 0
        self._total_timeouts = 0
        self._window_start = time.time()
        self._window_requests = 0
        self._window_errors = 0
        self._window_timeouts = 0
        self._window_size = 10
        self._rtt_samples = []

    def record_request(self, success: bool, timeout: bool = False, rtt_ms: float = 0):
        self._total_requests += 1
        self._window_requests += 1
        if not success:
            self._total_errors += 1
            self._window_errors += 1
        if timeout:
            self._total_timeouts += 1
            self._window_timeouts += 1
        if rtt_ms > 0:
            self._rtt_samples.append(rtt_ms)
            if len(self._rtt_samples) > 1000:
                self._rtt_samples = self._rtt_samples[-500:]

    def get_error_rate(self) -> float:
        if self._window_requests == 0:
            return 0.0
        return (self._window_errors / self._window_requests) * 100

    def get_avg_rtt(self) -> float:
        if not self._rtt_samples:
            return 0.0
        return sum(self._rtt_samples[-100:]) / min(len(self._rtt_samples), 100)

    def get_p95_rtt(self) -> float:
        if not self._rtt_samples:
            return 0.0
        samples = sorted(self._rtt_samples[-100:])
        idx = int(len(samples) * 0.95)
        return samples[min(idx, len(samples) - 1)]

    def get_p99_rtt(self) -> float:
        if not self._rtt_samples:
            return 0.0
        samples = sorted(self._rtt_samples[-100:])
        idx = int(len(samples) * 0.99)
        return samples[min(idx, len(samples) - 1)]

    def adapt(self) -> Dict:
        elapsed = time.time() - self._window_start
        if elapsed < self._window_size:
            return {"state": self.state, "rps": self.current_rps}

        error_rate = self.get_error_rate()
        avg_rtt = self.get_avg_rtt()

        decisions = []

        if error_rate > self.target_error_pct:
            self.state = AdaptiveState.BACKOFF
            self.current_rps = max(self.min_rps, int(self.current_rps * 0.5))
            decisions.append(f"ERROR_HIGH({error_rate:.0f}%) -> backoff to {self.current_rps} RPS")

        if avg_rtt > self.target_timeout_ms:
            self.state = AdaptiveState.SWITCH_METHOD
            self.current_rps = max(self.min_rps, int(self.current_rps * 0.7))
            decisions.append(f"RTT_HIGH({avg_rtt:.0f}ms) -> switch method, reduce to {self.current_rps} RPS")

        if error_rate < 10 and avg_rtt < self.target_timeout_ms * 0.5:
            if self.state in (AdaptiveState.IDLE, AdaptiveState.SUSTAIN):
                self.state = AdaptiveState.RAMP_UP
                self.current_rps = min(self.max_rps, int(self.current_rps * 1.3))
                decisions.append(f"LOW_LOAD -> ramp up to {self.current_rps} RPS")
            else:
                self.state = AdaptiveState.SUSTAIN
                decisions.append(f"SUSTAIN at {self.current_rps} RPS")

        if error_rate < 30 and avg_rtt < self.target_timeout_ms:
            self.state = AdaptiveState.SUSTAIN
            decisions.append(f"STABLE at {self.current_rps} RPS")

        if error_rate == 0 and self._window_requests == 0:
            self.state = AdaptiveState.RAMP_UP
            self.current_rps = min(self.max_rps, int(self.current_rps * 2))
            decisions.append(f"NO_RESPONSE -> increase to {self.current_rps} RPS (target may be down)")

        self._window_requests = 0
        self._window_errors = 0
        self._window_timeouts = 0
        self._window_start = time.time()

        return {
            "state": self.state,
            "rps": self.current_rps,
            "error_rate": round(error_rate, 1),
            "avg_rtt_ms": round(avg_rtt, 1),
            "p95_rtt_ms": round(self.get_p95_rtt(), 1),
            "p99_rtt_ms": round(self.get_p99_rtt(), 1),
            "decisions": decisions,
            "total_requests": self._total_requests,
            "total_errors": self._total_errors,
            "total_timeouts": self._total_timeouts,
        }

    def get_status(self) -> Dict:
        return {
            "state": self.state,
            "current_rps": self.current_rps,
            "error_rate": round(self.get_error_rate(), 1),
            "avg_rtt_ms": round(self.get_avg_rtt(), 1),
            "total_requests": self._total_requests,
        }

    def suggest_method(self, current_method: str, available_methods: list) -> str:
        error_rate = self.get_error_rate()
        if error_rate > self.target_error_pct:
            # Switch to next method
            if current_method in available_methods:
                idx = available_methods.index(current_method)
                return available_methods[(idx + 1) % len(available_methods)]
        return current_method
