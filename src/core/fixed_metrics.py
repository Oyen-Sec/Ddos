import asyncio
import time
import statistics
import logging
from typing import Dict, List, Any

class FixedMetricsV2:
    """
    Standardized metrics tracking with balanced accounting.
    Ensures: Attempted == Completed + Failed + Timeout + Cancelled.
    """
    def __init__(self):
        self.attempted = 0
        self.completed = 0
        self.failed = 0
        self.timeout = 0
        self.cancelled = 0
        self.latencies: List[float] = []
        self.start_time = time.monotonic()
        self._lock = asyncio.Lock()
        self.logger = logging.getLogger("FixedMetricsV2")

    async def record_attempt(self):
        async with self._lock:
            self.attempted += 1

    async def record_complete(self, status: int, latency_ms: float):
        async with self._lock:
            self.completed += 1
            self.latencies.append(latency_ms)

    async def record_failed(self, error_type: str):
        async with self._lock:
            self.failed += 1

    async def record_timeout(self):
        async with self._lock:
            self.timeout += 1

    async def record_cancelled(self):
        async with self._lock:
            self.cancelled += 1

    @property
    def error_rate(self) -> float:
        if self.attempted == 0: return 0.0
        # Correct calculation: (Failed + Timeout) / Attempted
        return (self.failed + self.timeout) / self.attempted

    @property
    def rps(self) -> float:
        duration = time.monotonic() - self.start_time
        if duration <= 0: return 0.0
        return self.attempted / duration

    @property
    def avg_latency_ms(self) -> float:
        if not self.latencies: return 0.0
        return statistics.mean(self.latencies)

    def validate(self) -> tuple[bool, str]:
        total = self.completed + self.failed + self.timeout + self.cancelled
        if self.attempted != total:
            return False, f"MISMATCH: A={self.attempted}, T={total}, Diff={self.attempted - total}"
        return True, "BALANCED"

    def get_summary(self) -> Dict[str, Any]:
        valid, msg = self.validate()
        return {
            "valid": valid,
            "validation_msg": msg,
            "attempted": self.attempted,
            "completed": self.completed,
            "failed": self.failed,
            "timeout": self.timeout,
            "cancelled": self.cancelled,
            "error_rate": round(self.error_rate, 4),
            "rps": round(self.rps, 2),
            "avg_latency_ms": round(self.avg_latency_ms, 2),
            "duration_sec": round(time.monotonic() - self.start_time, 2)
        }
