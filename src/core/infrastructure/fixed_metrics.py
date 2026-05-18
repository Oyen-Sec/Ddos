import asyncio
import statistics
import time
import logging
from collections import Counter
from typing import Dict

class FixedMetrics:
    """
    Standardized metrics tracking for request accounting.
    """
    def __init__(self):
        self.attempted = 0
        self.completed = 0
        self.failed = 0
        self.timeout = 0
        self.cancelled = 0
        self.latencies = []
        self.status_codes = Counter()
        self.error_types = Counter()
        self._lock = asyncio.Lock()
        self.start_time = time.monotonic()
        self.logger = logging.getLogger("FixedMetrics")

    async def record_attempt(self):
        async with self._lock:
            self.attempted += 1

    async def record_complete(self, status: int, latency_ms: float):
        async with self._lock:
            self.completed += 1
            self.status_codes[status] += 1
            self.latencies.append(latency_ms)

    async def record_failed(self, error_type: str):
        async with self._lock:
            self.failed += 1
            self.error_types[error_type] += 1

    async def record_timeout(self):
        async with self._lock:
            self.timeout += 1
            self.error_types["TimeoutError"] += 1

    async def record_cancelled(self):
        async with self._lock:
            self.cancelled += 1

    @property
    def error_rate(self) -> float:
        if self.attempted == 0: return 0.0
        # CORRECT: Failed + Timeout count as errors
        return (self.failed + self.timeout) / self.attempted

    @property
    def rps(self) -> float:
        """Throughput based on attempted requests per second."""
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
            return False, f"MISMATCH: Att={self.attempted}, Acc={total}, Diff={self.attempted - total}"
        return True, "BALANCED"

    def get_summary(self) -> Dict:
        valid, msg = self.validate()
        duration = time.monotonic() - self.start_time
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
            "status_distribution": dict(self.status_codes),
            "error_distribution": dict(self.error_types),
            "duration_sec": round(duration, 2)
        }
