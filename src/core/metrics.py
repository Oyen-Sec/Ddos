import asyncio
import statistics
import time
import logging
from collections import Counter
from typing import Dict

class AttackMetrics:
    """
    Core request accounting and performance monitoring.
    Ensures Attempted == Completed + Failed + Timeout + Cancelled.
    """
    def __init__(self):
        self.attempted = 0
        self.completed = 0
        self.failed = 0
        self.timeout = 0
        self.cancelled = 0
        self.latencies = []
        self.status_codes = Counter()
        self.errors = Counter()
        self._lock = asyncio.Lock()
        self.start_time = time.monotonic()
        self.logger = logging.getLogger("AttackMetrics")

    async def record_attempt(self):
        async with self._lock:
            self.attempted += 1

    async def record_complete(self, status: int, latency_ms: float):
        async with self._lock:
            self.completed += 1
            self.latencies.append(latency_ms / 1000.0) # Store in seconds
            self.status_codes[status] += 1

    async def record_fail(self, error_type: str):
        async with self._lock:
            self.failed += 1
            self.errors[error_type] += 1

    async def record_timeout(self):
        async with self._lock:
            self.timeout += 1
            self.errors["TimeoutError"] += 1

    async def record_cancelled(self):
        async with self._lock:
            self.cancelled += 1

    def validate(self) -> bool:
        """Verifies accounting integrity."""
        accounted = self.completed + self.failed + self.timeout + self.cancelled
        if self.attempted != accounted:
            self.logger.critical(f"ACCOUNTING MISMATCH: Attempted={self.attempted}, Accounted={accounted}")
            self.logger.critical(f"  Details: Comp={self.completed}, Fail={self.failed}, TO={self.timeout}, Can={self.cancelled}")
            self.logger.critical(f"  Missing={self.attempted - accounted}")
            return False
        return True

    def get_summary(self) -> Dict:
        duration = time.monotonic() - self.start_time
        
        if not self.latencies:
            return {
                "total_attempted": self.attempted,
                "total_completed": self.completed,
                "total_failed": self.failed,
                "total_timeout": self.timeout,
                "total_cancelled": self.cancelled,
                "avg_latency_ms": 0,
                "error_rate": (self.failed + self.timeout) / self.attempted if self.attempted > 0 else 0,
                "rps": 0,
                "status_distribution": dict(self.status_codes),
                "error_distribution": dict(self.errors),
                "duration_sec": round(duration, 2),
                "valid": self.validate()
            }

        return {
            "total_attempted": self.attempted,
            "total_completed": self.completed,
            "total_failed": self.failed,
            "total_timeout": self.timeout,
            "total_cancelled": self.cancelled,
            "avg_latency_ms": round(statistics.mean(self.latencies) * 1000, 2),
            "p99_latency_ms": round(sorted(self.latencies)[int(len(self.latencies) * 0.99)] * 1000, 2),
            "error_rate": round((self.failed + self.timeout) / self.attempted, 4) if self.attempted > 0 else 0,
            "rps": round(self.completed / duration, 2),
            "status_distribution": dict(self.status_codes),
            "error_distribution": dict(self.errors),
            "duration_sec": round(duration, 2),
            "valid": self.validate()
        }
