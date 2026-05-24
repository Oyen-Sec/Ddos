import time
import json
import os
import logging
from typing import Dict, List, Optional
from collections import deque
from dataclasses import dataclass, field

logger = logging.getLogger("metrics_collector")

@dataclass
class MetricsSnapshot:
    timestamp: float
    total_requests: int
    completed: int
    failed: int
    timeout: int
    current_rps: float
    peak_rps: float
    avg_rtt_ms: float
    p50_rtt_ms: float
    p95_rtt_ms: float
    p99_rtt_ms: float
    active_connections: int
    active_proxies: int
    bandwidth_up: float
    bandwidth_down: float
    error_rate: float
    attack_method: str
    state: str

class MetricsCollector:
    def __init__(self, window_size: int = 60, log_dir: str = "output/logs"):
        self.window_size = window_size
        self.log_dir = log_dir
        self._snapshots: deque = deque(maxlen=3600)
        self._start_time = time.time()
        self._last_bytes_sent = 0
        self._last_bytes_recv = 0
        os.makedirs(log_dir, exist_ok=True)

    def record_snapshot(self, metrics: Dict):
        snapshot = MetricsSnapshot(
            timestamp=time.time(),
            total_requests=metrics.get("total_requests", 0),
            completed=metrics.get("completed", 0),
            failed=metrics.get("failed", 0),
            timeout=metrics.get("timeout", 0),
            current_rps=metrics.get("current_rps", 0),
            peak_rps=metrics.get("peak_rps", 0),
            avg_rtt_ms=metrics.get("avg_response_time_ms", 0),
            p50_rtt_ms=metrics.get("p50_rtt_ms", 0),
            p95_rtt_ms=metrics.get("p95_rtt_ms", 0),
            p99_rtt_ms=metrics.get("p99_rtt_ms", 0),
            active_connections=metrics.get("active_connections", 0),
            active_proxies=metrics.get("active_proxies", 0),
            bandwidth_up=metrics.get("bandwidth_up", 0),
            bandwidth_down=metrics.get("bandwidth_down", 0),
            error_rate=metrics.get("error_rate", 0),
            attack_method=metrics.get("attack_method", "unknown"),
            state=metrics.get("state", "UNKNOWN"),
        )
        self._snapshots.append(snapshot)

    def get_recent(self, seconds: int = 10) -> List[MetricsSnapshot]:
        now = time.time()
        return [s for s in self._snapshots if now - s.timestamp <= seconds]

    def get_average_rps(self, seconds: int = 10) -> float:
        recent = self.get_recent(seconds)
        if not recent:
            return 0.0
        return sum(s.current_rps for s in recent) / len(recent)

    def get_total_requests(self) -> int:
        if not self._snapshots:
            return 0
        return self._snapshots[-1].total_requests

    def get_completed(self) -> int:
        if not self._snapshots:
            return 0
        return self._snapshots[-1].completed

    def get_failed(self) -> int:
        if not self._snapshots:
            return 0
        return self._snapshots[-1].failed

    def get_error_rate(self) -> float:
        recent = self.get_recent(30)
        if not recent:
            return 0.0
        total = sum(s.total_requests for s in recent)
        failed = sum(s.failed for s in recent)
        if total == 0:
            return 0.0
        return (failed / total) * 100

    def get_rtt_stats(self) -> Dict:
        recent = self.get_recent(60)
        if not recent:
            return {"avg": 0, "p50": 0, "p95": 0, "p99": 0}
        rtts = [s.avg_rtt_ms for s in recent if s.avg_rtt_ms > 0]
        if not rtts:
            return {"avg": 0, "p50": 0, "p95": 0, "p99": 0}
        sorted_rtts = sorted(rtts)
        n = len(sorted_rtts)
        return {
            "avg": sum(rtts) / n,
            "p50": sorted_rtts[int(n * 0.5)],
            "p95": sorted_rtts[int(n * 0.95)],
            "p99": sorted_rtts[int(n * 0.99)],
        }

    def summary(self) -> Dict:
        if not self._snapshots:
            return {"status": "NO_DATA"}
        last = self._snapshots[-1]
        elapsed = time.time() - self._start_time
        return {
            "elapsed_seconds": round(elapsed, 1),
            "total_requests": last.total_requests,
            "completed": last.completed,
            "failed": last.failed,
            "timeout": last.timeout,
            "current_rps": round(last.current_rps, 1),
            "peak_rps": round(last.peak_rps, 1),
            "avg_rtt_ms": round(last.avg_rtt_ms, 1),
            "error_rate": round(self.get_error_rate(), 1),
            "active_proxies": last.active_proxies,
            "method": last.attack_method,
            "state": last.state,
        }

    def export_json(self, path: Optional[str] = None) -> str:
        data = {
            "start_time": self._start_time,
            "duration": time.time() - self._start_time,
            "snapshots": [
                {
                    "t": s.timestamp,
                    "rps": s.current_rps,
                    "ok": s.completed,
                    "fail": s.failed,
                    "to": s.timeout,
                    "rtt": s.avg_rtt_ms,
                }
                for s in self._snapshots
            ],
        }
        if path:
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
        return json.dumps(data)
