"""
REAL-TIME ANALYTICS & MONITORING SYSTEM v2.0 [2026]
===================================================
World-class observability with predictive analytics
"""

import asyncio
import time
import json
import logging
from typing import Dict, List, Any, Optional
from collections import deque
from dataclasses import dataclass, asdict
import statistics
import math

@dataclass
class AnalyticsSnapshot:
    timestamp: float
    rps: float
    latency_ms: float
    error_rate: float
    timeout_rate: float
    p50_latency: float
    p95_latency: float
    p99_latency: float
    throughput_trend: str  # up, down, stable
    attack_health: float  # 0-1

class AdvancedAnalyticsEngine:
    """
    Real-time analytics with:
    - Predictive modeling
    - Anomaly detection
    - Performance forecasting
    - Adaptive reporting
    """
    
    def __init__(self, metrics: Any):
        self.metrics = metrics
        self.logger = logging.getLogger("AnalyticsEngine")
        
        # Historical data (time-series)
        self.snapshots: deque = deque(maxlen=3600)  # 1 hour at 1 Hz
        self.latency_history: deque = deque(maxlen=1000)
        self.error_history: deque = deque(maxlen=1000)
        self.rps_history: deque = deque(maxlen=1000)
        
        # Trend detection
        self.trend_window = 60  # 60-second windows for trend
        self.anomalies = []
        
        # Predictive models (simple)
        self.latency_trend = 0  # slope
        self.rps_trend = 0  # slope
        
        self.is_running = False

    async def run_analytics_loop(self):
        """Main analytics loop."""
        self.is_running = True
        self.logger.info("Analytics Engine started")
        
        cycle = 0
        while self.is_running:
            await asyncio.sleep(1)
            cycle += 1
            
            # Collect metrics
            summary = self.metrics.get_summary()
            if summary["attempted"] == 0:
                continue
            
            # Create snapshot
            snapshot = self._create_snapshot(summary)
            self.snapshots.append(snapshot)
            
            # Update histories
            self.latency_history.append(snapshot.latency_ms)
            self.error_history.append(snapshot.error_rate)
            self.rps_history.append(snapshot.rps)
            
            # Analyze trends every 30 seconds
            if cycle % 30 == 0:
                self._analyze_trends()
                self._detect_anomalies()
                self._forecast_impact()
                self._generate_report()

    def _create_snapshot(self, summary: Dict[str, Any]) -> AnalyticsSnapshot:
        """Create analytics snapshot."""
        
        # Calculate percentiles from raw latencies
        if self.metrics.latencies:
            sorted_latencies = sorted(self.metrics.latencies)
            p50 = sorted_latencies[int(len(sorted_latencies) * 0.50)]
            p95 = sorted_latencies[int(len(sorted_latencies) * 0.95)]
            p99 = sorted_latencies[int(len(sorted_latencies) * 0.99)]
        else:
            p50 = p95 = p99 = 0
        
        # Detect trend
        trend = self._detect_throughput_trend()
        
        # Attack health score
        health = self._calculate_health_score(
            summary["rps"],
            summary["avg_latency_ms"],
            summary["error_rate"]
        )
        
        return AnalyticsSnapshot(
            timestamp=time.monotonic(),
            rps=summary["rps"],
            latency_ms=summary["avg_latency_ms"],
            error_rate=summary["error_rate"],
            timeout_rate=summary["timeout"] / max(summary["attempted"], 1),
            p50_latency=p50,
            p95_latency=p95,
            p99_latency=p99,
            throughput_trend=trend,
            attack_health=health
        )

    def _detect_throughput_trend(self) -> str:
        """Detect if throughput is increasing, decreasing, or stable."""
        if len(self.rps_history) < 10:
            return "unknown"
        
        # Simple trend: compare last 10 vs previous 10
        recent = list(self.rps_history)[-10:]
        previous = list(self.rps_history)[-20:-10]
        
        if not previous:
            return "unknown"
        
        recent_avg = statistics.mean(recent)
        previous_avg = statistics.mean(previous)
        
        change_percent = (recent_avg - previous_avg) / previous_avg if previous_avg > 0 else 0
        
        if change_percent > 0.1:
            return "up"
        elif change_percent < -0.1:
            return "down"
        else:
            return "stable"

    def _calculate_health_score(self, rps: float, latency: float, error_rate: float) -> float:
        """
        Calculate overall attack health (0-1).
        Combines RPS, latency, and error rate.
        """
        
        # Normalize metrics (0-1)
        rps_score = min(rps / 1000, 1.0)  # Target 1000+ RPS
        latency_score = max(1 - (latency / 10000), 0)  # Target <10s
        error_score = max(1 - error_rate, 0)  # Target <1% error
        
        # Weighted average
        health = (rps_score * 0.4 + latency_score * 0.3 + error_score * 0.3)
        
        return min(max(health, 0), 1.0)

    def _analyze_trends(self):
        """Analyze performance trends."""
        
        if len(self.snapshots) < 2:
            return
        
        # Calculate trend slopes
        recent_snapshots = list(self.snapshots)[-60:]  # Last 60 seconds
        
        if len(recent_snapshots) > 1:
            time_deltas = [recent_snapshots[i+1].timestamp - recent_snapshots[i].timestamp 
                          for i in range(len(recent_snapshots)-1)]
            
            rps_values = [s.rps for s in recent_snapshots]
            latency_values = [s.latency_ms for s in recent_snapshots]
            
            # Simple linear regression
            self.rps_trend = self._calculate_trend(rps_values)
            self.latency_trend = self._calculate_trend(latency_values)

    def _calculate_trend(self, values: List[float]) -> float:
        """Calculate linear trend (slope)."""
        if len(values) < 2:
            return 0
        
        n = len(values)
        x_values = list(range(n))
        
        x_mean = statistics.mean(x_values)
        y_mean = statistics.mean(values)
        
        numerator = sum((x_values[i] - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((x - x_mean) ** 2 for x in x_values)
        
        if denominator == 0:
            return 0
        
        return numerator / denominator

    def _detect_anomalies(self):
        """Detect anomalies in metrics."""
        
        if len(self.latency_history) < 20:
            return
        
        recent = list(self.latency_history)[-20:]
        baseline = list(self.latency_history)[:-20]
        
        recent_mean = statistics.mean(recent)
        baseline_mean = statistics.mean(baseline)
        baseline_std = statistics.stdev(baseline) if len(baseline) > 1 else 1
        
        # Z-score
        z_score = (recent_mean - baseline_mean) / baseline_std if baseline_std > 0 else 0
        
        if abs(z_score) > 3:  # 3-sigma anomaly
            self.anomalies.append({
                "timestamp": time.monotonic(),
                "type": "latency_spike" if z_score > 0 else "latency_improvement",
                "z_score": z_score,
                "baseline": baseline_mean,
                "current": recent_mean,
            })
            self.logger.warning(f"[ANOMALY] Detected {abs(z_score):.2f}-sigma anomaly")

    def _forecast_impact(self):
        """Forecast future performance based on trends."""
        
        if len(self.snapshots) < 30:
            return  # Need at least 30 seconds of data
        
        # Simple forecast: if trends continue
        recent = list(self.snapshots)[-30:]
        
        if recent[-1].rps < 10 and self.rps_trend < 0:
            self.logger.warning("[FORECAST] RPS declining - target may be adapting")
        
        if recent[-1].latency_ms > 5000 and self.latency_trend > 0:
            self.logger.warning("[FORECAST] Latency increasing - target hardening detected")

    def _generate_report(self):
        """Generate analytics report."""
        
        if not self.snapshots:
            return
        
        latest = list(self.snapshots)[-1]
        
        report = {
            "timestamp": latest.timestamp,
            "current_rps": latest.rps,
            "current_latency_ms": latest.latency_ms,
            "current_error_rate": latest.error_rate * 100,
            "latency_percentiles": {
                "p50": latest.p50_latency,
                "p95": latest.p95_latency,
                "p99": latest.p99_latency,
            },
            "trend": {
                "throughput": latest.throughput_trend,
                "rps_slope": round(self.rps_trend, 4),
                "latency_slope": round(self.latency_trend, 4),
            },
            "health": {
                "score": round(latest.attack_health, 2),
                "status": "excellent" if latest.attack_health > 0.8 else "good" if latest.attack_health > 0.5 else "degraded"
            },
            "anomalies": len(self.anomalies),
        }
        
        self.logger.info(
            f"[ANALYTICS] RPS: {report['current_rps']:.1f} | "
            f"Latency: {report['current_latency_ms']:.0f}ms | "
            f"Error: {report['current_error_rate']:.1f}% | "
            f"Health: {report['health']['status']}"
        )

    def get_analytics_summary(self) -> Dict[str, Any]:
        """Get current analytics summary."""
        
        if not self.snapshots:
            return {}
        
        recent = list(self.snapshots)[-1]
        
        return {
            "current": asdict(recent),
            "trend": {
                "rps_slope": round(self.rps_trend, 4),
                "latency_slope": round(self.latency_trend, 4),
            },
            "anomalies": self.anomalies[-10:],  # Last 10
            "uptime_seconds": recent.timestamp,
        }

    def stop(self):
        """Stop analytics loop."""
        self.is_running = False
        self.logger.info("Analytics Engine stopped")
