import time
import logging

class RateController:
    """
    Adaptive rate limiting and timing control per target.
    Mimics legitimate user behavior or manages attack intensity.
    """
    def __init__(self):
        self.logger = logging.getLogger("RateController")
        self.target_stats = {}

    def get_sleep_time(self, target: str, mode: str = "aggressive") -> float:
        """
        Calculates sleep time between requests based on target response or mode.
        """
        if mode == "stealth":
            return 1.0 + (time.time() % 2) # 1-3 seconds
        elif mode == "adaptive":
            # In a real scenario, this would check target's response time
            return 0.1
        else: # aggressive
            return 0.0

    def update_stats(self, target: str, response_time: float, status_code: int):
        if target not in self.target_stats:
            self.target_stats[target] = []
        
        self.target_stats[target].append({
            "time": response_time,
            "status": status_code,
            "timestamp": time.time()
        })
        
        # Keep only last 100 stats
        if len(self.target_stats[target]) > 100:
            self.target_stats[target].pop(0)
