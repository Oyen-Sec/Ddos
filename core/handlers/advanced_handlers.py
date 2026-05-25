"""
Advanced Attack Handlers - 2026
===============================
Menu handlers for new advanced attack modules.
"""
import asyncio
from typing import Dict

from rich.panel import Panel
from rich.table import Table
from rich import box


async def run_advanced_2026(target: str, cfg: dict):
    """Execute advanced 2026 attack with all bypass techniques."""
    try:
        from main import c, get_input, _RICH_CONSOLE
    except (ImportError, AttributeError) as e:
        print(f"Error importing from main: {e}")
        return

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    _RICH_CONSOLE.print()
    _RICH_CONSOLE.print(Panel("[bold cyan]ADVANCED 2026 ATTACK[/]", border_style="cyan", box=box.HEAVY))
    _RICH_CONSOLE.print(f"  [bold white]Target:[/] [cyan]{target}[/]")

    tech_table = Table(box=box.SIMPLE, show_header=False, border_style="dim cyan")
    tech_table.add_column("Status", style="bold green", width=3)
    tech_table.add_column("Technique")
    tech_table.add_row("[+]", "AI-driven behavioral mimicry")
    tech_table.add_row("[+]", "Advanced fingerprint evasion (JA3/JA4, Canvas, WebGL)")
    tech_table.add_row("[+]", "Origin server discovery")
    tech_table.add_row("[+]", "Cache poisoning")
    tech_table.add_row("[+]", "Session persistence")
    tech_table.add_row("[+]", "Adaptive learning from WAF responses")
    _RICH_CONSOLE.print(Panel(tech_table, title="[bold cyan]Attack Techniques[/]", border_style="cyan"))

    duration = int(get_input(" Duration (seconds, default 300): ") or "300")
    target_rps = int(get_input(" Target RPS (default 1000): ") or "1000")

    attack_modes = {
        '1': 'hybrid',
        '2': 'business_logic',
        '3': 'origin_direct'
    }

    _RICH_CONSOLE.print()
    mode_table = Table(box=box.SIMPLE, show_header=False, border_style="cyan")
    mode_table.add_column("Option", style="bold cyan", width=4)
    mode_table.add_column("Mode", style="bold white")
    mode_table.add_column("Description", style="dim white")
    mode_table.add_row("[1]", "Hybrid", "All techniques")
    mode_table.add_row("[2]", "Business Logic", "Low-slow")
    mode_table.add_row("[3]", "Origin Direct", "Bypass CDN")
    _RICH_CONSOLE.print(Panel(mode_table, title="[bold cyan]Attack Modes[/]", border_style="cyan"))

    mode_choice = get_input(" Select mode (default 1): ") or "1"
    attack_mode = attack_modes.get(mode_choice, 'hybrid')

    _RICH_CONSOLE.print()
    _RICH_CONSOLE.print(f"[bold cyan][*][/] Starting Advanced 2026 Attack...")
    _RICH_CONSOLE.print(f"[bold cyan][*][/] Mode: [white]{attack_mode}[/]")
    _RICH_CONSOLE.print(f"[bold cyan][*][/] Duration: [white]{duration}s[/] | RPS: [white]{target_rps}[/]")
    _RICH_CONSOLE.rule(style="dim cyan")

    try:
        from core.bypass.orchestrator import execute_advanced_attack

        result = await execute_advanced_attack(
            target_url=target,
            duration=duration,
            target_rps=target_rps,
            attack_mode=attack_mode
        )

        _RICH_CONSOLE.print()
        summary_panel = Panel(f"[bold white]Target:[/] {target}\n"
                              f"[bold white]Mode:[/] {result.get('attack_mode', 'unknown')}\n"
                              f"[bold white]Duration:[/] {result.get('duration', 0)}s\n"
                              f"[bold white]Target RPS:[/] {result.get('target_rps', 0)}",
                              title="[bold cyan]ADVANCED 2026 ATTACK SUMMARY[/]",
                              border_style="cyan", box=box.HEAVY)
        _RICH_CONSOLE.print(summary_panel)

        phases = result.get('phases', [])
        for phase in phases:
            phase_name = phase.get('phase', 'unknown')
            _RICH_CONSOLE.print(f"\n[bold cyan]{phase_name.upper()}:[/]")

            if phase_name == 'reconnaissance':
                recon = phase.get('results', {})
                origins = recon.get('techniques', {}).get('origin_discovery', {}).get('origin_servers', [])
                _RICH_CONSOLE.print(f"  [bold green]Origin servers found:[/] {len(origins)}")

            elif phase_name == 'session_establishment':
                sessions = phase.get('sessions_created', 0)
                _RICH_CONSOLE.print(f"  [bold green]Sessions created:[/] {sessions}")

            elif phase_name == 'attack_execution':
                attack_res = phase.get('results', {})
                total = attack_res.get('total_requests', 0)
                success = attack_res.get('successful', 0)
                success_rate = attack_res.get('success_rate', 0)
                sr_color = "green" if success_rate > 0.7 else "yellow"

                _RICH_CONSOLE.print(f"  Total requests: [white]{total:,}[/]")
                _RICH_CONSOLE.print(f"  Successful: [bold green]{success}[/]")
                _RICH_CONSOLE.print(f"  Success rate: [{sr_color}]{success_rate*100:.1f}%[/]")

        _RICH_CONSOLE.rule(style="dim cyan")

    except Exception as e:
        _RICH_CONSOLE.print(f"[bold red][-][/] Attack failed: {e}")
        import traceback
        traceback.print_exc()


async def run_business_logic_attack(target: str, cfg: dict):
    """Execute business logic exhaustion attack."""
    try:
        from main import c, get_input, _RICH_CONSOLE
    except (ImportError, AttributeError) as e:
        print(f"Error importing from main: {e}")
        return

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    _RICH_CONSOLE.print()
    _RICH_CONSOLE.print(Panel("[bold cyan]BUSINESS LOGIC EXHAUSTION ATTACK[/]", border_style="cyan", box=box.HEAVY))
    _RICH_CONSOLE.print(f"  [bold white]Target:[/] [cyan]{target}[/]")

    vec_table = Table(box=box.SIMPLE, show_header=False, border_style="dim cyan")
    vec_table.add_column("Status", style="bold green", width=3)
    vec_table.add_column("Vector")
    vec_table.add_row("[+]", "Complex database queries (full table scans)")
    vec_table.add_row("[+]", "Expensive API operations (exports, reports)")
    vec_table.add_row("[+]", "Cart/checkout calculations")
    vec_table.add_row("[+]", "2FA/SMS operations (costs money)")
    vec_table.add_row("[+]", "Image processing requests")
    vec_table.add_row("[+]", "Email operations")
    _RICH_CONSOLE.print(Panel(vec_table, title="[bold cyan]Attack Vectors[/]", border_style="cyan"))

    duration = int(get_input(" Duration (seconds, default 300): ") or "300")
    rps = float(get_input(" RPS (low-slow, default 0.5): ") or "0.5")

    _RICH_CONSOLE.print()
    _RICH_CONSOLE.print(f"[bold cyan][*][/] Starting Business Logic Attack...")
    _RICH_CONSOLE.print(f"[bold cyan][*][/] Duration: [white]{duration}s[/] | RPS: [white]{rps}[/] (low-slow)")
    _RICH_CONSOLE.print(f"[bold yellow][!][/] This attack is STEALTHY - low volume, high impact")
    _RICH_CONSOLE.rule(style="dim cyan")

    try:
        from core.bypass.business_logic import execute_business_logic_attack

        result = await execute_business_logic_attack(
            target_url=target,
            duration=duration,
            rps=rps
        )

        _RICH_CONSOLE.print()
        summary_panel = Panel(f"[bold white]Target:[/] {target}\n"
                              f"[bold white]Duration:[/] {result.get('duration', 0)}s\n"
                              f"[bold white]Target RPS:[/] {result.get('target_rps', 0)}\n"
                              f"[bold white]Requests sent:[/] {result.get('requests_sent', 0):,}\n"
                              f"[bold white]Successful:[/] [green]{result.get('successful', 0)}[/]\n"
                              f"[bold white]Success rate:[/] [green]{result.get('success_rate', 0)*100:.1f}%[/]\n"
                              f"[bold white]Vectors used:[/] {result.get('vectors_used', 0)}\n"
                              f"[bold white]Estimated cost:[/] [red]${result.get('estimated_cost_impact', 0):.2f}[/]\n"
                              f"[bold white]Avg cost/request:[/] [red]${result.get('avg_cost_per_request', 0):.2f}[/]",
                              title="[bold cyan]BUSINESS LOGIC ATTACK SUMMARY[/]",
                              border_style="cyan", box=box.HEAVY)
        _RICH_CONSOLE.print(summary_panel)

        high_impact = result.get('high_impact_vectors', [])
        if high_impact:
            hi_table = Table(box=box.SIMPLE, header_style="bold cyan")
            hi_table.add_column("Vector Name", style="bold white")
            hi_table.add_column("Cost Multiplier", justify="right")
            hi_table.add_column("Stealth", justify="right")
            for v in high_impact:
                hi_table.add_row(v['name'], f"{v['cost_multiplier']:.1f}x", f"{v['detection_difficulty']*100:.0f}%")
            _RICH_CONSOLE.print(Panel(hi_table, title="[bold cyan]TOP 5 HIGH-IMPACT VECTORS[/]", border_style="cyan"))

        _RICH_CONSOLE.rule(style="dim cyan")

    except Exception as e:
        _RICH_CONSOLE.print(f"[bold red][-][/] Attack failed: {e}")
        import traceback
        traceback.print_exc()


async def run_seo_attack(target_domain: str, cfg: dict):
    """Execute negative SEO attack."""
    try:
        from main import c, get_input, _RICH_CONSOLE
    except (ImportError, AttributeError) as e:
        print(f"Error importing from main: {e}")
        return

    target_domain = target_domain.replace('https://', '').replace('http://', '').split('/')[0]

    _RICH_CONSOLE.print()
    _RICH_CONSOLE.print(Panel("[bold cyan]NEGATIVE SEO ATTACK[/]", border_style="cyan", box=box.HEAVY))
    _RICH_CONSOLE.print(f"  [bold white]Target Domain:[/] [cyan]{target_domain}[/]")

    tech_table = Table(box=box.SIMPLE, show_header=False, border_style="dim cyan")
    tech_table.add_column("Status", style="bold green", width=3)
    tech_table.add_column("Technique")
    tech_table.add_row("[+]", "Toxic backlink generation (10k+ spam links)")
    tech_table.add_row("[+]", "GSC spam (fake traffic patterns)")
    tech_table.add_row("[+]", "Content scraping & republishing")
    tech_table.add_row("[+]", "Crawl error injection")
    tech_table.add_row("[+]", "Manual action triggers")
    tech_table.add_row("[+]", "Competitor boosting")
    _RICH_CONSOLE.print(Panel(tech_table, title="[bold cyan]Attack Techniques[/]", border_style="cyan"))

    keywords_input = get_input(" Target keywords (comma-separated): ")
    keywords = [k.strip() for k in keywords_input.split(',') if k.strip()]

    if not keywords:
        keywords = ['default', 'keyword']

    competitors_input = get_input(" Competitor domains (comma-separated, optional): ")
    competitors = [c.strip() for c in competitors_input.split(',') if c.strip()]

    intensity_map = {'1': 'low', '2': 'medium', '3': 'high', '4': 'extreme'}
    int_table = Table(box=box.SIMPLE, show_header=False, border_style="cyan")
    int_table.add_column("Option", style="bold cyan", width=4)
    int_table.add_column("Intensity")
    int_table.add_column("Backlinks", style="dim white")
    int_table.add_row("[1]", "Low", "3k backlinks")
    int_table.add_row("[2]", "Medium", "6k backlinks")
    int_table.add_row("[3]", "High", "10k backlinks")
    int_table.add_row("[4]", "Extreme", "20k backlinks")
    _RICH_CONSOLE.print(Panel(int_table, title="[bold cyan]Intensity Levels[/]", border_style="cyan"))

    intensity_choice = get_input(" Select intensity (default 3): ") or "3"
    intensity = intensity_map.get(intensity_choice, 'high')

    _RICH_CONSOLE.print()
    _RICH_CONSOLE.print(f"[bold cyan][*][/] Starting Negative SEO Campaign...")
    _RICH_CONSOLE.print(f"[bold cyan][*][/] Target: [white]{target_domain}[/]")
    _RICH_CONSOLE.print(f"[bold cyan][*][/] Keywords: [white]{', '.join(keywords)}[/]")
    _RICH_CONSOLE.print(f"[bold cyan][*][/] Intensity: [white]{intensity}[/]")
    _RICH_CONSOLE.print(f"[bold yellow][!][/] WARNING: This will generate toxic SEO signals")
    _RICH_CONSOLE.rule(style="dim cyan")

    try:
        from core.seo.negative_seo import execute_seo_attack

        result = await execute_seo_attack(
            target_domain=target_domain,
            keywords=keywords,
            competitors=competitors,
            intensity=intensity
        )

        _RICH_CONSOLE.print()
        summary_panel = Panel(f"[bold white]Target:[/] {result.get('target', 'unknown')}\n"
                              f"[bold white]Campaign start:[/] {result.get('campaign_start', 'unknown')}\n"
                              f"[bold white]Intensity:[/] {result.get('intensity', 'unknown')}",
                              title="[bold cyan]NEGATIVE SEO CAMPAIGN SUMMARY[/]",
                              border_style="cyan", box=box.HEAVY)
        _RICH_CONSOLE.print(summary_panel)

        attacks = result.get('attacks', {})

        backlinks = attacks.get('backlink_poisoning', {})
        bl_panel = Panel(f"[bold white]Total backlinks:[/] {backlinks.get('total_backlinks', 0):,}\n"
                         f"[bold white]Unique domains:[/] {backlinks.get('unique_domains', 0):,}\n"
                         f"[bold white]Toxic score:[/] [red]{backlinks.get('toxic_score', 0)}%[/]",
                         title="[bold cyan]BACKLINK POISONING[/]", border_style="cyan")
        _RICH_CONSOLE.print(bl_panel)

        gsc = attacks.get('gsc_spam', {})
        gsc_panel = Panel(f"[bold white]Fake traffic:[/] {gsc.get('fake_traffic', 0):,} patterns\n"
                          f"[bold white]Crawl errors:[/] {gsc.get('crawl_errors', 0):,}",
                          title="[bold cyan]GSC SPAM[/]", border_style="cyan")
        _RICH_CONSOLE.print(gsc_panel)

        scraping = attacks.get('content_scraping', {})
        sc_panel = Panel(f"[bold white]Republished:[/] {scraping.get('total_republished', 0):,}\n"
                         f"[bold white]Indexed copies:[/] {scraping.get('indexed_copies', 0):,}\n"
                         f"[bold white]Scraper sites:[/] {scraping.get('scraper_sites', 0)}",
                         title="[bold cyan]CONTENT SCRAPING[/]", border_style="cyan")
        _RICH_CONSOLE.print(sc_panel)

        impact = result.get('estimated_impact', {})
        imp_panel = Panel(f"[bold white]Rank drop:[/] [red]{impact.get('rank_drop_estimate', 0)} positions[/]\n"
                          f"[bold white]Traffic loss:[/] [red]{impact.get('traffic_loss_estimate', 'unknown')}[/]\n"
                          f"[bold white]Recovery time:[/] {impact.get('recovery_time_estimate', 'unknown')}\n"
                          f"[bold white]Penalty prob:[/] [red]{impact.get('penalty_probability', 'unknown')}[/]\n"
                          f"[bold white]Deindex risk:[/] [red]{impact.get('deindexing_risk', 'unknown')}[/]",
                          title="[bold red]ESTIMATED IMPACT[/]", border_style="red")
        _RICH_CONSOLE.print(imp_panel)

        _RICH_CONSOLE.rule(style="dim cyan")

    except Exception as e:
        _RICH_CONSOLE.print(f"[bold red][-][/] SEO attack failed: {e}")
        import traceback
        traceback.print_exc()
