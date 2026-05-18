import asyncio
import aiohttp
import time
import logging
import socket
from typing import Dict, Optional, List

class StaticResolver(aiohttp.abc.AbstractResolver):
    def __init__(self, domain, ip):
        self.domain = domain
        self.ip = ip

    async def resolve(self, host, port=0, family=socket.AF_INET) -> list:
        if host == self.domain and self.ip:
            return [{
                'hostname': host,
                'host': self.ip,
                'port': port,
                'family': family,
                'proto': 0,
                'flags': 0
            }]
        return await aiohttp.DefaultResolver().resolve(host, port, family)

    async def close(self):
        pass

class UniversalBenchmark:
    """
    Manages session lifecycle for benchmarking and attack execution.
    Ensures connection reuse and accurate performance metrics.
    """
    def __init__(self, domain: str, ip: str, threads: int):
        self.domain = domain
        self.ip = ip
        self.threads = threads
        self.session = None
        self.connector = None
        self.logger = logging.getLogger("UniversalBenchmark")

    async def __aenter__(self):
        # Create single connector for the entire operation
        resolver = StaticResolver(self.domain, self.ip)
        
        self.connector = aiohttp.TCPConnector(
            limit=self.threads * 2,
            limit_per_host=self.threads,
            ssl=False, 
            resolver=resolver,
            use_dns_cache=False
        )
        
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }

        self.session = aiohttp.ClientSession(
            connector=self.connector,
            timeout=timeout,
            headers=headers
        )
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.session:
            await self.session.close()
        if self.connector:
            await self.connector.close()

    async def health_check(self) -> Dict:
        """
        Verifies target is alive via multiple connection methods.
        """
        methods = [
            {"name": "ip_host_header", "url": f"https://{self.domain}/", "use_ip": True},
            {"name": "domain_system_dns", "url": f"https://{self.domain}/", "use_ip": False},
        ]
        
        last_error = "Unknown"
        
        for method in methods:
            try:
                # Setup connector based on method
                if method["use_ip"]:
                    resolver = StaticResolver(self.domain, self.ip)
                else:
                    resolver = aiohttp.DefaultResolver()
                
                async with aiohttp.TCPConnector(resolver=resolver, ssl=False) as connector:
                    async with aiohttp.ClientSession(connector=connector) as session:
                        start = time.monotonic()
                        async with session.get(method["url"], timeout=aiohttp.ClientTimeout(total=5)) as resp:
                            latency = (time.monotonic() - start) * 1000
                            
                            if resp.status < 400:
                                return {
                                    "ok": True,
                                    "method": method["name"],
                                    "status": resp.status,
                                    "latency_ms": latency
                                }
                            else:
                                last_error = f"HTTP {resp.status}"
            except asyncio.TimeoutError:
                last_error = "Connection timeout"
            except aiohttp.ClientConnectorError as e:
                last_error = f"Connection refused ({type(e).__name__})"
            except Exception as e:
                last_error = str(e)
                
        return {
            "ok": False,
            "error": last_error,
            "suggestion": "Check if target blocks direct IP or specific SNI. Try domain-based attack."
        }

    async def benchmark(self, duration: int = 3) -> Dict:
        """Measures throughput on the root path with strict timeout."""
        url = f"https://{self.domain}/"
        start = time.monotonic()
        count = 0
        errors = 0
        
        req_timeout = aiohttp.ClientTimeout(total=5, connect=2)
        
        while time.monotonic() - start < duration:
            try:
                async with self.session.get(url, timeout=req_timeout, ssl=False) as resp:
                    if resp.status < 400:
                        count += 1
                    else:
                        errors += 1
            except:
                errors += 1
                await asyncio.sleep(0.01)
        
        elapsed = time.monotonic() - start
        rps = count / elapsed if elapsed > 0 else 0
        
        return {
            "rps": rps,
            "total_requests": count,
            "errors": errors,
            "duration": elapsed
        }
