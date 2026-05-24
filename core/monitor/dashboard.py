"""
Real-time Attack Dashboard
HTTP + WebSocket server for live monitoring
"""
import asyncio
import json
import time
import logging
import platform
import threading
from typing import Dict, Set, Optional, List
from dataclasses import dataclass, asdict, field
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

logger = logging.getLogger("dashboard")

try:
    import websockets
    HAS_WEBSOCKETS = True
except ImportError:
    logger.error("websockets not installed - run: pip install websockets")
    HAS_WEBSOCKETS = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


@dataclass
class MetricsSnapshot:
    timestamp: float
    rps: float
    latency_ms: float
    error_rate: float
    health_score: float
    adaptive_state: str
    adaptive_strategy: str
    total_requests: int
    completed: int
    failed: int
    timeout: int
    method: str
    target: str
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    threat_level: float = 0.0


@dataclass
class EventLog:
    timestamp: str
    event_type: str
    source: str
    action: str
    status: str


def get_system_stats() -> Dict[str, float]:
    """Get current system CPU/memory."""
    if not HAS_PSUTIL:
        return {"cpu": 0.0, "memory": 0.0}
    try:
        return {
            "cpu": psutil.cpu_percent(interval=None),
            "memory": psutil.virtual_memory().percent,
        }
    except Exception:
        return {"cpu": 0.0, "memory": 0.0}


# ============================================================================
# DASHBOARD HTML (served via HTTP)
# ============================================================================
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Multi-Protocol Concurrency Layer - Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Orbitron:wght@600;700;900&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #07091a;
  --bg-2: #0d1126;
  --surface: #141a35;
  --surface-2: #1c2347;
  --border: #2d3766;
  --text: #e8ecff;
  --text-dim: #8a93c4;
  --text-mute: #5a638a;
  --cyan: #00e5ff;
  --magenta: #ff2bd6;
  --green: #00ff9c;
  --yellow: #ffd60a;
  --orange: #ff7a18;
  --red: #ff3860;
  --purple: #b14aff;
  --blue: #4d8dff;
}

* { box-sizing: border-box; margin: 0; padding: 0; }
html, body { height: 100%; }
body {
  background: var(--bg);
  background-image:
    radial-gradient(circle at 12% 18%, rgba(255, 43, 214, 0.10) 0%, transparent 45%),
    radial-gradient(circle at 88% 30%, rgba(0, 229, 255, 0.10) 0%, transparent 45%);
  color: var(--text);
  font-family: 'JetBrains Mono', monospace;
  font-size: 13px;
  overflow-x: hidden;
}

header {
  background: linear-gradient(90deg, rgba(20,26,53,.95), rgba(28,35,71,.95));
  border-bottom: 2px solid;
  border-image: linear-gradient(90deg, var(--cyan), var(--magenta)) 1;
  padding: 14px 28px;
  display: flex; justify-content: space-between; align-items: center;
}
.brand { display: flex; align-items: center; gap: 14px; }
.logo {
  font-family: 'Orbitron', sans-serif; font-weight: 900;
  font-size: 18px; letter-spacing: 2px;
  background: linear-gradient(90deg, var(--cyan), var(--magenta));
  -webkit-background-clip: text; background-clip: text; color: transparent;
}
.version-badge {
  background: linear-gradient(135deg, var(--green), var(--cyan));
  color: #001;
  padding: 3px 10px; border-radius: 4px;
  font-weight: 700; font-size: 11px;
}
.tagline { color: var(--text-dim); font-size: 11px; letter-spacing: 1px; }

.status-bar { display: flex; align-items: center; gap: 18px; }
.conn-pill {
  display: flex; align-items: center; gap: 8px;
  padding: 6px 14px; border-radius: 999px;
  background: var(--surface-2); border: 1px solid var(--red);
}
.conn-pill.connected { border-color: var(--green); }
.conn-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--red); }
.conn-pill.connected .conn-dot { background: var(--green); animation: pulse 1.5s infinite; }
@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .5; } }
.conn-text { font-weight: 700; letter-spacing: 1px; font-size: 11px; }
.conn-pill.connected .conn-text { color: var(--green); }
.conn-pill:not(.connected) .conn-text { color: var(--red); }

main { max-width: 1500px; margin: 0 auto; padding: 22px; display: flex; flex-direction: column; gap: 18px; }

.metrics-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; }
.metric-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px; padding: 18px;
  position: relative; overflow: hidden;
}
.metric-card::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px;
}
.metric-card.cyan::before { background: var(--cyan); }
.metric-card.magenta::before { background: var(--magenta); }
.metric-card.yellow::before { background: var(--yellow); }
.metric-card.green::before { background: var(--green); }

.metric-label {
  font-size: 10px; letter-spacing: 2px; font-weight: 700;
  margin-bottom: 10px;
}
.metric-card.cyan .metric-label { color: var(--cyan); }
.metric-card.magenta .metric-label { color: var(--magenta); }
.metric-card.yellow .metric-label { color: var(--yellow); }
.metric-card.green .metric-label { color: var(--green); }

.metric-value {
  font-family: 'Orbitron', sans-serif; font-weight: 700;
  font-size: 32px; line-height: 1;
}
.metric-card.cyan .metric-value { color: var(--cyan); }
.metric-card.magenta .metric-value { color: var(--magenta); }
.metric-card.yellow .metric-value { color: var(--yellow); }
.metric-card.green .metric-value { color: var(--green); }

.metric-delta { font-size: 11px; color: var(--text-dim); margin-top: 6px; }

.split-row { display: grid; grid-template-columns: 2fr 1fr; gap: 14px; }
.chart-card, .system-card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 18px;
}
.chart-card { height: 320px; display: flex; flex-direction: column; }
.card-header {
  display: flex; justify-content: space-between; align-items: center;
  padding-bottom: 12px; border-bottom: 1px solid var(--border);
  margin-bottom: 12px;
}
.card-title {
  font-size: 11px; letter-spacing: 2px; font-weight: 700;
  background: linear-gradient(90deg, var(--cyan), var(--magenta));
  -webkit-background-clip: text; background-clip: text; color: transparent;
}

#chart-container {
  flex: 1; display: flex; align-items: flex-end;
  justify-content: space-between; gap: 2px; padding: 0 4px;
}
.chart-bar {
  flex: 1; min-height: 2px; border-radius: 2px 2px 0 0;
  transition: all .2s;
}
.chart-bar.normal { background: linear-gradient(180deg, var(--cyan), var(--blue)); }
.chart-bar.warn { background: linear-gradient(180deg, var(--yellow), var(--orange)); }
.chart-bar.spike { background: linear-gradient(180deg, var(--red), var(--magenta)); }

.bar-block { margin-bottom: 14px; }
.bar-label {
  display: flex; justify-content: space-between;
  font-size: 11px; letter-spacing: 1px; font-weight: 600;
  margin-bottom: 6px; color: var(--text-dim);
}
.bar-track {
  height: 8px; background: var(--bg-2); border-radius: 4px; overflow: hidden;
}
.bar-fill {
  height: 100%; border-radius: 4px;
  transition: width .4s ease;
}
.bar-fill.cpu { background: linear-gradient(90deg, var(--green), var(--cyan)); }
.bar-fill.mem { background: linear-gradient(90deg, var(--cyan), var(--magenta)); }

.counter-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; }
.counter-card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 14px;
}
.counter-label {
  font-size: 10px; letter-spacing: 1.5px; color: var(--text-dim);
  margin-bottom: 6px; font-weight: 600;
}
.counter-value {
  font-family: 'Orbitron', sans-serif; font-weight: 700;
  font-size: 22px;
}
.counter-card.total .counter-value { color: var(--cyan); }
.counter-card.ok .counter-value { color: var(--green); }
.counter-card.fail .counter-value { color: var(--red); }
.counter-card.timeout .counter-value { color: var(--yellow); }

.log-card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; overflow: hidden;
}
.log-header { padding: 14px 18px; border-bottom: 1px solid var(--border); }
.log-table { width: 100%; border-collapse: collapse; }
.log-table thead { background: var(--bg-2); }
.log-table th {
  padding: 10px 14px; text-align: left;
  font-size: 10px; letter-spacing: 1.5px; font-weight: 700;
  color: var(--text-dim);
}
.log-table td { padding: 10px 14px; border-top: 1px solid var(--border); font-size: 12px; }
.log-body-scroll { max-height: 280px; overflow-y: auto; }

.status-tag { padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 10px; }
.status-OK { background: rgba(0,255,156,.15); color: var(--green); border: 1px solid var(--green); }
.status-ERROR { background: rgba(255,56,96,.15); color: var(--red); border: 1px solid var(--red); }
.status-WARN { background: rgba(255,214,10,.15); color: var(--yellow); border: 1px solid var(--yellow); }

footer {
  text-align: center; padding: 20px; color: var(--text-mute);
  font-size: 11px; letter-spacing: 1.5px;
  border-top: 1px solid var(--border); margin-top: 20px;
}
</style>
</head>
<body>

<header>
  <div class="brand">
    <span class="logo">MULTI-PROTOCOL CONCURRENCY LAYER</span>
    <span class="version-badge">v5.0</span>
    <span class="tagline">| MONITORING DASHBOARD</span>
  </div>
  <div class="status-bar">
    <div id="conn-pill" class="conn-pill">
      <span class="conn-dot"></span>
      <span id="conn-text" class="conn-text">CONNECTING...</span>
    </div>
    <span id="clock" class="clock">--:--:--</span>
  </div>
</header>

<main>

  <div class="metrics-row">
    <div class="metric-card cyan">
      <div class="metric-label">REQUESTS / SEC</div>
      <div class="metric-value" id="rps-value">0.0</div>
      <div class="metric-delta" id="rps-delta">awaiting traffic...</div>
    </div>
    <div class="metric-card magenta">
      <div class="metric-label">AVG LATENCY</div>
      <div class="metric-value" id="latency-value">0ms</div>
      <div class="metric-delta" id="latency-delta">&mdash;</div>
    </div>
    <div class="metric-card yellow">
      <div class="metric-label">ERROR RATE</div>
      <div class="metric-value" id="error-value">0.0%</div>
      <div class="metric-delta" id="error-status">STABLE</div>
    </div>
    <div class="metric-card green">
      <div class="metric-label">STATE</div>
      <div class="metric-value" id="state-value" style="font-size:24px">IDLE</div>
      <div class="metric-delta" id="state-target">no target</div>
    </div>
  </div>

  <div class="split-row">
    <div class="chart-card">
      <div class="card-header">
        <div class="card-title">TRAFFIC TREND (LAST 60s)</div>
      </div>
      <div id="chart-container"></div>
    </div>
    <div class="system-card">
      <div class="card-header">
        <div class="card-title">SYSTEM</div>
      </div>
      <div class="bar-block">
        <div class="bar-label"><span>CPU LOAD</span><span id="cpu-text">0%</span></div>
        <div class="bar-track"><div id="cpu-bar" class="bar-fill cpu" style="width:0%"></div></div>
      </div>
      <div class="bar-block">
        <div class="bar-label"><span>MEMORY</span><span id="mem-text">0%</span></div>
        <div class="bar-track"><div id="mem-bar" class="bar-fill mem" style="width:0%"></div></div>
      </div>
    </div>
  </div>

  <div class="counter-row">
    <div class="counter-card total"><div class="counter-label">TOTAL REQUESTS</div><div class="counter-value" id="cnt-total">0</div></div>
    <div class="counter-card ok"><div class="counter-label">COMPLETED</div><div class="counter-value" id="cnt-completed">0</div></div>
    <div class="counter-card fail"><div class="counter-label">FAILED</div><div class="counter-value" id="cnt-failed">0</div></div>
    <div class="counter-card timeout"><div class="counter-label">TIMEOUT</div><div class="counter-value" id="cnt-timeout">0</div></div>
  </div>

  <div class="log-card">
    <div class="log-header">
      <div class="card-title">EVENT LOG</div>
    </div>
    <div class="log-body-scroll">
      <table class="log-table">
        <thead>
          <tr><th>TIME</th><th>EVENT</th><th>SOURCE</th><th>ACTION</th><th>STATUS</th></tr>
        </thead>
        <tbody id="event-body">
          <tr><td colspan="5" style="text-align:center;color:var(--text-mute);padding:24px">No events. Run an attack from CLI to see live data.</td></tr>
        </tbody>
      </table>
    </div>
  </div>

</main>

<footer>Multi-Protocol Concurrency Layer v5.0 &middot; <span id="footer-time">--</span></footer>

<script>
const WS_URL = `ws://${window.location.hostname}:__WS_PORT__`;
let ws = null;
let lastRps = 0, lastLatency = 0;
let history = [];
let reconnectTimer = null;

function setConnected(on) {
  const pill = document.getElementById('conn-pill');
  const text = document.getElementById('conn-text');
  if (on) {
    pill.classList.add('connected');
    text.textContent = 'CONNECTED';
  } else {
    pill.classList.remove('connected');
    text.textContent = 'DISCONNECTED';
  }
}

function connect() {
  try {
    setConnected(false);
    document.getElementById('conn-text').textContent = 'CONNECTING...';
    ws = new WebSocket(WS_URL);
  } catch (e) {
    scheduleReconnect();
    return;
  }
  ws.onopen = () => {
    setConnected(true);
    if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
  };
  ws.onclose = () => { setConnected(false); scheduleReconnect(); };
  ws.onerror = () => { setConnected(false); };
  ws.onmessage = (event) => {
    let data;
    try { data = JSON.parse(event.data); } catch { return; }
    if (data.type === 'metrics' || data.type === 'full_state') {
      if (data.current) updateMetrics(data.current);
      if (data.history) { history = data.history; updateChart(); }
      if (data.events) updateEvents(data.events);
    } else if (data.type === 'event') {
      if (data.events) updateEvents(data.events);
    }
  };
}

function scheduleReconnect() {
  if (reconnectTimer) return;
  reconnectTimer = setTimeout(() => { reconnectTimer = null; connect(); }, 1500);
}

function fmtNum(n) {
  if (!isFinite(n)) return '0';
  if (n >= 1000000) return (n/1000000).toFixed(2) + 'M';
  if (n >= 1000) return (n/1000).toFixed(2) + 'k';
  return n.toFixed(1);
}

function updateMetrics(m) {
  const rpsDelta = m.rps - lastRps;
  const latDelta = m.latency_ms - lastLatency;

  document.getElementById('rps-value').textContent = fmtNum(m.rps);
  document.getElementById('rps-delta').textContent = (rpsDelta >= 0 ? '+' : '') + rpsDelta.toFixed(1);
  document.getElementById('latency-value').textContent = m.latency_ms.toFixed(0) + 'ms';
  document.getElementById('latency-delta').textContent = (latDelta >= 0 ? '+' : '') + latDelta.toFixed(0) + 'ms';
  document.getElementById('error-value').textContent = (m.error_rate * 100).toFixed(2) + '%';
  const errStatus = m.error_rate < 0.05 ? 'STABLE' : m.error_rate < 0.2 ? 'ELEVATED' : 'CRITICAL';
  document.getElementById('error-status').textContent = errStatus;

  document.getElementById('state-value').textContent = m.adaptive_state || 'IDLE';
  document.getElementById('state-target').textContent = m.target && m.target !== '--' ? m.target.substring(0, 28) : 'no target';

  const cpu = m.cpu_percent || 0;
  const mem = m.memory_percent || 0;
  document.getElementById('cpu-bar').style.width = cpu + '%';
  document.getElementById('cpu-text').textContent = cpu.toFixed(0) + '%';
  document.getElementById('mem-bar').style.width = mem + '%';
  document.getElementById('mem-text').textContent = mem.toFixed(0) + '%';

  document.getElementById('cnt-total').textContent = (m.total_requests || 0).toLocaleString();
  document.getElementById('cnt-completed').textContent = (m.completed || 0).toLocaleString();
  document.getElementById('cnt-failed').textContent = (m.failed || 0).toLocaleString();
  document.getElementById('cnt-timeout').textContent = (m.timeout || 0).toLocaleString();

  lastRps = m.rps;
  lastLatency = m.latency_ms;
  document.getElementById('footer-time').textContent = new Date().toLocaleTimeString();
}

function updateChart() {
  const c = document.getElementById('chart-container');
  c.innerHTML = '';
  if (!history.length) {
    c.innerHTML = '<div style="margin:auto;color:var(--text-mute);font-size:11px">NO DATA</div>';
    return;
  }
  const maxRps = Math.max(...history.map(h => h.rps), 1);
  history.forEach(h => {
    const bar = document.createElement('div');
    let kind = 'normal';
    if (h.error_rate > 0.2) kind = 'spike';
    else if (h.error_rate > 0.05) kind = 'warn';
    bar.className = 'chart-bar ' + kind;
    bar.style.height = Math.max(2, (h.rps / maxRps) * 100) + '%';
    c.appendChild(bar);
  });
}

function updateEvents(events) {
  const tbody = document.getElementById('event-body');
  tbody.innerHTML = '';
  if (!events.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-mute);padding:24px">No events yet.</td></tr>';
  } else {
    events.slice(0, 15).forEach(e => {
      const row = document.createElement('tr');
      row.innerHTML = `
        <td style="color:var(--text-dim)">${e.timestamp}</td>
        <td style="color:var(--cyan);font-weight:600">${e.event_type}</td>
        <td style="color:var(--text-dim)">${e.source}</td>
        <td>${e.action}</td>
        <td><span class="status-tag status-${e.status}">${e.status}</span></td>`;
      tbody.appendChild(row);
    });
  }
}

setInterval(() => { document.getElementById('clock').textContent = new Date().toLocaleTimeString(); }, 1000);

connect();
</script>
</body>
</html>"""


# ============================================================================
# DASHBOARD SERVER (HTTP + WebSocket)
# ============================================================================
class DashboardServer:
    """Combined HTTP + WebSocket dashboard server"""
    
    def __init__(self, host: str = "127.0.0.1", http_port: int = 8080, ws_port: int = 8765):
        self.host = host
        self.http_port = http_port
        self.ws_port = ws_port
        self.clients: Set = set()
        self.current_metrics: Optional[MetricsSnapshot] = None
        self.metrics_history: List[Dict] = []
        self.event_log: List[Dict] = []
        self.max_history = 60
        self.max_events = 50
        self.is_running = False
        self._http_thread = None
        self._broadcast_task = None

    def add_event(self, event_type: str, source: str, action: str, status: str = "OK"):
        ts = datetime.now().strftime("%H:%M:%S.") + f"{int(time.time()*1000)%1000:03d}"
        evt = EventLog(timestamp=ts, event_type=event_type, source=source, action=action, status=status)
        self.event_log.insert(0, asdict(evt))
        if len(self.event_log) > self.max_events:
            self.event_log = self.event_log[:self.max_events]

    async def register_client(self, websocket, *args, **kwargs):
        """Handle new WebSocket client"""
        self.clients.add(websocket)
        logger.info(f"Dashboard client connected. Total: {len(self.clients)}")
        try:
            # Send full state on connect
            payload = {
                "type": "full_state",
                "current": asdict(self.current_metrics) if self.current_metrics else None,
                "history": self.metrics_history,
                "events": self.event_log,
            }
            await websocket.send(json.dumps(payload))
            
            # Keep connection alive
            async for message in websocket:
                try:
                    data = json.loads(message)
                    if data.get("type") == "ping":
                        await websocket.send(json.dumps({"type": "pong", "ts": time.time()}))
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"Client loop ended: {e}")
        finally:
            self.clients.discard(websocket)
            logger.info(f"Dashboard client disconnected. Total: {len(self.clients)}")

    async def broadcast_metrics(self, metrics: MetricsSnapshot):
        """Broadcast metrics to all connected clients"""
        sys_stats = get_system_stats()
        metrics.cpu_percent = sys_stats["cpu"]
        metrics.memory_percent = sys_stats["memory"]
        metrics.threat_level = min(1.0, metrics.error_rate * 0.6 + (metrics.latency_ms / 5000) * 0.4)

        self.current_metrics = metrics
        self.metrics_history.append(asdict(metrics))
        if len(self.metrics_history) > self.max_history:
            self.metrics_history.pop(0)

        if self.clients:
            payload = {
                "type": "metrics",
                "current": asdict(metrics),
                "history": self.metrics_history,
                "events": self.event_log[:15],
            }
            message = json.dumps(payload)
            await asyncio.gather(
                *[c.send(message) for c in self.clients],
                return_exceptions=True
            )

    async def _periodic_system_broadcast(self):
        """Periodically broadcast system stats even when idle"""
        while self.is_running:
            try:
                if not self.current_metrics:
                    # Send idle state with system stats
                    metrics = MetricsSnapshot(
                        timestamp=time.time(),
                        rps=0.0, latency_ms=0.0, error_rate=0.0,
                        health_score=1.0, adaptive_state="IDLE",
                        adaptive_strategy="--",
                        total_requests=0, completed=0, failed=0, timeout=0,
                        method="--", target="--",
                    )
                    await self.broadcast_metrics(metrics)
                await asyncio.sleep(1)
            except Exception as e:
                logger.debug(f"Periodic broadcast error: {e}")
                await asyncio.sleep(1)

    def _start_http_server(self):
        """Start HTTP server in separate thread"""
        ws_port = self.ws_port
        html = DASHBOARD_HTML.replace("__WS_PORT__", str(ws_port))
        
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/" or self.path == "/index.html":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Cache-Control", "no-cache")
                    self.end_headers()
                    self.wfile.write(html.encode("utf-8"))
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def log_message(self, format, *args):
                # Suppress HTTP server logs
                pass
        
        try:
            httpd = HTTPServer((self.host, self.http_port), Handler)
            logger.info(f"HTTP server running on http://{self.host}:{self.http_port}")
            httpd.serve_forever()
        except Exception as e:
            logger.error(f"HTTP server failed: {e}")

    async def start(self):
        """Start both HTTP and WebSocket servers"""
        if not HAS_WEBSOCKETS:
            print("ERROR: websockets library not installed")
            print("Install: pip install websockets")
            return
        
        self.is_running = True
        
        # Start HTTP server in thread
        self._http_thread = threading.Thread(target=self._start_http_server, daemon=True)
        self._http_thread.start()
        
        # Start periodic broadcast
        self._broadcast_task = asyncio.create_task(self._periodic_system_broadcast())
        
        # Start WebSocket server
        logger.info(f"WebSocket server starting on ws://{self.host}:{self.ws_port}")
        self.add_event("DASHBOARD_START", "SYSTEM", "WS_LISTEN", "OK")
        
        try:
            async with websockets.serve(self.register_client, self.host, self.ws_port):
                logger.info(f"Dashboard ready: http://{self.host}:{self.http_port}")
                while self.is_running:
                    await asyncio.sleep(1)
        except Exception as e:
            logger.error(f"WebSocket server failed: {e}")

    async def stop(self):
        """Stop dashboard server"""
        self.is_running = False
        if self._broadcast_task:
            self._broadcast_task.cancel()
        for client in list(self.clients):
            try:
                await client.close()
            except Exception:
                pass
        logger.info("Dashboard server stopped")


# ============================================================================
# GLOBAL INSTANCE & ENTRY POINT
# ============================================================================
_dashboard_instance: Optional[DashboardServer] = None


def get_dashboard() -> DashboardServer:
    """Get global dashboard instance"""
    global _dashboard_instance
    if _dashboard_instance is None:
        _dashboard_instance = DashboardServer()
    return _dashboard_instance


async def start_dashboard(host: str = "127.0.0.1", http_port: int = 8080, ws_port: int = 8765):
    """Start dashboard server (entry point for [0] menu)"""
    if not HAS_WEBSOCKETS:
        print("\n  [-] websockets library not installed")
        print("  [*] Install with: pip install websockets")
        return
    
    server = DashboardServer(host=host, http_port=http_port, ws_port=ws_port)
    
    print(f"\n  [+] Dashboard starting...")
    print(f"  [*] Open browser: http://{host}:{http_port}")
    print(f"  [*] WebSocket: ws://{host}:{ws_port}")
    print(f"  [*] Press Ctrl+C to stop\n")
    
    try:
        await server.start()
    except KeyboardInterrupt:
        print("\n  [*] Dashboard stopping...")
        await server.stop()
    except Exception as e:
        print(f"\n  [-] Dashboard error: {e}")
        await server.stop()
