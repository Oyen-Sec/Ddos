"""
Real-time Attack Dashboard v1.0
Vibrant cyberpunk UI - colorful palette, prominent DDoS controls.
Streams live metrics, system status, event log.
"""
import asyncio
import json
import time
import logging
import platform
from typing import Dict, Set, Optional, List
from dataclasses import dataclass, asdict, field
from datetime import datetime

logger = logging.getLogger("dashboard")

try:
    import websockets
except ImportError:
    logger.error("websockets not installed")
    websockets = None

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
    status: str  # RESOLVED, MONITORING, PENDING, OK, ERROR


@dataclass
class NodeHealth:
    node_id: str
    health: float  # 0-1
    region: str = "LOCAL"


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


class DashboardServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 8765):
        self.host = host
        self.port = port
        self.clients: Set = set()
        self.current_metrics: Optional[MetricsSnapshot] = None
        self.metrics_history: List[Dict] = []
        self.event_log: List[Dict] = []
        self.node_health: List[NodeHealth] = [
            NodeHealth(f"NODE_{i:02d}", 0.9 if i < 7 else 0.4) for i in range(8)
        ]
        self.max_history = 60
        self.max_events = 50
        self.is_running = False
        self.command_handler = None

    def set_command_handler(self, handler):
        self.command_handler = handler

    def add_event(self, event_type: str, source: str, action: str, status: str = "OK"):
        ts = datetime.now().strftime("%H:%M:%S.") + f"{int(time.time()*1000)%1000:03d}"
        evt = EventLog(timestamp=ts, event_type=event_type, source=source, action=action, status=status)
        self.event_log.insert(0, asdict(evt))
        if len(self.event_log) > self.max_events:
            self.event_log = self.event_log[: self.max_events]

    async def register_client(self, websocket, *args, **kwargs):
        """Handler that accepts both old (websocket, path) and new (websocket) signatures."""
        self.clients.add(websocket)
        logger.info(f"Client connected. Total: {len(self.clients)}")
        try:
            await self._send_full_state(websocket)
            async for message in websocket:
                try:
                    data = json.loads(message)
                    if data.get("type") == "command" and self.command_handler:
                        result = await self.command_handler(data.get("action"), data.get("payload", {}))
                        await websocket.send(json.dumps({
                            "type": "command_result",
                            "action": data.get("action"),
                            "result": result,
                        }))
                    elif data.get("type") == "ping":
                        await websocket.send(json.dumps({"type": "pong", "ts": time.time()}))
                except Exception as e:
                    logger.warning(f"Command handle error: {e}")
        except Exception as e:
            logger.debug(f"Client loop ended: {e}")
        finally:
            self.clients.discard(websocket)
            logger.info(f"Client disconnected. Total: {len(self.clients)}")

    async def _send_full_state(self, websocket):
        payload = {
            "type": "full_state",
            "current": asdict(self.current_metrics) if self.current_metrics else None,
            "history": self.metrics_history,
            "events": self.event_log,
            "nodes": [asdict(n) for n in self.node_health],
        }
        await websocket.send(json.dumps(payload))

    async def broadcast_metrics(self, metrics: MetricsSnapshot):
        sys_stats = get_system_stats()
        metrics.cpu_percent = sys_stats["cpu"]
        metrics.memory_percent = sys_stats["memory"]
        metrics.threat_level = min(1.0, metrics.error_rate * 0.6 + (metrics.latency_ms / 5000) * 0.4)

        self.current_metrics = metrics
        self.metrics_history.append(asdict(metrics))
        if len(self.metrics_history) > self.max_history:
            self.metrics_history.pop(0)

        payload = {
            "type": "metrics",
            "current": asdict(metrics),
            "history": self.metrics_history,
            "events": self.event_log[:15],
            "nodes": [asdict(n) for n in self.node_health],
        }
        message = json.dumps(payload)
        if self.clients:
            await asyncio.gather(
                *[c.send(message) for c in self.clients],
                return_exceptions=True
            )

    async def broadcast_event(self, event_type: str, source: str, action: str, status: str = "OK"):
        self.add_event(event_type, source, action, status)
        if self.clients:
            payload = {"type": "event", "events": self.event_log[:15]}
            await asyncio.gather(
                *[c.send(json.dumps(payload)) for c in self.clients],
                return_exceptions=True
            )

    async def start(self):
        self.is_running = True
        logger.info(f"Dashboard WS starting on ws://{self.host}:{self.port}")
        async with websockets.serve(self.register_client, self.host, self.port):
            self.add_event("DASHBOARD_START", "SYSTEM", "WS_LISTEN", "OK")
            logger.info(f"Dashboard WS ready on ws://{self.host}:{self.port}")
            while self.is_running:
                await asyncio.sleep(1)

    async def stop(self):
        self.is_running = False
        for client in list(self.clients):
            try:
                await client.close()
            except Exception:
                pass
        logger.info("Dashboard server stopped")


# ============================================================================
# COLORFUL CYBERPUNK DASHBOARD - v1.0
# ============================================================================
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NOIR DDoS v1.0 — Attack Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Orbitron:wght@600;700;900&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #07091a;
  --bg-2: #0d1126;
  --surface: #141a35;
  --surface-2: #1c2347;
  --surface-3: #252e58;
  --border: #2d3766;
  --border-bright: #3d4d8a;
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
  --pink: #ff6ec7;
}

* { box-sizing: border-box; margin: 0; padding: 0; }
html, body { height: 100%; }
body {
  background: var(--bg);
  background-image:
    radial-gradient(circle at 12% 18%, rgba(255, 43, 214, 0.10) 0%, transparent 45%),
    radial-gradient(circle at 88% 30%, rgba(0, 229, 255, 0.10) 0%, transparent 45%),
    radial-gradient(circle at 50% 95%, rgba(177, 74, 255, 0.10) 0%, transparent 50%);
  color: var(--text);
  font-family: 'JetBrains Mono', monospace;
  font-size: 13px;
  -webkit-font-smoothing: antialiased;
  overflow-x: hidden;
}

::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: var(--bg-2); }
::-webkit-scrollbar-thumb { background: linear-gradient(180deg, var(--cyan), var(--magenta)); border-radius: 4px; }

/* Header */
header {
  background: linear-gradient(90deg, rgba(20,26,53,.95), rgba(28,35,71,.95));
  border-bottom: 2px solid transparent;
  border-image: linear-gradient(90deg, var(--cyan), var(--magenta), var(--yellow)) 1;
  padding: 14px 28px;
  display: flex; justify-content: space-between; align-items: center;
  position: sticky; top: 0; z-index: 100;
  backdrop-filter: blur(10px);
}
.brand { display: flex; align-items: center; gap: 14px; }
.logo {
  font-family: 'Orbitron', sans-serif; font-weight: 900;
  font-size: 22px; letter-spacing: 2px;
  background: linear-gradient(90deg, var(--cyan), var(--magenta), var(--yellow));
  -webkit-background-clip: text; background-clip: text; color: transparent;
  text-shadow: 0 0 30px rgba(0,229,255,.4);
}
.version-badge {
  background: linear-gradient(135deg, var(--green), var(--cyan));
  color: #001;
  padding: 3px 10px; border-radius: 4px;
  font-weight: 700; font-size: 11px;
  letter-spacing: 1px;
}
.tagline { color: var(--text-dim); font-size: 11px; letter-spacing: 1px; }

.status-bar { display: flex; align-items: center; gap: 18px; }
.conn-pill {
  display: flex; align-items: center; gap: 8px;
  padding: 6px 14px; border-radius: 999px;
  background: var(--surface-2); border: 1px solid var(--red);
  transition: all .3s;
}
.conn-pill.connected { border-color: var(--green); box-shadow: 0 0 14px rgba(0,255,156,.3); }
.conn-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--red); }
.conn-pill.connected .conn-dot { background: var(--green); animation: pulse 1.5s infinite; }
@keyframes pulse { 0%,100% { opacity: 1; transform: scale(1); } 50% { opacity: .5; transform: scale(1.3); } }
.conn-text { font-weight: 700; letter-spacing: 1px; font-size: 11px; }
.conn-pill.connected .conn-text { color: var(--green); }
.conn-pill:not(.connected) .conn-text { color: var(--red); }

.clock { color: var(--text-dim); font-size: 11px; font-variant-numeric: tabular-nums; }

/* Main */
main { max-width: 1500px; margin: 0 auto; padding: 22px; display: flex; flex-direction: column; gap: 18px; }

/* Attack panel - PROMINENT */
.attack-panel {
  background: linear-gradient(135deg, rgba(255,43,214,.08), rgba(0,229,255,.08));
  border: 2px solid var(--magenta);
  border-radius: 12px; padding: 22px;
  position: relative; overflow: hidden;
  box-shadow: 0 0 40px rgba(255,43,214,.15);
}
.attack-panel::before {
  content: ''; position: absolute; inset: 0;
  background: linear-gradient(90deg, transparent, rgba(255,43,214,.05), transparent);
  animation: shine 4s infinite;
}
@keyframes shine { 0% { transform: translateX(-100%); } 100% { transform: translateX(100%); } }
.attack-title {
  font-family: 'Orbitron', sans-serif; font-weight: 900;
  font-size: 18px; letter-spacing: 3px;
  background: linear-gradient(90deg, var(--magenta), var(--cyan));
  -webkit-background-clip: text; background-clip: text; color: transparent;
  margin-bottom: 4px;
}
.attack-subtitle { color: var(--text-dim); margin-bottom: 18px; font-size: 12px; }

.form-grid {
  display: grid; grid-template-columns: 2fr 1fr 1fr 1fr; gap: 12px;
  margin-bottom: 16px;
}
.form-group label {
  display: block; font-size: 10px; letter-spacing: 1.5px;
  color: var(--cyan); margin-bottom: 6px; font-weight: 700;
}
.form-group input, .form-group select {
  width: 100%; background: var(--bg-2); border: 1px solid var(--border);
  padding: 10px 12px; color: var(--text);
  font-family: 'JetBrains Mono', monospace; font-size: 13px;
  border-radius: 6px; transition: all .2s;
}
.form-group input:focus, .form-group select:focus {
  outline: none; border-color: var(--cyan);
  box-shadow: 0 0 0 3px rgba(0,229,255,.15);
}

.action-row {
  display: grid; grid-template-columns: 2fr 1fr 1fr 1fr 1fr; gap: 10px;
}
.btn {
  border: none; padding: 14px 16px; cursor: pointer;
  font-family: 'JetBrains Mono', monospace; font-weight: 700;
  font-size: 12px; letter-spacing: 1.5px; border-radius: 6px;
  transition: all .2s; position: relative; overflow: hidden;
  display: flex; align-items: center; justify-content: center; gap: 8px;
}
.btn:hover:not(:disabled) { transform: translateY(-2px); }
.btn:disabled { opacity: .4; cursor: not-allowed; }
.btn-icon { font-size: 16px; }

.btn-attack {
  background: linear-gradient(135deg, var(--magenta), var(--red));
  color: white;
  box-shadow: 0 4px 16px rgba(255,43,214,.4);
}
.btn-attack:hover:not(:disabled) { box-shadow: 0 6px 24px rgba(255,43,214,.6); }

.btn-stop {
  background: linear-gradient(135deg, var(--red), #c92242);
  color: white; box-shadow: 0 4px 12px rgba(255,56,96,.3);
}
.btn-scan { background: linear-gradient(135deg, var(--cyan), var(--blue)); color: #001; }
.btn-origin { background: linear-gradient(135deg, var(--yellow), var(--orange)); color: #001; }
.btn-proxy { background: linear-gradient(135deg, var(--purple), var(--magenta)); color: white; }

/* Metrics row */
.metrics-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; }
.metric-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px; padding: 18px;
  position: relative; overflow: hidden;
  transition: all .3s;
}
.metric-card::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px;
}
.metric-card:hover { transform: translateY(-2px); border-color: var(--border-bright); }
.metric-card.cyan::before { background: var(--cyan); }
.metric-card.magenta::before { background: var(--magenta); }
.metric-card.yellow::before { background: var(--yellow); }
.metric-card.green::before { background: var(--green); }

.metric-label {
  font-size: 10px; letter-spacing: 2px; font-weight: 700;
  margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center;
}
.metric-card.cyan .metric-label { color: var(--cyan); }
.metric-card.magenta .metric-label { color: var(--magenta); }
.metric-card.yellow .metric-label { color: var(--yellow); }
.metric-card.green .metric-label { color: var(--green); }

.metric-value {
  font-family: 'Orbitron', sans-serif; font-weight: 700;
  font-size: 32px; line-height: 1; letter-spacing: -1px;
}
.metric-card.cyan .metric-value { color: var(--cyan); }
.metric-card.magenta .metric-value { color: var(--magenta); }
.metric-card.yellow .metric-value { color: var(--yellow); }
.metric-card.green .metric-value { color: var(--green); }

.metric-delta { font-size: 11px; color: var(--text-dim); margin-top: 6px; }
.metric-icon { font-size: 18px; opacity: .8; }

/* Charts + System */
.split-row { display: grid; grid-template-columns: 2fr 1fr; gap: 14px; }

.chart-card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 18px; height: 320px;
  display: flex; flex-direction: column;
}
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
.legend { display: flex; gap: 12px; font-size: 10px; color: var(--text-dim); }
.legend-dot { display: inline-block; width: 8px; height: 8px; margin-right: 4px; vertical-align: middle; }

#chart-container {
  flex: 1; display: flex; align-items: flex-end;
  justify-content: space-between; gap: 2px; padding: 0 4px;
}
.chart-bar {
  flex: 1; min-height: 2px; border-radius: 2px 2px 0 0;
  transition: all .2s; cursor: pointer;
}
.chart-bar:hover { filter: brightness(1.4); }
.chart-bar.normal { background: linear-gradient(180deg, var(--cyan), var(--blue)); }
.chart-bar.warn { background: linear-gradient(180deg, var(--yellow), var(--orange)); }
.chart-bar.spike { background: linear-gradient(180deg, var(--red), var(--magenta)); }

.system-card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 18px;
}
.bar-block { margin-bottom: 14px; }
.bar-block:last-child { margin-bottom: 0; }
.bar-label {
  display: flex; justify-content: space-between;
  font-size: 11px; letter-spacing: 1px; font-weight: 600;
  margin-bottom: 6px; color: var(--text-dim);
}
.bar-track {
  height: 8px; background: var(--bg-2); border-radius: 4px; overflow: hidden;
  position: relative;
}
.bar-fill {
  height: 100%; border-radius: 4px;
  transition: width .4s ease, background .3s;
}
.bar-fill.cpu { background: linear-gradient(90deg, var(--green), var(--cyan)); }
.bar-fill.mem { background: linear-gradient(90deg, var(--cyan), var(--magenta)); }
.bar-fill.threat-low { background: linear-gradient(90deg, var(--green), var(--cyan)); }
.bar-fill.threat-med { background: linear-gradient(90deg, var(--yellow), var(--orange)); }
.bar-fill.threat-high { background: linear-gradient(90deg, var(--orange), var(--red)); }

/* Counters */
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
  font-size: 22px; font-variant-numeric: tabular-nums;
}
.counter-card.total .counter-value { color: var(--cyan); }
.counter-card.ok .counter-value { color: var(--green); }
.counter-card.fail .counter-value { color: var(--red); }
.counter-card.timeout .counter-value { color: var(--yellow); }

/* Event log */
.log-card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; overflow: hidden;
}
.log-header { padding: 14px 18px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
.log-table { width: 100%; border-collapse: collapse; }
.log-table thead { background: var(--bg-2); }
.log-table th {
  padding: 10px 14px; text-align: left;
  font-size: 10px; letter-spacing: 1.5px; font-weight: 700;
  color: var(--text-dim);
}
.log-table td { padding: 10px 14px; border-top: 1px solid var(--border); font-size: 12px; }
.log-table tr:hover { background: var(--surface-2); }
.log-body-scroll { max-height: 280px; overflow-y: auto; }

.status-tag { padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 10px; letter-spacing: 1px; }
.status-OK { background: rgba(0,255,156,.15); color: var(--green); border: 1px solid var(--green); }
.status-RESOLVED { background: rgba(0,255,156,.15); color: var(--green); border: 1px solid var(--green); }
.status-PENDING { background: rgba(255,214,10,.15); color: var(--yellow); border: 1px solid var(--yellow); }
.status-MONITORING { background: rgba(0,229,255,.15); color: var(--cyan); border: 1px solid var(--cyan); }
.status-ERROR { background: rgba(255,56,96,.15); color: var(--red); border: 1px solid var(--red); }

/* Toast */
#toast-container { position: fixed; top: 80px; right: 20px; z-index: 1000; display: flex; flex-direction: column; gap: 10px; }
.toast {
  background: var(--surface-2); border-left: 4px solid var(--cyan);
  padding: 12px 18px; border-radius: 6px;
  min-width: 280px; max-width: 380px;
  box-shadow: 0 4px 20px rgba(0,0,0,.4);
  animation: slideIn .3s; font-size: 12px;
}
.toast.success { border-color: var(--green); }
.toast.error { border-color: var(--red); }
.toast.info { border-color: var(--cyan); }
.toast.warn { border-color: var(--yellow); }
.toast-title { font-weight: 700; margin-bottom: 4px; letter-spacing: 1px; }
.toast.success .toast-title { color: var(--green); }
.toast.error .toast-title { color: var(--red); }
.toast.info .toast-title { color: var(--cyan); }
.toast.warn .toast-title { color: var(--yellow); }
.toast-body { color: var(--text-dim); word-break: break-word; }
@keyframes slideIn { from { transform: translateX(120%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }

/* Footer */
footer {
  text-align: center; padding: 20px; color: var(--text-mute);
  font-size: 11px; letter-spacing: 1.5px;
  border-top: 1px solid var(--border); margin-top: 20px;
}

@media (max-width: 1100px) {
  .form-grid { grid-template-columns: 1fr 1fr; }
  .action-row { grid-template-columns: 1fr 1fr; }
  .metrics-row { grid-template-columns: 1fr 1fr; }
  .split-row { grid-template-columns: 1fr; }
  .counter-row { grid-template-columns: 1fr 1fr; }
}
</style>
</head>
<body>

<header>
  <div class="brand">
    <span class="logo">NOIR DDoS</span>
    <span class="version-badge">v1.0</span>
    <span class="tagline">| ATTACK CONTROL CENTER</span>
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

  <!-- ATTACK PANEL -->
  <div class="attack-panel">
    <div class="attack-title">&gt;&gt; LAUNCH ATTACK</div>
    <div class="attack-subtitle">Target a URL, pick a method, fire away. Real-time metrics will stream below.</div>

    <div class="form-grid">
      <div class="form-group">
        <label>TARGET URL</label>
        <input id="ctrl-target" type="text" placeholder="https://example.com" autocomplete="off">
      </div>
      <div class="form-group">
        <label>METHOD</label>
        <select id="ctrl-method">
          <option value="http_get_flood">HTTP GET FLOOD</option>
          <option value="http_post_flood">HTTP POST FLOOD</option>
          <option value="browser">BROWSER (JS)</option>
          <option value="dynamic">DYNAMIC</option>
          <option value="slow">SLOW</option>
          <option value="slowloris">SLOWLORIS</option>
        </select>
      </div>
      <div class="form-group">
        <label>DURATION (s)</label>
        <input id="ctrl-duration" type="number" value="30" min="5" max="3600">
      </div>
      <div class="form-group">
        <label>TARGET RPS</label>
        <input id="ctrl-rps" type="number" value="100" min="1" max="10000">
      </div>
    </div>

    <div class="action-row">
      <button class="btn btn-attack" data-cmd="attack_direct">
        <span class="btn-icon">&#9889;</span> START DDoS ATTACK
      </button>
      <button class="btn btn-stop" data-cmd="stop">
        <span class="btn-icon">&#9209;</span> STOP
      </button>
      <button class="btn btn-scan" data-cmd="seo_scan">
        <span class="btn-icon">&#128270;</span> SCAN
      </button>
      <button class="btn btn-origin" data-cmd="find_origin">
        <span class="btn-icon">&#127919;</span> FIND ORIGIN
      </button>
      <button class="btn btn-proxy" data-cmd="test_proxies">
        <span class="btn-icon">&#128272;</span> TEST PROXIES
      </button>
    </div>
  </div>

  <!-- METRICS ROW -->
  <div class="metrics-row">
    <div class="metric-card cyan">
      <div class="metric-label"><span>REQUESTS / SEC</span><span class="metric-icon">&#9889;</span></div>
      <div class="metric-value" id="rps-value">0.0</div>
      <div class="metric-delta" id="rps-delta">awaiting traffic...</div>
    </div>
    <div class="metric-card magenta">
      <div class="metric-label"><span>AVG LATENCY</span><span class="metric-icon">&#9201;</span></div>
      <div class="metric-value" id="latency-value">0ms</div>
      <div class="metric-delta" id="latency-delta">&mdash;</div>
    </div>
    <div class="metric-card yellow">
      <div class="metric-label"><span>ERROR RATE</span><span class="metric-icon">&#9888;</span></div>
      <div class="metric-value" id="error-value">0.0%</div>
      <div class="metric-delta" id="error-status">STABLE</div>
    </div>
    <div class="metric-card green">
      <div class="metric-label"><span>STATE</span><span class="metric-icon">&#9678;</span></div>
      <div class="metric-value" id="state-value" style="font-size:24px">IDLE</div>
      <div class="metric-delta" id="state-target">no target</div>
    </div>
  </div>

  <!-- CHART + SYSTEM -->
  <div class="split-row">
    <div class="chart-card">
      <div class="card-header">
        <div class="card-title">TRAFFIC TREND (LAST 60s)</div>
        <div class="legend">
          <span><span class="legend-dot" style="background:var(--cyan)"></span>NORMAL</span>
          <span><span class="legend-dot" style="background:var(--yellow)"></span>WARN</span>
          <span><span class="legend-dot" style="background:var(--red)"></span>SPIKE</span>
        </div>
      </div>
      <div id="chart-container"></div>
    </div>
    <div class="system-card">
      <div class="card-header">
        <div class="card-title">SYSTEM</div>
        <span id="status-text" style="color:var(--green);font-size:10px;font-weight:700;letter-spacing:2px">IDLE</span>
      </div>
      <div class="bar-block">
        <div class="bar-label"><span>CPU LOAD</span><span id="cpu-text">0%</span></div>
        <div class="bar-track"><div id="cpu-bar" class="bar-fill cpu" style="width:0%"></div></div>
      </div>
      <div class="bar-block">
        <div class="bar-label"><span>MEMORY</span><span id="mem-text">0%</span></div>
        <div class="bar-track"><div id="mem-bar" class="bar-fill mem" style="width:0%"></div></div>
      </div>
      <div class="bar-block">
        <div class="bar-label"><span>THREAT LEVEL</span><span id="threat-text">LOW</span></div>
        <div class="bar-track"><div id="threat-bar" class="bar-fill threat-low" style="width:0%"></div></div>
      </div>
    </div>
  </div>

  <!-- COUNTERS -->
  <div class="counter-row">
    <div class="counter-card total"><div class="counter-label">TOTAL REQUESTS</div><div class="counter-value" id="cnt-total">0</div></div>
    <div class="counter-card ok"><div class="counter-label">COMPLETED</div><div class="counter-value" id="cnt-completed">0</div></div>
    <div class="counter-card fail"><div class="counter-label">FAILED</div><div class="counter-value" id="cnt-failed">0</div></div>
    <div class="counter-card timeout"><div class="counter-label">TIMEOUT</div><div class="counter-value" id="cnt-timeout">0</div></div>
  </div>

  <!-- EVENT LOG -->
  <div class="log-card">
    <div class="log-header">
      <div class="card-title">EVENT LOG</div>
      <span id="event-count" style="font-size:11px;color:var(--text-dim)">0 events</span>
    </div>
    <div class="log-body-scroll">
      <table class="log-table">
        <thead>
          <tr><th>TIME</th><th>EVENT</th><th>SOURCE</th><th>ACTION</th><th>STATUS</th></tr>
        </thead>
        <tbody id="event-body">
          <tr><td colspan="5" style="text-align:center;color:var(--text-mute);padding:24px">No events yet. Launch an attack to begin.</td></tr>
        </tbody>
      </table>
    </div>
  </div>

</main>

<footer>NOIR DDoS v1.0 &middot; ENGINE: ENHANCED &middot; <span id="footer-time">--</span></footer>

<div id="toast-container"></div>

<script>
const WS_URL = `ws://${window.location.hostname}:__WS_PORT__`;
let ws = null;
let lastRps = 0, lastLatency = 0;
let history = [];
let reconnectTimer = null;

function toast(title, body, kind) {
  const c = document.getElementById('toast-container');
  const t = document.createElement('div');
  t.className = 'toast ' + (kind || 'info');
  t.innerHTML = `<div class="toast-title">${title}</div><div class="toast-body">${body}</div>`;
  c.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; t.style.transform = 'translateX(120%)'; t.style.transition = 'all .3s'; setTimeout(() => t.remove(), 300); }, 4500);
}

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
    toast('CONNECTED', 'Live stream active', 'success');
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
    } else if (data.type === 'command_result') {
      handleCmdResult(data.action, data.result);
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
  document.getElementById('rps-delta').textContent = (rpsDelta >= 0 ? '+' : '') + rpsDelta.toFixed(1) + ' from last';
  document.getElementById('latency-value').textContent = m.latency_ms.toFixed(0) + 'ms';
  document.getElementById('latency-delta').textContent = (latDelta >= 0 ? '+' : '') + latDelta.toFixed(0) + 'ms';
  document.getElementById('error-value').textContent = (m.error_rate * 100).toFixed(2) + '%';
  const errStatus = m.error_rate < 0.05 ? 'STABLE' : m.error_rate < 0.2 ? 'ELEVATED' : 'CRITICAL';
  document.getElementById('error-status').textContent = errStatus;

  document.getElementById('state-value').textContent = m.adaptive_state || 'IDLE';
  document.getElementById('state-target').textContent = m.target && m.target !== '--' ? m.target.substring(0, 28) : 'no target';

  const cpu = m.cpu_percent || 0;
  const mem = m.memory_percent || 0;
  const threat = (m.threat_level || 0) * 100;
  document.getElementById('cpu-bar').style.width = cpu + '%';
  document.getElementById('cpu-text').textContent = cpu.toFixed(0) + '%';
  document.getElementById('mem-bar').style.width = mem + '%';
  document.getElementById('mem-text').textContent = mem.toFixed(0) + '%';

  const threatBar = document.getElementById('threat-bar');
  threatBar.style.width = threat + '%';
  threatBar.className = 'bar-fill ' + (threat > 60 ? 'threat-high' : threat > 30 ? 'threat-med' : 'threat-low');
  document.getElementById('threat-text').textContent = threat > 60 ? 'CRITICAL' : threat > 30 ? 'ELEVATED' : 'LOW';

  document.getElementById('status-text').textContent = m.adaptive_state || 'IDLE';
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
    c.innerHTML = '<div style="margin:auto;color:var(--text-mute);font-size:11px;letter-spacing:2px">NO DATA</div>';
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
    bar.title = `RPS: ${h.rps.toFixed(1)} | Lat: ${h.latency_ms.toFixed(0)}ms | Err: ${(h.error_rate*100).toFixed(1)}%`;
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
        <td style="color:var(--text-dim);font-variant-numeric:tabular-nums">${e.timestamp}</td>
        <td style="color:var(--cyan);font-weight:600">${e.event_type}</td>
        <td style="color:var(--text-dim)">${e.source}</td>
        <td>${e.action}</td>
        <td><span class="status-tag status-${e.status}">${e.status}</span></td>`;
      tbody.appendChild(row);
    });
  }
  document.getElementById('event-count').textContent = `${events.length} events`;
}

function handleCmdResult(action, result) {
  if (result && result.error) {
    toast('ERROR: ' + action.toUpperCase(), result.error, 'error');
  } else if (result && result.status === 'started') {
    toast('ATTACK LAUNCHED', `${result.method} -> ${result.target} | ${result.duration}s @ ${result.rps} RPS`, 'success');
  } else if (result && result.status === 'stopped') {
    toast('STOPPED', 'Attack halted', 'warn');
  } else if (action === 'seo_scan' && !result.error) {
    toast('SCAN COMPLETE', `CMS: ${result.cms || '?'} | WAF: ${result.waf || '?'} | ${result.accessible || 0}/${result.endpoints || 0} endpoints`, 'info');
  } else if (action === 'find_origin' && !result.error) {
    toast('ORIGIN', result.verified_origin ? `Found: ${result.verified_origin}` : `${result.candidates ? result.candidates.length : 0} candidates`, 'info');
  } else if (action === 'test_proxies' && !result.error) {
    toast('PROXIES', `${result.alive || 0}/${result.loaded || 0} alive`, 'info');
  } else {
    toast(action.toUpperCase(), JSON.stringify(result).substring(0, 120), 'info');
  }
}

document.querySelectorAll('.btn[data-cmd]').forEach(btn => {
  btn.addEventListener('click', () => {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      toast('NOT CONNECTED', 'Reconnecting... try again in a moment.', 'error');
      scheduleReconnect();
      return;
    }
    const action = btn.dataset.cmd;
    const target = document.getElementById('ctrl-target').value.trim();
    if (action !== 'stop' && action !== 'test_proxies' && !target) {
      toast('TARGET REQUIRED', 'Enter a target URL first.', 'warn');
      return;
    }
    const payload = {
      target: target,
      method: document.getElementById('ctrl-method').value,
      duration: parseInt(document.getElementById('ctrl-duration').value) || 30,
      rps: parseInt(document.getElementById('ctrl-rps').value) || 100,
    };
    ws.send(JSON.stringify({ type: 'command', action, payload }));
    toast('SENT', action.replace('_', ' ').toUpperCase(), 'info');
  });
});

setInterval(() => { document.getElementById('clock').textContent = new Date().toLocaleTimeString(); }, 1000);

connect();
</script>
</body>
</html>"""
