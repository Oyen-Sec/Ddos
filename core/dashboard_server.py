"""
NOIR PROJECT - Real-time Dashboard Server v1.0
WebSocket server broadcasting attack metrics live.
Supports multiple concurrent attack sessions.
"""
import asyncio
import json
import logging
import time
from typing import Dict, Set
from dataclasses import dataclass, asdict
import websockets
from websockets.server import WebSocketServerProtocol

logger = logging.getLogger("dashboard_server")

@dataclass
class AttackMetrics:
    timestamp: float
    target: str
    method: str
    duration: int
    elapsed: float
    total_requests: int
    completed: int
    failed: int
    timeout: int
    rps: float
    avg_latency_ms: float
    error_rate: float
    status: str  # "running", "completed", "failed"

class DashboardServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8765):
        self.host = host
        self.port = port
        self.clients: Set[WebSocketServerProtocol] = set()
        self.metrics_history: Dict[str, list] = {}  # target -> [metrics...]
        self.current_attacks: Dict[str, AttackMetrics] = {}  # target -> latest metrics
        self.is_running = False

    async def register_client(self, websocket: WebSocketServerProtocol):
        """Register new WebSocket client."""
        self.clients.add(websocket)
        logger.info(f"Client connected: {websocket.remote_address}")
        
        # Send current state to new client
        await self.send_state(websocket)

    async def unregister_client(self, websocket: WebSocketServerProtocol):
        """Unregister WebSocket client."""
        self.clients.discard(websocket)
        logger.info(f"Client disconnected: {websocket.remote_address}")

    async def send_state(self, websocket: WebSocketServerProtocol):
        """Send current attack state to client."""
        state = {
            "type": "state",
            "attacks": {k: asdict(v) for k, v in self.current_attacks.items()},
            "history": self.metrics_history,
        }
        try:
            await websocket.send(json.dumps(state))
        except Exception as e:
            logger.debug(f"Failed to send state: {e}")

    async def broadcast_metrics(self, target: str, metrics: AttackMetrics):
        """Broadcast metrics to all connected clients."""
        self.current_attacks[target] = metrics
        
        # Keep history (last 300 samples = 5 min at 1 Hz)
        if target not in self.metrics_history:
            self.metrics_history[target] = []
        self.metrics_history[target].append(asdict(metrics))
        if len(self.metrics_history[target]) > 300:
            self.metrics_history[target].pop(0)

        message = {
            "type": "metrics",
            "target": target,
            "data": asdict(metrics),
        }
        
        # Broadcast to all clients
        if self.clients:
            message_json = json.dumps(message)
            await asyncio.gather(
                *[client.send(message_json) for client in self.clients],
                return_exceptions=True
            )

    async def handle_client(self, websocket: WebSocketServerProtocol, path: str):
        """Handle WebSocket client connection."""
        await self.register_client(websocket)
        try:
            async for message in websocket:
                try:
                    data = json.loads(message)
                    cmd = data.get("cmd")
                    
                    if cmd == "get_state":
                        await self.send_state(websocket)
                    elif cmd == "clear_history":
                        target = data.get("target")
                        if target and target in self.metrics_history:
                            self.metrics_history[target] = []
                    elif cmd == "ping":
                        await websocket.send(json.dumps({"type": "pong"}))
                except json.JSONDecodeError:
                    pass
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            await self.unregister_client(websocket)

    async def start(self):
        """Start WebSocket server."""
        self.is_running = True
        logger.info(f"Dashboard server starting on ws://{self.host}:{self.port}")
        async with websockets.serve(self.handle_client, self.host, self.port):
            logger.info(f"Dashboard server running on ws://{self.host}:{self.port}")
            while self.is_running:
                await asyncio.sleep(1)

    async def stop(self):
        """Stop WebSocket server."""
        self.is_running = False
        logger.info("Dashboard server stopping")

# Global instance
_dashboard_server: DashboardServer = None

def get_dashboard_server(host: str = "127.0.0.1", port: int = 8765) -> DashboardServer:
    """Get or create dashboard server instance."""
    global _dashboard_server
    if _dashboard_server is None:
        _dashboard_server = DashboardServer(host, port)
    return _dashboard_server

async def start_dashboard_server(host: str = "127.0.0.1", port: int = 8765):
    """Start dashboard server in background."""
    server = get_dashboard_server(host, port)
    asyncio.create_task(server.start())
    await asyncio.sleep(0.5)  # Give server time to start
    return server
