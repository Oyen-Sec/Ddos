import asyncio
import time
import json
import logging
import os
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from enum import Enum

logger = logging.getLogger("node_coordinator")

HEARTBEAT_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "nodes.json")
TASK_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "tasks.json")
NODE_TIMEOUT = 15
HEARTBEAT_INTERVAL = 5
REPORT_INTERVAL = 5


class NodeStatus(Enum):
    ALIVE = "alive"
    DEAD = "dead"
    BUSY = "busy"


class TaskStatus(Enum):
    PENDING = "pending"
    ASSIGNED = "assigned"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class NodeInfo:
    node_id: str
    hostname: str = ""
    location: str = ""
    status: NodeStatus = NodeStatus.ALIVE
    last_heartbeat: float = 0.0
    completed: int = 0
    failed: int = 0
    timeout: int = 0
    avg_rtt: float = 0.0
    current_task: str = ""


@dataclass
class TaskInfo:
    task_id: str
    target_url: str
    method: str
    duration: int
    rps: int
    assigned_node: str = ""
    status: TaskStatus = TaskStatus.PENDING
    created_at: float = 0.0
    assigned_at: float = 0.0
    result: Dict[str, Any] = field(default_factory=dict)


class FileCoordinator:
    def __init__(self, heartbeat_file: str = HEARTBEAT_FILE,
                 task_file: str = TASK_FILE):
        self.heartbeat_file = heartbeat_file
        self.task_file = task_file
        self._lock = asyncio.Lock()
        self._ensure_files()

    def _ensure_files(self):
        for fpath in [self.heartbeat_file, self.task_file]:
            dirname = os.path.dirname(fpath)
            if dirname and not os.path.exists(dirname):
                os.makedirs(dirname, exist_ok=True)
            if not os.path.exists(fpath):
                with open(fpath, "w") as f:
                    json.dump([], f)

    async def _read_json(self, filepath: str) -> list:
        try:
            with open(filepath, "r") as f:
                content = f.read().strip()
                return json.loads(content) if content else []
        except (json.JSONDecodeError, FileNotFoundError):
            return []

    async def _write_json(self, filepath: str, data: list):
        async with self._lock:
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2)

    async def register_node(self, node_id: str, hostname: str = "",
                            location: str = "") -> bool:
        nodes = await self._read_json(self.heartbeat_file)
        for node in nodes:
            if node.get("node_id") == node_id:
                node["last_heartbeat"] = time.time()
                node["status"] = NodeStatus.ALIVE.value
                await self._write_json(self.heartbeat_file, nodes)
                return True
        nodes.append({
            "node_id": node_id,
            "hostname": hostname,
            "location": location,
            "status": NodeStatus.ALIVE.value,
            "last_heartbeat": time.time(),
            "completed": 0,
            "failed": 0,
            "timeout": 0,
            "avg_rtt": 0.0,
            "current_task": "",
        })
        await self._write_json(self.heartbeat_file, nodes)
        logger.info("Node registered: %s (%s)", node_id, location)
        return True

    async def heartbeat(self, node_id: str, metrics: Dict[str, Any] = None) -> bool:
        nodes = await self._read_json(self.heartbeat_file)
        found = False
        for node in nodes:
            if node.get("node_id") == node_id:
                node["last_heartbeat"] = time.time()
                node["status"] = NodeStatus.ALIVE.value
                if metrics:
                    node["completed"] = metrics.get("completed", node.get("completed", 0))
                    node["failed"] = metrics.get("failed", node.get("failed", 0))
                    node["timeout"] = metrics.get("timeout", node.get("timeout", 0))
                    node["avg_rtt"] = metrics.get("avg_response_time_ms", node.get("avg_rtt", 0.0))
                found = True
                break
        if found:
            await self._write_json(self.heartbeat_file, nodes)
        return found

    async def get_alive_nodes(self) -> List[dict]:
        nodes = await self._read_json(self.heartbeat_file)
        now = time.time()
        alive = []
        for node in nodes:
            if now - node.get("last_heartbeat", 0) <= NODE_TIMEOUT:
                node["status"] = NodeStatus.ALIVE.value
                alive.append(node)
            else:
                node["status"] = NodeStatus.DEAD.value
        await self._write_json(self.heartbeat_file, nodes)
        return alive

    async def detect_dead_nodes(self) -> List[str]:
        nodes = await self._read_json(self.heartbeat_file)
        now = time.time()
        dead_ids = []
        for node in nodes:
            if now - node.get("last_heartbeat", 0) > NODE_TIMEOUT:
                if node.get("status") != NodeStatus.DEAD.value:
                    node["status"] = NodeStatus.DEAD.value
                    dead_ids.append(node["node_id"])
                    logger.warning("Dead node detected: %s", node["node_id"])
        if dead_ids:
            await self._write_json(self.heartbeat_file, nodes)
        return dead_ids

    async def create_task(self, target_url: str, method: str,
                          duration: int, rps: int) -> str:
        task = {
            "task_id": str(uuid.uuid4())[:8],
            "target_url": target_url,
            "method": method,
            "duration": duration,
            "rps": rps,
            "assigned_node": "",
            "status": TaskStatus.PENDING.value,
            "created_at": time.time(),
            "assigned_at": 0.0,
            "result": {},
        }
        tasks = await self._read_json(self.task_file)
        tasks.append(task)
        await self._write_json(self.task_file, tasks)
        logger.info("Task created: %s -> %s [%s]", task["task_id"], target_url, method)
        return task["task_id"]

    async def assign_task(self, task_id: str, node_id: str) -> bool:
        tasks = await self._read_json(self.task_file)
        for task in tasks:
            if task.get("task_id") == task_id:
                task["assigned_node"] = node_id
                task["status"] = TaskStatus.ASSIGNED.value
                task["assigned_at"] = time.time()
                await self._write_json(self.task_file, tasks)
                nodes = await self._read_json(self.heartbeat_file)
                for node in nodes:
                    if node.get("node_id") == node_id:
                        node["current_task"] = task_id
                        node["status"] = NodeStatus.BUSY.value
                        break
                await self._write_json(self.heartbeat_file, nodes)
                logger.info("Task %s assigned to node %s", task_id, node_id)
                return True
        return False

    async def complete_task(self, task_id: str, result: Dict[str, Any]) -> bool:
        tasks = await self._read_json(self.task_file)
        for task in tasks:
            if task.get("task_id") == task_id:
                task["status"] = TaskStatus.COMPLETED.value
                task["result"] = result
                await self._write_json(self.task_file, tasks)
                node_id = task.get("assigned_node", "")
                if node_id:
                    nodes = await self._read_json(self.heartbeat_file)
                    for node in nodes:
                        if node.get("node_id") == node_id:
                            node["current_task"] = ""
                            node["status"] = NodeStatus.ALIVE.value
                            break
                    await self._write_json(self.heartbeat_file, nodes)
                return True
        return False

    async def get_pending_tasks(self) -> List[dict]:
        tasks = await self._read_json(self.task_file)
        return [t for t in tasks if t.get("status") == TaskStatus.PENDING.value]

    async def distribute_tasks(self) -> List[dict]:
        alive_nodes = await self.get_alive_nodes()
        pending_tasks = await self.get_pending_tasks()
        if not alive_nodes or not pending_tasks:
            return []
        distributed = []
        for i, task in enumerate(pending_tasks):
            node = alive_nodes[i % len(alive_nodes)]
            success = await self.assign_task(task["task_id"], node["node_id"])
            if success:
                distributed.append(task)
        return distributed

    async def node_report(self, node_id: str, metrics: Dict[str, Any]) -> bool:
        return await self.heartbeat(node_id, metrics)


class NodeCoordinator:
    def __init__(self, node_id: str = "", hostname: str = "",
                 location: str = "local"):
        self.node_id = node_id or f"node-{uuid.uuid4().hex[:6]}"
        self.hostname = hostname or os.uname().nodename if hasattr(os, "uname") else "unknown"
        self.location = location
        self.coordinator = FileCoordinator()
        self._running = False
        self._heartbeat_task: Optional[asyncio.Task] = None

    async def start(self):
        self._running = True
        await self.coordinator.register_node(self.node_id, self.hostname, self.location)
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logger.info("Node coordinator started: %s", self.node_id)

    async def stop(self):
        self._running = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

    async def _heartbeat_loop(self):
        while self._running:
            await self.coordinator.heartbeat(self.node_id)
            await asyncio.sleep(HEARTBEAT_INTERVAL)

    async def report_metrics(self, metrics: Dict[str, Any]):
        await self.coordinator.node_report(self.node_id, metrics)

    async def get_my_task(self) -> Optional[dict]:
        tasks = await self.coordinator._read_json(TASK_FILE)
        for task in tasks:
            if task.get("assigned_node") == self.node_id and task.get("status") == TaskStatus.ASSIGNED.value:
                return task
        return None

    async def complete_my_task(self, result: Dict[str, Any]):
        task = await self.get_my_task()
        if task:
            await self.coordinator.complete_task(task["task_id"], result)

    async def get_alive_nodes(self) -> List[dict]:
        return await self.coordinator.get_alive_nodes()

    async def distribute(self) -> List[dict]:
        return await self.coordinator.distribute_tasks()
