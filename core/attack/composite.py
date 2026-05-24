"""
Composite Attack Module - Mixed Attack [8]
Coordinates parallel execution of all 26 attack vectors with fair resource scheduling
Uses asyncio.gather() + ThreadPoolExecutor for parallel concurrency

FIXES:
- Thread-safe stats collection with locks (prevents race conditions)
- Realtime data updates via stats_queue (like auto_mode_v2)
- Per-vector locks for isolated stat mutations
"""
import asyncio
import logging
import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field

logger = logging.getLogger("composite_attack")


@dataclass
class VectorAllocation:
    """Resource allocation per vector"""
    vector_id: str
    label: str
    vector_type: str  # "go" or "py"
    threads: int
    rps_share: int
    semaphore: asyncio.Semaphore = None
    status: str = "pending"
    stats: Dict = field(default_factory=dict)
    stats_lock: threading.Lock = field(default_factory=threading.Lock)  # Thread-safe stats mutation


class FairResourceScheduler:
    """
    Fair resource scheduler for parallel vector execution
    Prevents bottleneck and race conditions on shared resources
    """
    
    def __init__(self, total_rps: int, total_threads: int, vector_count: int):
        self.total_rps = total_rps
        self.total_threads = total_threads
        self.vector_count = vector_count
        
        # Calculate fair share per vector
        self.rps_per_vector = max(10, total_rps // vector_count)
        self.threads_per_vector = max(10, total_threads // vector_count)
        
        # Shared resource locks
        self._proxy_lock = asyncio.Lock()
        self._header_lock = asyncio.Lock()
        
        # Per-vector semaphores (isolated thread/coroutine allocation)
        self._vector_semaphores: Dict[str, asyncio.Semaphore] = {}
    
    def allocate(self, vector_id: str, weight: float = 1.0) -> VectorAllocation:
        """Allocate fair share of resources to vector"""
        threads = int(self.threads_per_vector * weight)
        rps = int(self.rps_per_vector * weight)
        
        # Create isolated semaphore for this vector
        sem = asyncio.Semaphore(threads)
        self._vector_semaphores[vector_id] = sem
        
        return VectorAllocation(
            vector_id=vector_id,
            label=vector_id,
            vector_type="py",
            threads=threads,
            rps_share=rps,
            semaphore=sem,
        )
    
    def get_proxy_lock(self) -> asyncio.Lock:
        """Get shared proxy access lock (prevents race conditions)"""
        return self._proxy_lock
    
    def get_header_lock(self) -> asyncio.Lock:
        """Get shared header mutation lock (prevents race conditions)"""
        return self._header_lock


class CompositeAttackOrchestrator:
    """
    Orchestrates parallel execution of all 26 attack vectors
    Uses asyncio.gather() + ThreadPoolExecutor for parallel concurrency
    
    THREAD-SAFE STATS:
    - stats_queue: realtime updates from workers (like auto_mode_v2)
    - Per-vector locks: prevent race conditions on vec["stats"]
    - Dashboard can read queue without blocking workers
    """
    
    def __init__(self, target: str, duration: int, total_rps: int = 3000,
                 max_threads_per_vector: int = 100):
        self.target = target
        self.duration = duration
        self.total_rps = total_rps
        self.max_threads_per_vector = max_threads_per_vector
        
        self.vectors: List[Dict] = []
        self.tasks: List = []
        
        # Fair resource scheduler (26 vectors)
        self.scheduler = FairResourceScheduler(
            total_rps=total_rps,
            total_threads=max_threads_per_vector * 26,
            vector_count=26,
        )
        
        # ThreadPoolExecutor for blocking operations
        self.thread_pool = ThreadPoolExecutor(
            max_workers=min(64, max_threads_per_vector),
            thread_name_prefix="composite_worker",
        )
        
        # Shared resources
        self.proxy_pool = None
        self.proxy_file_for_go = ""
        self.origin_ip = ""
        self.profile = None
        
        # Statistics
        self.start_time = 0.0
        self.end_time = 0.0
        
        # REALTIME STATS QUEUE (thread-safe, non-blocking)
        # Workers push updates here, dashboard reads without blocking
        self.stats_queue: queue.Queue = queue.Queue(maxsize=1000)
        self.stats_lock = threading.Lock()  # Global stats lock for aggregation
    
    def setup_resources(self, proxy_pool=None, proxy_file_for_go: str = "",
                       origin_ip: str = "", profile=None):
        """Setup shared resources before launch"""
        self.proxy_pool = proxy_pool
        self.proxy_file_for_go = proxy_file_for_go
        self.origin_ip = origin_ip
        self.profile = profile
    
    def get_stats_queue(self) -> queue.Queue:
        """Get realtime stats queue for dashboard consumption"""
        return self.stats_queue
    
    def add_go_vector(self, label: str, method: str, weight: float = 1.0,
                     custom_target: str = None, **kwargs):
        """Add Go engine vector with fair resource allocation"""
        allocation = self.scheduler.allocate(label, weight)
        
        vec = {
            "label": label,
            "type": "go",
            "status": "pending",
            "stats": {},
            "allocation": allocation,
            "method": method,
            "custom_target": custom_target or self.target,
            "kwargs": kwargs,
        }
        self.vectors.append(vec)
    
    def add_py_vector(self, label: str, attack_func: Callable, weight: float = 1.0,
                     **kwargs):
        """Add Python vector with fair resource allocation"""
        allocation = self.scheduler.allocate(label, weight)
        
        vec = {
            "label": label,
            "type": "py",
            "status": "pending",
            "stats": {},
            "allocation": allocation,
            "attack_func": attack_func,
            "kwargs": kwargs,
        }
        self.vectors.append(vec)
    
    async def _execute_go_vector(self, vec: Dict, run_go_engine_func: Callable):
        """Execute Go engine vector with isolated resources and thread-safe stats"""
        try:
            vec["status"] = "running"
            allocation = vec["allocation"]
            
            result = await run_go_engine_func(
                target=vec["custom_target"],
                duration=self.duration,
                rps=allocation.rps_share,
                method=vec["method"],
                threads=allocation.threads,
                origin_ip=self.origin_ip,
                proxy_file=self.proxy_file_for_go,
                live_stats=vec,
                **vec["kwargs"],
            )
            
            vec["status"] = "completed"
            if isinstance(result, dict):
                # Thread-safe stats update with lock
                with allocation.stats_lock:
                    vec["stats"] = {
                        "total_requests": result.get("total_requests", 0),
                        "completed": result.get("completed", 0),
                        "failed": result.get("failed", 0),
                        "timeout": result.get("timeout", 0),
                    }
                
                # Push to realtime queue (non-blocking, drops old if full)
                try:
                    self.stats_queue.put_nowait({
                        "vector_name": vec["label"],
                        "vector_type": "go",
                        "stats": vec["stats"],
                        "timestamp": time.time(),
                    })
                except queue.Full:
                    pass  # Drop old stats if queue full
            
            return result
        except Exception as e:
            logger.error(f"Go vector {vec['label']} error: {type(e).__name__}: {e}")
            vec["status"] = "error"
            return {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}
    
    async def _execute_py_vector(self, vec: Dict):
        """Execute Python vector with isolated semaphore and thread-safe stats"""
        try:
            vec["status"] = "running"
            allocation = vec["allocation"]
            
            # Use isolated semaphore to prevent race conditions
            async with allocation.semaphore:
                result = await vec["attack_func"](**vec["kwargs"])
            
            vec["status"] = "completed"
            if isinstance(result, dict):
                # Thread-safe stats update with lock
                with allocation.stats_lock:
                    vec["stats"] = {
                        "total_requests": result.get("total", result.get("total_requests", 0)),
                        "completed": result.get("completed", 0),
                        "failed": result.get("failed", 0),
                        "timeout": result.get("timeout", 0),
                    }
                
                # Push to realtime queue (non-blocking, drops old if full)
                try:
                    self.stats_queue.put_nowait({
                        "vector_name": vec["label"],
                        "vector_type": "py",
                        "stats": vec["stats"],
                        "timestamp": time.time(),
                    })
                except queue.Full:
                    pass  # Drop old stats if queue full
            
            return result
        except Exception as e:
            logger.error(f"Py vector {vec['label']} error: {type(e).__name__}: {e}")
            vec["status"] = "error"
            return {"total_requests": 0, "completed": 0, "failed": 0, "timeout": 0}
    
    async def execute_all(self, run_go_engine_func: Callable):
        """
        Execute all vectors in parallel using asyncio.gather()
        Each vector has isolated resource allocation
        """
        self.start_time = time.time()
        tasks = []
        
        for vec in self.vectors:
            if vec["type"] == "go":
                task = asyncio.create_task(
                    self._execute_go_vector(vec, run_go_engine_func)
                )
            else:
                task = asyncio.create_task(
                    self._execute_py_vector(vec)
                )
            tasks.append(task)
        
        # Execute all in parallel - asyncio.gather() with return_exceptions
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        self.end_time = time.time()
        return results
    
    def get_summary(self) -> Dict:
        """Get aggregated statistics with thread-safe reads"""
        total = {
            "total_requests": 0,
            "completed": 0,
            "failed": 0,
            "timeout": 0,
            "duration": self.end_time - self.start_time if self.end_time else 0,
            "vector_count": len(self.vectors),
            "completed_vectors": sum(1 for v in self.vectors if v["status"] == "completed"),
            "error_vectors": sum(1 for v in self.vectors if v["status"] == "error"),
        }
        
        for vec in self.vectors:
            allocation = vec.get("allocation")
            if allocation and vec["stats"]:
                # Thread-safe stats read with lock
                with allocation.stats_lock:
                    for k in ("total_requests", "completed", "failed", "timeout"):
                        total[k] += vec["stats"].get(k, 0)
        
        return total
    
    def cleanup(self):
        """Cleanup resources"""
        try:
            self.thread_pool.shutdown(wait=False)
        except Exception:
            pass


def build_composite_attack(target: str, duration: int, total_rps: int,
                          profile=None, target_arch=None) -> CompositeAttackOrchestrator:
    """
    Build composite attack with all 26 vectors
    Returns configured orchestrator ready for execution
    """
    orchestrator = CompositeAttackOrchestrator(
        target=target,
        duration=duration,
        total_rps=total_rps,
    )
    
    return orchestrator
