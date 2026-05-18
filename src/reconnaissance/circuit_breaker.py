import asyncio
import time
from enum import Enum
from typing import Callable, Any, Optional
from .logger import logger

class CircuitState(Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"

class CircuitBreaker:
    def __init__(self, name: str, failure_threshold: int = 3, recovery_timeout: int = 60):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.state = CircuitState.CLOSED
        self.failures = 0
        self.last_failure_time = 0

    async def call(self, func: Callable, *args, **kwargs) -> Any:
        if self.state == CircuitState.OPEN:
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = CircuitState.HALF_OPEN
                logger.info(f"[CircuitBreaker] {self.name} is HALF_OPEN, testing...")
            else:
                logger.warning(f"[CircuitBreaker] {self.name} is OPEN, skipping call.")
                return None

        try:
            result = await func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure(e)
            return None

    def _on_success(self):
        if self.state != CircuitState.CLOSED:
            logger.info(f"[CircuitBreaker] {self.name} restored to CLOSED.")
        self.state = CircuitState.CLOSED
        self.failures = 0

    def _on_failure(self, error: Exception):
        self.failures += 1
        self.last_failure_time = time.time()
        logger.error(f"[CircuitBreaker] {self.name} failure ({self.failures}/{self.failure_threshold}): {error}")
        
        if self.failures >= self.failure_threshold:
            self.state = CircuitState.OPEN
            logger.critical(f"[CircuitBreaker] {self.name} is now OPEN.")
