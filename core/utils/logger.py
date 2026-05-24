"""
Multi-Protocol Concurrency Layer - RAM-Only Logger
No disk writes - all logs kept in memory
"""
import logging
import sys
from io import StringIO
from typing import List, Optional
from datetime import datetime
from dataclasses import dataclass


@dataclass
class LogEntry:
    timestamp: datetime
    level: str
    message: str
    source: str = ""
    
    def __str__(self):
        return f"[{self.timestamp.strftime('%H:%M:%S')}] [{self.level}] {self.message}"


class MemoryLogHandler(logging.Handler):
    """Custom handler that stores logs in memory only"""
    
    def __init__(self, max_entries: int = 10000):
        super().__init__()
        self.max_entries = max_entries
        self.entries: List[LogEntry] = []
        self.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%H:%M:%S'
        ))
    
    def emit(self, record: logging.LogRecord):
        entry = LogEntry(
            timestamp=datetime.now(),
            level=record.levelname,
            message=self.format(record),
            source=record.name
        )
        self.entries.append(entry)
        
        if len(self.entries) > self.max_entries:
            self.entries = self.entries[-self.max_entries:]
    
    def get_entries(self, level: Optional[str] = None, count: int = 100) -> List[LogEntry]:
        entries = self.entries
        if level:
            entries = [e for e in entries if e.level == level]
        return entries[-count:]
    
    def clear(self):
        self.entries.clear()


class MPCLogger:
    """Main logger class for Multi-Protocol Concurrency Layer"""
    
    def __init__(self, name: str = "mpc_layer", level: int = logging.INFO):
        self.name = name
        self.level = level
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.logger.handlers = []
        
        # Memory-only handler
        self.memory_handler = MemoryLogHandler(max_entries=10000)
        self.logger.addHandler(self.memory_handler)
        
        # Console handler for real-time display
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
    
    def debug(self, message: str, *args, **kwargs):
        self.logger.debug(message, *args, **kwargs)
    
    def info(self, message: str, *args, **kwargs):
        self.logger.info(message, *args, **kwargs)
    
    def warning(self, message: str, *args, **kwargs):
        self.logger.warning(message, *args, **kwargs)
    
    def error(self, message: str, *args, **kwargs):
        self.logger.error(message, *args, **kwargs)
    
    def critical(self, message: str, *args, **kwargs):
        self.logger.critical(message, *args, **kwargs)
    
    def get_logs(self, level: Optional[str] = None, count: int = 100) -> List[LogEntry]:
        return self.memory_handler.get_entries(level, count)
    
    def clear_logs(self):
        self.memory_handler.clear()


# Global logger instance
logger = MPCLogger()
