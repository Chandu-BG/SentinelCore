"""
NovaSentinel — Scheduler
Centralized background task scheduler.
Replaces the disparate loops in main.py.
"""

import logging
import threading
import time
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class ScheduledTask:
    def __init__(self, func: Callable, interval_seconds: int):
        self.func = func
        self.interval = interval_seconds
        self._timer: Optional[threading.Timer] = None
        self._lock = threading.Lock()
        self._running = False

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._running = True
            self._schedule_next()

    def stop(self) -> None:
        with self._lock:
            self._running = False
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None

    def _schedule_next(self) -> None:
        if not self._running:
            return
        self._timer = threading.Timer(self.interval, self._run)
        self._timer.daemon = True
        self._timer.start()

    def _run(self) -> None:
        try:
            threading.Thread(target=self.func, daemon=True).start()
        except Exception as exc:
            logger.error("Scheduler task error: %s", exc)
        finally:
            self._schedule_next()


class Scheduler:
    def __init__(self):
        self._tasks: Dict[str, ScheduledTask] = {}
        self._running = False
        self._lock = threading.Lock()

    def schedule(self, func: Callable, interval_seconds: int) -> None:
        key = f"{func.__module__}.{func.__qualname__}:{interval_seconds}"
        with self._lock:
            if key in self._tasks:
                return
            self._tasks[key] = ScheduledTask(func, interval_seconds)
            if self._running:
                self._tasks[key].start()

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._running = True
            for task in self._tasks.values():
                task.start()

    def stop(self) -> None:
        with self._lock:
            if not self._running:
                return
            self._running = False
            for task in self._tasks.values():
                task.stop()


_instance: Optional[Scheduler] = None
def get_scheduler() -> Scheduler:
    global _instance
    if _instance is None:
        _instance = Scheduler()
    return _instance
