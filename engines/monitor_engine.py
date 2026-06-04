"""
SentinelCore - Real-Time Monitor Engine
Continuously monitors CPU usage, memory usage, and running processes.
Uses psutil to gather system metrics and publishes them to a shared state dict.
Runs in a background daemon thread.
"""

import threading
import time
import logging
import psutil
from datetime import datetime
from typing import Dict, Any, Callable, Optional

logger = logging.getLogger(__name__)


class MonitorEngine:
    """
    Collects real-time system metrics:
    - CPU usage (%)
    - Memory usage (%)
    - Running process list with PIDs, names, CPU/mem usage
    Emits callbacks when metrics are updated.
    """

    def __init__(
        self,
        monitor_interval: float = 2.0,
        on_update: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_alert: Optional[Callable[[str, str], None]] = None,
    ):
        self.monitor_interval = monitor_interval
        self.on_update = on_update   # callback(metrics_dict)
        self.on_alert = on_alert     # callback(alert_type, message)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Shared state
        self.state: Dict[str, Any] = {
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "processes": [],
            "timestamp": "",
            "process_count": 0,
        }

        # Thresholds for alerts
        self.cpu_alert_threshold = 85.0
        self.memory_alert_threshold = 85.0

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    def start(self) -> None:
        """Start the background monitoring thread."""
        if self._running:
            logger.warning("MonitorEngine already running.")
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="MonitorEngine"
        )
        self._thread.start()
        logger.info("MonitorEngine started.")

    def stop(self) -> None:
        """Signal the monitoring thread to stop."""
        self._running = False
        logger.info("MonitorEngine stopped.")

    def set_interval(self, interval: float) -> None:
        """Dynamically change the monitoring frequency."""
        self.monitor_interval = max(0.1, interval)

    # -------------------------------------------------------------------------
    # Internal loop
    # -------------------------------------------------------------------------

    def _monitor_loop(self) -> None:
        """Core loop: collect metrics, update state, fire callbacks."""
        while self._running:
            try:
                metrics = self._collect_metrics()
                with self._lock:
                    self.state.update(metrics)

                # Fire update callback
                if self.on_update:
                    self.on_update(dict(metrics))

                # Check thresholds and fire alerts
                self._check_thresholds(metrics)

            except Exception as e:
                logger.error(f"MonitorEngine error: {e}")

            time.sleep(self.monitor_interval)

    def _collect_metrics(self) -> Dict[str, Any]:
        """Gather CPU, memory, and process data."""
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()

        procs = []
        for p in psutil.process_iter(
            ["pid", "name", "status", "cpu_percent", "memory_percent", "exe", "create_time"]
        ):
            try:
                info = p.info
                procs.append(
                    {
                        "pid": info.get("pid"),
                        "name": info.get("name", "Unknown"),
                        "status": info.get("status", ""),
                        "cpu_percent": round(info.get("cpu_percent") or 0.0, 2),
                        "memory_percent": round(info.get("memory_percent") or 0.0, 3),
                        "exe": info.get("exe", ""),
                        "create_time": info.get("create_time", 0),
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        return {
            "cpu_percent": cpu,
            "memory_percent": mem.percent,
            "memory_used_mb": round(mem.used / 1024 / 1024, 1),
            "memory_total_mb": round(mem.total / 1024 / 1024, 1),
            "processes": procs,
            "process_count": len(procs),
            "timestamp": datetime.now().isoformat(),
        }

    def _check_thresholds(self, metrics: Dict[str, Any]) -> None:
        """Fire alerts when CPU or memory exceed safe thresholds."""
        if not self.on_alert:
            return

        if metrics["cpu_percent"] >= self.cpu_alert_threshold:
            self.on_alert(
                "HIGH_CPU",
                f"CPU usage critical: {metrics['cpu_percent']}%",
            )

        if metrics["memory_percent"] >= self.memory_alert_threshold:
            self.on_alert(
                "HIGH_MEMORY",
                f"Memory usage critical: {metrics['memory_percent']}%",
            )

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def get_state(self) -> Dict[str, Any]:
        """Thread-safe snapshot of current metrics."""
        with self._lock:
            return dict(self.state)

    def get_process_by_name(self, name: str):
        """Return all running processes with the given name."""
        with self._lock:
            return [p for p in self.state["processes"] if p["name"].lower() == name.lower()]

    def kill_process(self, pid: int) -> bool:
        """Attempt to terminate a process by PID. Returns True on success."""
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            logger.warning(f"Terminated process PID={pid} ({proc.name()})")
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.error(f"Failed to terminate PID={pid}: {e}")
            return False

    def simulate_high_load(self) -> Dict[str, Any]:
        """
        Attack simulation: return a fake metrics snapshot with
        a suspicious process injected.
        """
        metrics = self._collect_metrics()
        metrics["processes"].append(
            {
                "pid": 99999,
                "name": "suspicious_miner.exe",
                "status": "running",
                "cpu_percent": 95.0,
                "memory_percent": 40.0,
                "exe": "C:\\Windows\\Temp\\suspicious_miner.exe",
                "create_time": 0,
            }
        )
        metrics["cpu_percent"] = 95.0
        return metrics
