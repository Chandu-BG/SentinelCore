"""
NovaSentinel — Centralized Telemetry Manager
Single source of truth for all system metrics, consumed by every module.

Polls psutil every 2 seconds. All reads are lock-protected and instant (no blocking).
"""

import threading
import time
import logging
import psutil
from datetime import datetime
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

_POLL_INTERVAL = 2.0  # seconds — halved from 1.0 to reduce CPU overhead


class TelemetrySnapshot:
    """Immutable snapshot of system state at a point in time."""

    __slots__ = (
        "timestamp", "cpu_percent", "ram_percent", "ram_total_gb",
        "disk_percent", "net_sent_mbps", "net_recv_mbps",
        "process_count", "processes",
        "threat_count", "scan_results", "recent_alerts",
    )

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    def to_dict(self) -> Dict[str, Any]:
        return {k: getattr(self, k) for k in self.__slots__}


class TelemetryManager:
    """
    Singleton-style centralized telemetry hub.
    Start once from main.py; every other module calls get_snapshot().
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._snapshot: Optional[TelemetrySnapshot] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Mutable overlays — updated by main.py when scans complete
        self._threat_count: int = 0
        self._scan_results: List[Dict] = []
        self._recent_alerts: List[Dict] = []  # last 1000 alerts
        self._max_alerts = 1000

        # Net I/O baselines
        try:
            self._prev_net = psutil.net_io_counters()
        except Exception:
            self._prev_net = None
        self._prev_net_time = time.time()

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._poll_loop, daemon=True, name="TelemetryManager"
        )
        self._thread.start()
        logger.info("TelemetryManager started.")

    def stop(self) -> None:
        self._running = False

    # ── Snapshot access ────────────────────────────────────────────────────────

    def get_snapshot(self) -> TelemetrySnapshot:
        with self._lock:
            if self._snapshot is not None:
                return self._snapshot
        # First call before first poll — build one synchronously
        return self._build_snapshot()

    # ── Overlay updates (called by modules) ───────────────────────────────────

    def update_threat_count(self, count: int) -> None:
        with self._lock:
            self._threat_count = count

    def update_scan_results(self, results: List[Dict]) -> None:
        with self._lock:
            self._scan_results = results[-20:]  # keep latest 20

    def push_log(self, module: str, message: str, severity: str = "info") -> None:
        """Push a live event log to the centralized buffer."""
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "module": module,
            "message": message,
            "severity": severity,
        }
        with self._lock:
            self._recent_alerts.append(log_entry)
            if len(self._recent_alerts) > self._max_alerts:
                self._recent_alerts = self._recent_alerts[-self._max_alerts:]
        
        logger.info(f"[{module.upper()}] {message}")

    def push_alert(self, alert_type: str, message: str, severity: str = "info") -> None:
        """Compatibility method for push_log."""
        self.push_log(alert_type, message, severity)

    def get_recent_alerts(self, n: int = 50) -> List[Dict]:
        with self._lock:
            return list(self._recent_alerts[-n:])

    def get_all_logs(self) -> List[Dict]:
        """Return all logs in the current buffer."""
        with self._lock:
            return list(self._recent_alerts)

    # ── Internal poll loop ─────────────────────────────────────────────────────

    def _poll_loop(self) -> None:
        while self._running:
            try:
                snap = self._build_snapshot()
                with self._lock:
                    self._snapshot = snap
            except Exception as e:
                logger.debug(f"TelemetryManager poll error: {e}")
            time.sleep(_POLL_INTERVAL)

    def _build_snapshot(self) -> TelemetrySnapshot:
        cpu = psutil.cpu_percent(interval=None)
        vm = psutil.virtual_memory()
        ram_pct = vm.percent
        ram_gb = vm.total / (1024 ** 3)

        # Disk (cross-platform: try C:\ first, fall back to first available drive)
        try:
            disk = psutil.disk_usage("C:\\").percent
        except Exception:
            try:
                disk = psutil.disk_usage("/").percent
            except Exception:
                # Final fallback: enumerate available disk partitions
                try:
                    parts = psutil.disk_partitions(all=False)
                    if parts:
                        disk = psutil.disk_usage(parts[0].mountpoint).percent
                    else:
                        disk = 0.0
                except Exception:
                    disk = 0.0

        # Network throughput
        sent_mbps, recv_mbps = 0.0, 0.0
        try:
            now_net = psutil.net_io_counters()
            now_time = time.time()
            dt = max(now_time - self._prev_net_time, 0.001)
            if self._prev_net:
                sent_mbps = (now_net.bytes_sent - self._prev_net.bytes_sent) / 1_048_576 / dt
                recv_mbps = (now_net.bytes_recv - self._prev_net.bytes_recv) / 1_048_576 / dt
            self._prev_net = now_net
            self._prev_net_time = now_time
        except Exception:
            pass

        # PERF: ProcessManager already enumerates all processes every 1.5s in its own thread.
        # Running a second full process iteration here doubles system overhead.
        # Use a lightweight PID count instead — consumers needing details use ProcessManager.
        try:
            proc_count = len(psutil.pids())
        except Exception:
            proc_count = 0

        with self._lock:
            tc = self._threat_count
            sr = list(self._scan_results)
            ra = list(self._recent_alerts[-20:])

        return TelemetrySnapshot(
            timestamp=datetime.now().isoformat(),
            cpu_percent=round(cpu, 1),
            ram_percent=round(ram_pct, 1),
            ram_total_gb=round(ram_gb, 1),
            disk_percent=round(disk, 1),
            net_sent_mbps=round(sent_mbps, 3),
            net_recv_mbps=round(recv_mbps, 3),
            process_count=proc_count,
            processes=[],  # Use ProcessManager for live process data
            threat_count=tc,
            scan_results=sr,
            recent_alerts=ra,
        )


# Module-level singleton
_instance: Optional[TelemetryManager] = None


def get_telemetry() -> TelemetryManager:
    global _instance
    if _instance is None:
        _instance = TelemetryManager()
    return _instance
