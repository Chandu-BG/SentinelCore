"""
CoreBridge — thread-safe Qt signals from SecurityCore background workers.

v4.2 — Performance hardened:
  - Adaptive sleep: backs off if get_snapshot() is slow (baseline 2.0s)
  - Watchdog pulse: registers itself with ThreadWatchdog
  - Exception logging for all signal emissions
  - Early-exit guard on shutdown to prevent post-quit signal emissions
  - Dead-signal guard: checks QApplication alive before emitting
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Optional

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QApplication

logger = logging.getLogger(__name__)

# Minimum sleep between metric polls (seconds) — raised from 1.5 to 2.0
_BASELINE_SLEEP = 2.0
_MAX_SLEEP = 6.0


class CoreBridge(QObject):
    """Bridges SecurityCore callbacks and polling loops to the Qt GUI thread."""

    metrics_updated  = pyqtSignal(float, float, float, float, int)
    processes_updated = pyqtSignal(list)
    threat_detected  = pyqtSignal(dict)
    scan_progress    = pyqtSignal(dict)
    scan_complete    = pyqtSignal(dict)
    ai_token         = pyqtSignal(str)
    ai_done          = pyqtSignal(str)
    module_status    = pyqtSignal(str, str)

    def __init__(self, security_core: Any):
        super().__init__()
        self._core = security_core
        self._running = False
        self._prev_gui_cb: Optional[Callable[..., Any]] = getattr(
            security_core, "gui_callback", None
        )
        security_core.gui_callback = self._on_core_event
        self._metrics_thread: Optional[threading.Thread] = None

        # Adaptive sleep state
        self._sleep_interval: float = _BASELINE_SLEEP
        self._last_emit_time: float = 0.0

    def shutdown(self) -> None:
        """Signal the metrics loop to stop and restore previous callback."""
        self._running = False
        if self._prev_gui_cb is not None:
            try:
                self._core.gui_callback = self._prev_gui_cb
            except Exception:
                pass

    def start_metrics_loop(self) -> None:
        self._running = True
        self._metrics_thread = threading.Thread(
            target=self._metrics_loop, daemon=True, name="QtMetrics"
        )
        self._metrics_thread.start()

        # Register with watchdog if available
        try:
            from core.exception_handler import get_watchdog
            get_watchdog().register("QtMetrics", self._metrics_thread)
        except Exception:
            pass

    def _app_alive(self) -> bool:
        """Return True only if the Qt application is still running."""
        return QApplication.instance() is not None and self._running

    def _metrics_loop(self) -> None:
        # Get watchdog pulse function if available
        _pulse = None
        try:
            from core.exception_handler import get_watchdog
            wdog = get_watchdog()
            _pulse = lambda: wdog.pulse("QtMetrics")
        except Exception:
            pass

        while self._running:
            loop_start = time.monotonic()

            if not self._app_alive():
                break

            try:
                snap = self._core.get_snapshot()
                net = float(getattr(snap, "net_sent_mbps", 0.0) or 0.0) + float(
                    getattr(snap, "net_recv_mbps", 0.0) or 0.0
                )

                # ProcessManager.get_processes() returns a cached, lock-guarded snapshot
                # built by the background refresh thread — NOT a new psutil scan.
                procs = self._core.get_processes()

                if self._app_alive():
                    self.processes_updated.emit(procs)
                    self.metrics_updated.emit(
                        float(getattr(snap, "cpu_percent", 0.0) or 0.0),
                        float(getattr(snap, "ram_percent", 0.0) or 0.0),
                        float(getattr(snap, "disk_percent", 0.0) or 0.0),
                        net,
                        int(getattr(snap, "threat_count", 0) or 0),
                    )
                    self._last_emit_time = time.monotonic()

                # Adaptive sleep: back off if loop is slow (>1.0s)
                elapsed = time.monotonic() - loop_start
                if elapsed > 1.0:
                    self._sleep_interval = min(self._sleep_interval * 1.25, _MAX_SLEEP)
                    logger.debug(
                        f"Metrics loop slow ({elapsed:.2f}s), backing off to {self._sleep_interval:.1f}s"
                    )
                else:
                    # Gradually recover toward baseline
                    self._sleep_interval = max(self._sleep_interval * 0.90, _BASELINE_SLEEP)

            except Exception as exc:
                logger.debug("metrics loop: %s", exc)
                self._sleep_interval = min(self._sleep_interval + 0.5, _MAX_SLEEP)

            # Pulse watchdog to indicate we're alive
            if _pulse:
                try:
                    _pulse()
                except Exception:
                    pass

            # Interruptible sleep: break early on shutdown
            deadline = time.monotonic() + self._sleep_interval
            while time.monotonic() < deadline and self._running:
                time.sleep(0.1)

    def _on_core_event(self, event_type: str, data: Any) -> None:
        if not self._app_alive():
            return
        try:
            if event_type == "alert" and isinstance(data, (list, tuple)) and len(data) >= 3:
                alert_type, severity, message = data[0], data[1], data[2]
                if not isinstance(message, str):
                    message = str(message)
                self.threat_detected.emit(
                    {"type": alert_type, "severity": severity, "message": message}
                )
            elif event_type == "scanner_progress":
                self.scan_progress.emit({"message": data})
            elif event_type == "scanner_finding":
                self.scan_progress.emit({"finding": data})
            elif event_type == "scanner_complete":
                self.scan_complete.emit(data)
            elif event_type == "module_status" and isinstance(data, (list, tuple)) and len(data) >= 2:
                self.module_status.emit(str(data[0]), str(data[1]))
        except Exception as exc:
            logger.debug("core event bridge: %s", exc)
