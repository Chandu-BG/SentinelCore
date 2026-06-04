from __future__ import annotations

import logging
import threading
from datetime import datetime
from typing import Any

from PyQt6.QtCore import Qt, QTimer, pyqtSlot
from PyQt6.QtGui import QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from gui.core_bridge import CoreBridge
from gui.theme_manager import THEME_PALETTES, ThemeManager
from gui.views.dashboard_view import DashboardView
from gui.views.logs_view import LogsView
from gui.views.performance_view import PerformanceView
from gui.views.phishing_view import PhishingView
from gui.views.quarantine_view import AppsView, QuarantineView, SandboxView
from gui.views.scan_view import ScanView
from gui.views.settings_view import SettingsView
from gui.widgets.metrics_bar import MetricsBar
from gui.widgets.notification_toast import NotificationToast
from gui.widgets.sidebar import Sidebar

# ── Module-level logger (was missing — caused NameError in worker threads) ────
logger = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    def __init__(self, security_core: Any, bridge: CoreBridge, config_dir: str):
        super().__init__()
        self._core = security_core
        self._bridge = bridge
        self._last_procs: list = []
        self._terminating_pids: set[int] = set()

        self.setWindowTitle("NovaSentinel")
        self.resize(1280, 800)

        self._theme_manager = ThemeManager(config_dir)
        central = QWidget()
        central.setObjectName("centralWidget")
        self.setCentralWidget(central)
        h = QHBoxLayout(central)
        h.setContentsMargins(0, 0, 0, 0)

        self._sidebar = Sidebar(list(THEME_PALETTES.keys()))
        self._sidebar.navigate.connect(self._on_nav)
        self._sidebar.theme_changed.connect(self._on_theme_selected)
        self._sidebar.protection_toggled.connect(self._on_protection)
        h.addWidget(self._sidebar)

        right = QVBoxLayout()
        right_w = QWidget()
        right_w.setLayout(right)
        header = QHBoxLayout()
        self._title = QLabel("Dashboard")
        self._metrics = MetricsBar()
        header.addWidget(self._title, 1)
        header.addWidget(self._metrics, 2)
        right.addLayout(header)

        self._stack = QStackedWidget()
        self._views: dict[str, QWidget] = {}

        self._views["dashboard"] = DashboardView()
        self._views["scan"] = ScanView(self._core)
        pv = PhishingView()
        pv.check_url_requested.connect(self._on_phishing_url)
        self._views["phishing"] = pv
        self._views["performance"] = PerformanceView(self._theme_manager)
        self._views["quarantine"] = QuarantineView(
            self._core.file_engine.list_quarantine,
            self._core.file_engine.restore_from_quarantine,
            self._core.file_engine.delete_from_quarantine,
            self._core.quarantine_manager.quarantine,
        )
        self._views["apps"] = AppsView(self._core)
        self._views["sandbox"] = SandboxView(self._core.sandbox_file)
        self._views["logs"] = LogsView()
        sv = SettingsView(list(THEME_PALETTES.keys()), self._core.permissions.get_all, self._core.permissions.set_permission)
        sv.theme_picked.connect(self._on_theme_selected)
        self._views["settings"] = sv

        order = [
            "dashboard",
            "scan",
            "phishing",
            "performance",
            "quarantine",
            "apps",
            "sandbox",
            "logs",
            "settings",
        ]
        for key in order:
            self._stack.addWidget(self._views[key])
        right.addWidget(self._stack, 1)
        h.addWidget(right_w, 1)

        self._toast = NotificationToast(self)

        # Connect Dashboard actions
        dash: DashboardView = self._views["dashboard"]  # type: ignore
        dash.ai_message_sent.connect(self._on_ai_message)
        dash._quick_scan_btn.clicked.connect(self._on_dashboard_quick_scan)

        self._connect_bridge()
        self._theme_manager.apply(self._theme_manager.current_theme_name)
        self._sidebar.set_theme_selection(self._theme_manager.current_theme_name)

        # Set up keyboard navigation (F-keys only, avoid conflicting with text inputs)
        self._setup_keyboard_navigation()

    def _setup_keyboard_navigation(self) -> None:
        """
        Set up keyboard shortcuts for navigation.
        Only F-keys are used for navigation (1-9 keys NOT used to avoid
        conflicting with URL inputs, scan search, and other text fields).
        """
        # F-key shortcuts are context-safe and don't fire inside text inputs
        f_key_pairs = [
            (Qt.Key.Key_F1, 0),   # Dashboard
            (Qt.Key.Key_F2, 1),   # Scan
            (Qt.Key.Key_F3, 2),   # Phishing
            (Qt.Key.Key_F4, 3),   # Performance
            (Qt.Key.Key_F5, 4),   # Quarantine
            (Qt.Key.Key_F6, 5),   # Apps
            (Qt.Key.Key_F7, 6),   # Sandbox
            (Qt.Key.Key_F8, 7),   # Logs
            (Qt.Key.Key_F9, 8),   # Settings
        ]
        for key, idx in f_key_pairs:
            sc = QShortcut(QKeySequence(key), self)
            sc.setContext(Qt.ShortcutContext.WindowShortcut)
            sc.activated.connect(lambda i=idx: self._sidebar._on_nav_click(i))

        # Tab order
        self.setTabOrder(self._sidebar, self._stack.currentWidget())
        self._sidebar.setFocus()

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)

    def _connect_bridge(self) -> None:
        b = self._bridge
        b.metrics_updated.connect(self._metrics.set_metrics)
        b.metrics_updated.connect(self._on_metrics_bundle)
        b.metrics_updated.connect(self._views["dashboard"].update_metrics)
        b.processes_updated.connect(self._on_processes)
        b.threat_detected.connect(self._toast.show_alert)
        b.threat_detected.connect(lambda a: self._views["dashboard"].on_threat(a))
        b.scan_progress.connect(self._views["scan"].on_progress)
        b.scan_progress.connect(self._on_scan_progress_finding)
        b.scan_complete.connect(self._views["scan"].on_complete)
        b.scan_complete.connect(self._on_scan_complete_dashboard)
        b.ai_token.connect(self._views["dashboard"].append_ai_token)
        b.ai_done.connect(self._views["dashboard"].on_ai_response_complete)
        b.module_status.connect(self._on_module_status)
        b.module_status.connect(self._views["dashboard"].set_module_status)

        perf: PerformanceView = self._views["performance"]
        perf.terminate_process_requested.connect(self._on_terminate_process)

    def _toast_safe(self, alert: dict) -> None:
        """Thread-safe toast helper: always dispatches to the main thread."""
        QTimer.singleShot(0, lambda: self._toast.show_alert(alert))

    def _on_terminate_process(self, pid: int, name: str) -> None:
        if pid in self._terminating_pids:
            return
        self._terminating_pids.add(pid)

        # Show instantaneous feedback toast (already on main thread here)
        self._toast.show_alert({
            "severity": "info",
            "message": f"Terminating process {name} (PID: {pid})..."
        })

        perf: PerformanceView = self._views["performance"]
        QTimer.singleShot(0, lambda: perf.set_process_status(pid, "Terminating..."))

        def worker():
            try:
                import os
                import psutil
                import time

                # 1. Protect NovaSentinel & Core Infrastructure from self-termination
                current_pid = os.getpid()
                try:
                    current_proc = psutil.Process(current_pid)
                    sibling_pids = {p.pid for p in current_proc.children(recursive=True)}
                    sibling_pids.add(current_pid)
                    if current_proc.parent():
                        sibling_pids.add(current_proc.parent().pid)
                except Exception:
                    sibling_pids = {current_pid}

                is_our_python = False
                name_lower = name.lower()
                protected_infra = ("python.exe", "pythonw.exe", "novasentinel", "sentinelcore", "ollama.exe", "ollama")

                if name_lower in protected_infra:
                    try:
                        p_info = psutil.Process(pid)
                        cmdline = [c.lower() for c in p_info.cmdline()]
                        if any("main.py" in c for c in cmdline):
                            is_our_python = True
                    except Exception:
                        pass

                if pid in sibling_pids or name_lower in protected_infra or is_our_python:
                    self._toast_safe({
                        "severity": "critical",
                        "message": "Protected NovaSentinel process cannot be terminated."
                    })
                    QTimer.singleShot(0, lambda: perf.set_process_status(pid, "Protected Process"))
                    return

                # 2. Validate process existence
                if not psutil.pid_exists(pid):
                    self._toast_safe({
                        "severity": "warning",
                        "message": "Process already exited."
                    })
                    QTimer.singleShot(0, lambda: perf.set_process_status(pid, "Terminated"))
                    return

                # 3. Check System Critical or protected by Windows
                from core.process_manager import SYSTEM_CRITICAL
                if name_lower in SYSTEM_CRITICAL or pid in (0, 4):
                    self._toast_safe({
                        "severity": "critical",
                        "message": "This process is protected by Windows."
                    })
                    QTimer.singleShot(0, lambda: perf.set_process_status(pid, "Protected Process"))
                    return

                # 4. Graceful termination sequence
                proc = psutil.Process(pid)
                create_time = proc.create_time()

                proc.terminate()
                try:
                    proc.wait(timeout=1.5)
                except psutil.TimeoutExpired:
                    proc.kill()
                    try:
                        proc.wait(timeout=1.0)
                    except Exception:
                        pass

                # 5. Verify termination
                if psutil.pid_exists(pid):
                    try:
                        current_proc = psutil.Process(pid)
                        if current_proc.create_time() == create_time:
                            self._toast_safe({
                                "severity": "warning",
                                "message": "Termination failed: Application refused shutdown."
                            })
                            QTimer.singleShot(0, lambda: perf.set_process_status(pid, "Failed"))
                            return
                    except Exception:
                        pass

                # Check if it auto-restarted
                restarted = False
                now = time.time()
                for p in psutil.process_iter(["name", "create_time"]):
                    try:
                        if p.info["name"].lower() == name_lower and p.pid != pid:
                            if now - p.info["create_time"] < 3.0:
                                restarted = True
                                break
                    except Exception:
                        pass

                if restarted:
                    self._toast_safe({
                        "severity": "info",
                        "message": "Process restarted by system/service manager."
                    })
                    QTimer.singleShot(0, lambda: perf.set_process_status(pid, "Failed"))
                else:
                    self._toast_safe({
                        "severity": "success",
                        "message": "Process terminated successfully."
                    })
                    QTimer.singleShot(0, lambda: perf.set_process_status(pid, "Terminated"))

                QTimer.singleShot(0, self._force_refresh_performance_data)

            except psutil.AccessDenied:
                logger.warning(f"Access denied terminating PID {pid} ({name})")
                self._toast_safe({
                    "severity": "critical",
                    "message": "Access denied. Run as Administrator to terminate protected apps."
                })
                QTimer.singleShot(0, lambda: perf.set_process_status(pid, "Access Denied"))
            except psutil.NoSuchProcess:
                self._toast_safe({
                    "severity": "warning",
                    "message": "Process is already closed."
                })
                QTimer.singleShot(0, lambda: perf.set_process_status(pid, "Terminated"))
            except Exception as exc:
                logger.error(f"Process termination error for PID {pid}: {exc}")
                self._toast_safe({
                    "severity": "warning",
                    "message": "Security permissions blocked termination. Unable to terminate safely."
                })
                QTimer.singleShot(0, lambda: perf.set_process_status(pid, "Failed"))
            finally:
                self._terminating_pids.discard(pid)

        threading.Thread(target=worker, daemon=True, name=f"Terminator-{pid}").start()

    def _force_refresh_performance_data(self) -> None:
        import psutil
        try:
            active_pids = set(psutil.pids())
            self._last_procs = [
                p for p in self._last_procs
                if (p.get("pid") if isinstance(p, dict) else p.pid) in active_pids
            ]
            perf: PerformanceView = self._views["performance"]  # type: ignore[assignment]
            perf._all_processes = self._last_procs
            perf._refresh_tree()
        except Exception:
            pass

    @pyqtSlot(list)
    def _on_processes(self, procs: list) -> None:
        self._last_procs = list(procs)

    @pyqtSlot(float, float, float, float, int)
    def _on_metrics_bundle(self, cpu: float, ram: float, disk: float, net: float, _t: int) -> None:
        perf: PerformanceView = self._views["performance"]  # type: ignore[assignment]
        perf.set_metrics(self._last_procs, cpu, ram, net, disk)

    @pyqtSlot(int)
    def _on_nav(self, index: int) -> None:
        titles = Sidebar.NAV_LABELS
        if 0 <= index < len(titles):
            self._title.setText(titles[index])
        self._stack.setCurrentIndex(index)
        self._sidebar.set_active(index)

    def _on_theme_selected(self, name: str) -> None:
        self._theme_manager.apply(name)
        self._sidebar.set_theme_selection(name)

    def _on_protection(self, on: bool) -> None:
        self._sidebar.set_protection_checked(on)
        def worker() -> None:
            if on:
                self._core.start_protection()
                QTimer.singleShot(0, lambda: self._views["dashboard"].set_hero_status("protected"))
            else:
                self._core.stop_protection()
                QTimer.singleShot(0, lambda: self._views["dashboard"].set_hero_status("stopped"))
        threading.Thread(target=worker, daemon=True).start()

    def closeEvent(self, event) -> None:  # noqa: N802
        try:
            self._bridge.shutdown()
        except Exception:
            pass
        super().closeEvent(event)

    def _on_module_status(self, module: str, status: str) -> None:
        severity = "info"
        if status.lower() in {"stopped", "disabled", "failed"}:
            severity = "warning"
        self._toast.show_alert(
            {"severity": severity, "message": f"{module}: {status}"}
        )
        if module == "ML Models":
            self._metrics.set_status(status)

    def _on_phishing_url(self, url: str) -> None:
        if not url:
            return

        def worker() -> None:
            try:
                res = self._core.scan_url(url)
                if hasattr(res, "to_dict"):
                    res = res.to_dict()
                elif hasattr(res, "__dict__"):
                    res = {k: v for k, v in res.__dict__.items() if not k.startswith("_")}

                self._views["phishing"].result_ready.emit(res)

                def done_cb(full: str):
                    res["ai_explanation"] = full
                    self._views["phishing"].result_ready.emit(res)

                self._core.explain_url(url, res, None, done_cb)

            except Exception as exc:
                logger.error(f"Phishing scan failed for '{url}': {exc}", exc_info=True)
                err_res = {
                    "url": url,
                    "is_phishing": False,
                    "score": 0,
                    "reasons": [f"Audit Error: {exc}"],
                    "classification": "SAFE",
                    "ai_explanation": f"NovaSentinel Core Audit Failed: {exc}"
                }
                self._views["phishing"].result_ready.emit(err_res)

        threading.Thread(target=worker, daemon=True, name="PhishingWorker").start()

    @pyqtSlot(dict)
    def _on_scan_progress_finding(self, data: dict) -> None:
        if "finding" in data:
            finding = data["finding"]
            classification = getattr(finding, "classification", "SAFE")
            if classification in ("SUSPICIOUS", "MALICIOUS"):
                try:
                    self._views["quarantine"].refresh()
                except Exception:
                    pass
                name = getattr(finding, "name", "threat")
                self._toast.show_alert({
                    "severity": "critical",
                    "message": f"Auto-Quarantined: {name} isolated successfully!"
                })

    def _on_dashboard_quick_scan(self) -> None:
        """Triggered from dashboard Hero card."""
        self._on_nav(1)
        self._views["scan"]._start_quick()

    def _on_scan_complete_dashboard(self, data: dict) -> None:
        """Update dashboard with last scan time."""
        try:
            now = datetime.now().strftime("%I:%M %p")
            if now.startswith("0"):
                now = now[1:]
            mode = data.get("mode", "Quick Scan")
            threats = data.get("threats", 0)
            result = "Safe" if threats == 0 else f"{threats} Threats"
            last_scan_str = f"{mode} • {now} • {result}"
            self._views["dashboard"].update_scan_info(last_scan_str)
        except Exception as e:
            logger.debug(f"Dashboard scan complete update error: {e}")

    def _on_ai_message(self, text: str) -> None:
        hist = self._core.ai_context.get_history()
        snap = self._core.ai_context.get_snapshot()
        self._core.ai_context.add_to_history("user", text, "chat")

        def stream_cb(tok: str) -> None:
            self._bridge.ai_token.emit(tok)

        def done_cb(full: str) -> None:
            self._core.ai_context.add_to_history("assistant", full, "chat")
            self._bridge.ai_done.emit(full)

            if "[COMMAND: QUARANTINE_ALL_THREATS]" in full:
                self._execute_ai_quarantine()
            elif "[COMMAND: QUICK_SCAN]" in full:
                QTimer.singleShot(0, self._on_dashboard_quick_scan)
            elif "[COMMAND: TERMINATE_SUSPICIOUS]" in full:
                self._execute_ai_termination()

        threading.Thread(
            target=lambda: self._core.novasentinel.chat(
                user_message=text,
                history=hist,
                system_snapshot=snap,
                stream_cb=stream_cb,
                done_cb=done_cb,
            ),
            daemon=True,
            name="AIChat",
        ).start()

    def _execute_ai_quarantine(self):
        """Execute quarantine on all confirmed threats."""
        import os
        tm = self._core.threat_manager
        active_threats = tm.get_threats()

        count = 0
        for t in active_threats:
            path = t.get("path")
            if path and os.path.exists(path):
                success = self._core.quarantine_manager.quarantine(path, "AI Directed Remediation")
                if success:
                    count += 1

        if count > 0:
            self._toast.show_alert({"severity": "info", "message": f"AI Assistant quarantined {count} threats."})
            if self._stack.currentIndex() == 4:
                try:
                    self._views["quarantine"].refresh()
                except Exception:
                    pass
        else:
            self._toast.show_alert({"severity": "warning", "message": "AI attempted quarantine but no active file threats were found."})

    def _execute_ai_termination(self):
        """Terminate processes with high resource usage or anomaly."""
        procs = self._core.get_processes()
        count = 0
        for p in procs:
            if p.cpu_percent > 80 or p.gpu_percent > 50:
                success = self._core.terminate_process(p.pid, p.display_name)
                if success:
                    count += 1

        if count > 0:
            self._toast.show_alert({"severity": "info", "message": f"AI Assistant terminated {count} high-load processes."})
        else:
            self._toast.show_alert({"severity": "info", "message": "AI checked processes but none required immediate termination."})

