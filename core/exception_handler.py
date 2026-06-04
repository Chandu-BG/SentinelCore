"""
NovaSentinel — Centralized Exception Handler & Crash Recovery
Provides:
  - sys.excepthook override for uncaught exceptions
  - Structured JSON crash report generation
  - Qt crash dialog with clipboard copy
  - ThreadWatchdog for detecting frozen background threads
  - StartupDiagnostics for logging environment state
"""

from __future__ import annotations

import json
import logging
import os
import platform
import sys
import threading
import time
import traceback
from datetime import datetime
from typing import Callable, Dict, List, Optional, Type

logger = logging.getLogger(__name__)

# ── Crash report directory ────────────────────────────────────────────────────
def _get_app_root() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

APP_ROOT = _get_app_root()
CRASH_DIR = os.path.join(APP_ROOT, "crash_reports")
os.makedirs(CRASH_DIR, exist_ok=True)


# ── Crash Report Writer ───────────────────────────────────────────────────────

def write_crash_report(
    exc_type: Type[BaseException],
    exc_value: BaseException,
    exc_tb,
    context: str = "main",
) -> str:
    """Write a structured JSON crash report and return the file path."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(CRASH_DIR, f"crash_{context}_{ts}.json")

    tb_lines = traceback.format_exception(exc_type, exc_value, exc_tb)
    tb_text = "".join(tb_lines)

    report = {
        "timestamp": datetime.now().isoformat(),
        "context": context,
        "exception_type": exc_type.__name__ if exc_type else "Unknown",
        "exception_message": str(exc_value),
        "traceback": tb_text,
        "system": {
            "platform": platform.platform(),
            "python_version": sys.version,
            "frozen": getattr(sys, "frozen", False),
        },
    }

    try:
        # Collect system metrics safely
        try:
            import psutil
            vm = psutil.virtual_memory()
            report["system"]["ram_total_gb"] = round(vm.total / (1024 ** 3), 1)
            report["system"]["ram_available_gb"] = round(vm.available / (1024 ** 3), 1)
            report["system"]["cpu_count"] = psutil.cpu_count()
        except Exception:
            pass

        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        logger.critical(f"Crash report written: {report_path}")
    except Exception as write_err:
        logger.error(f"Failed to write crash report: {write_err}")

    # Also write a human-readable txt fallback
    try:
        txt_path = report_path.replace(".json", ".txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(f"NovaSentinel Crash Report\n")
            f.write(f"Timestamp: {report['timestamp']}\n")
            f.write(f"Context: {context}\n")
            f.write(f"Platform: {report['system']['platform']}\n")
            f.write(f"Python: {sys.version}\n\n")
            f.write(tb_text)
    except Exception:
        pass

    return report_path


# ── Qt Crash Dialog ──────────────────────────────────────────────────────────

def show_crash_dialog(
    exc_type: Type[BaseException],
    exc_value: BaseException,
    report_path: str,
) -> None:
    """Show a user-friendly Qt crash dialog. Safe to call from main thread only."""
    try:
        from PyQt6.QtWidgets import QApplication, QMessageBox, QPushButton
        from PyQt6.QtCore import Qt

        app = QApplication.instance()
        if app is None:
            return

        tb_short = traceback.format_exception_only(exc_type, exc_value)
        tb_str = "".join(tb_short).strip()

        msg = QMessageBox()
        msg.setWindowTitle("NovaSentinel — Unexpected Error")
        msg.setIcon(QMessageBox.Icon.Critical)
        msg.setText(
            f"<b>NovaSentinel encountered an unexpected error.</b><br><br>"
            f"<span style='color:#ef4444; font-family:monospace;'>{tb_str}</span><br><br>"
            f"A crash report has been saved to:<br>"
            f"<span style='color:#3b82f6;'>{report_path}</span>"
        )
        msg.setInformativeText(
            "The application will attempt to continue. "
            "If issues persist, please restart NovaSentinel."
        )

        copy_btn = msg.addButton("Copy Report Path", QMessageBox.ButtonRole.ActionRole)
        msg.addButton(QMessageBox.StandardButton.Ok)
        msg.setDefaultButton(QMessageBox.StandardButton.Ok)

        msg.exec()

        if msg.clickedButton() == copy_btn:
            clipboard = app.clipboard()
            if clipboard:
                clipboard.setText(report_path)

    except Exception as dialog_err:
        logger.error(f"Could not show crash dialog: {dialog_err}")


# ── Exception Hook Installer ──────────────────────────────────────────────────

def install_exception_hooks() -> None:
    """
    Install sys.excepthook override for uncaught main-thread exceptions.
    Also patches threading.excepthook for background thread crashes.
    """
    _original_excepthook = sys.excepthook

    def _main_excepthook(exc_type, exc_value, exc_tb):
        # Don't intercept KeyboardInterrupt
        if issubclass(exc_type, KeyboardInterrupt):
            _original_excepthook(exc_type, exc_value, exc_tb)
            return

        logger.critical(
            "Uncaught exception in main thread",
            exc_info=(exc_type, exc_value, exc_tb)
        )
        report_path = write_crash_report(exc_type, exc_value, exc_tb, "main_thread")
        show_crash_dialog(exc_type, exc_value, report_path)

    sys.excepthook = _main_excepthook

    # Patch threading to catch background thread crashes
    _original_thread_hook = getattr(threading, "excepthook", None)

    def _thread_excepthook(args):
        if args.exc_type is None or issubclass(args.exc_type, SystemExit):
            return
        thread_name = getattr(args.thread, "name", "unknown")
        logger.critical(
            f"Uncaught exception in thread '{thread_name}'",
            exc_info=(args.exc_type, args.exc_value, args.exc_traceback)
        )
        write_crash_report(
            args.exc_type, args.exc_value, args.exc_traceback,
            context=f"thread_{thread_name}"
        )
        if _original_thread_hook:
            _original_thread_hook(args)

    threading.excepthook = _thread_excepthook
    logger.info("Exception hooks installed.")


# ── Thread Watchdog ──────────────────────────────────────────────────────────

class ThreadWatchdog:
    """
    Monitors registered daemon threads by heartbeat.
    Logs warnings if a thread stops pulsing within the timeout window.
    """

    def __init__(self, timeout: float = 30.0):
        self._timeout = timeout
        self._heartbeats: Dict[str, float] = {}
        self._registered: Dict[str, threading.Thread] = {}
        self._lock = threading.Lock()
        self._running = False
        self._watchdog_thread: Optional[threading.Thread] = None

    def register(self, name: str, thread: threading.Thread) -> None:
        """Register a thread for watchdog monitoring."""
        with self._lock:
            self._registered[name] = thread
            self._heartbeats[name] = time.time()

    def pulse(self, name: str) -> None:
        """Called by monitored threads to indicate they are alive."""
        with self._lock:
            self._heartbeats[name] = time.time()

    def start(self) -> None:
        """Start the watchdog monitoring loop."""
        self._running = True
        self._watchdog_thread = threading.Thread(
            target=self._loop, daemon=True, name="ThreadWatchdog"
        )
        self._watchdog_thread.start()
        logger.info("ThreadWatchdog started.")

    def stop(self) -> None:
        self._running = False

    def _loop(self) -> None:
        while self._running:
            time.sleep(10.0)
            now = time.time()
            with self._lock:
                for name, thread in list(self._registered.items()):
                    if not thread.is_alive():
                        logger.warning(f"[Watchdog] Thread '{name}' is no longer alive!")
                        self._registered.pop(name, None)
                        continue
                    last_pulse = self._heartbeats.get(name, 0)
                    elapsed = now - last_pulse
                    if elapsed > self._timeout:
                        logger.warning(
                            f"[Watchdog] Thread '{name}' has not pulsed for "
                            f"{elapsed:.0f}s (timeout={self._timeout}s) — possible hang!"
                        )


# ── Startup Diagnostics ───────────────────────────────────────────────────────

def run_startup_diagnostics() -> Dict:
    """Log environment state at application startup. Returns diagnostic dict."""
    diag = {
        "timestamp": datetime.now().isoformat(),
        "platform": platform.platform(),
        "python_version": sys.version,
        "frozen": getattr(sys, "frozen", False),
        "app_root": APP_ROOT,
    }

    # RAM
    try:
        import psutil
        vm = psutil.virtual_memory()
        diag["ram_total_gb"] = round(vm.total / (1024 ** 3), 1)
        diag["ram_available_gb"] = round(vm.available / (1024 ** 3), 1)
        diag["cpu_count"] = psutil.cpu_count(logical=True)
        diag["cpu_count_physical"] = psutil.cpu_count(logical=False)
    except Exception:
        diag["ram_error"] = "psutil unavailable"

    # GPU
    try:
        import subprocess
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0 and result.stdout.strip():
            diag["gpu"] = result.stdout.strip()
    except Exception:
        diag["gpu"] = "Not detected or no NVIDIA GPU"

    # Key module availability
    optional_modules = ["pyqtgraph", "pefile", "yara", "wmi", "xgboost", "lightgbm", "sklearn"]
    module_status = {}
    for mod in optional_modules:
        try:
            __import__(mod)
            module_status[mod] = "available"
        except ImportError:
            module_status[mod] = "missing"
    diag["modules"] = module_status

    logger.info("=" * 60)
    logger.info("NovaSentinel Startup Diagnostics")
    logger.info(f"  Platform:   {diag['platform']}")
    logger.info(f"  Python:     {sys.version.split()[0]}")
    logger.info(f"  Frozen:     {diag['frozen']}")
    logger.info(f"  App Root:   {APP_ROOT}")
    if "ram_total_gb" in diag:
        logger.info(f"  RAM:        {diag['ram_available_gb']:.1f} GB free / {diag['ram_total_gb']:.1f} GB total")
    logger.info(f"  GPU:        {diag.get('gpu', 'N/A')}")
    for mod, status in module_status.items():
        icon = "✓" if status == "available" else "✗"
        logger.info(f"  Module [{icon}] {mod}: {status}")
    logger.info("=" * 60)

    return diag


# Module-level singleton watchdog
_watchdog: Optional[ThreadWatchdog] = None


def get_watchdog() -> ThreadWatchdog:
    global _watchdog
    if _watchdog is None:
        _watchdog = ThreadWatchdog(timeout=60.0)
    return _watchdog
