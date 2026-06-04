"""
PyQt6 application bootstrap for NovaSentinel (v4.1).
Production hardened:
  - High-DPI policy set before QApplication construction
  - Splash screen shown during SecurityCore initialization
  - SecurityCore loaded in background thread (non-blocking UI)
  - Graceful shutdown on aboutToQuit signal
  - Startup diagnostics logging
  - Startup time measurement
"""

from __future__ import annotations

import logging
import os
import sys
import time
import threading

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtWidgets import QApplication

logger = logging.getLogger(__name__)


class SentinelApp(QApplication):
    """Production QApplication with global overrides."""

    def __init__(self, argv: list):
        # Set High-DPI rounding policy BEFORE calling super().__init__
        try:
            QApplication.setHighDpiScaleFactorRoundingPolicy(
                Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
            )
        except Exception:
            pass  # Qt version may not support this — safe to ignore

        super().__init__(argv)

        self.setApplicationName("NovaSentinel")
        self.setApplicationVersion("4.1")
        self.setOrganizationName("NovaSentinel Security")

        # Set application icon
        try:
            from PyQt6.QtGui import QIcon
            base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
            root = os.path.dirname(base)
            ico = os.path.join(root, "assets", "novasentinel.ico")
            if os.path.exists(ico):
                self.setWindowIcon(QIcon(ico))
        except Exception:
            pass

    def notify(self, receiver, event):
        """Override to catch exceptions in Qt event dispatch."""
        try:
            return super().notify(receiver, event)
        except Exception as exc:
            logger.error(f"Qt event dispatch error: {exc}", exc_info=True)
            return False


class _CoreLoader(QObject):
    """Loads SecurityCore in a background thread and emits signals for progress."""

    status = pyqtSignal(str, int)   # (message, progress 0-100)
    ready  = pyqtSignal(object, object)  # (core, config_dir)
    error  = pyqtSignal(str)

    def __init__(self, config_dir: str):
        super().__init__()
        self._config_dir = config_dir

    def run(self) -> None:
        try:
            self.status.emit("Initializing database...", 10)
            from database.init_db import init_db
            init_db()

            self.status.emit("Loading security core...", 25)
            from core.security_core import get_security_core
            core = get_security_core()

            self.status.emit("Starting protection engines...", 60)
            # SecurityCore is now ready — main window can be created

            self.status.emit("Building user interface...", 85)
            self.ready.emit(core, self._config_dir)

        except Exception as exc:
            logger.exception("SecurityCore initialization failed: %s", exc)
            self.error.emit(str(exc))


def run_sentinel_pyqt() -> int:
    t_start = time.perf_counter()

    base_gui = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(base_gui)
    if root not in sys.path:
        sys.path.insert(0, root)

    config_dir = os.path.join(root, "config")

    # ── Create QApplication first ─────────────────────────────────────────────
    app = SentinelApp(sys.argv)

    # ── Show splash screen ────────────────────────────────────────────────────
    splash = None
    try:
        from gui.widgets.splash_screen import NovaSentinelSplash
        splash = NovaSentinelSplash()
        splash.set_status("Starting NovaSentinel v4.1...")
        splash.set_progress(5)
        splash.show()
        app.processEvents()
    except Exception as exc:
        logger.warning(f"Splash screen failed (non-fatal): {exc}")

    # ── Load SecurityCore in background thread ────────────────────────────────
    loader = _CoreLoader(config_dir)
    main_window_holder = [None]
    bridge_holder = [None]
    error_msg = [None]

    def _on_status(msg: str, progress: int):
        if splash:
            splash.set_status(msg)
            splash.set_progress(progress)
            app.processEvents()

    def _on_ready(core, cfg_dir: str):
        from gui.core_bridge import CoreBridge
        from gui.main_window import MainWindow

        bridge = CoreBridge(core)
        win = MainWindow(core, bridge, cfg_dir)
        main_window_holder[0] = win
        bridge_holder[0] = bridge

        if splash:
            splash.set_status("Ready!")
            splash.set_progress(100)
            app.processEvents()

        # Small delay so "Ready!" is visible before splash closes
        QTimer.singleShot(300, lambda: _show_window(win, bridge, splash))

    def _show_window(win, bridge, splash_ref):
        bridge.start_metrics_loop()
        win.show()
        if splash_ref:
            splash_ref.stop()
            splash_ref.finish(win)

        elapsed = time.perf_counter() - t_start
        logger.info(f"NovaSentinel UI visible in {elapsed:.2f}s.")

    def _on_error(msg: str):
        error_msg[0] = msg
        if splash:
            splash.stop()
            splash.close()
        from PyQt6.QtWidgets import QMessageBox
        QMessageBox.critical(
            None,
            "NovaSentinel — Startup Error",
            f"Failed to initialize security core:\n\n{msg}\n\n"
            "Please check sentinelcore.log for details."
        )
        app.quit()

    loader.status.connect(_on_status)
    loader.ready.connect(_on_ready)
    loader.error.connect(_on_error)

    # Run loader in daemon thread
    t = threading.Thread(target=loader.run, daemon=True, name="CoreLoader")
    t.start()

    # ── Graceful shutdown ─────────────────────────────────────────────────────
    def _on_quit():
        logger.info("Qt quit signal received — shutting down bridge...")
        bridge = bridge_holder[0]
        if bridge:
            try:
                bridge.shutdown()
            except Exception as exc:
                logger.warning(f"Bridge shutdown error: {exc}")

    app.aboutToQuit.connect(_on_quit)

    logger.info("NovaSentinel app event loop starting.")
    rc = app.exec()
    return int(rc)


def main() -> int:
    return run_sentinel_pyqt()
