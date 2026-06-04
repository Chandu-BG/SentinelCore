"""
SentinelCore - Main Application Entry Point (v4.1)
Production-hardened orchestrator:
  - Rotating log files (10 MB × 3 backups)
  - Centralized exception hooks for crash recovery
  - Startup diagnostics
  - Graceful shutdown via atexit
"""

import sys
import os
import atexit
import logging
from logging.handlers import RotatingFileHandler

# ── Resolve app root (works frozen + unfrozen) ────────────────────────────────
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

LOG_PATH = os.path.join(BASE_DIR, "sentinelcore.log")

# ── Configure UTF-8 encoding safely ──────────────────────────────────────────
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ── Production logging: RotatingFileHandler (10 MB × 3 backups) ──────────────
_fmt = logging.Formatter(
    "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

_stream_handler = logging.StreamHandler(sys.stdout)
_stream_handler.setFormatter(_fmt)

_file_handler = RotatingFileHandler(
    LOG_PATH,
    maxBytes=10 * 1024 * 1024,   # 10 MB per file
    backupCount=3,
    encoding="utf-8",
    delay=True,                   # Don't open file until first write
)
_file_handler.setFormatter(_fmt)

logging.basicConfig(
    level=logging.INFO,
    handlers=[_stream_handler, _file_handler],
)

logger = logging.getLogger("SentinelCore")


def main() -> int:
    logger.info("NovaSentinel v4.1 — Starting production build...")

    # ── 1. Install centralized exception hooks ────────────────────────────────
    try:
        from core.exception_handler import install_exception_hooks, run_startup_diagnostics
        install_exception_hooks()
        run_startup_diagnostics()
    except Exception as exc:
        logger.warning(f"Exception hooks setup failed (non-fatal): {exc}")

    # ── 2. Launch PyQt GUI ────────────────────────────────────────────────────
    logger.info("Launching PyQt6 interface...")
    try:
        from gui.app import run_sentinel_pyqt
        rc = run_sentinel_pyqt()
        logger.info(f"NovaSentinel exited cleanly with code {rc}.")
        return rc
    except Exception as exc:
        logger.exception("PyQt6 launch failed: %s", exc)
        # Attempt to show a minimal error dialog even without full Qt init
        try:
            from PyQt6.QtWidgets import QApplication, QMessageBox
            _app = QApplication.instance() or QApplication(sys.argv)
            QMessageBox.critical(
                None,
                "NovaSentinel — Launch Failed",
                f"Failed to start NovaSentinel:\n\n{exc}\n\n"
                "Please check sentinelcore.log for details."
            )
        except Exception:
            pass
        return 1


# ── Graceful shutdown hook ────────────────────────────────────────────────────
def _on_exit():
    logger.info("NovaSentinel shutdown complete.")
    logging.shutdown()


atexit.register(_on_exit)


if __name__ == "__main__":
    sys.exit(main())
