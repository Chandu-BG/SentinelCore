"""
SentinelCore - Self-Protection Engine
Monitors the integrity of the platform's own files.
Detects unauthorized modification of:
  - Main executable / source files
  - SQLite database
  - Configuration files (config/version.json)
  - AI model files
If tampering is detected, fires an alert and triggers auto-correction.
"""

import os
import logging
import threading
import time
from typing import Dict, Callable, Optional

from engines.hash_engine import hash_file, register_trusted, verify_executable

logger = logging.getLogger(__name__)

# Files SentinelCore should protect
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

PROTECTED_FILES = [
    os.path.join(BASE_DIR, "main.py"),
    os.path.join(BASE_DIR, "sentinelcore.db"),
    os.path.join(BASE_DIR, "config", "version.json"),
    os.path.join(BASE_DIR, "models", "ai_model.pkl"),
]


class SelfProtectionEngine:
    """
    Periodically re-hashes critical platform files and fires alerts
    if any file has been modified since the last known-good state.
    """

    CHECK_INTERVAL = 30  # seconds

    def __init__(
        self,
        on_tamper: Optional[Callable[[str, str], None]] = None,
    ):
        self.on_tamper = on_tamper  # callback(file_path, description)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._tamper_count: int = 0

    def start(self) -> None:
        """Register baseline hashes and start the integrity-check loop."""
        self._register_baselines()
        self._running = True
        self._thread = threading.Thread(
            target=self._check_loop, daemon=True, name="SelfProtectionEngine"
        )
        self._thread.start()
        logger.info("SelfProtectionEngine started – monitoring platform integrity.")

    def stop(self) -> None:
        self._running = False
        logger.info("SelfProtectionEngine stopped.")

    def _register_baselines(self) -> None:
        """Hash all protected files and store as trusted baselines."""
        for f in PROTECTED_FILES:
            if os.path.exists(f):
                register_trusted(f)
                logger.debug(f"Baseline registered: {f}")
            else:
                logger.debug(f"Protected file not yet present: {f}")

    def _check_loop(self) -> None:
        """Periodically verify every protected file."""
        while self._running:
            time.sleep(self.CHECK_INTERVAL)
            if self._running:
                self._run_checks()

    def _run_checks(self) -> None:
        """Verify all protected files against their baselines."""
        for f in PROTECTED_FILES:
            if not os.path.exists(f):
                continue  # File may not yet exist (e.g. model not trained yet)
            result = verify_executable(f)
            if result.get("modified"):
                self._tamper_count += 1
                desc = (
                    f"Platform file tampered: {os.path.basename(f)}\n"
                    f"Hash mismatch detected – possible integrity attack."
                )
                logger.critical(f"[TAMPER DETECTED] {desc}")
                if self.on_tamper:
                    self.on_tamper(f, desc)

    @property
    def tamper_count(self) -> int:
        return self._tamper_count
