"""
NovaSentinel — Update Manager
Handles system, signature, and ML model freshness checks.
"""

import glob
import logging
import os
import threading
import time
from datetime import datetime
from typing import List

logger = logging.getLogger(__name__)

MODEL_AGE_THRESHOLD_SECONDS = 7 * 24 * 3600  # 1 week


class UpdateManager:
    def __init__(self, check_interval_seconds: int = 3600):
        self.last_update = 0.0
        self.last_model_scan = 0.0
        self.update_status = "Unknown"
        self._running = False
        self._thread = None
        self.check_interval = check_interval_seconds
        self.models_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, "models"))

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._update_loop, daemon=True, name="UpdateManager")
        self._thread.start()

    def stop(self):
        self._running = False

    def check_for_updates(self):
        logger.info("Checking for signature and model freshness updates...")
        self.update_status = "Checking..."
        try:
            self._check_model_freshness()
            self.last_update = time.time()
            self.update_status = "Up to date"
            logger.info("UpdateManager: system and model freshness check complete.")
        except Exception as exc:
            self.update_status = "Update check failed"
            logger.warning("UpdateManager update check failed: %s", exc)

    def _check_model_freshness(self) -> None:
        if not os.path.isdir(self.models_dir):
            self.update_status = "Models missing"
            logger.warning("UpdateManager: models directory missing: %s", self.models_dir)
            return

        model_files = self._list_model_files()
        if not model_files:
            self.update_status = "No model artifacts found"
            logger.warning("UpdateManager: no model artifacts found in %s", self.models_dir)
            return

        newest = max(os.path.getmtime(path) for path in model_files)
        age = time.time() - newest
        self.last_model_scan = time.time()

        if age > MODEL_AGE_THRESHOLD_SECONDS:
            self.update_status = "Model artifacts stale"
            logger.warning("UpdateManager: model artifacts are stale (%.1f days old)", age / 86400)
        else:
            self.update_status = "Models are current"
            logger.info("UpdateManager: model artifacts are fresh.")

    def _list_model_files(self) -> List[str]:
        patterns = ["*.pkl", "*.joblib", "*.yara", "*.json", "*.npy"]
        files: List[str] = []
        for pattern in patterns:
            files.extend(glob.glob(os.path.join(self.models_dir, pattern)))
        return files

    def _update_loop(self):
        while self._running:
            self.check_for_updates()
            for _ in range(int(self.check_interval)):
                if not self._running:
                    break
                time.sleep(1)

_instance: UpdateManager = None  # type: ignore
def get_update_manager() -> UpdateManager:
    global _instance
    if _instance is None:
        _instance = UpdateManager()
    return _instance
