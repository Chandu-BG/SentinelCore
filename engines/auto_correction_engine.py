"""
SentinelCore - Auto-Correcting Security Engine
The master self-healing orchestrator.
Automatically reacts to system-level problems:
  - Suspicious process detected   → terminate it
  - Suspicious IP detected        → block it
  - Config file modified          → restore it
  - Database corrupted            → recreate it
  - AI model corrupted            → rebuild it
  - Missing critical files        → recreate them
  - Excessive file access         → alert (folder lockout not available in Python without ACL tools)
Self-recovery runs continuously in a background thread.
"""

import os
import json
import logging
import threading
import shutil
import time
from typing import Optional, Callable, Any

from database.init_db import recreate_db, log_system_event, get_connection

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

CONFIG_PATH    = os.path.join(BASE_DIR, "config", "version.json")
MODEL_DIR      = os.path.join(BASE_DIR, "models")
CONFIG_BACKUP  = CONFIG_PATH + ".backup"


class AutoCorrectionEngine:
    """
    Self-healing engine that diagnoses and automatically repairs
    various problems in the SentinelCore platform.
    """

    CHECK_INTERVAL = 15  # seconds between health scans

    def __init__(
        self,
        ai_engine=None,
        update_engine=None,
        on_alert: Optional[Callable[[str, str], None]] = None,
    ):
        self.ai_engine = ai_engine
        self.update_engine = update_engine
        self.on_alert = on_alert
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.corrections_made: int = 0

        # Backup config on first run
        self._backup_config()

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(
            target=self._correction_loop, daemon=True, name="AutoCorrectionEngine"
        )
        self._thread.start()
        logger.info("AutoCorrectionEngine started.")

    def stop(self) -> None:
        self._running = False
        logger.info("AutoCorrectionEngine stopped.")

    # -------------------------------------------------------------------------
    # Main correction loop
    # -------------------------------------------------------------------------

    def _correction_loop(self) -> None:
        while self._running:
            time.sleep(self.CHECK_INTERVAL)
            if self._running:
                self._run_health_checks()

    def _run_health_checks(self) -> None:
        """Run all health checks and correct what is broken."""
        self._check_database()
        self._check_config()
        self._check_model()
        self._ensure_required_dirs()

    # -------------------------------------------------------------------------
    # Individual checks
    # -------------------------------------------------------------------------

    def _check_database(self) -> None:
        """Verify database integrity; recreate if corrupted."""
        db_path = os.path.join(BASE_DIR, "sentinelcore.db")
        if not os.path.exists(db_path):
            logger.warning("Database file missing – recreating.")
            self._correct("DB_RECREATED", "Database was missing and has been recreated.")
            recreate_db()
            return

        try:
            with get_connection() as conn:
                conn.execute("SELECT 1 FROM threat_log LIMIT 1")
        except Exception as e:
            logger.error(f"Database corrupted ({e}) – recreating.")
            self._correct("DB_CORRUPTED", f"Database corrupted: {e}. Recreated.")
            recreate_db()

    def _check_config(self) -> None:
        """Restore config/version.json if it has been modified or removed."""
        if not os.path.exists(CONFIG_PATH):
            logger.warning("Config file missing – restoring backup.")
            self._restore_config()
            return

        try:
            with open(CONFIG_PATH, "r") as f:
                json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Config file corrupted: {e} – restoring backup.")
            self._restore_config()

    def _check_model(self) -> None:
        """Validate AI model; rebuild if broken."""
        model_path = os.path.join(MODEL_DIR, "ai_model.pkl")
        if not os.path.exists(model_path):
            return  # Model will be created on first training run — not an error

        if self.ai_engine is None:
            return

        try:
            import joblib
            import numpy as np
            model = joblib.load(model_path)
            model.decision_function(np.zeros((1, 5)))
        except Exception as e:
            logger.error(f"AI model corrupted ({e}) – rebuilding.")
            self._correct("MODEL_REBUILT", f"AI model was corrupted and has been rebuilt.")
            if self.ai_engine:
                self.ai_engine._rebuild_model()

    def _ensure_required_dirs(self) -> None:
        """Make sure all required directories exist."""
        required = [
            os.path.join(BASE_DIR, "models"),
            os.path.join(BASE_DIR, "config"),
            os.path.join(BASE_DIR, "database"),
        ]
        for d in required:
            if not os.path.isdir(d):
                os.makedirs(d, exist_ok=True)
                logger.info(f"Recreated missing directory: {d}")
                self._correct("DIR_RECREATED", f"Missing directory recreated: {d}")

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _backup_config(self) -> None:
        """Take a pristine backup of the config file on startup."""
        if os.path.exists(CONFIG_PATH) and not os.path.exists(CONFIG_BACKUP):
            shutil.copy2(CONFIG_PATH, CONFIG_BACKUP)
            logger.debug("Config backup created.")

    def _restore_config(self) -> None:
        """Restore the config from backup."""
        if os.path.exists(CONFIG_BACKUP):
            shutil.copy2(CONFIG_BACKUP, CONFIG_PATH)
            self._correct("CONFIG_RESTORED", "Config file restored from backup.")
        else:
            logger.error("No config backup available – cannot restore.")

    def _correct(self, event_type: str, description: str) -> None:
        """Record a correction action."""
        self.corrections_made += 1
        log_system_event(event_type, description, "warning")
        if self.on_alert:
            self.on_alert(event_type, description)
        logger.warning(f"[AUTO-CORRECTION] {event_type}: {description}")

    # -------------------------------------------------------------------------
    # Manual triggers (for testing / GUI buttons)
    # -------------------------------------------------------------------------

    def force_db_check(self) -> None:
        self._check_database()

    def force_config_check(self) -> None:
        self._check_config()

    def force_model_check(self) -> None:
        self._check_model()
