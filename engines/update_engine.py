"""
SentinelCore - Self-Updating AI Model Engine
Manages periodic retraining and safe replacement of the AI model.
  - Retrains in a background thread at a configurable interval
  - Safely replaces the old model file only after successful validation
  - Rebuilds from scratch if the production model is found to be corrupted
  - Exposes a status dict for the GUI
"""

import os
import time
import logging
import threading
from datetime import datetime
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "models", "ai_model.pkl"
)
MODEL_BACKUP_PATH = MODEL_PATH + ".bak"


class UpdateEngine:
    """
    Orchestrates scheduled AI model retraining and safe file replacement.
    Works with AIEngine to trigger retraining and persist results.
    """

    def __init__(
        self,
        ai_engine,  # AIEngine instance
        retrain_interval_sec: int = 600,
    ):
        self.ai_engine = ai_engine
        self.retrain_interval_sec = retrain_interval_sec
        self._running = False
        self._thread: Optional[threading.Thread] = None

        self.last_retrain: Optional[str] = None
        self.retrain_count: int = 0
        self.last_status: str = "idle"

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    def start(self) -> None:
        """Start the periodic update loop."""
        self._running = True
        self._thread = threading.Thread(
            target=self._update_loop, daemon=True, name="UpdateEngine"
        )
        self._thread.start()
        logger.info("UpdateEngine started.")

    def stop(self) -> None:
        self._running = False
        logger.info("UpdateEngine stopped.")

    # -------------------------------------------------------------------------
    # Update loop
    # -------------------------------------------------------------------------

    def _update_loop(self) -> None:
        """Periodically trigger retraining."""
        while self._running:
            time.sleep(self.retrain_interval_sec)
            if self._running:
                self.trigger_retrain()

    def trigger_retrain(self) -> bool:
        """
        Trigger an immediate model retrain cycle.
        1. Back up current model.
        2. Retrain via AIEngine._train().
        3. Validate new model.
        4. Replace old model, or restore backup on failure.
        """
        logger.info("UpdateEngine: starting retrain cycle…")
        self.last_status = "retraining"

        try:
            # Back up existing model
            if os.path.exists(MODEL_PATH):
                import shutil
                shutil.copy2(MODEL_PATH, MODEL_BACKUP_PATH)

            # Trigger training inside AIEngine
            self.ai_engine._train()

            # Validate the new model
            if self._validate_model():
                self.last_retrain = datetime.now().isoformat()
                self.retrain_count += 1
                self.last_status = "success"
                logger.info(f"UpdateEngine: retrain #{self.retrain_count} successful.")
                return True
            else:
                logger.warning("UpdateEngine: validation failed, restoring backup.")
                self._restore_backup()
                self.last_status = "restored"
                return False

        except Exception as e:
            logger.error(f"UpdateEngine retrain error: {e}")
            self._restore_backup()
            self.last_status = "error"
            return False

    # -------------------------------------------------------------------------
    # Validation & recovery
    # -------------------------------------------------------------------------

    def _validate_model(self) -> bool:
        """Run a quick sanity check on the saved model file."""
        try:
            import joblib
            import numpy as np
            model = joblib.load(MODEL_PATH)
            # Predict on a zero-vector to ensure the model is callable
            model.decision_function(np.zeros((1, 5)))
            return True
        except Exception as e:
            logger.error(f"Model validation failed: {e}")
            return False

    def _restore_backup(self) -> None:
        """Restore the backup model if the new model is invalid."""
        if os.path.exists(MODEL_BACKUP_PATH):
            import shutil
            shutil.copy2(MODEL_BACKUP_PATH, MODEL_PATH)
            logger.info("Model restored from backup.")
        else:
            # No backup → rebuild from scratch
            logger.warning("No backup found – rebuilding model from scratch.")
            self.ai_engine._rebuild_model()

    # -------------------------------------------------------------------------
    # Status
    # -------------------------------------------------------------------------

    def get_status(self) -> Dict[str, Any]:
        return {
            "last_retrain": self.last_retrain,
            "retrain_count": self.retrain_count,
            "last_status": self.last_status,
            "model_trained": self.ai_engine.is_trained,
            "sample_count": self.ai_engine.sample_count,
        }
