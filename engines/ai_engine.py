"""
SentinelCore - AI Engine
Implements a self-learning anomaly detection system using IsolationForest.
Features:
  - Trains on CPU / memory / process metrics
  - Detects anomalies (zero-day behaviour)
  - Retrains automatically (self-updating)
  - Rebuilds if the model file is corrupted
  - Persists model to disk via joblib
"""

import os
import time
import logging
import threading
import numpy as np
import joblib
from datetime import datetime
from typing import List, Optional, Dict, Any
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

# Model storage path
MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "models", "ai_model.pkl"
)
TRAINING_DATA_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "models", "training_data.npy"
)

# Ensure models directory exists
os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)


class AIEngine:
    """
    Self-learning IsolationForest-based anomaly detector.
    Continuously collects feature vectors from system metrics,
    retrains on clean baseline data, and scores new observations.
    """

    # Minimum number of samples before running inference
    MIN_SAMPLES = 30
    # Retrain after this many new observations
    RETRAIN_AFTER = 100

    def __init__(
        self,
        on_anomaly: Optional[callable] = None,
        contamination: float = 0.01,
        retrain_interval_sec: int = 300,

    ):
        self.contamination = contamination
        self.retrain_interval_sec = retrain_interval_sec
        self.on_anomaly = on_anomaly  # callback(score: float, description: str)

        self._model: Optional[IsolationForest] = None
        self._lock = threading.Lock()
        self._training_data: List[List[float]] = []
        self._new_samples_since_retrain: int = 0
        self._is_trained: bool = False
        self._anomaly_count: int = 0
        self._running: bool = False
        self._retrain_thread: Optional[threading.Thread] = None

        # Attempt to load an existing model
        self._load_model()

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    def start(self) -> None:
        """Start periodic retraining thread."""
        self._running = True
        self._retrain_thread = threading.Thread(
            target=self._retrain_loop, daemon=True, name="AIRetrainLoop"
        )
        self._retrain_thread.start()
        logger.info("AIEngine started.")

    def stop(self) -> None:
        self._running = False
        logger.info("AIEngine stopped.")

    # -------------------------------------------------------------------------
    # Feature extraction
    # -------------------------------------------------------------------------

    def _extract_features(self, metrics: Dict[str, Any]) -> List[float]:
        """
        Convert raw system metrics into a numeric feature vector.
        Features: [cpu%, memory%, process_count, avg_proc_cpu, max_proc_cpu]
        """
        cpu = metrics.get("cpu_percent", 0.0)
        mem = metrics.get("memory_percent", 0.0)
        procs = metrics.get("processes", [])
        proc_count = len(procs)
        cpu_vals = [p.get("cpu_percent", 0.0) for p in procs]
        avg_proc_cpu = float(np.mean(cpu_vals)) if cpu_vals else 0.0
        max_proc_cpu = float(np.max(cpu_vals)) if cpu_vals else 0.0
        return [cpu, mem, proc_count, avg_proc_cpu, max_proc_cpu]

    # -------------------------------------------------------------------------
    # Scoring / prediction
    # -------------------------------------------------------------------------

    def score(self, metrics: Dict[str, Any]) -> float:
        """
        Return an anomaly score in [0.0, 1.0].
        0.0 = perfectly normal, 1.0 = highly anomalous.
        Also fires on_anomaly callback when anomalous.
        """
        features = self._extract_features(metrics)

        # Add sample to training buffer
        with self._lock:
            self._training_data.append(features)
            self._new_samples_since_retrain += 1

        # Not enough data yet
        if not self._is_trained or len(self._training_data) < self.MIN_SAMPLES:
            return 0.0

        # Trigger incremental retrain if enough new samples
        if self._new_samples_since_retrain >= self.RETRAIN_AFTER:
            threading.Thread(target=self._train, daemon=True).start()

        try:
            with self._lock:
                X = np.array([features])
                raw_score = self._model.decision_function(X)[0]
                prediction = self._model.predict(X)[0]  # -1 = anomaly

            # Normalise to [0, 1]: lower decision_function → more anomalous
            # Typical range is roughly -0.5 to 0.5
            normalised = float(np.clip(0.5 - raw_score, 0.0, 1.0))

            if prediction == -1 and normalised > 0.7:
                self._anomaly_count += 1
                if self.on_anomaly:
                    self.on_anomaly(
                        normalised,
                        f"Unusual system activity detected (score={normalised:.2f})",
                    )


            return normalised
        except Exception as e:
            logger.error(f"AIEngine scoring error: {e}")
            return 0.0

    # -------------------------------------------------------------------------
    # Training
    # -------------------------------------------------------------------------

    def _train(self) -> None:
        """Fit the IsolationForest on accumulated training data."""
        with self._lock:
            if len(self._training_data) < self.MIN_SAMPLES:
                return
            X = np.array(self._training_data[-5000:])  # keep last 5000 samples

        try:
            logger.info(f"Training IsolationForest on {len(X)} samples …")
            model = IsolationForest(
                n_estimators=100,
                contamination=self.contamination,
                random_state=42,
                n_jobs=-1,
            )
            model.fit(X)
            with self._lock:
                self._model = model
                self._is_trained = True
                self._new_samples_since_retrain = 0

            self._save_model()
            logger.info("IsolationForest retrained and saved.")
        except Exception as e:
            logger.error(f"Training failed: {e}")

    def _retrain_loop(self) -> None:
        """Background thread: retrain every retrain_interval_sec seconds."""
        while self._running:
            time.sleep(self.retrain_interval_sec)
            if self._running:
                self._train()

    # -------------------------------------------------------------------------
    # Model persistence
    # -------------------------------------------------------------------------

    def _save_model(self) -> None:
        """Persist the trained model to disk."""
        try:
            joblib.dump(self._model, MODEL_PATH)
            np.save(TRAINING_DATA_PATH, np.array(self._training_data[-5000:]))
        except Exception as e:
            logger.error(f"Failed to save model: {e}")

    def _load_model(self) -> None:
        """Load persisted model from disk, or fall back to a new blank model."""
        if os.path.exists(MODEL_PATH):
            try:
                model = joblib.load(MODEL_PATH)
                # Quick sanity check
                model.decision_function(np.zeros((1, 5)))
                with self._lock:
                    self._model = model
                    self._is_trained = True
                logger.info("Loaded existing AI model from disk.")
            except Exception as e:
                logger.warning(f"Corrupted model detected, rebuilding: {e}")
                self._rebuild_model()
        else:
            self._init_blank_model()

        # Load training data if available
        if os.path.exists(TRAINING_DATA_PATH):
            try:
                data = np.load(TRAINING_DATA_PATH, allow_pickle=False)
                self._training_data = data.tolist()
            except Exception:
                self._training_data = []

    def _init_blank_model(self) -> None:
        """Create a fresh untrained IsolationForest."""
        with self._lock:
            self._model = IsolationForest(
                n_estimators=100, contamination=self.contamination, random_state=42
            )
            self._is_trained = False
        logger.info("Initialised blank AI model (not yet trained).")

    def _rebuild_model(self) -> None:
        """Remove corrupt model files and reinitialise."""
        for path in [MODEL_PATH, TRAINING_DATA_PATH]:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
        self._training_data = []
        self._init_blank_model()
        logger.info("AI model rebuilt from scratch.")

    # -------------------------------------------------------------------------
    # Properties
    # -------------------------------------------------------------------------

    @property
    def anomaly_count(self) -> int:
        return self._anomaly_count

    @property
    def is_trained(self) -> bool:
        return self._is_trained

    @property
    def sample_count(self) -> int:
        return len(self._training_data)
