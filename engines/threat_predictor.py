"""
SentinelCore - Threat Predictor Engine
Predicts attacks BEFORE they fully materialize using behavior trends.
Uses IsolationForest-based prediction on rolling metric windows.
Stores model at /models/prediction_model.pkl.
"""

import os
import time
import logging
import threading
import numpy as np
import joblib
from typing import Callable, Optional, List, Dict, Any, Deque
from collections import deque
from datetime import datetime

logger = logging.getLogger(__name__)

BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "prediction_model.pkl")
os.makedirs(os.path.join(BASE_DIR, "models"), exist_ok=True)

# Rolling window for behavioral trend calculation
WINDOW_SAMPLES  = 30   # samples in rolling window
MIN_SAMPLES     = 20   # minimum before prediction starts
RETRAIN_AFTER   = 200  # samples between retrains

# Thresholds
PREDICTION_THRESHOLD = 0.65    # score above this = emit warning
CRITICAL_THRESHOLD   = 0.85    # score above this = escalate


class ThreatPredictor:
    """
    Predicts impending threats by analyzing behavioral trends in metrics.
    Emits on_prediction(score, warning_message) when a threat is predicted.
    """

    def __init__(
        self,
        on_prediction: Optional[Callable[[float, str], None]] = None,
        on_alert:      Optional[Callable[[str, str], None]] = None,
    ):
        self.on_prediction = on_prediction
        self.on_alert      = on_alert

        self._running   = False
        self._thread: Optional[threading.Thread] = None
        self._lock      = threading.Lock()

        # Rolling metric history: list of feature vectors
        self._window: Deque[List[float]] = deque(maxlen=WINDOW_SAMPLES)
        self._all_training: List[List[float]] = []
        self._new_samples = 0

        self._model = None
        self._is_trained = False
        self._last_prediction: float = 0.0
        self._last_warn_time:  float = 0.0
        self._warn_cooldown:   float = 60.0   # seconds between repeated warnings

        self._load_model()

    # ──────────────────────────────────────────────────────────────────────────
    # Lifecycle
    # ──────────────────────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._predict_loop, daemon=True, name="ThreatPredictor"
        )
        self._thread.start()
        logger.info("ThreatPredictor started.")

    def stop(self) -> None:
        self._running = False
        logger.info("ThreatPredictor stopped.")

    # ──────────────────────────────────────────────────────────────────────────
    # Feature ingestion
    # ──────────────────────────────────────────────────────────────────────────

    def ingest(self, metrics: Dict[str, Any]) -> None:
        """
        Feed current system metrics for prediction.
        Call this from the metrics loop to keep the predictor updated.
        """
        features = self._extract_features(metrics)
        with self._lock:
            self._window.append(features)
            self._all_training.append(features)
            self._new_samples += 1

        # Trigger retrain if enough new data
        if self._new_samples >= RETRAIN_AFTER:
            threading.Thread(target=self._train, daemon=True).start()

    def _extract_features(self, metrics: Dict[str, Any]) -> List[float]:
        """Extract a feature vector for prediction."""
        cpu          = float(metrics.get("cpu_percent", 0.0))
        mem          = float(metrics.get("memory_percent", 0.0))
        proc_count   = float(metrics.get("process_count", 0))
        procs        = metrics.get("processes", [])
        net_bytes    = float(metrics.get("net_bytes_sent", 0))
        anomaly_score = float(metrics.get("anomaly_score", 0.0))

        cpu_vals = [p.get("cpu_percent", 0.0) for p in procs]
        max_cpu  = float(max(cpu_vals)) if cpu_vals else 0.0
        avg_cpu  = float(sum(cpu_vals) / len(cpu_vals)) if cpu_vals else 0.0

        return [cpu, mem, proc_count, max_cpu, avg_cpu, net_bytes / 1e6, anomaly_score]

    # ──────────────────────────────────────────────────────────────────────────
    # Prediction loop
    # ──────────────────────────────────────────────────────────────────────────

    def _predict_loop(self) -> None:
        while self._running:
            try:
                score = self._predict_from_window()
                if score is not None:
                    with self._lock:
                        self._last_prediction = score
                    self._maybe_emit_warning(score)
            except Exception as e:
                logger.debug(f"ThreatPredictor loop error: {e}")
            time.sleep(5)

    def _predict_from_window(self) -> Optional[float]:
        """Compute a prediction score from the current rolling window."""
        with self._lock:
            window_list = list(self._window)

        if len(window_list) < MIN_SAMPLES:
            return None

        # Trend features: compute derivative (rate of change) of key metrics
        features = self._build_trend_vector(window_list)

        if not self._is_trained:
            # Without model, use simple heuristic
            return self._heuristic_score(features)

        try:
            X   = np.array([features])
            raw = self._model.decision_function(X)[0]
            return float(np.clip(0.5 - raw, 0.0, 1.0))
        except Exception:
            return self._heuristic_score(features)

    def _build_trend_vector(self, window: List[List[float]]) -> List[float]:
        """
        Build a trend feature vector from a window of observations.
        Combines current mean, standard deviation, and rate of change.
        """
        arr = np.array(window)
        means     = arr.mean(axis=0).tolist()
        stds      = arr.std(axis=0).tolist()
        # Rate of change: last half vs first half
        half = max(1, len(window) // 2)
        first_mean = arr[:half].mean(axis=0)
        last_mean  = arr[half:].mean(axis=0)
        deltas     = (last_mean - first_mean).tolist()
        return means + stds + deltas

    def _heuristic_score(self, features: List[float]) -> float:
        """Simple heuristic when model not available."""
        cpu = features[0] if features else 0.0
        mem = features[1] if len(features) > 1 else 0.0
        # Score based on high CPU + memory trends
        score = (cpu / 100.0) * 0.5 + (mem / 100.0) * 0.3
        return min(score, 1.0)

    def _maybe_emit_warning(self, score: float) -> None:
        """Emit a prediction warning if score exceeds threshold."""
        now = time.time()
        if now - self._last_warn_time < self._warn_cooldown:
            return

        if score >= CRITICAL_THRESHOLD:
            msg = (
                f"⚠ CRITICAL THREAT PREDICTED (confidence={score:.0%})\n"
                "Behavior trend indicates imminent high-severity attack.\n"
                "Self-healing protection escalating."
            )
            self._last_warn_time = now
            logger.warning(f"ThreatPredictor CRITICAL: score={score:.2f}")
            if self.on_prediction:
                self.on_prediction(score, msg)
            if self.on_alert:
                self.on_alert("THREAT_PREDICTION_CRITICAL", msg)

        elif score >= PREDICTION_THRESHOLD:
            msg = self._build_warning_message(score)
            self._last_warn_time = now
            logger.warning(f"ThreatPredictor: score={score:.2f}")
            if self.on_prediction:
                self.on_prediction(score, msg)
            if self.on_alert:
                self.on_alert("THREAT_PREDICTION", msg)

    def _build_warning_message(self, score: float) -> str:
        """Generate a context-aware warning based on current metrics."""
        with self._lock:
            window = list(self._window)

        if not window:
            return f"Potential threat behavior developing (score={score:.0%})"

        arr = np.array(window)
        cpu_trend = float(arr[-5:, 0].mean() - arr[:5, 0].mean()) if len(arr) >= 10 else 0
        mem_trend = float(arr[-5:, 1].mean() - arr[:5, 1].mean()) if len(arr) >= 10 else 0

        if cpu_trend > 20:
            return (
                f"Potential ransomware behavior developing (confidence={score:.0%})\n"
                f"CPU usage rising sharply (+{cpu_trend:.0f}% trend). "
                "Increased monitoring activated."
            )
        elif mem_trend > 15:
            return (
                f"Potential memory-based attack developing (confidence={score:.0%})\n"
                f"Memory usage rising sharply (+{mem_trend:.0f}% trend). "
                "Injection detection heightened."
            )
        else:
            return (
                f"Abnormal system behavior trend detected (confidence={score:.0%})\n"
                "Monitoring sensitivity increased. Continue normal operations."
            )

    # ──────────────────────────────────────────────────────────────────────────
    # Model training
    # ──────────────────────────────────────────────────────────────────────────

    def _train(self) -> None:
        with self._lock:
            data = list(self._all_training[-5000:])
            self._new_samples = 0

        if len(data) < MIN_SAMPLES:
            return

        try:
            # Build trend vectors from all windows in training data
            X_trends = []
            step = max(1, len(data) // 100)
            for i in range(MIN_SAMPLES, len(data), step):
                window_slice = data[max(0, i - WINDOW_SAMPLES): i]
                if len(window_slice) >= MIN_SAMPLES:
                    tv = self._build_trend_vector(window_slice)
                    X_trends.append(tv)

            if len(X_trends) < 10:
                return

            from sklearn.ensemble import IsolationForest
            X = np.array(X_trends)
            model = IsolationForest(
                n_estimators=100, contamination=0.05, random_state=42, n_jobs=-1
            )
            model.fit(X)

            with self._lock:
                self._model      = model
                self._is_trained = True

            joblib.dump(model, MODEL_PATH)
            logger.info(f"ThreatPredictor model trained on {len(X_trends)} trend vectors.")
        except Exception as e:
            logger.error(f"ThreatPredictor training failed: {e}")

    def _load_model(self) -> None:
        if not os.path.exists(MODEL_PATH):
            return
        try:
            model = joblib.load(MODEL_PATH)
            with self._lock:
                self._model      = model
                self._is_trained = True
            logger.info("ThreatPredictor: loaded existing prediction model.")
        except Exception as e:
            logger.warning(f"ThreatPredictor: could not load model: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # Status
    # ──────────────────────────────────────────────────────────────────────────

    @property
    def last_prediction_score(self) -> float:
        return self._last_prediction

    @property
    def is_trained(self) -> bool:
        return self._is_trained

    @property
    def is_running(self) -> bool:
        return self._running
