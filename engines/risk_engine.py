"""
SentinelCore - Risk Engine
Computes an overall platform risk score (0–100) by combining:
  - CPU load
  - Memory load
  - AI anomaly score
  - Active threat count
  - Average trust score of running processes
Dynamically adjusts the platform's protection level:
  low (0–33) / medium (34–66) / high (67–100)
"""

import logging
import json
import os
from typing import Dict, Any, Optional, Callable

logger = logging.getLogger(__name__)

CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "config", "version.json"
)


def _load_weights() -> Dict[str, float]:
    """Load risk weight configuration from version.json."""
    default = {
        "cpu": 0.20,
        "memory": 0.15,
        "anomaly": 0.35,
        "threat_count": 0.20,
        "trust": 0.10,
    }
    try:
        with open(CONFIG_PATH, "r") as f:
            cfg = json.load(f)
        return cfg.get("risk_weights", default)
    except Exception:
        return default


class RiskEngine:
    """
    Calculates a live risk score and determines the appropriate
    protection level for the platform.
    """

    PROTECTION_LEVELS = {
        "low":    {"max_score": 33,  "monitor_interval": 5.0},
        "medium": {"max_score": 66,  "monitor_interval": 2.0},
        "high":   {"max_score": 100, "monitor_interval": 0.5},
    }

    def __init__(
        self,
        on_level_change: Optional[Callable[[str, str], None]] = None,
    ):
        self.weights = _load_weights()
        self._current_score: float = 0.0
        self._current_level: str = "low"
        self.on_level_change = on_level_change  # callback(old_level, new_level)

    # -------------------------------------------------------------------------
    # Score calculation
    # -------------------------------------------------------------------------

    def compute(
        self,
        cpu_percent: float,
        memory_percent: float,
        anomaly_score: float,
        threat_count: int,
        avg_trust_score: float,
    ) -> float:
        """
        Recompute risk score from current metrics.
        Returns a value in [0.0, 100.0].

        Parameters
        ----------
        cpu_percent    : 0–100
        memory_percent : 0–100
        anomaly_score  : 0–1 (from AIEngine)
        threat_count   : integer number of logged threats
        avg_trust_score: 0–100 (average trust of running processes)
        """
        w = self.weights

        # Normalise inputs to [0, 1]
        cpu_norm  = min(cpu_percent / 100.0, 1.0)
        mem_norm  = min(memory_percent / 100.0, 1.0)
        anm_norm  = min(anomaly_score, 1.0)
        thr_norm  = min(threat_count / 50.0, 1.0)   # cap at 50 threats = 1.0
        trust_inv = 1.0 - min(avg_trust_score / 100.0, 1.0)  # low trust → high risk

        score = (
            cpu_norm  * w.get("cpu",          0.20) +
            mem_norm  * w.get("memory",        0.15) +
            anm_norm  * w.get("anomaly",       0.35) +
            thr_norm  * w.get("threat_count",  0.20) +
            trust_inv * w.get("trust",         0.10)
        ) * 100.0

        self._current_score = round(min(score, 100.0), 1)
        new_level = self._classify_level(self._current_score)

        if new_level != self._current_level:
            old = self._current_level
            self._current_level = new_level
            logger.info(f"Protection level changed: {old} → {new_level} "
                        f"(risk score={self._current_score})")
            if self.on_level_change:
                self.on_level_change(old, new_level)

        return self._current_score

    @staticmethod
    def _classify_level(score: float) -> str:
        if score <= 33:
            return "low"
        elif score <= 66:
            return "medium"
        else:
            return "high"

    # -------------------------------------------------------------------------
    # Properties
    # -------------------------------------------------------------------------

    @property
    def score(self) -> float:
        """Current risk score (0–100)."""
        return self._current_score

    @property
    def level(self) -> str:
        """Current protection level: 'low', 'medium', or 'high'."""
        return self._current_level

    @property
    def monitor_interval(self) -> float:
        """Recommended monitoring interval (seconds) for the current level."""
        return self.PROTECTION_LEVELS[self._current_level]["monitor_interval"]

    def get_summary(self) -> Dict[str, Any]:
        return {
            "score": self._current_score,
            "level": self._current_level,
            "monitor_interval": self.monitor_interval,
        }
