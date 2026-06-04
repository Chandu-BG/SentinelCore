"""
NovaSentinel — Threat Manager
Centralized threat detection and scoring.
"""

import logging
import threading
from typing import List, Dict, Callable

logger = logging.getLogger(__name__)

class ThreatManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._active_threats: List[Dict] = []
        self._threat_score = 0.0
        self._callbacks: List[Callable[[Dict], None]] = []

    def add_threat(self, threat_type: str, severity: str, details: str, source: str) -> None:
        with self._lock:
            threat = {
                "type": threat_type,
                "severity": severity,
                "details": details,
                "source": source
            }
            self._active_threats.append(threat)
            self._update_score()
            for cb in self._callbacks:
                try:
                    cb(threat)
                except Exception as e:
                    logger.debug(f"Threat callback error: {e}")

    def on_threat(self, callback: Callable[[Dict], None]) -> None:
        if callback not in self._callbacks:
            self._callbacks.append(callback)

    def _update_score(self):
        # Basic scoring logic
        score = 0.0
        for t in self._active_threats:
            if t["severity"] == "CRITICAL": score += 30.0
            elif t["severity"] == "HIGH": score += 15.0
            elif t["severity"] == "MEDIUM": score += 5.0
            else: score += 1.0
        self._threat_score = min(score, 100.0)

    def get_score(self) -> float:
        return self._threat_score

    def get_active_threats(self) -> List[Dict]:
        with self._lock:
            return list(self._active_threats)

_instance = None
def get_threat_manager() -> ThreatManager:
    global _instance
    if _instance is None:
        _instance = ThreatManager()
    return _instance
