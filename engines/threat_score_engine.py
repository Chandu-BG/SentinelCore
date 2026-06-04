"""
SentinelCore - Threat Score Engine
Multi-signal weighted threat scoring system.

ThreatScore = Σ (w_i * signal_i)  — then normalized to 0–100.

Signals (all normalized 0.0–1.0):
  1. hash_match        – local malicious hash DB hit           w=1.0
  2. vt_score          – VirusTotal detection ratio            w=0.9
  3. ip_reputation     – AbuseIPDB confidence (0–100 → 0–1)   w=0.8
  4. entropy_score     – Shannon entropy normalized            w=0.6
  5. suspicious_ext    – file has suspicious extension         w=0.5
  6. hidden_flag       – file is hidden/system                 w=0.4
  7. location_risk     – file is in abnormal location          w=0.3
  8. behavior_score    – AI IsolationForest anomaly score      w=0.7

Severity mapping:
  0–25  → LOW
  26–50 → MEDIUM
  51–75 → HIGH
  76–100→ CRITICAL

Safety guard: auto-remediation only if ≥2 signals scored > 0.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

# ── Signal weights ─────────────────────────────────────────────────────────────
WEIGHTS: Dict[str, float] = {
    "hash_match":      1.0,
    "vt_score":        0.9,
    "ip_reputation":   0.8,
    "behavior_score":  0.7,
    "entropy_score":   0.6,
    "suspicious_ext":  0.5,
    "hidden_flag":     0.4,
    "location_risk":   0.3,
}

# Maximum possible weighted sum (all signals = 1.0)
_MAX_WEIGHTED_SUM = sum(WEIGHTS.values())   # = 5.2

SEVERITY_BANDS: List[Tuple[int, str]] = [
    (25,  "LOW"),
    (50,  "MEDIUM"),
    (75,  "HIGH"),
    (100, "CRITICAL"),
]


@dataclass
class ThreatSignals:
    """
    Container for all 8 detection signals.
    All values must be in [0.0, 1.0] range before passing to ThreatScoreEngine.
    """
    hash_match:     float = 0.0   # 1.0 if hash in malicious DB, else 0.0
    vt_score:       float = 0.0   # VT detections / total engines (0–1)
    ip_reputation:  float = 0.0   # AbuseIPDB confidence / 100
    entropy_score:  float = 0.0   # EntropyEngine.normalized (0–1)
    suspicious_ext: float = 0.0   # 1.0 if extension is suspicious, else 0.0
    hidden_flag:    float = 0.0   # 1.0 if file has hidden/system attribute
    location_risk:  float = 0.0   # 1.0 if file is in abnormal location
    behavior_score: float = 0.0   # AIEngine anomaly score (0–1)

    # Optional metadata — not used in scoring but logged
    file_name:  str = ""
    sha256:     str = ""
    entropy:    float = 0.0   # raw entropy value (for display)
    file_size:  int   = 0


@dataclass
class ThreatResult:
    score:              float           # 0–100 normalized threat score
    severity:           str             # LOW / MEDIUM / HIGH / CRITICAL
    signal_contributions: Dict[str, float] = field(default_factory=dict)
    active_signals:     int  = 0        # count of signals that fired (> 0)
    auto_remediate:     bool = False     # True only if active_signals >= 2
    dominant_signals:   List[str] = field(default_factory=list)  # top 3 by contribution
    raw_weighted_sum:   float = 0.0


def _clamp(v: float) -> float:
    return max(0.0, min(1.0, float(v)))


def _severity(score: float) -> str:
    for threshold, label in SEVERITY_BANDS:
        if score <= threshold:
            return label
    return "CRITICAL"


class ThreatScoreEngine:
    """
    Computes a 0–100 threat score from 8 normalized signals.
    Thread-safe (no shared state — pure computation).
    """

    def compute(self, signals: ThreatSignals) -> ThreatResult:
        """
        Apply weighted scoring formula and return a ThreatResult.

        Formula:
            raw = Σ (weight_i * clamp(signal_i))
            score = (raw / MAX_WEIGHTED_SUM) * 100
        """
        contributions: Dict[str, float] = {}
        raw_sum = 0.0
        active  = 0

        for signal_name, weight in WEIGHTS.items():
            raw_val   = _clamp(getattr(signals, signal_name, 0.0))
            weighted  = weight * raw_val
            contributions[signal_name] = round(weighted, 4)
            raw_sum  += weighted
            if raw_val > 0.0:
                active += 1

        score    = round((raw_sum / _MAX_WEIGHTED_SUM) * 100.0, 2)
        score    = max(0.0, min(100.0, score))
        severity = _severity(score)

        # Sort by contribution descending → get dominant signals
        dominant = [
            k for k, v in sorted(contributions.items(),
                                  key=lambda x: x[1], reverse=True)
            if v > 0
        ][:3]

        return ThreatResult(
            score               = score,
            severity            = severity,
            signal_contributions= contributions,
            active_signals      = active,
            auto_remediate      = active >= 2,
            dominant_signals    = dominant,
            raw_weighted_sum    = round(raw_sum, 4),
        )

    def signals_from_dict(self, d: dict) -> ThreatSignals:
        """Convenience: build ThreatSignals from a plain dict."""
        return ThreatSignals(
            hash_match     = _clamp(d.get("hash_match", 0.0)),
            vt_score       = _clamp(d.get("vt_score", 0.0)),
            ip_reputation  = _clamp(d.get("ip_reputation", 0.0)),
            entropy_score  = _clamp(d.get("entropy_score", 0.0)),
            suspicious_ext = _clamp(d.get("suspicious_ext", 0.0)),
            hidden_flag    = _clamp(d.get("hidden_flag", 0.0)),
            location_risk  = _clamp(d.get("location_risk", 0.0)),
            behavior_score = _clamp(d.get("behavior_score", 0.0)),
            file_name      = d.get("file_name", ""),
            sha256         = d.get("sha256", ""),
            entropy        = d.get("entropy", 0.0),
            file_size      = int(d.get("file_size", 0)),
        )
