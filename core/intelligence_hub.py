"""
NovaSentinel — Intelligence Hub
Coordinates all AI detection engines and deduplicates alerts.

Routes:
  - URL analysis → PhishingIntelEngine
  - File/PE analysis → MalwareIntelEngine
  - Network flows → NetworkIntelEngine
  - Behavioral reports → SandboxBehaviorEngine

Alert deduplication: hash(type + message[:60]) with 120s TTL suppression.
"""

import hashlib
import threading
import time
import logging
from typing import Optional, Callable, Dict, List, Tuple

logger = logging.getLogger(__name__)

_DEDUP_TTL = 120  # seconds before the same alert can fire again


class _AlertDeduplicator:
    """Suppresses identical alerts within the TTL window."""

    def __init__(self, ttl: float = _DEDUP_TTL):
        self._ttl = ttl
        self._seen: Dict[str, float] = {}
        self._lock = threading.Lock()

    def should_fire(self, alert_type: str, message: str) -> bool:
        key = hashlib.md5(f"{alert_type}:{message[:60]}".encode()).hexdigest()
        now = time.time()
        with self._lock:
            last = self._seen.get(key, 0)
            if now - last < self._ttl:
                return False
            self._seen[key] = now
            # Prune old entries
            self._seen = {k: v for k, v in self._seen.items() if now - v < self._ttl * 2}
            return True


class IntelligenceHub:
    """
    Central routing and deduplication hub for all NovaSentinel detection engines.
    All engines post alerts here; the hub suppresses duplicates and routes to GUI.
    """

    def __init__(
        self,
        on_alert: Optional[Callable[[str, str, str], None]] = None,  # (type, severity, message)
    ):
        self._on_alert = on_alert
        self._dedup = _AlertDeduplicator()

        # Engine references — set after engines are created
        self.phishing_engine = None
        self.malware_engine = None
        self.network_engine = None
        self.sandbox_engine = None

        self._stats: Dict[str, int] = {
            "phishing": 0, "malware": 0, "network": 0, "sandbox": 0, "suppressed": 0
        }
        self._lock = threading.Lock()

    def bind_engines(self, **engines) -> None:
        for k, v in engines.items():
            setattr(self, k, v)

    # ── Analysis routing ────────────────────────────────────────────────────────

    def analyze_url(self, url: str) -> Optional[dict]:
        """Route URL to PhishingIntelEngine only. Returns a result dict."""
        if self.phishing_engine is None:
            return None
        try:
            result = self.phishing_engine.analyze(url)
            if not result:
                return None
            cls = result.get("classification") or ""
            # PhishingIntelEngine uses SAFE / MONITOR / SUSPICIOUS / MALICIOUS (not PHISHING)
            if cls in ("MALICIOUS", "SUSPICIOUS"):
                sev = "high" if cls == "MALICIOUS" else "medium"
                conf = result.get("confidence", 0) or 0
                self._fire(
                    "PHISHING",
                    sev,
                    f"URL flagged as {cls}: {url[:60]} (confidence {float(conf):.0%})",
                )
                with self._lock:
                    self._stats["phishing"] += 1
            return result
        except Exception as e:
            logger.debug(f"IntelligenceHub.analyze_url error: {e}")
            return None

    def analyze_file(self, path: str) -> Optional[dict]:
        """Route file to malware engine. Returns result dict."""
        if self.malware_engine is None:
            return None
        try:
            result = self.malware_engine.analyze(path)
            if result and result.get("classification") in ("SUSPICIOUS", "MALICIOUS"):
                self._fire(
                    "MALWARE_DETECT",
                    "critical" if result["classification"] == "MALICIOUS" else "high",
                    f"File flagged as {result['classification']}: {path[-50:]} "
                    f"(confidence {result.get('confidence', 0):.0%})",
                )
                with self._lock:
                    self._stats["malware"] += 1
            return result
        except Exception as e:
            logger.debug(f"IntelligenceHub.analyze_file error: {e}")
            return None

    def analyze_connection(self, conn_info: dict) -> Optional[dict]:
        """Route network connection to intrusion engine. Returns result dict."""
        if self.network_engine is None:
            return None
        try:
            result = self.network_engine.analyze(conn_info)
            if result and result.get("threat_detected"):
                self._fire(
                    "NETWORK_THREAT",
                    "high",
                    f"Suspicious network activity: {result.get('description', '')} "
                    f"[{conn_info.get('raddr', '?')}]",
                )
                with self._lock:
                    self._stats["network"] += 1
            return result
        except Exception as e:
            logger.debug(f"IntelligenceHub.analyze_connection error: {e}")
            return None

    def analyze_behavior(self, behavior_report: dict) -> Optional[dict]:
        """Route sandbox behavior report. Returns result dict."""
        if self.sandbox_engine is None:
            return None
        try:
            result = self.sandbox_engine.analyze_behavior(behavior_report)
            if result and result.get("confidence", 0) > 0.55:
                self._fire(
                    "SANDBOX_BEHAVIOR",
                    "high" if result.get("confidence", 0) > 0.75 else "medium",
                    f"Suspicious behavior detected: {', '.join(result.get('behaviors', [])[:3])}",
                )
                with self._lock:
                    self._stats["sandbox"] += 1
            return result
        except Exception as e:
            logger.debug(f"IntelligenceHub.analyze_behavior error: {e}")
            return None

    # ── Alert routing ──────────────────────────────────────────────────────────

    def fire_alert(self, alert_type: str, severity: str, message: str) -> None:
        """External engines can post alerts here for deduplication."""
        self._fire(alert_type, severity, message)

    def _fire(self, alert_type: str, severity: str, message: str) -> None:
        if not isinstance(message, str):
            message = str(message)
        if not self._dedup.should_fire(alert_type, message):
            with self._lock:
                self._stats["suppressed"] += 1
            return
        logger.info(f"[IntelHub] [{severity.upper()}] {alert_type}: {message}")
        if self._on_alert:
            try:
                self._on_alert(alert_type, severity, message)
            except Exception as e:
                logger.debug(f"IntelligenceHub alert callback error: {e}")

    # ── Stats ──────────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)
