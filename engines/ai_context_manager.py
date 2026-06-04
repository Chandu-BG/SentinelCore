"""
SentinelCore - AI Context Manager
Collects live snapshots from all engines and manages conversation history in SQLite.
"""

import logging
import threading
from datetime import datetime
from typing import Dict, Any, List, Optional
import uuid

logger = logging.getLogger(__name__)

# ── SQLite helpers (uses existing DB connection) ───────────────────────────────
try:
    from database.init_db import get_connection
    _DB_AVAILABLE = True
except ImportError:
    _DB_AVAILABLE = False


def _ensure_ai_tables() -> None:
    """Create AI-specific tables if they don't exist."""
    if not _DB_AVAILABLE:
        return
    try:
        with get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ai_conversations (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id   TEXT NOT NULL,
                    timestamp    TEXT NOT NULL,
                    role         TEXT NOT NULL,
                    content      TEXT NOT NULL,
                    context_type TEXT DEFAULT 'chat'
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ai_scan_summaries (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp     TEXT NOT NULL,
                    scan_path     TEXT,
                    threat_count  INTEGER DEFAULT 0,
                    summary_text  TEXT NOT NULL
                )
            """)
            conn.commit()
    except Exception as e:
        logger.warning(f"AIContextManager: Could not create tables: {e}")


class AIContextManager:
    """
    Collects live data from all SentinelCore engines and provides
    context snapshots for NovaSentinel AI reasoning. Also manages
    conversation history persistence.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._session_id = str(uuid.uuid4())[:8]
        self._history: List[Dict] = []
        self._max_history = 20

        # Engine references — set by main.py
        self.telemetry = None
        self.ai_engine = None
        self.risk_engine = None
        self.trust_engine = None
        self.phishing_detector = None
        self.network_detector = None

        # Last known confirmed threat count
        self._confirmed_threats = 0
        self._last_scan_results: List[Dict] = []
        self._last_scan_path = ""

        _ensure_ai_tables()
        logger.info(f"AIContextManager initialized (session={self._session_id})")

    # ── Engine binding ─────────────────────────────────────────────────────────

    def bind_engines(self, **kwargs) -> None:
        """Bind engine references after all engines are instantiated."""
        for k, v in kwargs.items():
            if hasattr(self, k):
                setattr(self, k, v)

    # ── Live snapshot ─────────────────────────────────────────────────────────

    def get_snapshot(self) -> Dict[str, Any]:
        """Return a dict of current live system state from TelemetryManager."""
        snap: Dict[str, Any] = {
            "timestamp": datetime.now().isoformat(),
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "process_count": 0,
            "top_processes": [],
            "anomaly_score": 0.0,
            "risk_score": 0.0,
            "trust_score": 50.0,
            "confirmed_threats": self._confirmed_threats,
            "last_scan_results": self._last_scan_results[:5],
            "last_scan_path": self._last_scan_path,
            "recent_alerts": [],
        }

        try:
            if self.telemetry:
                tsnap = self.telemetry.get_snapshot()
                snap["cpu_percent"] = tsnap.cpu_percent
                snap["memory_percent"] = tsnap.ram_percent
                snap["process_count"] = tsnap.process_count
                snap["confirmed_threats"] = tsnap.threat_count
                snap["recent_alerts"] = tsnap.recent_alerts
                
                # Top 8 processes by CPU
                snap["top_processes"] = sorted(
                    tsnap.processes,
                    key=lambda p: p.get("cpu_percent", 0),
                    reverse=True
                )[:8]

                if self.ai_engine:
                    snap["anomaly_score"] = float(
                        self.ai_engine.score({"cpu_percent": tsnap.cpu_percent, "memory_percent": tsnap.ram_percent})
                    )
        except Exception as e:
            logger.debug(f"AIContextManager snapshot error: {e}")

        return snap

    def update_confirmed_threats(self, count: int) -> None:
        with self._lock:
            self._confirmed_threats = count

    def update_scan_results(self, results: List[Dict], path: str = "") -> None:
        with self._lock:
            self._last_scan_results = results
            self._last_scan_path = path

    # ── Conversation history ───────────────────────────────────────────────────

    def get_history(self) -> List[Dict]:
        with self._lock:
            return list(self._history)

    def add_to_history(self, role: str, content: str, context_type: str = "chat") -> None:
        with self._lock:
            entry = {
                "role": role,
                "content": content,
                "timestamp": datetime.now().isoformat(),
                "context_type": context_type,
            }
            self._history.append(entry)
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history:]

        self._persist_message(role, content, context_type)

    def clear_history(self) -> None:
        with self._lock:
            self._history.clear()
            self._session_id = str(uuid.uuid4())[:8]

    def save_scan_summary(self, summary: str, threat_count: int, scan_path: str = "") -> None:
        if not _DB_AVAILABLE:
            return
        try:
            with get_connection() as conn:
                conn.execute(
                    "INSERT INTO ai_scan_summaries (timestamp, scan_path, threat_count, summary_text) "
                    "VALUES (?, ?, ?, ?)",
                    (datetime.now().isoformat(), scan_path, threat_count, summary)
                )
                conn.commit()
        except Exception as e:
            logger.debug(f"Could not save scan summary: {e}")

    def get_recent_summaries(self, limit: int = 5) -> List[Dict]:
        if not _DB_AVAILABLE:
            return []
        try:
            with get_connection() as conn:
                rows = conn.execute(
                    "SELECT * FROM ai_scan_summaries ORDER BY id DESC LIMIT ?",
                    (limit,)
                ).fetchall()
                return [dict(r) for r in rows]
        except Exception:
            return []

    # ── Private ────────────────────────────────────────────────────────────────

    def _persist_message(self, role: str, content: str, context_type: str) -> None:
        if not _DB_AVAILABLE:
            return
        try:
            with get_connection() as conn:
                conn.execute(
                    "INSERT INTO ai_conversations (session_id, timestamp, role, content, context_type) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (self._session_id, datetime.now().isoformat(), role, content[:2000], context_type)
                )
                conn.commit()
        except Exception as e:
            logger.debug(f"Could not persist AI message: {e}")
