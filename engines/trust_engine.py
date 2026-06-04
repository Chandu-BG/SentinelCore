"""
SentinelCore - Adaptive Trust Engine
Manages per-application trust scores (0–100).
Trust score is based on:
  - Hash history (consistent hash → trusted)
  - AI anomaly count associated with the process
  - Number of clean runs vs anomaly runs
Scores are persisted in SQLite.
"""

import logging
import threading
from datetime import datetime
from typing import Dict, Optional, List

from database.init_db import get_connection, log_system_event

logger = logging.getLogger(__name__)

# Config
DEFAULT_TRUST = 50
DECAY_PER_ANOMALY = 10
GAIN_PER_CLEAN = 2
MAX_TRUST = 100
MIN_TRUST = 0


class TrustEngine:
    """
    Assigns and maintains a trust score for each application/process.
    Scores persist across sessions via SQLite.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._cache: Dict[str, float] = {}  # process_name → trust_score
        self._load_from_db()

    # -------------------------------------------------------------------------
    # Scoring
    # -------------------------------------------------------------------------

    def get_trust(self, process_name: str) -> float:
        """Return the current trust score for a process (creates if new)."""
        with self._lock:
            if process_name not in self._cache:
                self._cache[process_name] = DEFAULT_TRUST
                self._upsert_db(process_name, DEFAULT_TRUST, first_seen=True)
            return self._cache[process_name]

    def report_clean_run(self, process_name: str) -> float:
        """Call when a process completes a cycle without anomalies → gain trust."""
        with self._lock:
            score = self._cache.get(process_name, DEFAULT_TRUST)
            new_score = min(score + GAIN_PER_CLEAN, MAX_TRUST)
            self._cache[process_name] = new_score
        self._upsert_db(process_name, new_score, increment_clean=True)
        return new_score

    def report_anomaly(self, process_name: str) -> float:
        """Call when a process triggers an anomaly → reduce trust."""
        with self._lock:
            score = self._cache.get(process_name, DEFAULT_TRUST)
            new_score = max(score - DECAY_PER_ANOMALY, MIN_TRUST)
            self._cache[process_name] = new_score
        self._upsert_db(process_name, new_score, increment_anomaly=True)
        logger.warning(f"Trust decayed: {process_name} → {new_score}")

        if new_score <= 20:
            log_system_event(
                "LOW_TRUST",
                f"Process '{process_name}' trust score critically low: {new_score}",
                "warning",
            )
        return new_score

    def average_trust(self, process_names: Optional[List[str]] = None) -> float:
        """Return the average trust score across all known (or specified) processes."""
        with self._lock:
            if process_names:
                scores = [self._cache.get(n, DEFAULT_TRUST) for n in process_names]
            else:
                scores = list(self._cache.values())
        if not scores:
            return DEFAULT_TRUST
        return round(sum(scores) / len(scores), 1)

    def get_all(self) -> Dict[str, float]:
        """Return a snapshot of all trust scores."""
        with self._lock:
            return dict(self._cache)

    def reset_trust(self, process_name: str) -> None:
        """Reset a process to the default trust score."""
        with self._lock:
            self._cache[process_name] = DEFAULT_TRUST
        self._upsert_db(process_name, DEFAULT_TRUST)

    # -------------------------------------------------------------------------
    # DB operations
    # -------------------------------------------------------------------------

    def _load_from_db(self) -> None:
        """Pre-populate in-memory cache from the database."""
        try:
            with get_connection() as conn:
                rows = conn.execute(
                    "SELECT process_name, trust_score FROM process_trust"
                ).fetchall()
                for row in rows:
                    self._cache[row["process_name"]] = row["trust_score"]
        except Exception as e:
            logger.error(f"TrustEngine: failed to load from DB: {e}")

    def _upsert_db(
        self,
        process_name: str,
        trust_score: float,
        first_seen: bool = False,
        increment_anomaly: bool = False,
        increment_clean: bool = False,
    ) -> None:
        """Insert or update the trust record in the process_trust table."""
        try:
            with get_connection() as conn:
                now = datetime.now().isoformat()
                existing = conn.execute(
                    "SELECT id FROM process_trust WHERE process_name=?",
                    (process_name,),
                ).fetchone()

                if existing:
                    anomaly_delta = 1 if increment_anomaly else 0
                    clean_delta   = 1 if increment_clean   else 0
                    conn.execute(
                        """UPDATE process_trust SET
                           trust_score=?, last_seen=?,
                           anomaly_count = anomaly_count + ?,
                           clean_runs    = clean_runs    + ?
                           WHERE process_name=?""",
                        (trust_score, now, anomaly_delta, clean_delta, process_name),
                    )
                else:
                    conn.execute(
                        """INSERT INTO process_trust
                           (process_name, trust_score, first_seen, last_seen)
                           VALUES (?, ?, ?, ?)""",
                        (process_name, trust_score, now, now),
                    )
                conn.commit()
        except Exception as e:
            logger.error(f"TrustEngine DB error for '{process_name}': {e}")
