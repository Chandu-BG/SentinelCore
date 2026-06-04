"""
SentinelCore - Database Initialization Module
Initializes and manages the SQLite database for all platform data.

v4.1 — Production hardened:
  - WAL journal mode to eliminate 'database is locked' errors
  - PyInstaller-aware DB path resolution
  - Connection pooling with timeout
  - Pragma optimizations for concurrent access
"""

import sqlite3
import os
import sys
import logging
import threading
from datetime import datetime

logger = logging.getLogger(__name__)

# ── PyInstaller-aware DB path ─────────────────────────────────────────────────
def _get_app_root() -> str:
    """Return the application root directory, works both frozen and unfrozen."""
    if getattr(sys, "frozen", False):
        # Running as a PyInstaller bundle — use the directory of the executable
        return os.path.dirname(sys.executable)
    # Running as normal Python script
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

APP_ROOT = _get_app_root()
DB_PATH = os.path.join(APP_ROOT, "sentinelcore.db")

# ── Thread-local connection pool ──────────────────────────────────────────────
_local = threading.local()
_db_lock = threading.Lock()


def get_connection() -> sqlite3.Connection:
    """
    Return a thread-local connection to the SentinelCore database.
    Each thread gets its own connection (thread-safe by design).
    WAL mode allows concurrent reads + one writer without locking.
    """
    if not hasattr(_local, "conn") or _local.conn is None:
        try:
            conn = sqlite3.connect(DB_PATH, timeout=10.0, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            # WAL mode: eliminates 'database is locked' for concurrent writers
            conn.execute("PRAGMA journal_mode=WAL")
            # Balanced durability vs performance
            conn.execute("PRAGMA synchronous=NORMAL")
            # 64MB page cache for faster queries
            conn.execute("PRAGMA cache_size=-65536")
            conn.execute("PRAGMA temp_store=MEMORY")
            _local.conn = conn
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            raise
    return _local.conn


def close_connection() -> None:
    """Close the thread-local connection if open."""
    if hasattr(_local, "conn") and _local.conn is not None:
        try:
            _local.conn.close()
        except Exception:
            pass
        _local.conn = None


def init_db() -> None:
    """
    Create all required tables if they do not exist.
    Called on application startup and also when the DB is recreated.
    """
    logger.info(f"Initializing database at: {DB_PATH}")

    with get_connection() as conn:
        cursor = conn.cursor()

        # --- Threat Log Table ---
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                threat_type TEXT    NOT NULL,
                description TEXT,
                severity    TEXT    DEFAULT 'medium',
                process_name TEXT,
                pid         INTEGER,
                action_taken TEXT,
                resolved    INTEGER DEFAULT 0
            )
        """)

        # --- Process Trust Table ---
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS process_trust (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                process_name TEXT    NOT NULL UNIQUE,
                exe_hash     TEXT,
                trust_score  REAL    DEFAULT 50,
                first_seen   TEXT,
                last_seen    TEXT,
                anomaly_count INTEGER DEFAULT 0,
                clean_runs   INTEGER DEFAULT 0
            )
        """)

        # --- IP Block Table ---
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address  TEXT    NOT NULL UNIQUE,
                reason      TEXT,
                blocked_at  TEXT    NOT NULL,
                active      INTEGER DEFAULT 1
            )
        """)

        # --- Risk Score History ---
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS risk_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                risk_score  REAL    NOT NULL,
                protection_level TEXT NOT NULL
            )
        """)

        # --- File Event Log ---
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                event_type  TEXT    NOT NULL,
                file_path   TEXT,
                severity    TEXT    DEFAULT 'info',
                alerted     INTEGER DEFAULT 0
            )
        """)

        # --- System Events ---
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                event_type  TEXT    NOT NULL,
                description TEXT,
                severity    TEXT    DEFAULT 'info'
            )
        """)

        # --- Sandbox Results ---
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sandbox_results (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp        TEXT    NOT NULL,
                file_name        TEXT    NOT NULL,
                classification   TEXT    NOT NULL,
                behavior_report  TEXT
            )
        """)

        # --- User Behavior Log (for learning) ---
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_behavior (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                action      TEXT    NOT NULL,
                threat_type TEXT,
                detail      TEXT
            )
        """)

        # --- NovaSentinel AI Conversation History ---
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_conversations (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id   TEXT NOT NULL,
                timestamp    TEXT NOT NULL,
                role         TEXT NOT NULL,
                content      TEXT NOT NULL,
                context_type TEXT DEFAULT 'chat'
            )
        """)

        # --- NovaSentinel AI Scan Summaries ---
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_scan_summaries (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp     TEXT NOT NULL,
                scan_path     TEXT,
                threat_count  INTEGER DEFAULT 0,
                summary_text  TEXT NOT NULL
            )
        """)

        conn.commit()
    logger.info("Database initialized successfully.")


def log_threat(
    threat_type: str,
    description: str,
    severity: str = "medium",
    process_name: str = None,
    pid: int = None,
    action_taken: str = None,
) -> None:
    """Insert a threat event into the threat_log table."""
    try:
        with get_connection() as conn:
            conn.execute(
                """INSERT INTO threat_log
                   (timestamp, threat_type, description, severity, process_name, pid, action_taken)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    datetime.now().isoformat(),
                    threat_type,
                    description,
                    severity,
                    process_name,
                    pid,
                    action_taken,
                ),
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to log threat: {e}")


def log_system_event(event_type: str, description: str, severity: str = "info") -> None:
    """Insert a general system event."""
    try:
        with get_connection() as conn:
            conn.execute(
                """INSERT INTO system_events (timestamp, event_type, description, severity)
                   VALUES (?, ?, ?, ?)""",
                (datetime.now().isoformat(), event_type, description, severity),
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to log system event: {e}")


def get_threat_count() -> int:
    """Return the total number of threats logged."""
    try:
        with get_connection() as conn:
            row = conn.execute("SELECT COUNT(*) FROM threat_log").fetchone()
            return row[0] if row else 0
    except Exception:
        return 0


def get_threat_count_since(start_timestamp: str) -> int:
    """
    Return the number of threats logged SINCE the given ISO timestamp.
    Used to show session-only threat count (resets to 0 on each launch).
    """
    try:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM threat_log WHERE timestamp >= ?",
                (start_timestamp,)
            ).fetchone()
            return row[0] if row else 0
    except Exception:
        return 0


def log_sandbox_result(
    file_name: str,
    classification: str,
    behavior_report: str,
) -> None:
    """Insert a sandbox analysis result."""
    try:
        with get_connection() as conn:
            conn.execute(
                """INSERT INTO sandbox_results
                   (timestamp, file_name, classification, behavior_report)
                   VALUES (?, ?, ?, ?)""",
                (
                    datetime.now().isoformat(),
                    file_name,
                    classification,
                    behavior_report,
                ),
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to log sandbox result: {e}")


def log_user_behavior(action: str, threat_type: str = "", detail: str = "") -> None:
    """Track user security actions for behavior learning."""
    try:
        with get_connection() as conn:
            conn.execute(
                """INSERT INTO user_behavior (timestamp, action, threat_type, detail)
                   VALUES (?, ?, ?, ?)""",
                (datetime.now().isoformat(), action, threat_type, detail),
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to log user behavior: {e}")


def get_recent_threats(limit: int = 50):
    """Return the most recent threat records."""
    try:
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM threat_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]
    except Exception:
        return []


def recreate_db() -> None:
    """Drop all tables and re-initialize — used by auto-correction engine."""
    logger.warning("Recreating database from scratch.")
    try:
        close_connection()
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
        init_db()
        log_system_event("DB_RECREATED", "Database was corrupted and has been recreated.", "warning")
    except Exception as e:
        logger.error(f"Failed to recreate database: {e}")


# Auto-initialize when module is imported
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    init_db()
    print("Database initialized at:", DB_PATH)
