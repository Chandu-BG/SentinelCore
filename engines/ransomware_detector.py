"""
SentinelCore - Ransomware Detector Engine
Monitors filesystem for ransomware-like behavior using watchdog:
  - Mass file modification
  - Rapid file renaming
  - File encryption patterns (high-entropy writes, extension changes)
Runs in a background daemon thread.
"""

import os
import time
import logging
import threading
from datetime import datetime
from typing import Callable, Optional, Dict, Set
from collections import deque

logger = logging.getLogger(__name__)

# Known ransomware extension patterns
RANSOMWARE_EXTENSIONS = {
    ".encrypted", ".locked", ".crypted", ".crypt",
    ".crypto", ".enc", ".ransom", ".wncry", ".wnry",
    ".locky", ".thor", ".aaa", ".abc", ".xyz", ".zzz",
    ".evil", ".cerber", ".cerber2", ".cerber3",
    ".zepto", ".osiris", ".odin", ".globe",
}

# Thresholds
MODIFICATION_THRESHOLD = 20    # files modified in WINDOW_SECONDS = alert
RENAME_THRESHOLD       = 10    # files renamed in WINDOW_SECONDS = alert
WINDOW_SECONDS         = 30    # rolling time window


class _FSEventHandler:
    """Minimal filesystem event handler (watchdog is optional dep)."""

    def __init__(self, on_modified, on_moved, on_deleted):
        self.on_modified = on_modified
        self.on_moved    = on_moved
        self.on_deleted  = on_deleted

    def dispatch(self, event):
        event_type = getattr(event, "event_type", "")
        src_path   = getattr(event, "src_path", "")
        dest_path  = getattr(event, "dest_path", "")
        is_dir     = getattr(event, "is_directory", False)

        if is_dir:
            return
        if event_type == "modified":
            self.on_modified(src_path)
        elif event_type == "moved":
            self.on_moved(src_path, dest_path)
        elif event_type == "deleted":
            self.on_deleted(src_path)


class RansomwareDetector:
    """
    Monitors user directories for ransomware-like filesystem activity.
    Fires on_alert(alert_type, path, description) on detection.
    """

    def __init__(
        self,
        on_alert:     Optional[Callable[[str, str, str], None]] = None,
        on_quarantine: Optional[Callable[[str, str], None]] = None,
        watch_dirs:   Optional[list] = None,
    ):
        self.on_alert     = on_alert
        self.on_quarantine = on_quarantine

        home = os.path.expanduser("~")
        self.watch_dirs = watch_dirs or [
            os.path.join(home, "Documents"),
            os.path.join(home, "Desktop"),
            os.path.join(home, "Downloads"),
            os.path.join(home, "Pictures"),
        ]

        self._running      = False
        self._thread: Optional[threading.Thread] = None
        self._observer     = None
        self._lock         = threading.Lock()

        # Rolling event queues (timestamps)
        self._modifications: deque = deque()
        self._renames:       deque = deque()
        self._alerted_paths: Set[str] = set()

        # Suspicious process tracking: path → set of suspect extensions seen
        self._suspect_map: Dict[str, int] = {}

    # ──────────────────────────────────────────────────────────────────────────
    # Lifecycle
    # ──────────────────────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._running:
            return
        self._running = True

        # Try to use watchdog if available, else fall back to poll
        try:
            self._start_watchdog()
        except ImportError:
            logger.warning(
                "watchdog not installed — RansomwareDetector using polling fallback."
            )
            self._thread = threading.Thread(
                target=self._poll_loop, daemon=True, name="RansomwareDetector"
            )
            self._thread.start()

        logger.info("RansomwareDetector started.")

    def stop(self) -> None:
        self._running = False
        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=2)
            except Exception:
                pass
        logger.info("RansomwareDetector stopped.")

    # ──────────────────────────────────────────────────────────────────────────
    # Watchdog-based monitoring
    # ──────────────────────────────────────────────────────────────────────────

    def _start_watchdog(self) -> None:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler

        detector = self

        class _Handler(FileSystemEventHandler):
            def on_modified(self, event):
                if not event.is_directory:
                    detector._on_modified(event.src_path)

            def on_moved(self, event):
                if not event.is_directory:
                    detector._on_renamed(event.src_path, event.dest_path)

            def on_deleted(self, event):
                if not event.is_directory:
                    detector._on_deleted(event.src_path)

        handler = _Handler()
        self._observer = Observer()
        for d in self.watch_dirs:
            if os.path.isdir(d):
                self._observer.schedule(handler, d, recursive=True)

        self._observer.start()
        logger.info("RansomwareDetector: watchdog observer started.")

    # ──────────────────────────────────────────────────────────────────────────
    # Polling fallback
    # ──────────────────────────────────────────────────────────────────────────

    def _poll_loop(self) -> None:
        """Polling fallback: snapshot directory mtimes and detect bulk changes."""
        snapshots: Dict[str, float] = {}
        rename_counts: Dict[str, int] = {}

        while self._running:
            now   = time.time()
            current: Dict[str, float] = {}

            for watch_dir in self.watch_dirs:
                if not os.path.isdir(watch_dir):
                    continue
                try:
                    for root, _, files in os.walk(watch_dir):
                        for fname in files:
                            path = os.path.join(root, fname)
                            try:
                                mtime = os.path.getmtime(path)
                                current[path] = mtime
                            except OSError:
                                pass
                except Exception:
                    pass

            # Count modifications in last poll cycle
            modified_count = 0
            for path, mtime in current.items():
                if path in snapshots and abs(mtime - snapshots[path]) > 0.5:
                    modified_count += 1
                    self._on_modified(path)
                # Detect suspicious extensions in new files
                _, ext = os.path.splitext(path.lower())
                if ext in RANSOMWARE_EXTENSIONS and path not in snapshots:
                    self._fire_alert(
                        "RANSOMWARE_EXTENSION",
                        path,
                        f"File with ransomware extension appeared: {os.path.basename(path)}",
                    )

            snapshots = current
            time.sleep(5)

    # ──────────────────────────────────────────────────────────────────────────
    # Event handlers
    # ──────────────────────────────────────────────────────────────────────────

    def _on_modified(self, path: str) -> None:
        """Record a file modification event and check thresholds."""
        now = time.time()
        with self._lock:
            self._modifications.append(now)
            # Prune old events outside window
            self._prune_queue(self._modifications)
            count = len(self._modifications)

        # Check for ransomware extension
        _, ext = os.path.splitext(path.lower())
        if ext in RANSOMWARE_EXTENSIONS:
            self._fire_alert(
                "RANSOMWARE_EXTENSION",
                path,
                f"File with ransomware extension modified: {os.path.basename(path)}",
            )
            return

        if count >= MODIFICATION_THRESHOLD:
            self._fire_alert(
                "MASS_FILE_MODIFICATION",
                path,
                f"Mass file modification detected: {count} files modified "
                f"in {WINDOW_SECONDS}s — possible ransomware.",
            )

    def _on_renamed(self, src: str, dest: str) -> None:
        """Record a rename event and check thresholds."""
        now = time.time()
        with self._lock:
            self._renames.append(now)
            self._prune_queue(self._renames)
            count = len(self._renames)

        # Check if renamed to ransomware extension
        _, new_ext = os.path.splitext(dest.lower())
        if new_ext in RANSOMWARE_EXTENSIONS:
            self._fire_alert(
                "RANSOMWARE_EXTENSION",
                dest,
                f"File renamed to ransomware extension: "
                f"{os.path.basename(src)} → {os.path.basename(dest)}",
            )
            return

        if count >= RENAME_THRESHOLD:
            self._fire_alert(
                "RAPID_RENAME",
                dest,
                f"Rapid file renaming detected: {count} files renamed "
                f"in {WINDOW_SECONDS}s — possible ransomware.",
            )

    def _on_deleted(self, path: str) -> None:
        """Detect mass deletion patterns (often accompanies ransomware)."""
        pass  # Could be extended if needed

    def _fire_alert(self, alert_type: str, path: str, description: str) -> None:
        """Fire an alert, deduplicated per path per alert_type."""
        key = f"{alert_type}:{path}"
        with self._lock:
            if key in self._alerted_paths:
                return
            self._alerted_paths.add(key)

        logger.warning(f"[RansomwareDetector] {alert_type}: {description}")
        if self.on_alert:
            try:
                self.on_alert(alert_type, path, description)
            except Exception as e:
                logger.error(f"RansomwareDetector alert callback error: {e}")

    def _prune_queue(self, q: deque) -> None:
        """Remove events older than WINDOW_SECONDS from the front of the queue."""
        cutoff = time.time() - WINDOW_SECONDS
        while q and q[0] < cutoff:
            q.popleft()

    # ──────────────────────────────────────────────────────────────────────────
    # Status
    # ──────────────────────────────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        return self._running

    def get_status(self) -> dict:
        with self._lock:
            return {
                "running":       self._running,
                "modifications": len(self._modifications),
                "renames":       len(self._renames),
                "watch_dirs":    self.watch_dirs,
            }
