"""
NovaSentinel — Real-Time Monitor
Monitors the filesystem for real-time protection using watchdog.
Events for the same path are debounced: only one callback fires after
500 ms of silence, preventing duplicate notifications for rapid bursts.
"""

import os
import logging
import threading
import time
from collections import defaultdict

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger(__name__)

DEBOUNCE_SECONDS = 0.5


class _DebouncedHandler(FileSystemEventHandler):
    """
    Watchdog event handler that coalesces rapid filesystem events per path.

    Uses a single long-running background worker thread instead of high-overhead
    threading.Timer objects, reducing thread creation overhead to zero.
    """

    def __init__(self, callback):
        super().__init__()
        self._callback = callback
        # Maps path → last event time
        self._pending_events: dict = {}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._worker_thread: threading.Thread | None = None

    def start_worker(self):
        with self._lock:
            if self._worker_thread and self._worker_thread.is_alive():
                return
            self._stop_event.clear()
            self._pending_events.clear()
            self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True, name="RealtimeDebouncer")
            self._worker_thread.start()

    def stop_worker(self):
        self._stop_event.set()
        if self._worker_thread:
            self._worker_thread.join(timeout=1.0)
            self._worker_thread = None

    # ------------------------------------------------------------------
    # watchdog event hooks
    # ------------------------------------------------------------------

    def on_created(self, event):
        if event.is_directory:
            return
        self._debounce(event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._debounce(event.src_path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _debounce(self, path: str):
        """Update last event time for *path* in a thread-safe dictionary."""
        with self._lock:
            self._pending_events[path] = time.time()

    def _worker_loop(self):
        """Single thread loop checking for debounced paths every 100ms."""
        while not self._stop_event.is_set():
            time.sleep(0.1)
            now = time.time()
            to_fire = []
            
            with self._lock:
                for path, event_time in list(self._pending_events.items()):
                    if now - event_time >= DEBOUNCE_SECONDS:
                        to_fire.append(path)
                        del self._pending_events[path]
                        
            for path in to_fire:
                try:
                    self._callback(path)
                except Exception as exc:
                    logger.debug(f"_DebouncedHandler callback error for {path}: {exc}")


class RealtimeMonitor:
    """
    Watches high-risk directories for file creation/modification events and
    dispatches debounced callbacks to registered listeners.
    """

    def __init__(self):
        self._callbacks = []
        self._observer: Observer | None = None
        self._handler = _DebouncedHandler(self._dispatch)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_callback(self, cb):
        """Register a callable that receives a file path string on each event."""
        if cb not in self._callbacks:
            self._callbacks.append(cb)

    def start(self):
        """Start the watchdog observer and schedule all monitored paths in the background."""
        if self._observer is not None:
            return  # already running or starting

        self._observer = "starting"
        self._handler.start_worker()

        def startup_worker():
            try:
                obs = Observer()
                home = os.path.expanduser("~")
                paths_to_monitor = [
                    os.path.join(home, "Downloads"),
                    os.path.join(home, "Desktop"),
                    os.path.join(home, "AppData", "Local", "Temp"),
                    os.path.join(
                        home,
                        "AppData",
                        "Roaming",
                        "Microsoft",
                        "Windows",
                        "Start Menu",
                        "Programs",
                        "Startup",
                    ),
                ]

                for path in paths_to_monitor:
                    if os.path.exists(path):
                        try:
                            # Disable recursive watching on massive system Temp directory to eliminate high I/O and CPU spikes
                            is_temp = "Temp" in path
                            obs.schedule(self._handler, path, recursive=not is_temp)
                            logger.info(f"RealtimeMonitor: Watching {path} (recursive={not is_temp})")
                        except Exception as exc:
                            logger.debug(f"RealtimeMonitor: Failed to watch {path}: {exc}")

                obs.start()
                if self._observer is None:
                    obs.stop()
                    obs.join()
                    logger.info("RealtimeMonitor: Observer stopped immediately due to early cancellation.")
                else:
                    self._observer = obs
                    logger.info("RealtimeMonitor: Observer started in background thread.")
            except Exception as e:
                self._observer = None
                logger.error(f"RealtimeMonitor startup failed: {e}")

        threading.Thread(target=startup_worker, daemon=True, name="RealtimeStartup").start()

    def stop(self):
        """Stop the watchdog observer asynchronously to prevent blocking the UI thread."""
        self._handler.stop_worker()
        if self._observer is None:
            return
        
        obs = self._observer
        self._observer = None
        
        if obs == "starting":
            return

        def stop_worker():
            try:
                obs.stop()
                obs.join()
                logger.info("RealtimeMonitor: Observer stopped in background thread.")
            except Exception as e:
                logger.debug(f"Error stopping observer: {e}")

        threading.Thread(target=stop_worker, daemon=True, name="RealtimeShutdown").start()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _dispatch(self, path: str):
        """Forward a debounced event to all registered callbacks."""
        for cb in self._callbacks:
            try:
                cb(path)
            except Exception as exc:
                logger.debug(f"RealtimeMonitor callback error: {exc}")


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_instance: RealtimeMonitor | None = None


def get_realtime_monitor() -> RealtimeMonitor:
    global _instance
    if _instance is None:
        _instance = RealtimeMonitor()
    return _instance
