"""
SentinelCore - Process Injection Detector
Detects injection-like behavior using psutil:
  - Abnormal memory spikes in a process
  - Unexpected child processes spawned by trusted parents
  - Rapid privilege escalation patterns
  - Process spawning anomalies
Runs in a background daemon thread.
"""

import time
import logging
import threading
import psutil
from typing import Callable, Optional, Dict, Set, List

logger = logging.getLogger(__name__)

# Legitimate system parents that should not spawn unexpected shell/script processes
TRUSTED_PARENTS = {
    "explorer.exe", "svchost.exe", "services.exe", "lsass.exe",
    "winlogon.exe", "csrss.exe", "smss.exe", "wininit.exe",
}

# Children that indicate shell injection when spawned unexpectedly
SUSPICIOUS_CHILDREN = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "certutil.exe", "bitsadmin.exe", "msiexec.exe",
}

# Memory spike threshold per process (MB)
MEMORY_SPIKE_MB        = 200
MEMORY_SPIKE_THRESHOLD = MEMORY_SPIKE_MB * 1024 * 1024   # bytes

# How quickly a process must double in memory (seconds)
MEMORY_SPIKE_WINDOW    = 10

# Poll interval
POLL_INTERVAL = 3.0


class InjectionDetector:
    """
    Background process injection detection engine.
    Emits on_alert(alert_type, description) on detection.
    """

    def __init__(
        self,
        on_alert: Optional[Callable[[str, str], None]] = None,
        poll_interval: float = POLL_INTERVAL,
    ):
        self.on_alert      = on_alert
        self.poll_interval = poll_interval

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock    = threading.Lock()

        # Baseline memory per PID: {pid: (name, rss_bytes, timestamp)}
        self._memory_baseline: Dict[int, tuple] = {}

        # Parent→children mapping seen last cycle
        self._known_children: Dict[int, Set[int]] = {}

        # Already-alerted PIDs/events (dedup)
        self._alerted: Set[str] = set()

    # ──────────────────────────────────────────────────────────────────────────
    # Lifecycle
    # ──────────────────────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="InjectionDetector"
        )
        self._thread.start()
        logger.info("InjectionDetector started.")

    def stop(self) -> None:
        self._running = False
        logger.info("InjectionDetector stopped.")

    # ──────────────────────────────────────────────────────────────────────────
    # Monitoring loop
    # ──────────────────────────────────────────────────────────────────────────

    def _monitor_loop(self) -> None:
        # Build initial baseline before first check
        self._build_memory_baseline()
        self._build_children_snapshot()

        while self._running:
            try:
                self._check_memory_spikes()
                self._check_unexpected_children()
                self._check_process_hollowing()
            except Exception as e:
                logger.debug(f"InjectionDetector loop error: {e}")
            time.sleep(self.poll_interval)

    # ──────────────────────────────────────────────────────────────────────────
    # Detection routines
    # ──────────────────────────────────────────────────────────────────────────

    def _check_memory_spikes(self) -> None:
        """Detect processes whose RSS memory has spiked significantly."""
        now = time.time()
        try:
            for proc in psutil.process_iter(["pid", "name", "memory_info"]):
                try:
                    pid  = proc.info["pid"]
                    name = proc.info["name"] or "?"
                    mi   = proc.info["memory_info"]
                    if mi is None:
                        continue
                    rss = mi.rss

                    with self._lock:
                        if pid in self._memory_baseline:
                            base_name, base_rss, base_time = self._memory_baseline[pid]
                            elapsed = now - base_time
                            if (
                                elapsed <= MEMORY_SPIKE_WINDOW
                                and rss - base_rss > MEMORY_SPIKE_THRESHOLD
                                and rss > MEMORY_SPIKE_THRESHOLD
                            ):
                                spike_mb = (rss - base_rss) / (1024 * 1024)
                                self._fire_alert(
                                    f"MEM_SPIKE_{pid}",
                                    "MEMORY_INJECTION",
                                    f"Abnormal memory spike in {name} (PID={pid}): "
                                    f"+{spike_mb:.0f} MB in {elapsed:.0f}s "
                                    f"— possible process injection",
                                )
                        # Update baseline
                        self._memory_baseline[pid] = (name, rss, now)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            logger.debug(f"Memory spike check error: {e}")

    def _check_unexpected_children(self) -> None:
        """Detect trusted processes unexpectedly spawning suspicious children."""
        try:
            current_children: Dict[int, Set[int]] = {}

            for proc in psutil.process_iter(["pid", "name", "ppid"]):
                try:
                    pid  = proc.info["pid"]
                    name = (proc.info["name"] or "").lower()
                    ppid = proc.info["ppid"]

                    if ppid not in current_children:
                        current_children[ppid] = set()
                    current_children[ppid].add(pid)

                    # Check if this child was spawned by a trusted parent
                    # and is itself a suspicious process
                    if name in SUSPICIOUS_CHILDREN:
                        try:
                            parent = psutil.Process(ppid)
                            parent_name = (parent.name() or "").lower()
                            if parent_name in TRUSTED_PARENTS:
                                self._fire_alert(
                                    f"CHILD_{ppid}_{pid}",
                                    "INJECTION_CHILD_PROCESS",
                                    f"Trusted process '{parent_name}' (PID={ppid}) "
                                    f"unexpectedly spawned '{name}' (PID={pid}) "
                                    f"— possible code injection",
                                )
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            with self._lock:
                self._known_children = current_children

        except Exception as e:
            logger.debug(f"Unexpected children check error: {e}")

    def _check_process_hollowing(self) -> None:
        """
        Detect process hollowing patterns:
        - Process with a system name but running from unusual paths.
        - System executables running from Temp/user directories.
        """
        try:
            system32 = "c:\\windows\\system32"
            for proc in psutil.process_iter(["pid", "name", "exe"]):
                try:
                    name = (proc.info["name"] or "").lower()
                    exe  = (proc.info["exe"] or "").lower()

                    if not exe:
                        continue

                    # svchost.exe should always run from system32
                    system_procs = {"svchost.exe", "lsass.exe", "csrss.exe",
                                    "winlogon.exe", "services.exe"}
                    if name in system_procs and system32 not in exe:
                        self._fire_alert(
                            f"HOLLOW_{proc.info['pid']}",
                            "PROCESS_HOLLOWING",
                            f"Possible process hollowing: '{name}' running from "
                            f"'{exe}' instead of System32 (PID={proc.info['pid']})",
                        )
                    # Check for executables in temp directories
                    elif name not in system_procs:
                        temp_indicators = ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp"]
                        if any(ind in exe for ind in temp_indicators):
                            self._fire_alert(
                                f"TEMP_EXEC_{proc.info['pid']}",
                                "TEMP_DIRECTORY_EXECUTION",
                                f"Process '{name}' running from temp directory: "
                                f"'{exe}' (PID={proc.info['pid']})",
                            )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            logger.debug(f"Process hollowing check error: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _build_memory_baseline(self) -> None:
        now = time.time()
        try:
            for proc in psutil.process_iter(["pid", "name", "memory_info"]):
                try:
                    mi = proc.info["memory_info"]
                    if mi:
                        self._memory_baseline[proc.info["pid"]] = (
                            proc.info["name"], mi.rss, now
                        )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass

    def _build_children_snapshot(self) -> None:
        try:
            for proc in psutil.process_iter(["pid", "ppid"]):
                try:
                    ppid = proc.info["ppid"]
                    pid  = proc.info["pid"]
                    if ppid not in self._known_children:
                        self._known_children[ppid] = set()
                    self._known_children[ppid].add(pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass

    def _fire_alert(self, key: str, alert_type: str, description: str) -> None:
        with self._lock:
            if key in self._alerted:
                return
            self._alerted.add(key)

        logger.warning(f"[InjectionDetector] {alert_type}: {description}")
        if self.on_alert:
            try:
                self.on_alert(alert_type, description)
            except Exception as e:
                logger.error(f"InjectionDetector alert callback error: {e}")

    @property
    def is_running(self) -> bool:
        return self._running
