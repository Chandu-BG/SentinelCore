"""
SentinelCore - Performance Analyzer Engine
Monitors system performance and detects lag conditions.

Detects:
  - High CPU usage (> threshold%)
  - High RAM usage (> threshold%)
  - High disk I/O activity
  - Top resource-hogging background processes

Provides:
  - Safe-to-close process suggestions with confirmation via callback
  - Periodic background polling (non-intrusive, low-overhead)
"""

import time
import threading
import logging
import psutil
from typing import Callable, Optional, List, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)

# ── Thresholds ────────────────────────────────────────────────────────────────
CPU_LAG_THRESHOLD  = 80.0   # % sustained CPU usage
RAM_LAG_THRESHOLD  = 85.0   # % RAM usage
DISK_LAG_THRESHOLD = 90.0   # % disk I/O utilisation
POLL_INTERVAL      = 3.0   # seconds between checks
LAG_SUSTAIN_TICKS  = 5      # consecutive high readings before firing alert

# Processes that are never safe to suggest closing
PROTECTED_PROCESSES = {
    # Windows system
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
    "dwm.exe", "explorer.exe", "ntoskrnl.exe", "taskhost.exe",
    "taskhostw.exe", "sihost.exe", "ctfmon.exe", "dllhost.exe",
    "conhost.exe", "fontdrvhost.exe", "spoolsv.exe", "audiodg.exe",
    "wuauclt.exe", "msiexec.exe", "searchindexer.exe", "securityhealthservice.exe",
    # SentinelCore itself
    "python.exe", "python3.exe", "pythonw.exe", "main.py",
    # Common AV
    "msmpeng.exe", "nissrv.exe", "mpcmdrun.exe",
}

# Friendly category labels for common processes
PROCESS_CATEGORIES: Dict[str, str] = {
    "chrome.exe":       "Google Chrome (web browser)",
    "msedge.exe":       "Microsoft Edge (web browser)",
    "firefox.exe":      "Firefox (web browser)",
    "discord.exe":      "Discord (chat app)",
    "slack.exe":        "Slack (work chat)",
    "teams.exe":        "Microsoft Teams",
    "zoom.exe":         "Zoom (video calls)",
    "spotify.exe":      "Spotify (music)",
    "steam.exe":        "Steam (gaming platform)",
    "onedrive.exe":     "OneDrive (cloud sync)",
    "dropbox.exe":      "Dropbox (cloud sync)",
    "outlook.exe":      "Outlook (email)",
    "code.exe":         "Visual Studio Code",
    "devenv.exe":       "Visual Studio IDE",
    "obs64.exe":        "OBS Studio (screen recording)",
    "vlc.exe":          "VLC Media Player",
    "acrobat.exe":      "Adobe Acrobat",
    "powerpnt.exe":     "PowerPoint",
    "excel.exe":        "Excel",
    "winword.exe":      "Word",
    "skype.exe":        "Skype",
    "telegram.exe":     "Telegram",
    "whatsapp.exe":     "WhatsApp",
    "notepad++.exe":    "Notepad++",
    "7zfm.exe":         "7-Zip",
}


@dataclass
class ProcessInfo:
    pid:          int
    name:         str
    display_name: str
    cpu_percent:  float
    mem_mb:       float
    safe_to_close: bool = True

    def to_dict(self) -> dict:
        return {
            "pid":          self.pid,
            "name":         self.name,
            "display_name": self.display_name,
            "cpu_percent":  self.cpu_percent,
            "mem_mb":       self.mem_mb,
            "safe_to_close": self.safe_to_close,
        }


@dataclass
class LagReport:
    cpu_percent:    float
    ram_percent:    float
    disk_percent:   float
    timestamp:      str
    top_processes:  List[ProcessInfo] = field(default_factory=list)
    is_lagging:     bool = False

    def lag_reasons(self) -> List[str]:
        reasons = []
        if self.cpu_percent >= CPU_LAG_THRESHOLD:
            reasons.append(f"CPU is at {self.cpu_percent:.0f}% (very high)")
        if self.ram_percent >= RAM_LAG_THRESHOLD:
            reasons.append(f"RAM is at {self.ram_percent:.0f}% (nearly full)")
        if self.disk_percent >= DISK_LAG_THRESHOLD:
            reasons.append(f"Disk is at {self.disk_percent:.0f}% I/O (very busy)")
        return reasons

    def friendly_summary(self) -> str:
        reasons = self.lag_reasons()
        if not reasons:
            return "System performance is normal."
        base = "Your system is running slowly. "
        base += " ".join(reasons) + ". "
        closeable = [p for p in self.top_processes if p.safe_to_close]
        if closeable:
            names = ", ".join(p.display_name for p in closeable[:3])
            base += f"Consider closing: {names}."
        return base

    def to_dict(self) -> dict:
        return {
            "cpu_percent":   self.cpu_percent,
            "ram_percent":   self.ram_percent,
            "disk_percent":  self.disk_percent,
            "timestamp":     self.timestamp,
            "is_lagging":    self.is_lagging,
            "lag_reasons":   self.lag_reasons(),
            "top_processes": [p.to_dict() for p in self.top_processes],
        }


class PerformanceAnalyzer:
    """
    Background system performance monitor.
    Detects lag and surfaces safe-to-close process suggestions.
    Uses on_lag_detected(report) callback — never terminates processes
    without explicit GUI confirmation from the user.
    """

    def __init__(
        self,
        on_lag_detected: Optional[Callable[[LagReport], None]] = None,
        on_alert:        Optional[Callable[[str, str], None]]  = None,
        poll_interval:   float = POLL_INTERVAL,
        cpu_threshold:   float = CPU_LAG_THRESHOLD,
        ram_threshold:   float = RAM_LAG_THRESHOLD,
    ):
        self.on_lag_detected = on_lag_detected
        self.on_alert        = on_alert
        self.poll_interval   = poll_interval
        self.cpu_threshold   = cpu_threshold
        self.ram_threshold   = ram_threshold

        self._running         = False
        self._thread: Optional[threading.Thread] = None
        self._high_ticks      = 0        # consecutive high-load readings
        self._last_report:    Optional[LagReport] = None
        self._history:        List[LagReport] = []

    # ──────────────────────────────────────────────────────────────────────────
    # Lifecycle
    # ──────────────────────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="PerformanceAnalyzer"
        )
        self._thread.start()
        logger.info("PerformanceAnalyzer started.")

    def stop(self) -> None:
        self._running = False
        logger.info("PerformanceAnalyzer stopped.")

    # ──────────────────────────────────────────────────────────────────────────
    # Monitor loop
    # ──────────────────────────────────────────────────────────────────────────

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                report = self._collect()
                self._last_report = report
                self._history.append(report)
                if len(self._history) > 60:
                    self._history = self._history[-60:]

                if report.is_lagging:
                    self._high_ticks += 1
                    if self._high_ticks >= LAG_SUSTAIN_TICKS:
                        self._fire_lag(report)
                        self._high_ticks = 0   # reset — wait before re-alerting
                else:
                    self._high_ticks = 0

            except Exception as e:
                logger.debug(f"PerformanceAnalyzer error: {e}")

            time.sleep(self.poll_interval)

    # ──────────────────────────────────────────────────────────────────────────
    # Data collection
    # ──────────────────────────────────────────────────────────────────────────

    def _collect(self) -> LagReport:
        cpu  = psutil.cpu_percent(interval=1)
        ram  = psutil.virtual_memory().percent
        try:
            disk_io = psutil.disk_io_counters(perdisk=False)
            # Use a simple heuristic: if busy_time available (Linux) else 0
            disk = getattr(disk_io, 'busy_time', 0) or 0
        except Exception:
            disk = 0.0

        top_procs = self._top_processes(n=8)
        is_lagging = cpu >= self.cpu_threshold or ram >= self.ram_threshold or disk >= DISK_LAG_THRESHOLD

        return LagReport(
            cpu_percent   = cpu,
            ram_percent   = ram,
            disk_percent  = disk,
            timestamp     = datetime.now().strftime("%H:%M:%S"),
            top_processes = top_procs,
            is_lagging    = is_lagging,
        )

    def _top_processes(self, n: int = 12) -> List[ProcessInfo]:
        """Return top N processes by CPU+memory. Shows real user applications."""
        procs: List[ProcessInfo] = []
        try:
            for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info", "status"]):
                try:
                    info = p.info
                    pname = (info.get("name") or "").lower()
                    
                    # Essential system protection only
                    if pname in ["system", "registry", "smss.exe", "csrss.exe"]:
                        continue

                    mem_info = info.get("memory_info")
                    mem_mb = (mem_info.rss / 1024 / 1024) if mem_info else 0.0
                    cpu_pct = info.get("cpu_percent") or 0.0

                    # Show all processes using more than 0.1% CPU OR 50MB RAM
                    if cpu_pct < 0.1 and mem_mb < 50:
                        continue

                    display = PROCESS_CATEGORIES.get(pname, pname.replace(".exe", "").capitalize())
                    procs.append(ProcessInfo(
                        pid=info["pid"],
                        name=pname,
                        display_name=display,
                        cpu_percent=cpu_pct,
                        mem_mb=mem_mb,
                        safe_to_close=pname not in PROTECTED_PROCESSES,
                    ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            logger.debug(f"top_processes error: {e}")

        # Sort by impact score (CPU + mem impact)
        procs.sort(key=lambda p: p.cpu_percent + (p.mem_mb / 200), reverse=True)
        return procs[:n]

    # ──────────────────────────────────────────────────────────────────────────
    # Callbacks
    # ──────────────────────────────────────────────────────────────────────────

    def _fire_lag(self, report: LagReport) -> None:
        logger.warning(f"[Performance] Lag detected — CPU:{report.cpu_percent:.0f}% RAM:{report.ram_percent:.0f}%")
        if self.on_lag_detected:
            try:
                self.on_lag_detected(report)
            except Exception as e:
                logger.error(f"PerformanceAnalyzer callback error: {e}")
        if self.on_alert:
            try:
                self.on_alert("PERFORMANCE_LAG", report.friendly_summary())
            except Exception as e:
                logger.error(f"PerformanceAnalyzer alert callback error: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # Process management (confirmation required via GUI before calling)
    # ──────────────────────────────────────────────────────────────────────────

    def close_process(self, pid: int, name: str) -> bool:
        """
        Terminate a process by PID.
        NEVER call this without explicit user confirmation from the GUI.
        Returns True if successful.
        """
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            logger.info(f"[Performance] Terminated process: {name} (PID={pid})")
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.warning(f"[Performance] Could not terminate {name}: {e}")
            return False

    # ──────────────────────────────────────────────────────────────────────────
    # Status
    # ──────────────────────────────────────────────────────────────────────────

    def current_report(self) -> Optional[LagReport]:
        return self._last_report

    def history(self) -> List[LagReport]:
        return list(self._history)

    @property
    def is_running(self) -> bool:
        return self._running
