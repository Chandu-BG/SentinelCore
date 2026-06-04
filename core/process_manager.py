"""
NovaSentinel — Process Manager
Windows Task Manager-style real process enumerator.

Provides live process data with:
  - PID, Name, CPU%, RAM MB, Disk KB/s, Threads, Status
  - Safe-to-close classification
  - Trusted publisher detection
  - Delta CPU measurement (non-blocking)
  - Deduplication by PID
"""

import psutil
import os
import threading
import time
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set

logger = logging.getLogger(__name__)

try:
    import wmi as _wmi_mod
    _WMI_AVAILABLE = True
except ImportError:
    _wmi_mod = None
    _WMI_AVAILABLE = False

# Suppress deprecation warning for pynvml BEFORE any import attempt.
# nvidia-ml-py is the maintained replacement; pynvml is kept as a fallback.
import warnings as _w
_w.filterwarnings("ignore", category=FutureWarning, module="pynvml")
_w.filterwarnings("ignore", message=".*pynvml.*", category=FutureWarning)

try:
    # Prefer the actively-maintained nvidia-ml-py package
    import nvidia_ml_py as pynvml  # type: ignore
    _NVML_AVAILABLE = True
except ImportError:
    try:
        import pynvml  # type: ignore  # legacy fallback — FutureWarning suppressed above
        _NVML_AVAILABLE = True
    except ImportError:
        pynvml = None
        _NVML_AVAILABLE = False

# ── Classification tables ──────────────────────────────────────────────────────

# Processes that are NEVER safe to close
SYSTEM_CRITICAL: Set[str] = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
    "dwm.exe", "ntoskrnl.exe", "taskhost.exe", "taskhostw.exe",
    "sihost.exe", "ctfmon.exe", "fontdrvhost.exe", "spoolsv.exe",
    "audiodg.exe", "securityhealthservice.exe", "msmpeng.exe",
    "nissrv.exe", "mpcmdrun.exe", "runtimebroker.exe", "startmenuexperiencehost.exe",
    "searchindexer.exe", "wuauclt.exe",
}

# User apps that are safe to close
SAFE_TO_CLOSE: Set[str] = {
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
    "discord.exe", "slack.exe", "teams.exe", "zoom.exe", "skype.exe",
    "spotify.exe", "steam.exe", "epicgameslauncher.exe", "riotclientservices.exe",
    "onedrive.exe", "dropbox.exe", "googledrivefs.exe",
    "outlook.exe", "thunderbird.exe",
    "code.exe", "devenv.exe", "pycharm64.exe", "idea64.exe",
    "obs64.exe", "vlc.exe", "mpc-hc64.exe", "mpv.exe",
    "acrobat.exe", "acrord32.exe", "sumatra pdf.exe",
    "powerpnt.exe", "excel.exe", "winword.exe", "onenote.exe",
    "notepad.exe", "notepad++.exe", "sublime_text.exe",
    "7zfm.exe", "winrar.exe", "torrent.exe",
    "telegram.exe", "whatsapp.exe", "signal.exe",
    "gimp-2.10.exe", "inkscape.exe", "blender.exe",
    "ollama.exe", "python.exe", "pythonw.exe",
}

# Display name overrides
DISPLAY_NAMES: Dict[str, str] = {
    "chrome.exe": "Google Chrome",
    "msedge.exe": "Microsoft Edge",
    "firefox.exe": "Mozilla Firefox",
    "brave.exe": "Brave Browser",
    "discord.exe": "Discord",
    "slack.exe": "Slack",
    "teams.exe": "Microsoft Teams",
    "zoom.exe": "Zoom",
    "spotify.exe": "Spotify",
    "steam.exe": "Steam",
    "epicgameslauncher.exe": "Epic Games Launcher",
    "riotclientservices.exe": "Riot Client",
    "code.exe": "Visual Studio Code",
    "devenv.exe": "Visual Studio",
    "obs64.exe": "OBS Studio",
    "vlc.exe": "VLC Media Player",
    "acrobat.exe": "Adobe Acrobat",
    "powerpnt.exe": "PowerPoint",
    "excel.exe": "Excel",
    "winword.exe": "Word",
    "onenote.exe": "OneNote",
    "outlook.exe": "Outlook",
    "onedrive.exe": "OneDrive",
    "dropbox.exe": "Dropbox",
    "telegram.exe": "Telegram",
    "whatsapp.exe": "WhatsApp",
    "notepad++.exe": "Notepad++",
    "7zfm.exe": "7-Zip",
    "winrar.exe": "WinRAR",
    "python.exe": "Python",
    "ollama.exe": "Ollama (Local AI)",
    "explorer.exe": "Windows Explorer",
    "svchost.exe": "Windows Service Host",
    "dwm.exe": "Desktop Window Manager",
    "lsass.exe": "Windows Security (LSASS)",
    "antimalware service executable": "Windows Defender",
    "msmpeng.exe": "Windows Defender",
    "pycharm64.exe": "PyCharm",
    "idea64.exe": "IntelliJ IDEA",
    "gimp-2.10.exe": "GIMP",
}

# Trusted path fragments — publisher trust
TRUSTED_PATH_FRAGMENTS = [
    "\\program files\\microsoft",
    "\\program files (x86)\\microsoft",
    "\\program files\\google",
    "\\program files\\mozilla",
    "\\program files\\nvidia",
    "\\program files\\intel",
    "\\program files\\valve",
    "\\program files\\riot games",
    "\\program files\\discord",
    "\\program files\\adobe",
    "\\program files\\epic games",
    "\\program files\\python foundation",
    "\\program files\\github",
    "\\windows\\system32",
    "\\windows\\syswow64",
]


@dataclass
class ProcessEntry:
    pid: int
    name: str
    display_name: str
    exe: str
    cpu_percent: float
    ram_mb: float
    disk_read_kbps: float
    disk_write_kbps: float
    num_threads: int
    status: str
    gpu_percent: float = 0.0
    network_kbps: float = 0.0
    safe_to_close: bool = False
    trusted: bool = False
    risk_flag: str = ""   # empty = normal, "suspicious" = flagged
    group: str = "Background Processes" # "Apps", "Background Processes", "Windows Processes"
    user: str = "System"

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "name": self.name,
            "display_name": self.display_name,
            "exe": self.exe,
            "cpu_percent": self.cpu_percent,
            "ram_mb": self.ram_mb,
            "disk_read_kbps": self.disk_read_kbps,
            "disk_write_kbps": self.disk_write_kbps,
            "num_threads": self.num_threads,
            "status": self.status,
            "gpu_percent": self.gpu_percent,
            "network_kbps": self.network_kbps,
            "safe_to_close": self.safe_to_close,
            "trusted": self.trusted,
            "risk_flag": self.risk_flag,
            "group": self.group,
            "user": self.user,
        }


class ProcessManager:
    """
    Real-time Windows process enumerator.
    Maintains a live process table refreshed every 2 seconds.
    Thread-safe; GUI reads via get_processes() without blocking.
    """

    REFRESH_INTERVAL = 1.5   # seconds — slightly reduced polling to save CPU
    MIN_RAM_MB = 1.0          # hide micro-processes below this
    MIN_SHOW_CPU = 0.0        # show all (0 = show even idle)

    def __init__(self):
        self._lock = threading.Lock()
        self._processes: List[ProcessEntry] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        # Previous I/O counters for delta calculation
        self._prev_io: Dict[int, object] = {}
        self._prev_io_time: float = time.time()
        self._system_gpu_percent: float = 0.0
        self._wmi_ohm = None
        self._nvml_initialized = False

        if _WMI_AVAILABLE:
            try:
                self._wmi_ohm = _wmi_mod.WMI(namespace=r"root\OpenHardwareMonitor")
            except Exception:
                self._wmi_ohm = None

        if _NVML_AVAILABLE:
            try:
                pynvml.nvmlInit()
                self._nvml_initialized = True
            except Exception:
                self._nvml_initialized = False

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        
        # Initial population before thread starts
        try:
            self._processes = self._enumerate()
            logger.info(f"ProcessManager: Initialized with {len(self._processes)} processes.")
        except Exception as e:
            logger.error(f"ProcessManager: Initial population failed: {e}")

        self._thread = threading.Thread(
            target=self._refresh_loop, daemon=True, name="ProcessManager"
        )
        self._thread.start()
        logger.info("ProcessManager started.")

    def stop(self) -> None:
        self._running = False
        if self._nvml_initialized:
            try:
                pynvml.nvmlShutdown()
            except Exception:
                pass

    # ── Public API ─────────────────────────────────────────────────────────────

    def get_processes(self, sort_by: str = "cpu", top_n: int = 200) -> List[ProcessEntry]:
        """Thread-safe snapshot of current process list."""
        with self._lock:
            # If empty, try one more sync enumeration (fail-safe)
            if not self._processes:
                self._processes = self._enumerate()
            procs = list(self._processes)

        # Sort
        key_map = {
            "cpu":  lambda p: p.cpu_percent,
            "ram":  lambda p: p.ram_mb,
            "name": lambda p: p.display_name.lower(),
            "pid":  lambda p: p.pid,
            "disk": lambda p: p.disk_read_kbps + p.disk_write_kbps,
            "gpu":  lambda p: p.gpu_percent,
        }
        key_fn = key_map.get(sort_by, key_map["cpu"])
        reverse = sort_by != "name"
        procs.sort(key=key_fn, reverse=reverse)
        return procs[:top_n]

    def get_by_pid(self, pid: int) -> Optional[ProcessEntry]:
        with self._lock:
            for p in self._processes:
                if p.pid == pid:
                    return p
        return None

    def get_system_gpu_percent(self) -> float:
        """Last sampled overall GPU load."""
        return float(self._system_gpu_percent)

    def terminate(self, pid: int) -> bool:
        """Terminate a process by PID. Returns True on success."""
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            logger.info(f"ProcessManager: terminated PID={pid}")
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.warning(f"ProcessManager: cannot terminate PID={pid}: {e}")
            return False

    # ── Internal refresh ────────────────────────────────────────────────────────

    def _refresh_loop(self) -> None:
        # Warm up CPU percentages
        try:
            psutil.cpu_percent(interval=None)
        except Exception:
            pass

        while self._running:
            try:
                # Enumerate WITHOUT holding the lock — this is the expensive part
                procs = self._enumerate()
                if procs:
                    # Atomic swap: lock only for the final assignment
                    with self._lock:
                        self._processes = procs
            except Exception as e:
                logger.error(f"ProcessManager refresh error: {e}")
            time.sleep(self.REFRESH_INTERVAL)

    def _enumerate(self) -> List[ProcessEntry]:
        entries: List[ProcessEntry] = []
        now = time.time()
        dt = max(now - self._prev_io_time, 0.001)
        new_io: Dict[int, object] = {}

        self._system_gpu_percent = self._read_gpu_load()
        pid_gpu_map = self._get_nvml_pid_gpu_map()

        # Capture all processes
        for p in psutil.process_iter():
            try:
                # Use as_dict for better performance/reliability
                inf = p.as_dict(attrs=["pid", "name", "exe", "cpu_percent", "memory_info", "io_counters", "num_threads", "status", "username"])
                pid = inf["pid"]
                if pid is None or pid == 0: continue # Skip Idle

                name = (inf.get("name") or "").lower()
                exe = inf.get("exe") or ""
                user = (inf.get("username") or "").lower()

                cpu = inf.get("cpu_percent") or 0.0
                mi = inf.get("memory_info")
                ram_mb = (mi.rss / 1_048_576) if mi else 0.0

                # Disk I/O delta
                io = inf.get("io_counters")
                disk_r = disk_w = 0.0
                if io:
                    new_io[pid] = io
                    prev = self._prev_io.get(pid)
                    if prev:
                        disk_r = max((io.read_bytes - prev.read_bytes) / 1024 / dt, 0)
                        disk_w = max((io.write_bytes - prev.write_bytes) / 1024 / dt, 0)

                threads = inf.get("num_threads") or 0
                status = inf.get("status") or "running"

                # Better classification:
                # 1. Windows Processes: System services, System32, etc.
                # 2. Apps: Processes with a window or user-launched executables.
                # 3. Background Processes: Everything else.
                
                is_system = name in SYSTEM_CRITICAL or "system32" in exe.lower() or "syswow64" in exe.lower() or user == "nt authority\\system"
                is_trusted = is_system or self._is_trusted_path(exe)
                
                group = "Background Processes"
                if is_system:
                    group = "Windows Processes"
                elif name in SAFE_TO_CLOSE or (".exe" in name and not is_system and user != "nt authority\\system"):
                    # Heuristic: if it's in a user path or a known app
                    group = "Apps"

                display = DISPLAY_NAMES.get(name, name.replace(".exe", "").replace("-", " ").title())
                risk = ""
                if not is_trusted and exe and self._is_suspicious_location(exe):
                    risk = "suspicious"

                # GPU and Network placeholders
                gpu = pid_gpu_map.get(pid, 0.0)
                net = 0.0 # Would require packet inspection or ETW on Windows
                
                entries.append(ProcessEntry(
                    pid=pid,
                    name=name,
                    display_name=display,
                    exe=exe,
                    cpu_percent=round(cpu, 1),
                    ram_mb=round(ram_mb, 1),
                    disk_read_kbps=round(disk_r, 1),
                    disk_write_kbps=round(disk_w, 1),
                    gpu_percent=round(gpu, 1),
                    network_kbps=net,
                    num_threads=threads,
                    status=status,
                    safe_to_close=name in SAFE_TO_CLOSE,
                    trusted=is_trusted,
                    risk_flag=risk,
                    group=group,
                    user=user,
                ))

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            except Exception as e:
                logger.debug(f"ProcessManager enum error for PID: {e}")

        self._prev_io = new_io
        self._prev_io_time = now
        return entries

    def _read_gpu_load(self) -> float:
        """Query overall GPU load from NVML or OpenHardwareMonitor."""
        if self._nvml_initialized:
            try:
                device_count = pynvml.nvmlDeviceGetCount()
                total_load = 0.0
                for i in range(device_count):
                    handle = pynvml.nvmlDeviceGetHandleByIndex(i)
                    util = pynvml.nvmlDeviceGetUtilizationRates(handle)
                    total_load += util.gpu
                return total_load / device_count if device_count > 0 else 0.0
            except Exception:
                pass

        if self._wmi_ohm:
            try:
                best = 0.0
                for s in self._wmi_ohm.Sensor():
                    if getattr(s, "SensorType", "") == "Load" and "GPU" in str(getattr(s, "Name", "")):
                        v = float(getattr(s, "Value", 0.0) or 0.0)
                        if v > best:
                            best = v
                return max(0.0, min(best, 100.0))
            except Exception:
                pass
        return 0.0

    def _get_nvml_pid_gpu_map(self) -> Dict[int, float]:
        """Map PID to GPU utilization using NVML."""
        pid_map = {}
        if not self._nvml_initialized:
            return pid_map
        try:
            device_count = pynvml.nvmlDeviceGetCount()
            for i in range(device_count):
                handle = pynvml.nvmlDeviceGetHandleByIndex(i)
                # Compute processes
                try:
                    for proc in pynvml.nvmlDeviceGetComputeRunningProcesses(handle):
                        # NVML doesn't give per-process % easily, often just memory
                        # We might need to estimate or just report presence
                        pid_map[proc.pid] = pid_map.get(proc.pid, 0.0) + 1.0 # Placeholder
                except Exception:
                    pass
                # Graphics processes
                try:
                    for proc in pynvml.nvmlDeviceGetGraphicsRunningProcesses(handle):
                        pid_map[proc.pid] = pid_map.get(proc.pid, 0.0) + 1.0 # Placeholder
                except Exception:
                    pass
        except Exception:
            pass
        return pid_map

    @staticmethod
    def _is_trusted_path(exe: str) -> bool:
        if not exe:
            return False
        exe_lower = exe.lower()
        return any(frag in exe_lower for frag in TRUSTED_PATH_FRAGMENTS)

    @staticmethod
    def _is_suspicious_location(exe: str) -> bool:
        if not exe:
            return False
        exe_lower = exe.lower()
        suspicious = ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
                      "\\downloads\\", "\\public\\", "%temp%"]
        return any(s in exe_lower for s in suspicious)
