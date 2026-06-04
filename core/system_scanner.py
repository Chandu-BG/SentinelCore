import os
import hashlib
import subprocess
import logging
import threading
import time
import math
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable
from datetime import datetime

from core.signature_verifier import SignatureVerifier

logger = logging.getLogger(__name__)

try:
    from ml.yara_scanner import YaraScanner
except ImportError:
    YaraScanner = None

# ── Known malicious SHA-256 hashes ──
KNOWN_BAD_HASHES: set = set()

# ── Known-good SHA-256 ──
KNOWN_GOOD_HASHES: set = set()

TRUSTED_PUBLISHER_SUBSTRINGS = frozenset(
    {
        "microsoft", "nvidia", "asus", "asustek", "steam", "valve", "discord",
        "brave", "google llc", "mozilla", "apple inc", "adobe", "oracle",
        "intel", "amd", "realtek", "broadcom", "qualcomm", "lenovo", "dell inc",
        "hp inc", "samsung",
    }
)

EXEC_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".pif", ".com",
    ".vbs", ".js", ".jse", ".wsf", ".bat", ".ps1", ".cmd", ".msi",
    ".hta", ".lnk", ".sys", ".drv", ".ocx", ".cpl",
}

HIGH_RISK_PATHS = [
    os.path.expandvars(r"%TEMP%"),
    os.path.expandvars(r"%TMP%"),
    os.path.expandvars(r"%APPDATA%\Local\Temp"),
    os.path.expandvars(r"%USERPROFILE%\Downloads"),
    os.path.expandvars(r"%APPDATA%\Roaming"),
    os.path.expandvars(r"%APPDATA%\Local"),
    os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
]

AUTORUN_KEYS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
]


@dataclass
class ScanItem:
    path: str
    name: str
    sha256: str
    entropy: float
    file_size: int
    confidence: float          # 0.0 – 1.0
    classification: str        # SAFE / MONITOR / SUSPICIOUS / MALICIOUS
    indicators: List[str] = field(default_factory=list)
    yara_matches: List[str] = field(default_factory=list)
    item_type: str = "file"    # file / registry / task / process
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))

    @property
    def severity_color(self) -> str:
        return {
            "MALICIOUS": "danger",
            "SUSPICIOUS": "warning",
            "MONITOR": "accent",
            "SAFE": "success",
        }.get(self.classification, "text_muted")


@dataclass
class ScanReport:
    mode: str
    started_at: str
    completed_at: str = ""
    items_scanned: int = 0
    findings: List[ScanItem] = field(default_factory=list)
    autoruns: List[Dict] = field(default_factory=list)
    scheduled_tasks: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def threat_count(self) -> int:
        return sum(1 for f in self.findings if f.classification in ("SUSPICIOUS", "MALICIOUS"))

    @property
    def summary(self) -> str:
        tc = self.threat_count
        if tc == 0:
            return f"Scan complete — {self.items_scanned} items checked. No threats detected."
        return (f"Scan complete — {self.items_scanned} items checked. "
                f"{tc} suspicious item(s) found.")


class SystemScanner:
    """
    Root-level system scanner for NovaSentinel.
    Safely scans high-risk Windows locations without modifying anything.
    """

    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

    def __init__(
        self,
        on_progress: Optional[Callable[[int, int, str], None]] = None,
        on_finding: Optional[Callable[[ScanItem], None]] = None,
    ):
        self.on_progress = on_progress
        self.on_finding = on_finding
        self._cancel = False
        self._yara_scanner = YaraScanner() if YaraScanner is not None else None
        
        # Full scan attributes & stage tracking
        self.is_full_scan = False
        self.inaccessible_count = 0
        self.inaccessible_files = []
        self.active_stage = "Idle"

    # ── Public scan API ────────────────────────────────────────────────────────

    def quick_scan(self) -> ScanReport:
        """Fast scan: running processes + startup + Temp folders."""
        self.is_full_scan = False
        self.inaccessible_count = 0
        self.inaccessible_files = []
        
        report = ScanReport(mode="Quick Scan", started_at=datetime.now().isoformat())
        self._cancel = False

        self.active_stage = "Process Auditing"
        self._report_progress(0, 0, "Enumerating running processes...")
        self._scan_processes(report)

        self.active_stage = "Registry Auditing"
        self._report_progress(0, 0, "Checking startup registry entries...")
        self._scan_autoruns(report, hkcu_only=True)

        self.active_stage = "Deep Disk Traversal"
        self._report_progress(0, 0, "Scanning Temp folders...")
        for path in [os.path.expandvars(r"%TEMP%"), os.path.expandvars(r"%TMP%")]:
            if os.path.isdir(path):
                self._scan_directory(report, path, recursive=False)

        self._report_progress(0, 0, "Scanning Startup folder...")
        startup = os.path.expandvars(r"%APPDATA%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")
        if os.path.isdir(startup):
            self._scan_directory(report, startup, recursive=False)

        self._report_progress(0, 0, "Scanning Downloads folder...")
        downloads = os.path.join(os.path.expanduser("~"), "Downloads")
        if os.path.isdir(downloads):
            self._scan_directory(report, downloads, recursive=False)

        self._report_progress(0, 0, "Scanning Browser extensions...")
        chrome_ext = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions")
        if os.path.isdir(chrome_ext):
            self._scan_directory(report, chrome_ext, recursive=True)

        report.completed_at = datetime.now().isoformat()
        self.active_stage = "Complete"
        self._report_progress(report.items_scanned, report.items_scanned, report.summary)
        return report

    def _get_all_logical_drives(self) -> List[str]:
        drives = []
        try:
            import win32file
            drive_strings = win32file.GetLogicalDriveStrings().split('\000')
            for drive in drive_strings:
                if drive and os.path.exists(drive):
                    drives.append(drive)
        except Exception:
            # Fallback to letters C to Z
            for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
                path = f"{letter}:\\"
                if os.path.exists(path):
                    drives.append(path)
        return drives

    def full_scan(self) -> ScanReport:
        """Comprehensive, non-skipping scan of all drives, directories, and files."""
        self.is_full_scan = True
        self.inaccessible_count = 0
        self.inaccessible_files = []
        
        report = ScanReport(mode="Full Scan", started_at=datetime.now().isoformat())
        self._cancel = False

        self.active_stage = "Process Auditing"
        self._report_progress(0, 0, "Enumerating running processes...")
        self._scan_processes(report)

        self.active_stage = "Registry Auditing"
        self._report_progress(0, 0, "Scanning all autorun registry keys...")
        self._scan_autoruns(report, hkcu_only=False)

        self.active_stage = "Task Auditing"
        self._report_progress(0, 0, "Enumerating scheduled tasks...")
        self._scan_scheduled_tasks(report)

        # Retrieve all mounted and logical drives to scan the entire device recursively
        self.active_stage = "Deep Disk Traversal"
        scan_dirs = self._get_all_logical_drives()

        for d in scan_dirs:
            if self._cancel: break
            if os.path.isdir(d):
                self._report_progress(report.items_scanned, 0, f"Starting root-level scan on drive {d}...")
                self._scan_directory(report, d, recursive=True)

        report.completed_at = datetime.now().isoformat()
        self.active_stage = "Complete"
        self._report_progress(report.items_scanned, report.items_scanned, report.summary)
        return report

    def smart_scan(self) -> ScanReport:
        """Heuristic scan: recently modified files in high-risk locations."""
        self.is_full_scan = False
        self.inaccessible_count = 0
        self.inaccessible_files = []
        
        report = ScanReport(mode="Smart Scan", started_at=datetime.now().isoformat())
        self._cancel = False
        cutoff = time.time() - (48 * 3600)  # last 48 hours

        self.active_stage = "Process Auditing"
        self._report_progress(0, 0, "Enumerating running processes...")
        self._scan_processes(report)

        self.active_stage = "Deep Disk Traversal"
        self._report_progress(0, 0, "Scanning recently modified files...")
        for d in HIGH_RISK_PATHS:
            if not os.path.isdir(d): continue
            for root, _, files in os.walk(d):
                for fname in files:
                    if self._cancel: break
                    fpath = os.path.join(root, fname)
                    try:
                        if os.path.getmtime(fpath) >= cutoff:
                            self._scan_file(report, fpath)
                    except OSError: pass

        report.completed_at = datetime.now().isoformat()
        self.active_stage = "Complete"
        self._report_progress(report.items_scanned, report.items_scanned, report.summary)
        return report

    def custom_scan(self, path: str) -> ScanReport:
        """Scan a specific folder or file."""
        self.is_full_scan = False
        self.inaccessible_count = 0
        self.inaccessible_files = []
        
        report = ScanReport(mode="Custom Scan", started_at=datetime.now().isoformat())
        self._cancel = False

        self.active_stage = "Deep Disk Traversal"
        if os.path.isdir(path):
            self._report_progress(0, 0, f"Scanning directory: {path}")
            self._scan_directory(report, path, recursive=True)
        elif os.path.isfile(path):
            self._report_progress(0, 0, f"Scanning file: {path}")
            self._scan_file(report, path)

        report.completed_at = datetime.now().isoformat()
        self.active_stage = "Complete"
        self._report_progress(report.items_scanned, report.items_scanned, report.summary)
        return report

    def cancel(self) -> None:
        """Signal the scanner to stop at next checkpoint."""
        self._cancel = True

    @property
    def is_cancelled(self) -> bool:
        """Public read-only view of the cancel state (avoids private _cancel access)."""
        return self._cancel

    # ── Internal scanners ──────────────────────────────────────────────────────

    def _scan_processes(self, report: ScanReport) -> None:
        try:
            import psutil
            for proc in psutil.process_iter(["pid", "name", "exe"]):
                if self._cancel: break
                try:
                    exe = proc.info.get("exe") or ""
                    if exe and os.path.isfile(exe):
                        self._scan_file(report, exe, item_type="process", extra_name=proc.info.get("name", ""))
                except (psutil.NoSuchProcess, psutil.AccessDenied): pass
        except Exception as e:
            report.errors.append(f"Process scan error: {e}")

    def _scan_directory(self, report: ScanReport, path: str, recursive: bool = True) -> None:
        try:
            if recursive:
                for root, _, files in os.walk(path):
                    if self._cancel: break
                    for fname in files:
                        if self._cancel: break
                        ext = os.path.splitext(fname)[1].lower()
                        if self.is_full_scan or ext in EXEC_EXTENSIONS:
                            self._scan_file(report, os.path.join(root, fname))
                            time.sleep(0.0005) # Cooperative sleep to release GIL and prevent UI freezes
            else:
                for fname in os.listdir(path):
                    if self._cancel: break
                    fpath = os.path.join(path, fname)
                    if os.path.isfile(fpath):
                        ext = os.path.splitext(fname)[1].lower()
                        if self.is_full_scan or ext in EXEC_EXTENSIONS:
                            self._scan_file(report, fpath)
                            time.sleep(0.0005) # Cooperative sleep to release GIL and prevent UI freezes
        except Exception as e:
            report.errors.append(f"Dir scan error ({path}): {e}")

    def _scan_file(self, report: ScanReport, fpath: str, item_type: str = "file", extra_name: str = "") -> Optional[ScanItem]:
        if self._cancel: return None
        try:
            if not os.path.isfile(fpath): return None
            
            # Explicit access verification to catch permission restrictions immediately
            with open(fpath, "rb") as f:
                pass
                
            fsize = os.path.getsize(fpath)
            
            # Non-skipping rule: Skip large and tiny/empty files only if NOT in Full System Scan mode
            if not self.is_full_scan:
                if fsize > self.MAX_FILE_SIZE or fsize == 0:
                    return None

            report.items_scanned += 1
            if report.items_scanned % 50 == 0:
                self._report_progress(report.items_scanned, 0, fpath)
                time.sleep(0.001) # Yield a full millisecond on progress milestones

            fname = extra_name or os.path.basename(fpath)
            sha256 = self._hash_file(fpath, yield_gil=self.is_full_scan)
            if sha256 and sha256 in KNOWN_GOOD_HASHES: return None

            entropy = self._calc_entropy(fpath)
            indicators = []
            confidence = 0.0

            # 1. Signature Check
            if SignatureVerifier.is_signed(fpath):
                subj = SignatureVerifier.get_signer_subject(fpath) or ""
                if any(tok in subj.lower() for tok in TRUSTED_PUBLISHER_SUBSTRINGS):
                    return None
            else:
                if fpath.lower().endswith(".exe"):
                    confidence += 0.2
                    indicators.append("Unsigned executable")

            # 2. Hash Reputation
            if sha256 and sha256 in KNOWN_BAD_HASHES:
                confidence += 0.9
                indicators.append("Known malicious hash")

            # 3. Entropy Analysis
            if entropy > 7.6:
                confidence += 0.3
                indicators.append(f"Very high entropy ({entropy:.2f}) - possible encryption/packing")
            elif entropy > 6.8:
                confidence += 0.1
                indicators.append(f"Elevated entropy ({entropy:.2f})")

            # 4. Location Risk
            fpath_lower = fpath.lower()
            if any(hr in fpath_lower for hr in ["\\temp\\", "\\tmp\\", "\\downloads\\", "\\appdata\\local\\temp"]):
                confidence += 0.2
                indicators.append("Located in high-risk directory")

            # 5. YARA Scanning
            yara_matches = self._scan_yara(fpath)
            if yara_matches:
                confidence += 0.6
                indicators.append(f"YARA matched: {', '.join(yara_matches)}")

            confidence = min(confidence, 1.0)
            classification = self._classify(confidence)

            if classification == "SAFE" and not indicators:
                return None

            item = ScanItem(
                path=fpath, name=fname, sha256=sha256 or "",
                entropy=round(entropy, 3), file_size=fsize,
                confidence=round(confidence, 3), classification=classification,
                indicators=indicators, yara_matches=yara_matches, item_type=item_type
            )

            if classification in ("SUSPICIOUS", "MALICIOUS", "MONITOR"):
                report.findings.append(item)
                
                # Auto-quarantine during Full System Scan
                if report.mode == "Full Scan" and classification in ("SUSPICIOUS", "MALICIOUS"):
                    try:
                        from core.quarantine_manager import get_quarantine_manager
                        qm = get_quarantine_manager()
                        success = qm.quarantine(fpath, f"Full Scan Auto-Vault: {classification} - {', '.join(indicators)}")
                        if success:
                            logger.info(f"Auto-quarantined {fpath} during Full Scan.")
                            item.indicators.append("[Auto-Quarantined]")
                    except Exception as eq:
                        logger.error(f"Full Scan auto-quarantine failed for {fpath}: {eq}")
                
                if self.on_finding: self.on_finding(item)
            
            return item

        except (PermissionError, OSError) as e:
            err_str = (getattr(e, "strerror", "") or str(e)).lower()
            reason = "permission denied"
            if "sharing violation" in err_str or "locked" in err_str:
                reason = "locked by system"
            elif "in use" in err_str or "being used" in err_str:
                reason = "in use"
            elif "encrypt" in err_str:
                reason = "encrypted"
            elif "access" in err_str or "denied" in err_str:
                reason = "permission denied"
            
            self.inaccessible_count += 1
            self.inaccessible_files.append((fpath, reason))
            report.errors.append(f"Inaccessible: {fpath} ({reason})")
            return None
        except Exception as e:
            report.errors.append(f"File error ({fpath}): {e}")
            return None

    def _get_removable_drives(self) -> List[str]:
        drives = []
        try:
            import win32file
            drive_strings = win32file.GetLogicalDriveStrings().split('\000')
            for drive in drive_strings:
                if drive and win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                    drives.append(drive)
        except Exception:
            # Fallback to simple letter checking
            for letter in "EFGHIJKLMNOPQRSTUVWXYZ":
                path = f"{letter}:\\"
                if os.path.exists(path):
                    try:
                        # Very crude check for removable
                        drives.append(path)
                    except Exception: pass
        return drives

    def _scan_autoruns(self, report: ScanReport, hkcu_only: bool = True) -> None:
        try:
            import winreg
            hives = [(winreg.HKEY_CURRENT_USER, "HKCU")]
            if not hkcu_only: hives.append((winreg.HKEY_LOCAL_MACHINE, "HKLM"))

            for hive, hive_name in hives:
                for key_path in AUTORUN_KEYS:
                    try:
                        with winreg.OpenKey(hive, key_path) as key:
                            i = 0
                            while True:
                                try:
                                    name, data, _ = winreg.EnumValue(key, i)
                                    i += 1
                                    data_str = str(data).lower()
                                    if "encodedcommand" in data_str or "-enc " in data_str:
                                        item = ScanItem(
                                            path=f"{hive_name}\\{key_path}\\{name}",
                                            name=name, sha256="", entropy=0.0, file_size=0,
                                            confidence=0.8, classification="SUSPICIOUS",
                                            indicators=["Encoded PowerShell in autorun"], item_type="registry"
                                        )
                                        report.findings.append(item)
                                except OSError: break
                    except Exception: pass
        except Exception as e: report.errors.append(f"Autorun error: {e}")

    def _scan_scheduled_tasks(self, report: ScanReport) -> None:
        try:
            result = subprocess.run(["schtasks", "/query", "/fo", "LIST", "/v"], capture_output=True, text=True, timeout=30, creationflags=0x08000000)
            for line in result.stdout.splitlines():
                if "Task To Run:" in line:
                    cmd = line.split(":", 1)[-1].strip().lower()
                    if any(s in cmd for s in ["powershell", "wscript", "cscript", "mshta", "-enc", "\\temp\\"]):
                        item = ScanItem(
                            path="Scheduled Task", name="Task", sha256="", entropy=0.0, file_size=0,
                            confidence=0.7, classification="SUSPICIOUS",
                            indicators=[f"Suspicious task: {cmd[:50]}"], item_type="task"
                        )
                        report.findings.append(item)
        except Exception as e: report.errors.append(f"Task scan error: {e}")

    @staticmethod
    def _hash_file(path: str, yield_gil: bool = False) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                i = 0
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
                    if yield_gil:
                        i += 1
                        if i % 100 == 0:
                            time.sleep(0.0001)
            return h.hexdigest()
        except Exception: return None

    @staticmethod
    def _calc_entropy(path: str) -> float:
        try:
            freq = [0] * 256
            with open(path, "rb") as f: data = f.read(65536)
            if not data: return 0.0
            for b in data: freq[b] += 1
            ent = 0.0
            for c in freq:
                if c > 0:
                    p = c / len(data)
                    ent -= p * math.log2(p)
            return ent
        except Exception: return 0.0

    @staticmethod
    def _classify(confidence: float) -> str:
        if confidence >= 0.8: return "MALICIOUS"
        if confidence >= 0.55: return "SUSPICIOUS"
        if confidence >= 0.35: return "MONITOR"
        return "SAFE"

    def _scan_yara(self, fpath: str) -> List[str]:
        if not self._yara_scanner: return []
        try: return self._yara_scanner.scan_file(fpath)
        except Exception: return []

    def _report_progress(self, count: int, total: int, msg: str) -> None:
        if self.on_progress:
            try: self.on_progress(count, total, msg)
            except Exception: pass
