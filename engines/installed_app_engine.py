"""
SentinelCore - Installed Application Scanner Engine
Windows: Enumerates installed programs from the registry, verifies digital
signatures, checks publisher trust, computes SHA-256, and scores each app
for suspiciousness without falsely classifying all third-party apps.

Severity scoring (additive, 0-100):
  Unsigned executable           +30
  Unknown/untrusted publisher   +15
  Installed from temp/downloads +20
  VirusTotal positives          up to +40
  ──────────────────────────────────
  < 20 → CLEAN
  20-39 → LOW
  40-59 → MEDIUM
  60-79 → HIGH
  ≥ 80  → CRITICAL

Android: Stub implementation (package list + signature flag).
"""

import os
import sys
import hashlib
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

from core.signature_verifier import SignatureVerifier

logger = logging.getLogger(__name__)

# ─── Trusted publisher substrings (case-insensitive) ──────────────────────────
TRUSTED_PUBLISHERS = {
    "microsoft", "google llc", "google inc", "apple inc", "adobe inc",
    "adobe systems", "oracle", "intel", "nvidia", "amd", "realtek",
    "mozilla", "dropbox", "zoom", "slack", "python software foundation",
    "jetbrains", "canonical", "vmware", "oracle america", "amazon",
    "logitech", "samsung", "lenovo", "hp inc", "dell", "asus", "acer",
    "qualcomm", "broadcom", "marvell", "synaptics", "stmicroelectronics",
    "autodesk", "sony", "panasonic", "epson", "brother", "avast",
    "avg technologies", "eset", "malwarebytes", "bitdefender","kaspersky",
    "norton", "mcafee", "trend micro", "crowdstrike", "sentinel one", "riot games", "videolan", "winrar gmbh", "discord", "valve", "steam", "riot", "epic games",
    "ubisoft", "blizzard", "ea inc", "electronic arts", "spotify", "messenger", "meta platforms", "whatsapp", "telegram", "vlc", "obs project",     "github", "git for windows", "brave",
}

# Registry keys that hold installed application info
UNINSTALL_KEYS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
]

# High-risk install paths
HIGH_RISK_PATH_PARTS = {"temp", "tmp", "downloads", "appdata\\local\\temp"}


@dataclass
class AppScanResult:
    """Result for a single installed application."""
    display_name:   str
    publisher:      str
    install_loc:    str
    exe_path:       str
    sha256:         str
    signed:         bool
    trusted_publisher: bool
    high_risk_location: bool
    vt_score:       float         # 0.0–1.0 (ratio of AV detections)
    vt_details:     str
    severity_score: int           # 0–100
    severity:       str           # SAFE / SUSPICIOUS / MALICIOUS
    detection_reasons: List[str] = field(default_factory=list)
    version:        str = ""
    install_date:   str = ""
    size_mb:        float = 0.0
    action:         str = "None"


class InstalledAppEngine:
    """
    Scans Windows installed applications for suspicious characteristics.
    Uses registry enumeration, digital signature verification, and
    optional VirusTotal lookups (via the existing APIManager).
    """

    CACHE_TTL_SECONDS = 300   # 5-minute result cache

    def __init__(self, api_manager=None, on_progress: Optional[Any] = None):
        self._api         = api_manager
        self._on_progress = on_progress   # callable(current, total, name)
        self._cache:      Optional[List[AppScanResult]] = None
        self._cache_time: float = 0.0
        self._lock        = threading.Lock()

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    def scan(self, force: bool = False, on_progress: Optional[Any] = None) -> List[AppScanResult]:
        """
        Enumerate and score all installed applications.
        Returns cached results if available and TTL not expired.
        """
        with self._lock:
            if (not force and self._cache is not None
                    and (time.time() - self._cache_time) < self.CACHE_TTL_SECONDS):
                logger.info("InstalledAppEngine: returning cached results.")
                return self._cache

        logger.info("InstalledAppEngine: starting installed app scan...")
        entries = self._enumerate_registry()
        results = []
        total   = len(entries)

        prog_cb = on_progress or self._on_progress

        for i, entry in enumerate(entries):
            try:
                if prog_cb:
                    prog_cb(i + 1, total, entry.get("display_name", ""))
                result = self._process_entry(entry)
                if result:
                    results.append(result)
            except Exception as e:
                logger.debug(f"InstalledAppEngine: error processing {entry}: {e}")

        # Sort by severity_score desc
        results.sort(key=lambda r: r.severity_score, reverse=True)

        with self._lock:
            self._cache      = results
            self._cache_time = time.time()

        suspicious = sum(1 for r in results if r.severity != "SAFE")
        logger.info(
            f"InstalledAppEngine: scanned {len(results)} apps, "
            f"{suspicious} suspicious."
        )
        return results

    def clear_cache(self) -> None:
        with self._lock:
            self._cache = None

    # ─────────────────────────────────────────────────────────────────────────
    # Registry enumeration
    # ─────────────────────────────────────────────────────────────────────────

    def _enumerate_registry(self) -> List[Dict]:
        """Return raw info dicts from both HKLM and HKCU uninstall keys."""
        entries: List[Dict] = []
        if sys.platform != "win32":
            logger.warning("InstalledAppEngine: only supported on Windows.")
            return entries

        try:
            import winreg
        except ImportError:
            logger.error("InstalledAppEngine: winreg not available.")
            return entries

        hives = [
            (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
            (winreg.HKEY_CURRENT_USER,  "HKCU"),
        ]

        for hive, hive_name in hives:
            for key_path in UNINSTALL_KEYS:
                try:
                    with winreg.OpenKey(hive, key_path) as reg_key:
                        i = 0
                        while True:
                            try:
                                sub_name = winreg.EnumKey(reg_key, i)
                                i += 1
                                sub_path = f"{key_path}\\{sub_name}"
                                try:
                                    with winreg.OpenKey(hive, sub_path) as sub:
                                        entry = self._read_app_entry(sub, hive_name)
                                        if entry:
                                            entries.append(entry)
                                except Exception:
                                    pass
                            except OSError:
                                break
                except Exception:
                    pass

        # Deduplicate by display_name
        seen = set()
        unique: List[Dict] = []
        for e in entries:
            key = e.get("display_name", "").lower().strip()
            if key and key not in seen:
                seen.add(key)
                unique.append(e)
        return unique

    def _read_app_entry(self, key, hive: str) -> Optional[Dict]:
        """Read all useful values from a single uninstall key."""
        try:
            import winreg

            def _val(name):
                try:
                    v, _ = winreg.QueryValueEx(key, name)
                    return str(v).strip()
                except Exception:
                    return ""

            display_name = _val("DisplayName")
            if not display_name:
                return None             # skip components without a name

            return {
                "display_name":   display_name,
                "publisher":      _val("Publisher"),
                "install_loc":    _val("InstallLocation"),
                "display_icon":   _val("DisplayIcon"),
                "uninstall_str":  _val("UninstallString"),
                "version":        _val("DisplayVersion"),
                "install_date":   _val("InstallDate"),
                "hive":           hive,
            }
        except Exception:
            return None

    # ─────────────────────────────────────────────────────────────────────────
    # Per-app analysis
    # ─────────────────────────────────────────────────────────────────────────

    def _process_entry(self, entry: Dict) -> Optional[AppScanResult]:
        """Run the full analysis pipeline on a single registry entry."""
        display_name = entry.get("display_name", "Unknown")
        publisher    = entry.get("publisher", "")
        install_loc  = entry.get("install_loc", "")

        # Resolve best executable path
        exe_path = self._resolve_exe(entry)

        # Compute hash
        sha256 = ""
        if exe_path and os.path.isfile(exe_path):
            sha256 = self._sha256(exe_path)

        # Digital signature check
        signed = SignatureVerifier.is_signed(exe_path) if exe_path else False

        # Publisher trust
        trusted_pub = self._is_trusted_publisher(publisher)

        # Location risk
        high_risk_loc = self._is_high_risk_location(install_loc or exe_path)

        # VirusTotal lookup (optional, rate-limited)
        vt_score   = 0.0
        vt_details = ""
        if sha256 and self._api:
            try:
                vt_result  = self._api.lookup_hash(sha256)
                vt_score   = vt_result.score if vt_result else 0.0
                vt_details = vt_result.details if vt_result else ""
            except Exception:
                pass

        # Severity scoring
        score   = 0
        reasons = []

        is_standard_path = "program files" in (install_loc or exe_path).lower()

        if trusted_pub:
            pass # Trusted vendors are not penalized for being untrusted
        else:
            if not publisher:
                if not is_standard_path:
                    score += 10
                    reasons.append("No publisher information")
            else:
                # Lower penalty for unknown publishers in standard paths
                penalty = 5 if is_standard_path else 15
                score += penalty
                reasons.append(f"Publisher not in trusted list: '{publisher}'")

        if exe_path and os.path.isfile(exe_path) and not signed:
            if trusted_pub:
                score += 5
                reasons.append("Executable is unsigned (trusted vendor)")
            else:
                # Lower penalty if in standard path
                penalty = 15 if is_standard_path else 30
                score += penalty
                reasons.append("Executable is unsigned")

        if high_risk_loc:
            score += 25
            reasons.append("Installed from high-risk location (temp/downloads)")

        if vt_score > 0:
            vt_points = min(int(vt_score * 50), 50)
            score += vt_points
            reasons.append(f"VirusTotal detections: {vt_score:.2f} ({vt_points} pts)")

        # Cap at 100
        score = min(score, 100)
        
        if score < 30:
            severity = "SAFE"
        elif score < 65:
            severity = "SUSPICIOUS"
        else:
            severity = "MALICIOUS"

        # Special case: if it's signed OR a trusted pub, and score is borderline, mark safe
        if (signed or trusted_pub) and score < 40:
            severity = "SAFE"
            score = 0
            reasons = []

        # Only flag if at least one real reason beyond missing publisher
        if not reasons or (len(reasons) == 1 and "publisher" in reasons[0].lower() and score < 20):
            severity = "SAFE"
            score    = 0
            reasons  = []

        # Determine action taken
        action = "Verified"
        if severity == "MALICIOUS":
            action = "Threat Detected"
        elif severity == "SUSPICIOUS":
            action = "Needs Review"
        elif severity == "SAFE":
            action = "Verified"

        return AppScanResult(
            display_name      = display_name,
            publisher         = publisher or "(unknown)",
            install_loc       = install_loc or "(unknown)",
            exe_path          = exe_path or "",
            sha256            = sha256,
            signed            = signed,
            trusted_publisher = trusted_pub,
            high_risk_location= high_risk_loc,
            vt_score          = vt_score,
            vt_details        = vt_details,
            severity_score    = score,
            severity          = severity,
            detection_reasons = reasons,
            version           = entry.get("version", ""),
            install_date      = entry.get("install_date", ""),
            size_mb           = self._get_dir_size_mb(install_loc) if install_loc else 0.0,
            action            = action,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _resolve_exe(self, entry: Dict) -> str:
        """Try to find the main executable path from registry info."""
        # 1. InstallLocation + any .exe found there
        loc = entry.get("install_loc", "").strip().strip('"')
        if loc and os.path.isdir(loc):
            for fname in os.listdir(loc):
                if fname.lower().endswith(".exe"):
                    candidate = os.path.join(loc, fname)
                    if os.path.isfile(candidate):
                        return candidate

        # 2. DisplayIcon (often points to executable)
        icon = entry.get("display_icon", "").strip().strip('"').split(",")[0].strip()
        if icon and icon.lower().endswith(".exe") and os.path.isfile(icon):
            return icon

        # 3. UninstallString prefix
        uninstall = entry.get("uninstall_str", "").strip().strip('"')
        if uninstall:
            parts = uninstall.split('"')
            for p in parts:
                p = p.strip()
                if p.lower().endswith(".exe") and os.path.isfile(p):
                    return p

        return ""

    @staticmethod
    def _sha256(path: str) -> str:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    @staticmethod
    def _is_trusted_publisher(publisher: str) -> bool:
        if not publisher:
            return False
        pub_lower = publisher.lower()
        return any(tp in pub_lower for tp in TRUSTED_PUBLISHERS)

    @staticmethod
    def _is_high_risk_location(path: str) -> bool:
        if not path:
            return False
        path_lower = path.lower().replace("\\", "/")
        return any(part in path_lower for part in HIGH_RISK_PATH_PARTS)

    @staticmethod
    def _get_dir_size_mb(path: str) -> float:
        # Avoid heavy recursive os.walk which blocks disks and slows down scanning
        try:
            if os.path.isdir(path):
                # Just sum the size of files in the top-level directory (non-recursive)
                total = 0
                for f in os.listdir(path):
                    fpath = os.path.join(path, f)
                    if os.path.isfile(fpath):
                        total += os.path.getsize(fpath)
                return round(total / (1024 * 1024), 2)
            elif os.path.isfile(path):
                return round(os.path.getsize(path) / (1024 * 1024), 2)
        except Exception:
            pass
        return 0.1  # small fallback value


# ─── Android stub ─────────────────────────────────────────────────────────────

@dataclass
class AndroidAppResult:
    package_name: str
    signed:       bool
    store_install: bool   # True if installed from official store
    severity:     str     # CLEAN / LOW / HIGH
    reason:       str


class AndroidAppEngine:
    """
    Stub for Android app scanning. On real Android (Kivy/buildozer build),
    replace _get_packages() with the Pyjnius implementation.
    """

    def scan(self) -> List[AndroidAppResult]:
        packages = self._get_packages()
        results  = []
        for pkg in packages:
            signed       = pkg.get("signed",        True)
            store_install= pkg.get("store_install",  True)
            severity     = "CLEAN"
            reason       = ""
            if not signed:
                severity = "HIGH"
                reason   = "Package is unsigned"
            elif not store_install:
                severity = "LOW"
                reason   = "Installed outside official store"
            results.append(AndroidAppResult(
                package_name  = pkg["name"],
                signed        = signed,
                store_install = store_install,
                severity      = severity,
                reason        = reason,
            ))
        return results

    def _get_packages(self) -> List[Dict]:
        """
        On real Android, replace with:
          from jnius import autoclass
          PackageManager = autoclass("android.content.pm.PackageManager")
          ...
        """
        return []   # stub — no packages on desktop


# ─── Helpers ──────────────────────────────────────────────────────────────────

