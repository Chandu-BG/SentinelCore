"""
SentinelCore - File Protection Engine (v3 — Professional Detection)
Real file scanning integrated with:
  - EntropyEngine    : Shannon entropy (0–8) with 4-tier classification
  - ThreatScoreEngine: 8-signal weighted formula → 0–100 score + severity
  - APIManager       : VirusTotal + AbuseIPDB lookups (cached)
  - AIRemediationEngine: Context-aware explanation and remediation advice
  - Watchdog real-time monitoring
  - Quarantine & Rollback
  - Permission-gated (file_monitoring required)
  - Multi-signal safety guard before auto-remediation (≥2 signals)
"""

import os
import time
import shutil
import json
import hashlib
import logging
import threading
from collections import deque
from datetime import datetime
from typing import List, Optional, Callable, Dict, Any

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from database.init_db import log_threat, log_system_event
from engines.entropy_engine import EntropyEngine
from engines.threat_score_engine import ThreatScoreEngine, ThreatSignals
from engines.api_manager import APIManager
from engines.ai_remediation_engine import AIRemediationEngine
from core.quarantine_manager import get_quarantine_manager

logger = logging.getLogger(__name__)

BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUARANTINE_BASE = os.path.join(BASE_DIR, "quarantine")
QUARANTINE_ENC_DIR = os.path.join(QUARANTINE_BASE, "encrypted")
QUARANTINE_META_DIR = os.path.join(QUARANTINE_BASE, "metadata")

SUSPICIOUS_EXEC_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".pif", ".com",
    ".vbs", ".js", ".jse", ".wsf", ".bat",
    ".ps1", ".cmd", ".msi",
}
SENSITIVE_EXTENSIONS = {
    ".doc", ".docx", ".pdf", ".xls", ".xlsx", ".csv",
    ".key", ".pem", ".p12", ".pfx", ".db", ".sqlite",
    ".kdb", ".kdbx", ".wallet", ".env", ".config",
}

# Locations treated as high-risk for executable presence
HIGH_RISK_DIRS = {"temp", "tmp", "appdata", "downloads", "public", "programdata"}

# ── Hard size limit for on-demand scan ────────────────────────────────────────
MAX_SCAN_FILE_BYTES = 500 * 1024 * 1024  # 500 MB


def compute_sha256(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def _is_hidden(path: str) -> bool:
    """Return True if file has hidden or system attribute (Windows)."""
    try:
        import ctypes
        attrs = ctypes.windll.kernel32.GetFileAttributesW(path)  # type: ignore
        if attrs == -1:
            return False
        FILE_ATTRIBUTE_HIDDEN = 0x2
        FILE_ATTRIBUTE_SYSTEM = 0x4
        return bool(attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))
    except Exception:
        return False


def _location_risk(path: str) -> float:
    """Return 1.0 if file is in a high-risk directory, else 0.0."""
    parts = path.lower().replace("\\", "/").split("/")
    return 1.0 if any(part in HIGH_RISK_DIRS for part in parts) else 0.0


class _SentinelEventHandler(FileSystemEventHandler):
    def __init__(self, engine: "FileEngine"):
        super().__init__()
        self.engine = engine

    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            self.engine._handle_event("modified", event.src_path)

    def on_deleted(self, event: FileSystemEvent):
        self.engine._handle_event("deleted", event.src_path)

    def on_created(self, event: FileSystemEvent):
        if not event.is_directory:
            self.engine._handle_event("created", event.src_path)

    def on_moved(self, event: FileSystemEvent):
        self.engine._handle_event("moved", event.src_path)


class FileEngine:
    """
    Real-time file monitoring, on-demand scanning, quarantine & restore.
    Fully integrated with professional detection engines.
    """

    MASS_ACCESS_WINDOW_SEC = 10
    MASS_ACCESS_THRESHOLD  = 30

    def __init__(
        self,
        watch_paths:         Optional[List[str]] = None,
        permissions_engine=  None,
        on_alert:            Optional[Callable[[str, str, str], None]] = None,
        on_scan_result:      Optional[Callable[[Dict], None]] = None,
        entropy_engine:      Optional[EntropyEngine]         = None,
        threat_score_engine: Optional[ThreatScoreEngine]     = None,
        api_manager:         Optional[APIManager]            = None,
        ai_remediation:      Optional[AIRemediationEngine]   = None,
    ):
        if watch_paths is None:
            watch_paths = self._default_watch_paths()
        self.watch_paths         = [p for p in watch_paths if os.path.isdir(p)]
        self._permissions        = permissions_engine
        self.on_alert            = on_alert
        self.on_scan_result      = on_scan_result

        # Integrated detection engines (all optional — graceful fallback)
        self._entropy    = entropy_engine      or EntropyEngine()
        self._ts_engine  = threat_score_engine or ThreatScoreEngine()
        self._api        = api_manager         or APIManager()
        self._ai_remed   = ai_remediation      or AIRemediationEngine()

        self._observer: Optional[Observer] = None
        self._running   = False
        self._event_times: deque = deque()
        self._lock = threading.Lock()

        # Stats
        self.total_events:    int = 0
        self.alerts_fired:    int = 0
        self.files_scanned:   int = 0
        self.threats_found:   int = 0
        self.last_scan_result: str = "No scan run yet"

        self._file_sizes: Dict[str, int] = {}
        self._quarantine = get_quarantine_manager()

    # ─────────────────────────────────────────────────────────────────────────
    # Permission gate
    # ─────────────────────────────────────────────────────────────────────────

    def _permitted(self) -> bool:
        if self._permissions is None:
            return True
        return self._permissions.is_enabled("file_monitoring")

    # ─────────────────────────────────────────────────────────────────────────
    # Lifecycle
    # ─────────────────────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._running:
            return
        if not self._permitted():
            logger.info("FileEngine: blocked by permissions.")
            return
        self._running = True
        self._observer = Observer()
        handler = _SentinelEventHandler(self)
        for path in self.watch_paths:
            try:
                self._observer.schedule(handler, path, recursive=True)
                logger.info(f"FileEngine: watching '{path}'")
            except Exception as e:
                logger.error(f"Cannot watch '{path}': {e}")
        self._observer.start()
        logger.info("FileEngine started.")

    def stop(self) -> None:
        self._running = False
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=3)
        logger.info("FileEngine stopped.")

    def add_watch_path(self, path: str) -> None:
        if os.path.isdir(path) and path not in self.watch_paths:
            self.watch_paths.append(path)
            if self._observer and self._running:
                self._observer.schedule(_SentinelEventHandler(self), path, recursive=True)

    # ─────────────────────────────────────────────────────────────────────────
    # Real-time event handling
    # ─────────────────────────────────────────────────────────────────────────

    def _handle_event(self, event_type: str, file_path: str) -> None:
        if not self._permitted():
            return

        with self._lock:
            now = time.time()
            self._event_times.append(now)
            while (self._event_times and
                   (now - self._event_times[0]) > self.MASS_ACCESS_WINDOW_SEC):
                self._event_times.popleft()
            event_count = len(self._event_times)
            self.total_events += 1

        # Ransomware: mass access pattern
        if event_count >= self.MASS_ACCESS_THRESHOLD:
            self._fire_alert(
                "MASS_FILE_ACCESS", file_path,
                f"Mass file access: {event_count} events in "
                f"{self.MASS_ACCESS_WINDOW_SEC}s — possible ransomware",
                severity="high",
            )

        ext = os.path.splitext(file_path)[1].lower()

        # Sensitive file touched
        if ext in SENSITIVE_EXTENSIONS and event_type in ("modified", "deleted", "moved"):
            self._fire_alert(
                f"SENSITIVE_FILE_{event_type.upper()}", file_path,
                f"Sensitive file {event_type}: {file_path}",
                severity="medium",
            )

        # Executable created in user directories
        if ext in SUSPICIOUS_EXEC_EXTENSIONS and event_type == "created":
            threading.Thread(
                target=self._deep_scan_file,
                args=(file_path,),
                daemon=True,
            ).start()

        # Ransomware size change
        if event_type == "modified" and os.path.isfile(file_path):
            try:
                new_size = os.path.getsize(file_path)
                old_size = self._file_sizes.get(file_path, new_size)
                if (old_size > 0 and new_size > old_size * 1.5
                        and ext in SENSITIVE_EXTENSIONS):
                    self._fire_alert(
                        "RAPID_SIZE_INCREASE", file_path,
                        f"File grew {new_size - old_size:,} bytes rapidly: "
                        f"{file_path} — possible ransomware encryption",
                        severity="high",
                    )
                self._file_sizes[file_path] = new_size
            except OSError:
                pass

        if event_type == "deleted":
            log_threat("FILE_DELETED", f"File deleted: {file_path}", severity="low")

    def _fire_alert(self, alert_type: str, path: str,
                    description: str, severity: str = "high") -> None:
        self.alerts_fired += 1
        log_threat(alert_type, description, severity=severity)
        if self.on_alert:
            self.on_alert(alert_type, path, description)
        logger.warning(f"[FILE] {alert_type}: {description}")

    # ─────────────────────────────────────────────────────────────────────────
    # Deep single-file scan (entropy + threat score + API + AI)
    # ─────────────────────────────────────────────────────────────────────────

    def _deep_scan_file(self, file_path: str) -> Optional[Dict]:
        """Run the full detection pipeline on a single file."""
        if not os.path.isfile(file_path):
            return None
        try:
            fsize = os.path.getsize(file_path)
        except OSError:
            return None

        ext      = os.path.splitext(file_path)[1].lower()
        sha256   = compute_sha256(file_path)
        entropy_result = self._entropy.analyze(file_path)
        vt_result      = self._api.lookup_hash(sha256) if sha256 else None

        signals = ThreatSignals(
            hash_match     = 0.0,
            vt_score       = vt_result.score if vt_result else 0.0,
            ip_reputation  = 0.0,
            entropy_score  = entropy_result.normalized,
            suspicious_ext = 1.0 if ext in SUSPICIOUS_EXEC_EXTENSIONS else 0.0,
            hidden_flag    = 1.0 if _is_hidden(file_path) else 0.0,
            location_risk  = _location_risk(file_path),
            behavior_score = 0.0,
            file_name      = os.path.basename(file_path),
            sha256         = sha256 or "",
            entropy        = entropy_result.entropy,
            file_size      = fsize,
        )

        result  = self._ts_engine.compute(signals)
        advice  = self._ai_remed.explain(
            signals_dict     = {k: getattr(signals, k, 0.0)
                                for k in ["hash_match","vt_score","ip_reputation",
                                          "entropy_score","suspicious_ext",
                                          "hidden_flag","location_risk","behavior_score"]},
            contributions    = result.signal_contributions,
            dominant_signals = result.dominant_signals,
            severity         = result.severity,
            threat_score     = result.score,
            file_name        = signals.file_name,
            sha256           = signals.sha256,
            entropy          = entropy_result.entropy,
        )

        scan_detail = {
            "path":              file_path,
            "sha256":            sha256,
            "entropy":           entropy_result.entropy,
            "entropy_label":     entropy_result.label,
            "threat_score":      result.score,
            "severity":          result.severity,
            "signal_contributions": result.signal_contributions,
            "dominant_signals":  result.dominant_signals,
            "active_signals":    result.active_signals,
            "auto_remediate":    result.auto_remediate,
            "ai_explanation":    advice.explanation,
            "ai_actions":        advice.actions,
            "ai_prevention":     advice.prevention,
        }

        log_threat(
            f"FILE_THREAT_{result.severity}",
            f"{os.path.basename(file_path)} | score={result.score:.1f} "
            f"| entropy={entropy_result.entropy:.3f} | SHA256={sha256 or 'N/A'}",
            severity=result.severity.lower(),
        )

        if self.on_alert:
            self.on_alert(
                f"THREAT_{result.severity}",
                file_path,
                f"[{result.severity}] Score={result.score:.0f}/100 "
                f"entropy={entropy_result.entropy:.2f} — {os.path.basename(file_path)}",
            )

        if self.on_scan_result:
            self.on_scan_result(scan_detail)

        # Auto-quarantine only if ≥2 independent signals fired
        if result.auto_remediate and result.score >= 75:
            self.quarantine_file(
                file_path,
                reason=f"Auto-quarantine: score={result.score:.1f} "
                       f"severity={result.severity} signals={result.active_signals}",
            )

        return scan_detail

    # ─────────────────────────────────────────────────────────────────────────
    # On-demand full directory scan
    # ─────────────────────────────────────────────────────────────────────────

    def scan_directory(
        self,
        path:        str,
        recursive:   bool = True,
        progress_cb: Optional[Callable[[int, int, str], None]] = None,
    ) -> Dict:
        if not self._permitted():
            return {"error": "File Monitoring permission is disabled."}

        results = {
            "path":            path,
            "started_at":      datetime.now().isoformat(),
            "files_scanned":   0,
            "threats_found":   0,
            "threat_details":  [],
            "high_entropy":    [],
            "suspicious_exe":  [],
            "errors":          [],
        }

        # Collect files
        all_files: List[str] = []
        try:
            if recursive:
                for root, dirs, files in os.walk(path):
                    dirs[:] = [d for d in dirs if not d.startswith('.')]
                    for fname in files:
                        all_files.append(os.path.join(root, fname))
            else:
                all_files = [
                    os.path.join(path, f)
                    for f in os.listdir(path)
                    if os.path.isfile(os.path.join(path, f))
                ]
        except PermissionError as e:
            results["errors"].append(str(e))
            return results

        total = len(all_files)
        logger.info(f"FileEngine: scanning {total} files in {path}")

        for i, fpath in enumerate(all_files):
            try:
                if not os.path.isfile(fpath):
                    continue

                if progress_cb and i % 10 == 0:
                    progress_cb(i, total, fpath)

                fsize = os.path.getsize(fpath)
                if fsize > MAX_SCAN_FILE_BYTES:
                    continue

                results["files_scanned"] += 1
                ext    = os.path.splitext(fpath)[1].lower()
                sha256 = compute_sha256(fpath)
                if not sha256:
                    continue

                # ── Entropy ───────────────────────────────────────────────
                er = self._entropy.analyze(fpath)

                # ── API lookup (non-blocking, cached) ─────────────────────
                vt_result = self._api.lookup_hash(sha256)

                # ── Compute all signals ───────────────────────────────────
                signals = ThreatSignals(
                    hash_match     = 0.0,
                    vt_score       = vt_result.score,
                    ip_reputation  = 0.0,
                    entropy_score  = er.normalized,
                    suspicious_ext = 1.0 if ext in SUSPICIOUS_EXEC_EXTENSIONS else 0.0,
                    hidden_flag    = 1.0 if _is_hidden(fpath) else 0.0,
                    location_risk  = _location_risk(fpath),
                    behavior_score = 0.0,
                    file_name      = os.path.basename(fpath),
                    sha256         = sha256,
                    entropy        = er.entropy,
                    file_size      = fsize,
                )

                tr = self._ts_engine.compute(signals)

                # ── Collect results ───────────────────────────────────────
                if er.is_suspicious:
                    results["high_entropy"].append({
                        "path":    fpath,
                        "entropy": er.entropy,
                        "label":   er.label,
                        "sha256":  sha256,
                        "size":    fsize,
                    })

                if ext in SUSPICIOUS_EXEC_EXTENSIONS:
                    results["suspicious_exe"].append({
                        "path":    fpath,
                        "sha256":  sha256,
                        "entropy": er.entropy,
                        "size":    fsize,
                    })

                if tr.score >= 26:      # MEDIUM or above
                    results["threats_found"] += 1

                    # AI remediation advice
                    advice = self._ai_remed.explain(
                        signals_dict     = {k: getattr(signals, k, 0.0)
                                            for k in ["hash_match","vt_score",
                                                      "ip_reputation","entropy_score",
                                                      "suspicious_ext","hidden_flag",
                                                      "location_risk","behavior_score"]},
                        contributions    = tr.signal_contributions,
                        dominant_signals = tr.dominant_signals,
                        severity         = tr.severity,
                        threat_score     = tr.score,
                        file_name        = signals.file_name,
                        sha256           = sha256,
                        entropy          = er.entropy,
                    )

                    detail = {
                        "path":               fpath,
                        "file_name":          os.path.basename(fpath),
                        "sha256":             sha256,
                        "entropy":            er.entropy,
                        "entropy_label":      er.label,
                        "threat_score":       tr.score,
                        "severity":           tr.severity,
                        "signal_contributions": tr.signal_contributions,
                        "dominant_signals":   tr.dominant_signals,
                        "active_signals":     tr.active_signals,
                        "auto_remediate":     tr.auto_remediate,
                        "vt_score":           vt_result.score,
                        "vt_details":         vt_result.details,
                        "ai_explanation":     advice.explanation,
                        "ai_actions":         advice.actions,
                        "ai_prevention":      advice.prevention,
                    }
                    results["threat_details"].append(detail)

                    log_threat(
                        f"SCAN_THREAT_{tr.severity}",
                        f"{os.path.basename(fpath)} score={tr.score:.1f} "
                        f"entropy={er.entropy:.3f} sha256={sha256}",
                        severity=tr.severity.lower(),
                    )

                    if self.on_alert:
                        self.on_alert(
                            f"SCAN_{tr.severity}",
                            fpath,
                            f"[{tr.severity}] {os.path.basename(fpath)} "
                            f"score={tr.score:.0f}/100 entropy={er.entropy:.2f}",
                        )

                    if self.on_scan_result:
                        self.on_scan_result(detail)

                    # Auto-quarantine HIGH/CRITICAL with multi-signal guard
                    if tr.auto_remediate and tr.score >= 75:
                        self.quarantine_file(
                            fpath,
                            reason=f"score={tr.score:.1f} severity={tr.severity}",
                        )

            except (PermissionError, OSError) as e:
                results["errors"].append(f"{fpath}: {e}")

        results["completed_at"] = datetime.now().isoformat()
        self.files_scanned += results["files_scanned"]
        self.threats_found += results["threats_found"]
        self.last_scan_result = (
            f"Scanned {results['files_scanned']} files — "
            f"{results['threats_found']} threats found"
        )

        if progress_cb:
            progress_cb(total, total, "Complete")

        log_system_event(
            "SCAN_COMPLETE",
            f"Scan of {path}: {results['files_scanned']} files, "
            f"{results['threats_found']} threats",
            "info",
        )
        logger.info(self.last_scan_result)
        return results

    # ─────────────────────────────────────────────────────────────────────────
    # Quarantine / Restore
    # ─────────────────────────────────────────────────────────────────────────

    def quarantine_file(self, file_path: str, reason: str = "") -> bool:
        return self._quarantine.quarantine(file_path, reason)

    def restore_from_quarantine(self, vault_path: str) -> bool:
        return self._quarantine.restore(vault_path)

    def delete_from_quarantine(self, vault_path: str) -> bool:
        return self._quarantine.delete(vault_path)

    def list_quarantine(self) -> List[Dict]:
        return self._quarantine.list_all()

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _default_watch_paths() -> List[str]:
        home = os.path.expanduser("~")
        candidates = [
            os.path.join(home, "Documents"),
            os.path.join(home, "Desktop"),
            os.path.join(home, "Downloads"),
        ]
        return [p for p in candidates if os.path.isdir(p)]
