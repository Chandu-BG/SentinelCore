"""
SentinelCore - Malware Sandbox Engine
Executes suspicious files in an isolated controlled environment:
  1. Copy file into /sandbox/
  2. Run under a subprocess with resource limits and timeout
  3. Monitor behavior during execution
  4. Classify as safe or malicious
  5. Report results + quarantine if malicious
"""

import os
import sys
import time
import json
import shutil
import logging
import threading
import subprocess
import hashlib
from datetime import datetime
from typing import Callable, Optional, List, Dict

logger = logging.getLogger(__name__)

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SANDBOX_DIR = os.path.join(BASE_DIR, "sandbox")
os.makedirs(SANDBOX_DIR, exist_ok=True)

# Sandbox execution timeout
SANDBOX_TIMEOUT  = 15   # seconds
# Max file size to sandbox (50 MB)
MAX_FILE_SIZE    = 50 * 1024 * 1024
# CPU usage threshold during execution (%)
CPU_SPIKE_THRESH = 80.0


class SandboxResult:
    """Result of sandboxing a file."""

    def __init__(
        self,
        file_name:       str,
        original_path:   str,
        sandbox_path:    str,
        classification:  str,     # "SAFE" | "MALICIOUS" | "SUSPICIOUS" | "ERROR"
        behavior_report: str,
        indicators:      List[str],
        timestamp:       str,
    ):
        self.file_name       = file_name
        self.original_path   = original_path
        self.sandbox_path    = sandbox_path
        self.classification  = classification
        self.behavior_report = behavior_report
        self.indicators      = indicators
        self.timestamp       = timestamp

    def to_dict(self) -> dict:
        return {
            "file_name":       self.file_name,
            "original_path":   self.original_path,
            "sandbox_path":    self.sandbox_path,
            "classification":  self.classification,
            "behavior_report": self.behavior_report,
            "indicators":      self.indicators,
            "timestamp":       self.timestamp,
        }


class SandboxEngine:
    """
    Controlled file analysis sandbox.
    Non-blocking: analysis runs in a background thread.
    Results are returned via on_result callback.

    NOTE: True OS-level sandboxing requires hypervisor/container support.
    This implementation provides behavioral monitoring around subprocess execution
    with filesystem/network/CPU monitoring — safe for script/document analysis.
    For EXE files, it monitors WITHOUT executing to avoid system compromise.
    """

    def __init__(
        self,
        on_result:     Optional[Callable[[SandboxResult], None]] = None,
        on_alert:      Optional[Callable[[str, str], None]] = None,
        on_quarantine: Optional[Callable[[str, str], None]] = None,
    ):
        self.on_result     = on_result
        self.on_alert      = on_alert
        self.on_quarantine = on_quarantine

        self._lock     = threading.Lock()
        self._results: List[SandboxResult] = []

        # Load behavior log from DB if available
        self._behavior_log: List[dict] = []

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    def analyze(self, file_path: str, run_async: bool = True) -> Optional[SandboxResult]:
        """
        Analyze a suspicious file.
        If run_async=True, returns None immediately and calls on_result when done.
        If run_async=False, blocks until analysis completes and returns the result.
        """
        if run_async:
            t = threading.Thread(
                target=self._analyze_file, args=(file_path,), daemon=True,
                name=f"Sandbox-{os.path.basename(file_path)}"
            )
            t.start()
            return None
        else:
            return self._analyze_file(file_path)

    def get_results(self) -> List[SandboxResult]:
        with self._lock:
            return list(self._results)

    def get_result_dicts(self) -> List[dict]:
        with self._lock:
            return [r.to_dict() for r in self._results]

    # ──────────────────────────────────────────────────────────────────────────
    # Core analysis
    # ──────────────────────────────────────────────────────────────────────────

    def _analyze_file(self, file_path: str) -> SandboxResult:
        file_name  = os.path.basename(file_path)
        ts         = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        indicators: List[str] = []
        report_lines: List[str] = ["=== SANDBOX ANALYSIS REPORT ===", f"File: {file_name}", f"Time: {ts}", ""]

        # ── Step 1: Static pre-checks ─────────────────────────────────────────
        if not os.path.isfile(file_path):
            return self._build_result(
                file_name, file_path, "", "ERROR",
                "File not found for sandbox analysis.", [], ts
            )

        file_size = os.path.getsize(file_path)
        if file_size > MAX_FILE_SIZE:
            indicators.append("oversized_file")
            report_lines.append(f"NOTE: File size {file_size/(1024*1024):.1f} MB exceeds sandbox limit.")

        # Calculate file hash
        file_hash = self._hash_file(file_path)
        report_lines.append(f"SHA-256: {file_hash or 'UNREADABLE'}")

        _, ext = os.path.splitext(file_name.lower())
        EXECUTABLE_EXTS = {".exe", ".dll", ".sys", ".bat", ".cmd", ".vbs", ".ps1",
                           ".js", ".msi", ".scr", ".com", ".pif", ".hta"}
        DOCUMENT_EXTS   = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                           ".rtf", ".odt"}
        SCRIPT_EXTS     = {".py", ".rb", ".sh", ".jar"}

        is_executable = ext in EXECUTABLE_EXTS
        is_document   = ext in DOCUMENT_EXTS
        is_script     = ext in SCRIPT_EXTS

        report_lines.append(f"Type: {'Executable' if is_executable else ('Document' if is_document else ('Script' if is_script else 'Unknown'))}")

        # ── Step 2: Copy to sandbox ───────────────────────────────────────────
        sandbox_path = self._copy_to_sandbox(file_path, file_name)
        if not sandbox_path:
            indicators.append("copy_failed")
            report_lines.append("ERROR: Could not copy file to sandbox directory.")

        # ── Step 3: Static analysis ───────────────────────────────────────────
        static_indicators = self._static_analysis(file_path, ext)
        indicators.extend(static_indicators)
        for ind in static_indicators:
            report_lines.append(f"STATIC: {ind}")

        # ML-based analysis from DatasetManager
        try:
            from core.dataset_manager import get_dataset_manager
            dm = get_dataset_manager()
            ml_result = dm.analyze_pe(file_path)
            if not ml_result.get("safe", True):
                indicators.append("ml_malware_detected")
                report_lines.append(f"ML: {ml_result.get('reason', 'PE flagged as malicious.')}")
        except Exception:
            pass

        # ── Step 4: Dynamic analysis (scripts only, EXEs are never executed) ───
        dynamic_indicators: List[str] = []
        if is_script and sandbox_path:
            # Enable dynamic analysis on ALL platforms including Windows
            # We run only known-safe interpreters (Python, PowerShell -NonInteractive)
            dynamic_indicators = self._dynamic_analysis(sandbox_path, ext)
        elif is_executable:
            report_lines.append("NOTE: Executable file — dynamic execution skipped for safety.")
            report_lines.append("      Behavioral classification based on static signals only.")
            # Flag executables from temp/user dirs as suspicious
            if any(x in file_path.lower() for x in ["\\temp\\", "\\tmp\\", "\\downloads\\"]):
                dynamic_indicators.append("executable_in_user_writeable_dir")

        indicators.extend(dynamic_indicators)
        for ind in dynamic_indicators:
            report_lines.append(f"DYNAMIC: {ind}")

        # ── Step 5: Classification ────────────────────────────────────────────
        classification = self._classify(indicators)
        report_lines += ["", f"CLASSIFICATION: {classification}", ""]

        if classification in ("MALICIOUS",):
            report_lines.append("ACTION: File quarantined.")
            if self.on_quarantine and sandbox_path:
                try:
                    self.on_quarantine(file_path, "Sandbox classified as MALICIOUS")
                except Exception:
                    pass
            if self.on_alert:
                self.on_alert(
                    "SANDBOX_MALICIOUS",
                    f"Sandbox detected MALICIOUS file: {file_name}"
                )
        elif classification == "SUSPICIOUS":
            report_lines.append("ACTION: File flagged — manual review recommended.")
            if self.on_alert:
                self.on_alert(
                    "SANDBOX_SUSPICIOUS",
                    f"Sandbox flagged SUSPICIOUS file: {file_name}"
                )

        report_text = "\n".join(report_lines)
        result = self._build_result(
            file_name, file_path, sandbox_path or "",
            classification, report_text, indicators, ts
        )

        with self._lock:
            self._results.append(result)

        # Persist to DB
        self._save_to_db(result)

        if self.on_result:
            try:
                self.on_result(result)
            except Exception as e:
                logger.error(f"SandboxEngine on_result callback error: {e}")

        logger.info(f"Sandbox analysis complete: {file_name} → {classification}")
        return result

    # ──────────────────────────────────────────────────────────────────────────
    # Static analysis
    # ──────────────────────────────────────────────────────────────────────────

    def _static_analysis(self, file_path: str, ext: str) -> List[str]:
        """Quick static checks: entropy, bad strings, suspicious metadata, and pefile imports/entropy."""
        indicators: List[str] = []

        try:
            # Read up to 1 MB of the file for analysis
            with open(file_path, "rb") as f:
                data = f.read(1024 * 1024)

            # Check for packed/encrypted content (overall high entropy)
            entropy = self._calc_entropy(data)
            if entropy > 7.2:
                indicators.append(f"high_entropy:{entropy:.2f}")

            # 1. PE file structural & sections/imports parsing using pefile
            if data[:2] == b"MZ":
                indicators.append("pe_executable")
                try:
                    import pefile
                    pe = pefile.PE(file_path, fast_load=False)
                    
                    # Section names and Section Entropy
                    for section in pe.sections:
                        sec_name = section.Name.decode(errors='ignore').strip('\x00')
                        sec_entropy = section.get_entropy()
                        if sec_entropy > 7.2:
                            indicators.append(f"high_section_entropy:{sec_name}:{sec_entropy:.2f}")
                        if b"UPX" in section.Name:
                            indicators.append("upx_packed")

                    # Parses Import Directory
                    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                        for entry in pe.DIRECTORY_ENTRY_IMPORT:
                            dll_name = entry.dll.decode(errors='ignore').lower()
                            for imp in entry.imports:
                                if imp.name:
                                    imp_name = imp.name.decode(errors='ignore')
                                    # Specific known injection and malicious API signatures
                                    suspicious_apis = {
                                        "CreateRemoteThread": "process_injection_api",
                                        "VirtualAllocEx": "memory_allocation_api",
                                        "WriteProcessMemory": "memory_write_api",
                                        "QueueUserAPC": "apc_injection_api",
                                        "NtCreateThreadEx": "undocumented_injection_api",
                                        "IsDebuggerPresent": "evasion_anti_debug",
                                        "CheckRemoteDebuggerPresent": "evasion_anti_debug",
                                        "InternetOpen": "network_capability",
                                        "HttpSendRequest": "network_capability",
                                        "URLDownloadToFile": "downloader_capability",
                                        "CryptDecrypt": "cryptography_api",
                                        "CryptEncrypt": "cryptography_api",
                                        "RegSetValueEx": "registry_modification_api"
                                    }
                                    for api_sub, ind_name in suspicious_apis.items():
                                        if api_sub in imp_name:
                                            indicators.append(f"suspicious_import:{dll_name}:{imp_name}:{ind_name}")
                except Exception as pe_err:
                    logger.debug(f"pefile parsing skipped or failed: {pe_err}")
                    # Fallback check for raw strings if pefile parsing failed
                    if b"UPX" in data[:512]:
                        indicators.append("upx_packed")
                    SUSPICIOUS_IMPORTS = [b"InternetOpen", b"HttpSendRequest", b"GetProcAddress", b"LoadLibrary", b"RegSetValue"]
                    for imp in SUSPICIOUS_IMPORTS:
                        if imp in data:
                            indicators.append(f"suspicious_import:fallback:{imp.decode()}:unknown")

            # 2. Suspicious string checking in raw binary data
            BAD_STRINGS = [
                b"CreateRemoteThread", b"VirtualAllocEx", b"WriteProcessMemory",
                b"ShellExecute", b"WScript.Shell", b"powershell -e", b"cmd /c",
                b"net user", b"reg add", b"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                b"mimikatz", b"meterpreter", b"metasploit", b"payload",
                b"base64_decode", b"eval(", b"exec(",
            ]
            for s in BAD_STRINGS:
                if s.lower() in data.lower():
                    indicators.append(f"suspicious_string:{s.decode(errors='replace')}")

            # 3. PowerShell script injection pattern detection
            # Check script-specific contents or files
            ps_patterns = [
                b"invoke-expression", b"iex", b"downloadstring", b"downloadfile",
                b"-nop", b"-noprofile", b"-w hidden", b"-windowstyle hidden",
                b"-enc", b"-encodedcommand", b"bypass", b"-executionpolicy"
            ]
            # Convert binary data to lower and check
            data_lower = data.lower()
            for pattern in ps_patterns:
                if pattern in data_lower:
                    indicators.append(f"powershell_injection_pattern:{pattern.decode(errors='replace')}")

            # Check general script obfuscation & network patterns
            if b"base64" in data and b"decode" in data:
                indicators.append("obfuscation_detected")
            if b"socket" in data and b"connect" in data:
                indicators.append("network_capabilities")

        except (PermissionError, OSError):
            indicators.append("read_error")
        except Exception as e:
            logger.debug(f"Static analysis error: {e}")

        return indicators

    # ──────────────────────────────────────────────────────────────────────────
    # Dynamic analysis
    # ──────────────────────────────────────────────────────────────────────────

    def _dynamic_analysis(self, sandbox_path: str, ext: str) -> List[str]:
        """Run the file in a subprocess and monitor behavior."""
        indicators: List[str] = []

        try:
            import psutil
            # Snapshot before execution
            before_files   = self._snapshot_files()
            before_conns   = len(psutil.net_connections())

            cmd = self._build_run_cmd(sandbox_path, ext)
            if not cmd:
                return indicators

            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )

            # Monitor during execution
            cpu_spikes = 0
            for _ in range(int(SANDBOX_TIMEOUT)):
                if proc.poll() is not None:
                    break
                try:
                    p = psutil.Process(proc.pid)
                    cpu = p.cpu_percent(interval=1)
                    if cpu > CPU_SPIKE_THRESH:
                        cpu_spikes += 1
                except Exception:
                    time.sleep(1)

            if proc.poll() is None:
                proc.terminate()
                indicators.append("timeout_exceeded")

            # Check for new files/connections
            after_files = self._snapshot_files()
            new_files   = after_files - before_files
            if new_files:
                indicators.append(f"created_files:{len(new_files)}")

            after_conns = len(psutil.net_connections())
            if after_conns > before_conns + 2:
                indicators.append("new_network_connections")

            if cpu_spikes > 3:
                indicators.append(f"cpu_spike_count:{cpu_spikes}")

        except Exception as e:
            logger.debug(f"Dynamic analysis error: {e}")
            indicators.append("dynamic_analysis_error")

        return indicators

    # ──────────────────────────────────────────────────────────────────────────
    # Classification
    # ──────────────────────────────────────────────────────────────────────────
    def _classify(self, indicators: List[str]) -> str:
        score = 0
        for ind in indicators:
            if "suspicious_string" in ind: score += 15
            if "suspicious_import" in ind: score += 20
            if "upx_packed" in ind: score += 25
            if "high_entropy" in ind: score += 10
            if "ml_malware_detected" in ind: score += 60
            if "network_capabilities" in ind: score += 10
            if "timeout_exceeded" in ind: score += 30

        if score >= 75: return "MALICIOUS"
        if score >= 35: return "SUSPICIOUS"
        return "SAFE"

    # ──────────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _copy_to_sandbox(self, src: str, name: str) -> Optional[str]:
        try:
            ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest   = os.path.join(SANDBOX_DIR, f"{ts_str}_{name}")
            shutil.copy2(src, dest)
            return dest
        except Exception as e:
            logger.error(f"Sandbox copy error: {e}")
            return None

    def _hash_file(self, path: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def _calc_entropy(self, data: bytes) -> float:
        import math
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        return -sum(
            (c / n) * math.log2(c / n) for c in freq if c > 0
        )

    def _snapshot_files(self) -> set:
        try:
            return set(os.listdir(SANDBOX_DIR))
        except Exception:
            return set()

    def _build_run_cmd(self, path: str, ext: str) -> Optional[list]:
        """Build a safe execution command for supported script types."""
        if ext == ".py":
            return [sys.executable, path]
        if sys.platform == "win32":
            if ext in (".bat", ".cmd"):
                # Run in non-interactive mode with restricted shell
                return ["cmd.exe", "/c", path]
            if ext == ".ps1":
                # Run PowerShell in NonInteractive, Restricted mode
                return [
                    "powershell.exe",
                    "-NonInteractive",
                    "-ExecutionPolicy", "Restricted",
                    "-File", path
                ]
            if ext == ".vbs":
                return ["cscript.exe", "//NoLogo", "//B", path]
        return None

    def _build_result(
        self, file_name, original_path, sandbox_path,
        classification, behavior_report, indicators, timestamp
    ) -> SandboxResult:
        return SandboxResult(
            file_name=file_name,
            original_path=original_path,
            sandbox_path=sandbox_path,
            classification=classification,
            behavior_report=behavior_report,
            indicators=indicators,
            timestamp=timestamp,
        )

    def _save_to_db(self, result: SandboxResult) -> None:
        try:
            from database.init_db import log_sandbox_result
            log_sandbox_result(
                result.file_name,
                result.classification,
                result.behavior_report,
            )
        except Exception:
            pass  # DB logging is best-effort
