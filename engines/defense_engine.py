"""
SentinelCore - Defense Engine (Enhanced with Real Remediation)
Performs actual OS-level remediation when threats are detected:
  - Kill processes via psutil (+ taskkill fallback)
  - Quarantine files via FileEngine
  - Block IPs via Windows Firewall (netsh)
  - Decay trust scores
  - Log all actions to database

No simulated actions. All operations affect the real OS.
"""

import os
import subprocess
import logging
import psutil
from datetime import datetime
from typing import Callable, Optional

from database.init_db import log_threat, log_system_event

logger = logging.getLogger(__name__)


class DefenseEngine:
    """
    Real OS-level threat response coordinator.
    All remediation actions are genuine system operations.
    """

    def __init__(
        self,
        monitor_engine,
        ip_blocker_module,
        trust_engine,
        file_engine=None,
        on_alert: Optional[Callable[[str, str], None]] = None,
    ):
        self.monitor_engine = monitor_engine
        self.ip_blocker     = ip_blocker_module
        self.trust_engine   = trust_engine
        self.file_engine    = file_engine
        self.on_alert       = on_alert

        self.actions_taken: int = 0
        self.last_action:   str = "None"

    # ─────────────────────────────────────────────────────────────────────────
    # Process Termination (real)
    # ─────────────────────────────────────────────────────────────────────────

    def terminate_process(self, pid: int, process_name: str = "") -> bool:
        """
        Terminate a process by PID.
        1. Tries psutil.Process.kill() (sends SIGKILL / TerminateProcess)
        2. Falls back to 'taskkill /F /PID <pid>' if psutil fails
        Returns True if process was successfully terminated.
        """
        killed = False
        try:
            proc = psutil.Process(pid)
            pname = proc.name()
            proc.kill()
            killed = True
            logger.warning(f"DEFENSE: Killed process '{pname}' PID={pid}")
        except psutil.NoSuchProcess:
            logger.info(f"DEFENSE: Process PID={pid} no longer exists.")
            killed = True  # already gone
        except psutil.AccessDenied:
            logger.warning(f"DEFENSE: Access denied killing PID={pid}, trying taskkill…")
            try:
                result = subprocess.run(
                    ["taskkill", "/F", "/PID", str(pid)],
                    capture_output=True, text=True, timeout=8,
                )
                killed = result.returncode == 0
                if killed:
                    logger.warning(f"DEFENSE: taskkill succeeded for PID={pid}")
                else:
                    logger.error(f"DEFENSE: taskkill failed for PID={pid}: {result.stderr}")
            except Exception as e:
                logger.error(f"DEFENSE: taskkill exception for PID={pid}: {e}")

        action = f"Process '{process_name or pid}' {'KILLED' if killed else 'KILL FAILED'}"
        self._record_action(action, "PROCESS_TERMINATED" if killed else "PROCESS_KILL_FAILED")

        if self.trust_engine and process_name:
            self.trust_engine.report_anomaly(process_name)

        if self.on_alert:
            self.on_alert("PROCESS_TERMINATED", f"{action} (PID={pid})")

        return killed

    # ─────────────────────────────────────────────────────────────────────────
    # Legacy wrapper (called by monitor_engine.kill_process)
    # ─────────────────────────────────────────────────────────────────────────

    def respond_to_suspicious_process(self, process_name: str, pid: int) -> None:
        self.terminate_process(pid, process_name)

    # ─────────────────────────────────────────────────────────────────────────
    # File Quarantine (real — delegates to FileEngine)
    # ─────────────────────────────────────────────────────────────────────────

    def quarantine_file(self, file_path: str, reason: str = "") -> bool:
        """
        Move a file to the quarantine directory via FileEngine.
        """
        if self.file_engine is None:
            logger.warning("DEFENSE: FileEngine not available for quarantine.")
            return False
        ok = self.file_engine.quarantine_file(file_path, reason)
        action = f"Quarantined '{os.path.basename(file_path)}'" + (" OK" if ok else " FAILED")
        self._record_action(action, "FILE_QUARANTINED" if ok else "QUARANTINE_FAILED")
        if self.on_alert:
            self.on_alert("FILE_QUARANTINED", f"{file_path} — {action}")
        return ok

    # ─────────────────────────────────────────────────────────────────────────
    # IP Blocking (real — Windows Firewall via netsh)
    # ─────────────────────────────────────────────────────────────────────────

    def respond_to_suspicious_ip(self, ip_address: str, reason: str = "") -> bool:
        """
        Block an IP address using the Windows Advanced Firewall via netsh.
        Also records the block in the SentinelCore database.
        Returns True if the firewall rule was created successfully.
        """
        rule_name = f"SentinelCore_Block_{ip_address.replace('.', '_')}"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=out",
            "action=block",
            f"remoteip={ip_address}",
            "enable=yes",
            "profile=any",
        ]
        blocked = False
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10,
            )
            blocked = result.returncode == 0
            if blocked:
                logger.warning(f"DEFENSE: Firewall rule added, blocked IP {ip_address}")
            else:
                logger.warning(
                    f"DEFENSE: netsh returned {result.returncode} for {ip_address}: "
                    f"{result.stderr.strip()}"
                )
        except subprocess.TimeoutExpired:
            logger.error(f"DEFENSE: netsh timed out blocking {ip_address}")
        except FileNotFoundError:
            logger.error("DEFENSE: netsh not found — running without admin?")

        # Always record in DB regardless of netsh outcome
        log_threat(
            "IP_BLOCKED",
            f"IP block attempted: {ip_address} | netsh={'OK' if blocked else 'FAILED'} | {reason}",
            severity="high",
        )
        from engines import ip_blocker as ipm
        ipm.block_ip(ip_address, reason or "Flagged by DefenseEngine")

        action = f"IP {ip_address} {'BLOCKED' if blocked else 'block attempted'}"
        self._record_action(action, "IP_BLOCKED")
        if self.on_alert:
            self.on_alert("IP_BLOCKED", f"Blocked suspicious IP: {ip_address}")
        return blocked

    # ─────────────────────────────────────────────────────────────────────────
    # Anomaly response
    # ─────────────────────────────────────────────────────────────────────────

    def respond_to_anomaly(self, process_name: str, anomaly_score: float) -> None:
        """
        Respond to an AI anomaly: decay trust, escalate to kill if critically low.
        """
        new_trust = self.trust_engine.report_anomaly(process_name)
        logger.warning(
            f"DEFENSE: Anomaly '{process_name}' score={anomaly_score:.2f} trust={new_trust}"
        )
        if new_trust <= 15:
            procs = self.monitor_engine.get_process_by_name(process_name)
            for proc in procs:
                self.terminate_process(proc["pid"], process_name)
        else:
            if self.on_alert:
                self.on_alert(
                    "ANOMALY_RESPONSE",
                    f"Anomaly in '{process_name}' — trust reduced to {new_trust}.",
                )

    # ─────────────────────────────────────────────────────────────────────────
    # Protection level escalation
    # ─────────────────────────────────────────────────────────────────────────

    def escalate_protection(self, new_level: str) -> None:
        intervals = {"low": 5.0, "medium": 2.0, "high": 0.5}
        interval = intervals.get(new_level, 2.0)
        self.monitor_engine.set_interval(interval)
        logger.info(f"DEFENSE: Level -> '{new_level}' (interval={interval}s)")
        if self.on_alert:
            self.on_alert("LEVEL_CHANGE", f"Protection level: {new_level.upper()}")

    # ─────────────────────────────────────────────────────────────────────────
    # Internal helper
    # ─────────────────────────────────────────────────────────────────────────

    def _record_action(self, action: str, event_type: str) -> None:
        self.actions_taken += 1
        self.last_action   = f"[{datetime.now().strftime('%H:%M:%S')}] {action}"
        log_system_event(event_type, action, "warning")
        logger.info(f"DEFENSE action #{self.actions_taken}: {action}")
