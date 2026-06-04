"""
NovaSentinel — Security Core (v4.0)
Central orchestrator for the backend architecture.
Connects telemetry, processes, ML datasets, and ALL active engines.
"""

import logging
import threading
import os
import time
from datetime import datetime
from typing import Optional, Callable, Dict, List, Any

# Core Managers
from core.telemetry_manager import get_telemetry
from core.process_manager import ProcessManager
from core.threat_manager import get_threat_manager
from core.dataset_manager import get_dataset_manager
from core.notification_manager import get_notification_manager
from core.realtime_monitor import get_realtime_monitor
from core.update_manager import get_update_manager
from core.scheduler import get_scheduler
from core.intelligence_hub import IntelligenceHub
from core.system_scanner import SystemScanner
from core.quarantine_manager import get_quarantine_manager

# Engine Imports
from engines.monitor_engine        import MonitorEngine
from engines.ai_engine             import AIEngine
from engines.file_engine           import FileEngine
from engines.risk_engine           import RiskEngine
from engines.trust_engine          import TrustEngine
from engines.update_engine         import UpdateEngine
from engines.self_protection_engine import SelfProtectionEngine
from engines.defense_engine        import DefenseEngine
from engines.auto_correction_engine import AutoCorrectionEngine
from engines.permissions_engine    import PermissionsEngine
from engines.entropy_engine        import EntropyEngine
from engines.threat_score_engine   import ThreatScoreEngine
from engines.api_manager           import APIManager
from engines.ai_remediation_engine import AIRemediationEngine
from engines.installed_app_engine  import InstalledAppEngine
from engines.ransomware_detector   import RansomwareDetector
from engines.network_detector      import NetworkDetector
from engines.injection_detector    import InjectionDetector
from engines.sandbox_engine        import SandboxEngine
from engines.threat_predictor      import ThreatPredictor
from engines.suggestion_engine     import SuggestionEngine
from engines.phishing_detector     import PhishingDetector
from engines.performance_analyzer  import PerformanceAnalyzer
from engines.browser_protection    import BrowserProtection
from engines.novasentinel_engine   import NovaSentinelEngine
from engines.ai_context_manager    import AIContextManager

from engines.intelligence_engines import (PhishingIntelEngine,
                                           MalwareIntelEngine,
                                           NetworkIntelEngine,
                                           SandboxBehaviorEngine)

logger = logging.getLogger(__name__)

class SecurityCore:
    """
    Unified central backend for NovaSentinel.
    Manages lifecycle and inter-connectivity of all security modules.
    """
    def __init__(self, gui_callback: Optional[Callable] = None):
        logger.info("Initializing SecurityCore v4.0 Master Orchestrator...")
        
        self.gui_callback = gui_callback
        self._protection_active = False
        self._lock = threading.Lock()

        # 1. Base Infrastructure
        self.telemetry = get_telemetry()
        self.process_manager = ProcessManager()
        self.threat_manager = get_threat_manager()
        self.dataset_manager = get_dataset_manager()
        self.notification_manager = get_notification_manager()
        self.realtime_monitor = get_realtime_monitor()
        self.update_manager = get_update_manager()
        self.scheduler = get_scheduler()
        self.quarantine_manager = get_quarantine_manager()
        
        # 2. Permissions & Policy
        self.permissions = PermissionsEngine(on_change=self._on_permission_change)
        
        # 3. Intelligence Hub & Scanning
        self.intel_hub = IntelligenceHub(on_alert=self._on_intel_alert)
        self.system_scanner = SystemScanner(
            on_progress=self._on_scanner_progress,
            on_finding=self._on_scanner_finding
        )
        
        # 4. Core Security Engines
        self.monitor_engine  = MonitorEngine(on_alert=self._on_legacy_alert)
        self.ai_engine       = AIEngine(on_anomaly=self._on_anomaly)
        self.trust_engine    = TrustEngine()
        self.risk_engine     = RiskEngine(on_level_change=self._on_risk_change)
        self.entropy_engine  = EntropyEngine()
        self.threat_score_eng = ThreatScoreEngine()
        self.api_manager     = APIManager()
        self.ai_remediation  = AIRemediationEngine()

        self.file_engine = FileEngine(
            permissions_engine = self.permissions,
            on_alert           = self._on_file_alert,
            on_scan_result     = self._on_scan_result,
            entropy_engine     = self.entropy_engine,
            threat_score_engine= self.threat_score_eng,
            api_manager        = self.api_manager,
            ai_remediation     = self.ai_remediation,
        )

        self.defense_engine = DefenseEngine(
            monitor_engine   = self.monitor_engine,
            ip_blocker_module= None, # handled via NetworkDetector now
            trust_engine     = self.trust_engine,
            file_engine      = self.file_engine,
            on_alert         = self._on_legacy_alert,
        )

        self.update_engine   = UpdateEngine(self.ai_engine)
        self.self_protection = SelfProtectionEngine(on_tamper=self._on_tamper)
        self.auto_correction = AutoCorrectionEngine(
            ai_engine=self.ai_engine,
            update_engine=self.update_engine,
            on_alert=self._on_legacy_alert,
        )
        self.installed_app_engine = InstalledAppEngine(api_manager=self.api_manager)

        # 5. Advanced Detection Engines
        self.ransomware_detector = RansomwareDetector(on_alert=self._on_ransomware_alert)
        self.network_detector    = NetworkDetector(on_alert=self._on_network_alert)
        self.injection_detector  = InjectionDetector(on_alert=self._on_injection_alert)
        self.sandbox_engine      = SandboxEngine(
            on_result=self._on_sandbox_result,
            on_alert=self._on_legacy_alert,
            on_quarantine=self._on_sandbox_quarantine,
        )
        self.threat_predictor    = ThreatPredictor(
            on_prediction=self._on_threat_prediction,
            on_alert=self._on_legacy_alert,
        )
        self.suggestion_engine   = SuggestionEngine()
        self.phishing_detector   = PhishingDetector(on_alert=self._on_phishing_alert)
        self.browser_protection  = BrowserProtection(
            on_alert=self._on_browser_alert,
            phishing_detector=self.phishing_detector,
        )

        # 6. NovaSentinel AI Assistant Core
        self.ai_context = AIContextManager()
        self.novasentinel = NovaSentinelEngine(on_status_change=self._on_novasentinel_status)
        
        # Bind AI Context to live telemetry
        self.ai_context.bind_engines(
            monitor_engine=self.monitor_engine,
            ai_engine=self.ai_engine,
            risk_engine=self.risk_engine,
            trust_engine=self.trust_engine,
            phishing_detector=self.phishing_detector,
            telemetry=self.telemetry,
        )

        # Bind ML engines to Intelligence Hub
        self.intel_hub.bind_engines(
            phishing_engine=PhishingIntelEngine(),
            malware_engine=MalwareIntelEngine(),
            network_engine=NetworkIntelEngine(),
            sandbox_engine=SandboxBehaviorEngine()
        )

        # Register core event handlers for real-time monitoring
        self._safe_files_cache: dict = {}  # file_path -> last_scan_time
        self._cache_lock = threading.Lock()
        self.realtime_monitor.add_callback(self._on_realtime_file_event)

        # Start background cache pruner (evict entries older than 60s)
        threading.Thread(
            target=self._cache_pruner_loop,
            daemon=True,
            name="CachePruner"
        ).start()
        
    def _cache_pruner_loop(self) -> None:
        """Periodically evict stale entries from _safe_files_cache."""
        while True:
            time.sleep(60)
            now = time.time()
            with self._cache_lock:
                stale = [k for k, v in self._safe_files_cache.items() if now - v > 60]
                for k in stale:
                    del self._safe_files_cache[k]
            if stale:
                logger.debug(f"CachePruner: evicted {len(stale)} stale file cache entries.")

    # ── Lifecycle Management ──────────────────────────────────────────────────

    def start_protection(self):
        with self._lock:
            if self._protection_active: return
            self._protection_active = True
        
        logger.info("NovaSentinel SecurityCore starting ALL protection layers...")
        
        # Start Core Infrastructure
        self.telemetry.start()
        self.process_manager.start()
        self.realtime_monitor.start()
        self.update_manager.start()
        self.scheduler.start()
        
        # Start AI Engine
        self.novasentinel.start()
        
        # Start Monitoring Engines
        self.monitor_engine.start()
        self.ransomware_detector.start()
        self.network_detector.start()
        self.injection_detector.start()
        self.browser_protection.start()
        self.self_protection.start()

        # Load ML Models in background
        threading.Thread(target=self._load_ml_models_background, daemon=True, name="MLLoader").start()
        
        # Schedule Health Checks
        self.scheduler.schedule(self._backend_health_check, 15)
        
        self.notification_manager.fire_alert("SYSTEM", "info", "All NovaSentinel protection layers are active.")

    def _load_ml_models_background(self) -> None:
        """Load ML models in background thread to avoid blocking startup."""
        try:
            # Update status
            if self.gui_callback:
                self.gui_callback("module_status", ("ML Models", "Loading..."))
            
            self.dataset_manager.load_models()
            
            if self.gui_callback:
                self.gui_callback("module_status", ("ML Models", "Loaded"))
                
        except Exception as exc:
            logger.warning(f"ML model loading failed: {exc}")
            if self.gui_callback:
                self.gui_callback("module_status", ("ML Models", "Failed - Pattern-only mode"))
            # Emit toast notification
            self.notification_manager.fire_alert("SYSTEM", "warning", "ML models unavailable — pattern-only detection active")

    def stop_protection(self):
        with self._lock:
            if not self._protection_active: return
            self._protection_active = False
        
        logger.info("NovaSentinel SecurityCore stopping protection...")
        
        # Stop everything in reverse order
        self.self_protection.stop()
        self.browser_protection.stop()
        self.injection_detector.stop()
        self.network_detector.stop()
        self.ransomware_detector.stop()
        self.monitor_engine.stop()
        self.novasentinel.stop()
        self.scheduler.stop()
        self.update_manager.stop()
        self.realtime_monitor.stop()
        self.process_manager.stop()
        self.telemetry.stop()
        
        logger.info("All protection layers stopped.")

    # ── Event Handlers ────────────────────────────────────────────────────────

    def _on_realtime_file_event(self, file_path: str):
        """Handle real-time file system events asynchronously with safe caching & duplicate prevention."""
        now = time.time()
        
        # 1. Skip non-existent files or directories
        if not os.path.exists(file_path) or os.path.isdir(file_path):
            return
            
        # 2. Check safe scanned cache (15-second cooldown for redundant scans)
        with self._cache_lock:
            last_scan = self._safe_files_cache.get(file_path)
            if last_scan and (now - last_scan < 15.0):
                return # Skip redundant scan within cooldown window
            self._safe_files_cache[file_path] = now

        def analysis_worker():
            try:
                # Check against ML models (EMBER/SOREL)
                result = self.dataset_manager.analyze_pe(file_path)
                if not result.get("safe", True):
                    sev = result.get("severity", "warning")
                    msg = f"Suspicious activity detected in file: {os.path.basename(file_path)}"
                    
                    self.intel_hub.fire_alert("REALTIME_MALWARE", sev, msg)
                    self.notification_manager.fire_alert("THREAT", sev, msg)
                    self.telemetry.push_log("MALWARE_ENGINE", f"Detected threat in {file_path} (Score: {result.get('score')})", sev)
                    
                    # Auto-quarantine if critical
                    if result.get("score", 0) > 0.8:
                        self.quarantine_manager.quarantine(file_path, "Auto-quarantine: ML detection high confidence")
                        self.telemetry.push_log("QUARANTINE", f"Auto-quarantined critical threat: {file_path}", "critical")
                        
                    # If unsafe, remove from safe cache so it gets re-analyzed next time
                    with self._cache_lock:
                        self._safe_files_cache.pop(file_path, None)
            except Exception as e:
                logger.error(f"Real-time analysis failed for {file_path}: {e}")
                with self._cache_lock:
                    self._safe_files_cache.pop(file_path, None)

        # Offload to background thread
        threading.Thread(target=analysis_worker, daemon=True, name=f"Analysis-{os.path.basename(file_path)}").start()

    def _on_scanner_progress(self, count: int, total: int, message: str):
        if self.gui_callback: self.gui_callback("scanner_progress", (count, total, message))

    def _on_scanner_finding(self, item):
        # Log finding to threat manager
        self.threat_manager.log_threat(
            alert_type=f"SCAN_{item.classification}",
            description=f"Scanner found {item.classification}: {item.path}",
            severity=item.severity_color
        )
        if self.gui_callback: self.gui_callback("scanner_finding", item)

    # ── Scanning API ──────────────────────────────────────────────────────────

    def start_quick_scan(self) -> Any:
        return self.system_scanner.quick_scan()

    def start_full_scan(self) -> Any:
        return self.system_scanner.full_scan()

    def start_smart_scan(self) -> Any:
        return self.system_scanner.smart_scan()

    def start_custom_scan(self, path: str) -> Any:
        return self.system_scanner.custom_scan(path)

    def _on_intel_alert(self, alert_type, severity, message):
        self.notification_manager.fire_alert(alert_type, severity, message)
        if self.gui_callback: self.gui_callback("alert", (alert_type, severity, message))

    def _on_permission_change(self, perms): pass
    def _on_anomaly(self, info): pass
    def _on_risk_change(self, level): pass
    def _on_file_alert(self, type, msg): self._on_legacy_alert(type, msg)
    def _on_scan_result(self, res): pass
    def _on_tamper(self, msg): self._on_legacy_alert("TAMPER", msg)
    def _on_ransomware_alert(self, msg, sev): self._on_legacy_alert("RANSOMWARE", msg)
    def _on_network_alert(self, msg, sev): self._on_legacy_alert("NETWORK", msg)
    def _on_injection_alert(self, msg, sev): self._on_legacy_alert("INJECTION", msg)
    def _on_sandbox_result(self, res): pass
    def _on_sandbox_quarantine(self, path, reason):
        self.quarantine_manager.quarantine(path, reason)
    def _on_threat_prediction(self, pred): pass
    def _on_phishing_alert(self, url, cls, reason): self._on_legacy_alert("PHISHING", f"{cls}: {url}")
    def _on_browser_alert(self, msg, url): self._on_legacy_alert("BROWSER", msg)
    def _on_novasentinel_status(self, status): pass

    def _on_legacy_alert(self, alert_type, message):
        self.notification_manager.fire_alert(alert_type, "warning", message)
        self.telemetry.push_log(alert_type, message, "warning")
        if self.gui_callback: self.gui_callback("alert", (alert_type, "warning", message))

    def _backend_health_check(self):
        """Internal stability check for all engines."""
        snap = self.telemetry.get_snapshot()
        if snap.cpu_percent > 90:
            logger.warning(f"Extreme system load detected: {snap.cpu_percent}% CPU")

    # ── Public API for UI ─────────────────────────────────────────────────────

    def get_snapshot(self):
        return self.telemetry.get_snapshot()

    def get_processes(self):
        return self.process_manager.get_processes()

    def terminate_process(self, pid, name=None):
        return self.process_manager.terminate(pid)

    def scan_url(self, url: str):
        return self.phishing_detector.analyze(url)

    def explain_url(self, url: str, result: dict, stream_cb=None, done_cb=None):
        """Request AI explanation for a phishing result."""
        from engines.ai_reasoning import build_url_analysis_prompt
        prompt = build_url_analysis_prompt(url, result)
        self.novasentinel.generate_response(prompt, stream_cb, done_cb, "phishing")

    def sandbox_file(self, path: str):
        return self.sandbox_engine.analyze(path)

_instance = None
_instance_lock = threading.Lock()

def get_security_core() -> SecurityCore:
    """Thread-safe singleton factory for SecurityCore."""
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:  # Double-checked locking
                _instance = SecurityCore()
    return _instance
