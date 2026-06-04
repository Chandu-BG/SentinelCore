"""
SentinelCore - AI Suggestion Engine
Primary: OpenAI ChatGPT API for intelligent remediation suggestions.
Fallback: Offline rule-based suggestions when API is unavailable.
"""

import os
import logging
import threading
import json
from typing import Optional, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)

BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY_FILE     = os.path.join(BASE_DIR, "config", "openai_key.txt")

# Prompt template for ChatGPT
SYSTEM_PROMPT = (
    "You are SentinelCore AI, an expert cybersecurity analyst. "
    "When given threat data, provide a concise response with:\n"
    "1. EXPLANATION: What this threat is (2-3 sentences)\n"
    "2. IMMEDIATE ACTIONS: 3-5 bullet points\n"
    "3. PREVENTION: 2-3 prevention tips\n"
    "Keep response under 300 words. Be specific and actionable."
)

# Offline fallback rules keyed by (severity, threat_type_keyword)
OFFLINE_SUGGESTIONS: Dict[str, str] = {
    "CRITICAL": (
        "⚠ CRITICAL THREAT DETECTED\n\n"
        "EXPLANATION:\n"
        "A critical severity threat has been identified. This type of threat can "
        "cause severe system compromise, data theft, or ransomware encryption.\n\n"
        "IMMEDIATE ACTIONS:\n"
        "• Quarantine the identified file immediately\n"
        "• Terminate all related processes\n"
        "• Disconnect from network temporarily\n"
        "• Run a full system scan\n"
        "• Change all passwords from a clean device\n\n"
        "PREVENTION:\n"
        "• Keep all software and OS updated\n"
        "• Enable Windows Defender real-time protection\n"
        "• Avoid running untrusted executables"
    ),
    "HIGH": (
        "⚠ HIGH SEVERITY THREAT\n\n"
        "EXPLANATION:\n"
        "A high severity threat has been detected. Immediate action is required "
        "to prevent potential data loss or system compromise.\n\n"
        "IMMEDIATE ACTIONS:\n"
        "• Review and quarantine the flagged file\n"
        "• Check running processes for anomalies\n"
        "• Review recent network connections\n"
        "• Run a full antivirus scan\n\n"
        "PREVENTION:\n"
        "• Enable automatic updates\n"
        "• Use strong, unique passwords\n"
        "• Avoid downloading files from untrusted sources"
    ),
    "MEDIUM": (
        "⚠ MEDIUM SEVERITY ALERT\n\n"
        "EXPLANATION:\n"
        "A medium severity threat indicator has been found. While not immediately "
        "critical, this requires your attention and investigation.\n\n"
        "IMMEDIATE ACTIONS:\n"
        "• Review the flagged file or process\n"
        "• Check if this process/file is expected\n"
        "• Monitor for further suspicious activity\n\n"
        "PREVENTION:\n"
        "• Regularly audit installed applications\n"
        "• Review startup programs periodically"
    ),
    "LOW": (
        "ℹ LOW SEVERITY NOTICE\n\n"
        "EXPLANATION:\n"
        "A low severity indicator was detected. This may be a false positive "
        "or a minor security concern that warrants monitoring.\n\n"
        "RECOMMENDED ACTIONS:\n"
        "• Monitor the flagged item over time\n"
        "• No immediate action required\n\n"
        "PREVENTION:\n"
        "• Continue regular security scans\n"
        "• Keep SentinelCore protection active"
    ),
    "RANSOMWARE": (
        "⚠ RANSOMWARE BEHAVIOR DETECTED\n\n"
        "EXPLANATION:\n"
        "Ransomware-like behavior has been detected. Files are being modified or "
        "renamed in bulk, which is a hallmark of ransomware encryption activity.\n\n"
        "IMMEDIATE ACTIONS:\n"
        "• IMMEDIATELY terminate the suspicious process\n"
        "• Disconnect from the internet NOW\n"
        "• Do NOT pay any ransom\n"
        "• Take a system snapshot/backup if possible\n"
        "• Report to your IT team or authorities\n\n"
        "PREVENTION:\n"
        "• Maintain offline backups of important data\n"
        "• Never open email attachments from unknown senders\n"
        "• Keep Windows and Office fully patched"
    ),
    "INJECTION": (
        "⚠ PROCESS INJECTION DETECTED\n\n"
        "EXPLANATION:\n"
        "Code injection into a running process has been detected. Attackers inject "
        "malicious code into trusted processes to evade detection and gain privileges.\n\n"
        "IMMEDIATE ACTIONS:\n"
        "• Terminate the affected process immediately\n"
        "• Scan the system for rootkits\n"
        "• Check for unauthorized scheduled tasks/startup entries\n"
        "• Review event logs for lateral movement\n\n"
        "PREVENTION:\n"
        "• Enable Data Execution Prevention (DEP)\n"
        "• Keep Controlled Folder Access enabled\n"
        "• Use application whitelisting"
    ),
    "NETWORK": (
        "⚠ NETWORK THREAT DETECTED\n\n"
        "EXPLANATION:\n"
        "A suspicious network connection has been identified. This may indicate "
        "data exfiltration, C2 communication, or unauthorized remote access.\n\n"
        "IMMEDIATE ACTIONS:\n"
        "• Block the suspicious IP via Windows Firewall\n"
        "• Identify and terminate the process making the connection\n"
        "• Check for data that may have been exfiltrated\n"
        "• Review DNS settings for tampering\n\n"
        "PREVENTION:\n"
        "• Use a reputable DNS filtering service\n"
        "• Enable network-level monitoring\n"
        "• Restrict outbound connection rules in firewall"
    ),
    "DEFAULT": (
        "ℹ SECURITY ALERT\n\n"
        "EXPLANATION:\n"
        "SentinelCore has detected anomalous system behavior that may indicate "
        "a security threat.\n\n"
        "RECOMMENDED ACTIONS:\n"
        "• Review the alert details carefully\n"
        "• Run a full system scan\n"
        "• Check running processes for anomalies\n\n"
        "PREVENTION:\n"
        "• Keep all software updated\n"
        "• Maintain regular backups"
    ),
}


class SuggestionEngine:
    """
    AI-powered suggestion engine.
    Tries OpenAI API first, falls back to offline rules.
    Thread-safe: suggestions are generated in background threads.
    """

    def __init__(self):
        self._api_key    = self._load_api_key()
        self._api_available = bool(self._api_key)
        self._lock       = threading.Lock()
        self._last_check = 0.0
        self._cooldown   = 300.0    # 5 min between API failures before retry

        if self._api_available:
            logger.info("SuggestionEngine: OpenAI API key loaded — using ChatGPT.")
        else:
            logger.info("SuggestionEngine: No API key — offline mode active.")

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    def get_suggestion(
        self,
        process_name:    str   = "",
        anomaly_score:   float = 0.0,
        reputation_score: float = 0.0,
        severity:        str   = "LOW",
        detection_reason: str  = "",
        threat_type:     str   = "",
        callback:        Optional[callable] = None,
    ) -> str:
        """
        Get an AI suggestion for a threat.
        If callback is provided, runs asynchronously and calls callback(suggestion_text).
        Otherwise blocks and returns the suggestion text.
        """
        threat_data = {
            "process_name":     process_name,
            "anomaly_score":    round(anomaly_score, 3),
            "reputation_score": round(reputation_score, 3),
            "severity":         severity,
            "detection_reason": detection_reason,
            "threat_type":      threat_type,
            "timestamp":        datetime.now().isoformat(),
        }

        if callback:
            threading.Thread(
                target=self._generate_and_callback,
                args=(threat_data, callback),
                daemon=True, name="SuggestionGen",
            ).start()
            return ""  # async
        else:
            return self._generate(threat_data)

    def clean_suggestion(self) -> str:
        return (
            "✓  No security issues detected.\n\n"
            "No recommendations required.\n\n"
            "SentinelCore completed its analysis and found no suspicious files, "
            "processes, applications, or network activity.\n\n"
            "Continue regular scanning to maintain system security."
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Internal generation
    # ──────────────────────────────────────────────────────────────────────────

    def _generate_and_callback(self, threat_data: dict, callback: callable) -> None:
        suggestion = self._generate(threat_data)
        try:
            callback(suggestion)
        except Exception as e:
            logger.error(f"SuggestionEngine callback error: {e}")

    def _generate(self, threat_data: dict) -> str:
        """Try API → fallback to offline."""
        if self._api_available:
            result = self._try_openai(threat_data)
            if result:
                return result
            # API failed — back off
            with self._lock:
                self._api_available = False
                self._last_check = 0.0

        return self._offline_suggestion(threat_data)

    # ──────────────────────────────────────────────────────────────────────────
    # OpenAI API
    # ──────────────────────────────────────────────────────────────────────────

    def _try_openai(self, threat_data: dict) -> Optional[str]:
        """Call OpenAI ChatGPT API. Returns None on failure."""
        try:
            import urllib.request
            import json as _json

            user_msg = (
                f"Threat Analysis Request:\n"
                f"Process: {threat_data.get('process_name', 'Unknown')}\n"
                f"Severity: {threat_data.get('severity', 'UNKNOWN')}\n"
                f"Threat Type: {threat_data.get('threat_type', 'Unknown')}\n"
                f"Detection Reason: {threat_data.get('detection_reason', 'N/A')}\n"
                f"Anomaly Score: {threat_data.get('anomaly_score', 0):.3f}\n"
                f"Reputation Score: {threat_data.get('reputation_score', 0):.3f}\n"
            )

            payload = {
                "model": "gpt-3.5-turbo",
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": user_msg},
                ],
                "max_tokens": 400,
                "temperature": 0.3,
            }

            req = urllib.request.Request(
                "https://api.openai.com/v1/chat/completions",
                data=_json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type":  "application/json",
                    "Authorization": f"Bearer {self._api_key}",
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=15) as resp:
                body = _json.loads(resp.read().decode("utf-8"))
                content = body["choices"][0]["message"]["content"]
                logger.info("SuggestionEngine: OpenAI response received.")
                return f"[ChatGPT Analysis]\n\n{content}"

        except Exception as e:
            logger.warning(f"SuggestionEngine: OpenAI API failed: {e}")
            return None

    # ──────────────────────────────────────────────────────────────────────────
    # Offline fallback
    # ──────────────────────────────────────────────────────────────────────────

    def _offline_suggestion(self, threat_data: dict) -> str:
        """Rule-based offline fallback suggestions."""
        severity     = threat_data.get("severity", "LOW").upper()
        threat_type  = threat_data.get("threat_type", "").upper()
        reason       = threat_data.get("detection_reason", "").upper()

        # Pick the most specific suggestion
        if "RANSOM" in threat_type or "RANSOM" in reason:
            base = OFFLINE_SUGGESTIONS["RANSOMWARE"]
        elif "INJECT" in threat_type or "INJECT" in reason or "HOLLOW" in reason:
            base = OFFLINE_SUGGESTIONS["INJECTION"]
        elif "NETWORK" in threat_type or "TRAFFIC" in reason or "IP" in reason:
            base = OFFLINE_SUGGESTIONS["NETWORK"]
        elif severity in OFFLINE_SUGGESTIONS:
            base = OFFLINE_SUGGESTIONS[severity]
        else:
            base = OFFLINE_SUGGESTIONS["DEFAULT"]

        process = threat_data.get("process_name", "")
        header  = f"[Offline Analysis — API unavailable]\n" if not self._api_available else ""
        suffix  = f"\n\nProcess: {process}" if process else ""
        return header + base + suffix

    # ──────────────────────────────────────────────────────────────────────────
    # Key loading
    # ──────────────────────────────────────────────────────────────────────────

    def _load_api_key(self) -> str:
        """Load OpenAI key from file or environment variable."""
        # 1. Environment variable takes priority
        env_key = os.environ.get("OPENAI_API_KEY", "").strip()
        if env_key and env_key.startswith("sk-"):
            return env_key

        # 2. Key file
        try:
            if os.path.exists(KEY_FILE):
                with open(KEY_FILE, "r") as f:
                    key = f.read().strip()
                if key and key.startswith("sk-"):
                    return key
        except Exception:
            pass

        return ""

    @property
    def api_available(self) -> bool:
        return self._api_available

    def set_api_key(self, key: str) -> None:
        """Allow runtime key update."""
        self._api_key = key.strip()
        self._api_available = bool(self._api_key and self._api_key.startswith("sk-"))
