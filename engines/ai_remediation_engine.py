"""
SentinelCore - AI Remediation Engine
Context-aware threat explanation and remediation advisor.

Always available (no API key required):
  Rule-based explanation generator driven by signal dominance.
  - Identifies which signals contributed most.
  - Generates explanation referencing real detection values.
  - Provides severity-matched remediation steps.
  - Provides signal-specific prevention guidance.

Optional (if env var is set):
  GROQ_API_KEY  → Groq LLaMA-3 (free, fast)
  OPENAI_API_KEY → OpenAI GPT-4o-mini (paid, premium)
  Falls back to rule-based silently if API call fails.
"""

import os
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


# ─── Signal human-readable names and explanations ────────────────────────────

SIGNAL_LABELS: Dict[str, str] = {
    "hash_match":      "Malicious Hash Match",
    "vt_score":        "VirusTotal Detection",
    "ip_reputation":   "IP Reputation (AbuseIPDB)",
    "entropy_score":   "High File Entropy",
    "suspicious_ext":  "Suspicious Extension",
    "hidden_flag":     "Hidden/System File",
    "location_risk":   "Abnormal File Location",
    "behavior_score":  "AI Behavioral Anomaly",
}

SIGNAL_EXPLANATIONS: Dict[str, str] = {
    "hash_match": (
        "The file's SHA-256 hash matches a known malicious file in the "
        "threat intelligence database. This is the strongest possible indicator "
        "of a known threat."
    ),
    "vt_score": (
        "VirusTotal analysis shows that multiple antivirus engines flagged this "
        "file as malicious or suspicious. Higher detection ratios indicate "
        "well-documented threats."
    ),
    "ip_reputation": (
        "The associated IP address has a high abuse confidence score, linked to "
        "known threat actors, malware C&C servers, or botnets."
    ),
    "entropy_score": (
        "The file exhibits abnormally high Shannon entropy, consistent with "
        "encrypted payloads, compressed malware droppers, or packed executables "
        "that attempt to evade static signature detection."
    ),
    "suspicious_ext": (
        "The file extension is classified as potentially dangerous (executable, "
        "script, or loader type) and was found in an unexpected user-accessible "
        "location."
    ),
    "hidden_flag": (
        "The file has system or hidden attributes set, a common tactic to "
        "conceal malware from casual inspection and some security tools."
    ),
    "location_risk": (
        "The file resides in an anomalous location — such as a temp directory, "
        "public folder, or user data path — where executable files are rarely "
        "legitimate."
    ),
    "behavior_score": (
        "The AI behavioral model (IsolationForest) detected anomalous system "
        "activity patterns consistent with processes associated with this file, "
        "deviating significantly from established baseline behavior."
    ),
}

# ─── Severity-based remediation action templates ─────────────────────────────

SEVERITY_ACTIONS: Dict[str, List[str]] = {
    "LOW": [
        "Monitor the file for further activity.",
        "Review the file's origin — was it downloaded or created recently?",
        "Run a full directory scan if additional signals emerge.",
        "No immediate action required, but keep the file under observation.",
    ],
    "MEDIUM": [
        "Quarantine the file immediately to prevent execution.",
        "Identify the process that created or modified this file.",
        "Check network connections made around the time of file creation.",
        "Review user activity logs for the time period in question.",
        "If the file is unknown, submit its SHA-256 to VirusTotal manually.",
    ],
    "HIGH": [
        "Quarantine the file immediately — do not allow execution.",
        "Terminate any processes associated with this file.",
        "Block any outbound connections to associated IP addresses via firewall.",
        "Preserve a forensic copy before taking any remediation action.",
        "Review all recently created or modified files in the same directory.",
        "Change credentials if the file had access to credential stores.",
    ],
    "CRITICAL": [
        "IMMEDIATE QUARANTINE — move file to secure quarantine now.",
        "Kill ALL processes associated with this file or its parent.",
        "Block ALL network access from this machine until investigation completes.",
        "Trigger a full system scan across all drives.",
        "Preserve a forensic image of affected directories.",
        "Rotate any credentials, API keys, or certificates accessible from this machine.",
        "Notify security team and escalate to incident response procedures.",
        "Review audit logs for lateral movement or data exfiltration indicators.",
    ],
}

# ─── Signal-specific prevention guidance ─────────────────────────────────────

SIGNAL_PREVENTION: Dict[str, str] = {
    "hash_match": (
        "Keep your threat database updated regularly. Enable automatic signature "
        "updates and integrate threat intelligence feeds."
    ),
    "vt_score": (
        "Enable cloud-based antivirus scanning. Submit unknown executables to "
        "VirusTotal before running them."
    ),
    "ip_reputation": (
        "Use DNS-based blocking (e.g., Pi-hole with threat feeds) and firewall "
        "geo-blocking. Monitor outbound connections with network flow analysis."
    ),
    "entropy_score": (
        "Treat high-entropy unknown files as suspicious by default. Use "
        "application whitelisting to prevent unsigned or packed executables from "
        "running. Static unpackers can help analyze suspicious samples."
    ),
    "suspicious_ext": (
        "Enforce extension-based execution policies via AppLocker or Windows "
        "Defender WDAC. Disable macro execution in Office documents by policy. "
        "Block script interpreters from running from user directories."
    ),
    "hidden_flag": (
        "Configure Windows Explorer and security tools to show hidden and system "
        "files. Alert on processes that set the hidden attribute programmatically."
    ),
    "location_risk": (
        "Restrict execution from Temp, Downloads, and AppData directories using "
        "Group Policy or AppLocker. Audit all executable files in user-writeable "
        "locations."
    ),
    "behavior_score": (
        "Establish a clean behavioral baseline when the system is in a known-good "
        "state. Use EDR (Endpoint Detection and Response) tools to correlate "
        "process behavior across time."
    ),
}


@dataclass
class RemediationAdvice:
    explanation:       str
    actions:           List[str]
    prevention:        List[str]
    dominant_signals:  List[str]
    severity:          str
    threat_score:      float
    used_llm:          bool = False


class AIRemediationEngine:
    """
    Generates threat explanations and remediation advice.

    Rule-based engine is always active.
    LLM (Groq/OpenAI) is used if key is present in environment.
    """

    def __init__(self):
        self._groq_key   = os.environ.get("GROQ_API_KEY",   "").strip() or None
        self._openai_key = os.environ.get("OPENAI_API_KEY", "").strip() or None
        if self._groq_key:
            logger.info("AIRemediationEngine: Groq LLaMA-3 available.")
        elif self._openai_key:
            logger.info("AIRemediationEngine: OpenAI GPT available.")
        else:
            logger.info("AIRemediationEngine: using rule-based engine (no LLM key).")

    @staticmethod
    def clean_message() -> str:
        """
        Standard message shown in the AI panel when no threats are detected.
        Ensures the panel is never blank.
        """
        return (
            "✓  No security issues detected.\n\n"
            "No recommendations required.\n\n"
            "SentinelCore has completed its analysis and found no\n"
            "suspicious files, processes, applications, or network\n"
            "activity during this scan cycle.\n\n"
            "Continue regular scanning to maintain system security."
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Main entry point
    # ─────────────────────────────────────────────────────────────────────────

    def explain(
        self,
        signals_dict:      Dict[str, float],
        contributions:     Dict[str, float],
        dominant_signals:  List[str],
        severity:          str,
        threat_score:      float,
        file_name:         str = "",
        sha256:            str = "",
        entropy:           float = 0.0,
    ) -> RemediationAdvice:
        """
        Generate a full remediation advice package.

        Parameters mirror the ThreatResult + ThreatSignals data.
        Always returns a RemediationAdvice — never raises.
        """
        # Try LLM first
        if self._groq_key or self._openai_key:
            try:
                return self._llm_explain(
                    signals_dict, contributions, dominant_signals,
                    severity, threat_score, file_name, sha256, entropy,
                )
            except Exception as e:
                logger.warning(f"LLM explain failed, falling back to rules: {e}")

        return self._rule_explain(
            signals_dict, contributions, dominant_signals,
            severity, threat_score, file_name, sha256, entropy,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Rule-based explanation (always available)
    # ─────────────────────────────────────────────────────────────────────────

    def _rule_explain(
        self, signals_dict, contributions, dominant_signals,
        severity, threat_score, file_name, sha256, entropy,
    ) -> RemediationAdvice:

        fname = file_name or "the file"

        # Build explanation body
        lines = [
            f"SENTINEL THREAT ANALYSIS — {severity} (Score: {threat_score:.1f}/100)",
            "",
            f"Target: {fname}",
        ]
        if sha256:
            lines.append(f"SHA-256: {sha256[:32]}…")
        if entropy > 0:
            lines.append(f"Entropy: {entropy:.3f} bits/byte")
        lines.append("")

        # How was it detected
        if dominant_signals:
            lines.append("DETECTION REASONING")
            lines.append("─" * 50)
            for i, sig in enumerate(dominant_signals, 1):
                label   = SIGNAL_LABELS.get(sig, sig)
                val     = signals_dict.get(sig, 0.0)
                contrib = contributions.get(sig, 0.0)
                lines.append(
                    f"{i}. {label}  (signal={val:.2f}, weighted contribution={contrib:.3f})"
                )
                detail = SIGNAL_EXPLANATIONS.get(sig, "")
                if detail:
                    # Wrap at ~65 chars
                    words, curr = detail.split(), ""
                    for word in words:
                        if len(curr) + len(word) + 1 > 65:
                            lines.append(f"   {curr.rstrip()}")
                            curr = word + " "
                        else:
                            curr += word + " "
                    if curr.strip():
                        lines.append(f"   {curr.rstrip()}")
                lines.append("")

        # Severity context
        severity_context = {
            "LOW":      "This threat poses minimal immediate risk but warrants monitoring.",
            "MEDIUM":   "This threat is moderately suspicious and should be quarantined.",
            "HIGH":     "This threat is actively dangerous. Immediate isolation is required.",
            "CRITICAL": "CRITICAL THREAT — immediate containment and forensic response required.",
        }
        ctx = severity_context.get(severity, "")
        if ctx:
            lines += [ctx, ""]

        explanation = "\n".join(lines)
        actions     = SEVERITY_ACTIONS.get(severity, SEVERITY_ACTIONS["MEDIUM"])
        prevention  = [
            SIGNAL_PREVENTION[sig]
            for sig in dominant_signals
            if sig in SIGNAL_PREVENTION
        ][:3]   # top 3 prevention tips

        return RemediationAdvice(
            explanation      = explanation,
            actions          = actions,
            prevention       = prevention,
            dominant_signals = dominant_signals,
            severity         = severity,
            threat_score     = threat_score,
            used_llm         = False,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # LLM explanation (Groq preferred, OpenAI fallback)
    # ─────────────────────────────────────────────────────────────────────────

    def _llm_explain(
        self, signals_dict, contributions, dominant_signals,
        severity, threat_score, file_name, sha256, entropy,
    ) -> RemediationAdvice:
        """Call Groq (LLaMA-3) or OpenAI to generate richer explanation."""
        prompt = self._build_prompt(
            signals_dict, contributions, dominant_signals,
            severity, threat_score, file_name, sha256, entropy,
        )

        response_text = ""
        if self._groq_key:
            response_text = self._groq_request(prompt)
        elif self._openai_key:
            response_text = self._openai_request(prompt)

        if not response_text:
            raise RuntimeError("LLM returned empty response")

        return RemediationAdvice(
            explanation      = response_text,
            actions          = SEVERITY_ACTIONS.get(severity, []),
            prevention       = [],
            dominant_signals = dominant_signals,
            severity         = severity,
            threat_score     = threat_score,
            used_llm         = True,
        )

    def _build_prompt(
        self, signals_dict, contributions, dominant_signals,
        severity, threat_score, file_name, sha256, entropy,
    ) -> str:
        sig_lines = "\n".join(
            f"  {SIGNAL_LABELS.get(s, s)}: {signals_dict.get(s, 0):.3f} "
            f"(weighted={contributions.get(s, 0):.3f})"
            for s in dominant_signals
        )
        return (
            f"You are a senior cybersecurity analyst. Analyze this threat detection result.\n\n"
            f"File: {file_name or 'unknown'}\n"
            f"SHA-256: {sha256[:32] if sha256 else 'N/A'}\n"
            f"Entropy: {entropy:.3f}\n"
            f"Threat Score: {threat_score:.1f}/100\n"
            f"Severity: {severity}\n\n"
            f"Top contributing signals:\n{sig_lines}\n\n"
            f"Provide:\n"
            f"1. A precise explanation of WHY this file was flagged, referencing signal values.\n"
            f"2. The most likely attack category (ransomware/trojan/dropper/etc.).\n"
            f"3. Immediate remediation steps for {severity} severity.\n"
            f"4. Specific prevention measures targeting the dominant signals.\n"
            f"Be concise, technical, and factual. Do not use generic language."
        )

    def _groq_request(self, prompt: str) -> str:
        import urllib.request
        body = json_encode({
            "model": "llama3-8b-8192",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 600,
            "temperature": 0.2,
        })
        req = urllib.request.Request(
            "https://api.groq.com/openai/v1/chat/completions",
            data=body.encode(),
            headers={
                "Authorization": f"Bearer {self._groq_key}",
                "Content-Type": "application/json",
            },
        )
        import json
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]

    def _openai_request(self, prompt: str) -> str:
        import urllib.request, json
        body = json.dumps({
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 600,
            "temperature": 0.2,
        })
        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=body.encode(),
            headers={
                "Authorization": f"Bearer {self._openai_key}",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]


def json_encode(obj) -> str:
    import json
    return json.dumps(obj)
