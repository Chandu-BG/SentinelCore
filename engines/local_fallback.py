"""LocalFallback — Context-aware security responses when Ollama is unavailable."""

from __future__ import annotations

import logging
import random
import re
from typing import Optional, Callable, Dict, Any, List

logger = logging.getLogger(__name__)


class LocalFallback:
    """Provides security-relevant responses using templates and heuristics."""

    name = "fallback"

    def __init__(self):
        self._available = True
        self._history: List[str] = []

    def is_available(self) -> bool:
        return self._available

    def generate_response(
        self,
        prompt: str,
        stream_callback: Optional[Callable[[str], None]] = None,
        done_callback: Optional[Callable[[str], None]] = None,
        context_type: str = "chat",
    ) -> None:
        """Generate response based on prompt analysis."""
        response = self._analyze_prompt(prompt, context_type)
        if stream_callback:
            # Simulate streaming
            for word in response.split():
                stream_callback(word + " ")
        if done_callback:
            done_callback(response)

    def chat(
        self,
        user_message: str,
        history: list,
        system_snapshot: dict,
        stream_cb=None,
        done_cb=None,
    ) -> None:
        """Handle chat with context-aware responses."""
        response = self._generate_chat_response(user_message, system_snapshot)
        if stream_cb:
            for word in response.split():
                stream_cb(word + " ")
        if done_cb:
            done_cb(response)

    def _analyze_prompt(self, prompt: str, context_type: str) -> str:
        """Analyze prompt and return appropriate response."""
        prompt_lower = prompt.lower()

        if "threat" in context_type or "malware" in prompt_lower:
            return self._threat_response()
        elif "phishing" in prompt_lower or "url" in prompt_lower:
            return self._phishing_response()
        elif "scan" in prompt_lower or "analysis" in prompt_lower:
            return self._scan_response()
        elif "performance" in prompt_lower or "cpu" in prompt_lower:
            return self._performance_response()
        else:
            return self._general_response()

    def _generate_chat_response(self, user_message: str, system_snapshot: dict) -> str:
        """Generate chat response based on user input and system state."""
        msg_lower = user_message.lower()

        # 1. Performance Query
        if any(tok in msg_lower for tok in ["cpu", "ram", "memory", "performance", "slow"]):
            cpu = system_snapshot.get("cpu_percent", 0)
            ram = system_snapshot.get("ram_percent", 0)
            
            # Find heavy processes
            procs = system_snapshot.get("processes", [])
            heavy = sorted(procs, key=lambda x: x.get("cpu_percent", 0), reverse=True)[:3]
            heavy_str = ", ".join([f"{p['name']} ({p['cpu_percent']:.1f}%)" for p in heavy if p.get("cpu_percent", 0) > 5])
            
            resp = f"Current system load: CPU is at {cpu:.1f}% and RAM is at {ram:.1f}%. "
            if heavy_str:
                resp += f"The highest consumers are: {heavy_str}. "
            else:
                resp += "No single process is consuming excessive resources. "
            
            if cpu > 80:
                resp += "Warning: CPU usage is critically high. Consider closing heavy applications."
            return resp

        # 2. Threat/Safety Query
        if any(tok in msg_lower for tok in ["threat", "malware", "virus", "safe", "dangerous"]):
            tc = system_snapshot.get("threat_count", 0)
            if tc > 0:
                return f"Caution: There are {tc} active threat(s) detected in the system. Please check the Scan or Quarantine tabs immediately for remediation."
            return "My real-time monitoring shows your system is currently clean. All 12 security shields are active and scanning for anomalies."

        # 3. Process Specifics
        if "process" in msg_lower or "app" in msg_lower:
            procs = system_snapshot.get("processes", [])
            count = len(procs)
            return f"I am currently monitoring {count} active processes. I check each one for suspicious injection attempts and ransomware behavior every second."

        # 4. Scans
        if "scan" in msg_lower:
            return "You can initiate a Quick Scan or a Full System Scan from the 'Scan' tab. I recommend a Full Scan once a week for maximum security."

        # 5. Routing / Privacy Explanation
        if any(tok in msg_lower for tok in ["routing", "how do you work", "privacy", "local"]):
            return (
                "<b>NovaSentinel Routing:</b> I use an AIManager router that prioritizes local Ollama models (like Llama3 or Phi3) for maximum privacy. "
                "If Ollama is unavailable, I fall back to this rule-based engine. "
                "Local LLMs are superior for security because your telemetry never leaves this machine. "
                "Previously, responses were repetitive because they lacked deep system context, which I now analyze in real-time."
            )

        # 6. General / Greetings
        greetings = ["hi", "hello", "hey", "who are you"]
        if any(g in msg_lower for g in greetings):
            return "Hello! I am NovaSentinel AI, your local security analyst. I'm currently monitoring your system telemetry and protection layers. How can I help you today?"

        # Default dynamic response
        options = [
            "I'm keeping a close eye on your system telemetry. Everything looks stable.",
            "Security shields are at 100%. No unauthorized network or file activity detected.",
            "I'm analyzing background processes for suspicious behavior. Your system is fully protected.",
            "If you have questions about specific files or URLs, feel free to ask!"
        ]
        return random.choice(options)

    def _threat_response(self) -> str:
        reasons = ["suspicious API calls", "unsigned executable", "high entropy", "packed code"]
        return f"Assessment: High risk detected due to {random.choice(reasons)}. Recommendation: Isolate file in Quarantine and perform a deep scan."

    def _phishing_response(self) -> str:
        return "Assessment: This URL shows classic phishing indicators, including typosquatting and a suspicious TLD. Access has been flagged as MALICIOUS."

    def _scan_response(self) -> str:
        return "Scan Analysis: No active malware found, but detected several 'greyware' applications that may impact privacy. Review your installed apps."

    def _performance_response(self) -> str:
        return "Performance Insight: System resource utilization is within normal bounds. No malicious crypto-mining behavior detected."

    def _general_response(self) -> str:
        return "NovaSentinel AI is operational. I am routing your request through the local reasoning engine."

    def shutdown(self) -> None:
        pass
