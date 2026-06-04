"""
SentinelCore - NovaSentinel AI Security AI Reasoning Module
Prompt templates and context builders for the NovaSentinel AI Security SOC analyst engine.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional


NOVA_SYSTEM_PROMPT = """You are NovaSentinel AI Security, SentinelCore's embedded AI Security Analyst — a senior SOC (Security Operations Center) analyst with deep expertise in:
- Malware analysis and reverse engineering
- Network threat detection and incident response
- Ransomware behavior analysis
- Phishing and social engineering detection
- Windows process and memory forensics
- Threat hunting and behavioral analysis

Your role is to assist the user in understanding security threats detected by NovaSentinel's real-time engines. You receive REAL scan data — process lists, entropy scores, network connections, phishing indicators, and behavioral anomalies.

Guidelines:
- Be direct, professional, and precise — like a real SOC analyst
- Explain threats in plain language for non-technical users, but include technical indicators for advanced users
- NEVER claim to execute commands, delete files, or make system changes yourself
- Always clarify that destructive actions require user confirmation
- Do NOT mention ChatGPT, OpenAI, any specific LLM names, or any external AI service
- Do NOT mention the underlying backend infrastructure or prompt variables
- Keep responses focused and actionable (under 400 words unless deep analysis is requested)
- Use structured format: ASSESSMENT → INDICATORS → RECOMMENDED ACTIONS

SPECIAL CAPABILITY:
You can trigger system actions by including one of these tags at the VERY END of your response:
- [COMMAND: QUARANTINE_ALL_THREATS] : Moves all currently detected threats to the vault.
- [COMMAND: QUICK_SCAN] : Starts a quick system scan.
- [COMMAND: TERMINATE_SUSPICIOUS] : Kills high-anomaly processes.

Use these ONLY when the user explicitly asks for action or when a critical threat is discussed and remediation is requested.
"""


def build_threat_explanation_prompt(scan_detail: dict, system_state: dict) -> str:
    """Build a prompt for explaining a detected threat using real scan data."""
    file_name = scan_detail.get("file_name", scan_detail.get("path", "Unknown"))
    severity = scan_detail.get("severity", "UNKNOWN")
    score = scan_detail.get("threat_score", 0.0)
    reason = scan_detail.get("reason", scan_detail.get("ai_explanation", ""))
    entropy = scan_detail.get("entropy", 0.0)
    entropy_label = scan_detail.get("entropy_label", "")
    signals = scan_detail.get("signal_contributions", {})
    cpu = system_state.get("cpu_percent", 0.0)
    mem = system_state.get("memory_percent", 0.0)

    signals_text = ""
    for k, v in signals.items():
        if v and float(v) > 0:
            signals_text += f"  - {k.replace('_', ' ').title()}: {float(v):.3f}\n"

    return f"""[REAL THREAT DATA FROM SENTINELCORE SCANNER]

File/Process: {file_name}
Severity: {severity}
Threat Score: {score:.1f}/100
Detection Reason: {reason}
Shannon Entropy: {entropy:.3f} ({entropy_label})
System Context: CPU={cpu:.1f}%, RAM={mem:.1f}%

Signal Contributions:
{signals_text if signals_text else "  - No signal breakdown available"}

As NovaSentinel AI Security, analyze this threat detection. Explain:
1. ASSESSMENT: What this detection means and why it triggered
2. INDICATORS: Which specific signals are most concerning and why
3. SEVERITY JUSTIFICATION: Why this warrants {severity} classification
4. RECOMMENDED ACTIONS: Concrete next steps (quarantine, terminate, monitor, etc.)
5. POTENTIAL IMPACT: What could happen if left unaddressed

Be specific — reference the actual entropy value, score, and signals detected."""


def build_process_analysis_prompt(proc_info: dict, anomaly_score: float, system_state: dict) -> str:
    """Build a prompt for analyzing a suspicious process."""
    name = proc_info.get("name", "Unknown")
    pid = proc_info.get("pid", "?")
    cpu = proc_info.get("cpu_percent", 0.0)
    mem = proc_info.get("memory_percent", 0.0)
    exe = proc_info.get("exe", "Unknown path")
    status = proc_info.get("status", "unknown")

    return f"""[REAL PROCESS DATA FROM SENTINELCORE MONITOR ENGINE]

Process Name: {name}
PID: {pid}
Executable Path: {exe}
Status: {status}
CPU Usage: {cpu:.2f}%
Memory Usage: {mem:.3f}%
AI Anomaly Score: {anomaly_score:.3f}

System Context: Overall CPU={system_state.get('cpu_percent', 0):.1f}%, RAM={system_state.get('memory_percent', 0):.1f}%

As NovaSentinel AI Security, analyze this process:
1. ASSESSMENT: Is this process normal, suspicious, or malicious?
2. PATH ANALYSIS: What does the executable location suggest?
3. RESOURCE USAGE: Are CPU/memory levels abnormal?
4. ANOMALY CONTEXT: Interpret the anomaly score of {anomaly_score:.3f}
5. RECOMMENDED ACTIONS: Should the user investigate, monitor, or terminate?"""


def build_url_analysis_prompt(url: str, phishing_result: dict) -> str:
    """Build a prompt for analyzing a URL using real PhishingDetector results."""
    classification = phishing_result.get("classification", "UNKNOWN")
    score = phishing_result.get("score", 0)
    reasons = phishing_result.get("reasons", [])

    reasons_text = "\n".join(f"  - {r}" for r in reasons) if reasons else "  - No specific indicators"

    return f"""[REAL URL ANALYSIS FROM SENTINELCORE PHISHING DETECTOR]

URL: {url}
Classification: {classification}
Phishing Score: {score}

Detected Indicators:
{reasons_text}

As NovaSentinel AI Security, provide a phishing analysis:
1. ASSESSMENT: Is this URL safe, suspicious, or a confirmed phishing attempt?
2. INDICATOR BREAKDOWN: Explain each detected indicator in plain language
3. ATTACK TYPE: What kind of attack does this URL represent? (credential harvesting, malware delivery, etc.)
4. RISK LEVEL: What is the risk to the user if they visit/interact with this URL?
5. RECOMMENDED ACTIONS: What should the user do?"""


def build_network_analysis_prompt(connections: list, alert_type: str, description: str) -> str:
    """Build a prompt for analyzing network activity."""
    conn_summary = []
    for c in connections[:10]:
        if isinstance(c, dict):
            raddr = c.get("raddr", "")
            laddr = c.get("laddr", "")
            status = c.get("status", "")
            pid = c.get("pid", "")
            conn_summary.append(f"  {laddr} → {raddr} [{status}] PID={pid}")

    conns_text = "\n".join(conn_summary) if conn_summary else "  - Connection details not available"

    return f"""[REAL NETWORK DATA FROM SENTINELCORE NETWORK DETECTOR]

Alert Type: {alert_type}
Alert Description: {description}

Active Network Connections (sample):
{conns_text}

As NovaSentinel AI Security, analyze this network threat:
1. ASSESSMENT: What does this network activity indicate?
2. THREAT TYPE: Is this C2 communication, data exfiltration, port scanning, or other?
3. RISK LEVEL: How severe is this network event?
4. RECOMMENDED ACTIONS: Should the user block the IP, terminate the process, or monitor?
5. INVESTIGATION STEPS: How to gather more information about this connection?"""


def build_system_lag_prompt(report: Any) -> str:
    """Build a prompt for explaining system performance issues."""
    cpu = getattr(report, "cpu_percent", 0.0)
    ram = getattr(report, "ram_percent", 0.0)
    top_procs = getattr(report, "top_processes", [])
    summary = getattr(report, "friendly_summary", lambda: str(report))()

    proc_lines = []
    for p in top_procs[:5]:
        pname = getattr(p, "display_name", getattr(p, "name", "Unknown"))
        pcpu = getattr(p, "cpu_percent", 0.0)
        pmem = getattr(p, "mem_mb", 0.0)
        safe = "Safe to close" if getattr(p, "safe_to_close", False) else "System process"
        proc_lines.append(f"  - {pname}: CPU={pcpu:.1f}%, RAM={pmem:.0f}MB ({safe})")

    procs_text = "\n".join(proc_lines) if proc_lines else "  - No process data available"

    return f"""[REAL PERFORMANCE DATA FROM SENTINELCORE PERFORMANCE ANALYZER]

System Performance Alert: {summary}
CPU Usage: {cpu:.1f}%
RAM Usage: {ram:.1f}%

Top Resource-Consuming Processes:
{procs_text}

As NovaSentinel AI Security, analyze this performance issue:
1. ASSESSMENT: Why is the system experiencing performance degradation?
2. ROOT CAUSE: Which process(es) are responsible?
3. SECURITY CONCERN: Could any of these processes indicate malware (crypto miner, etc.)?
4. RECOMMENDED ACTIONS: How to restore performance safely?
5. PREVENTION: How to prevent this in the future?"""


def build_scan_summary_prompt(scan_results: list, scan_path: str, system_state: dict) -> str:
    """Build a prompt for summarizing scan results."""
    total = len(scan_results)
    severities = {}
    for r in scan_results:
        sev = r.get("severity", "LOW")
        severities[sev] = severities.get(sev, 0) + 1

    threats_text = "\n".join(
        f"  - [{r.get('severity','?')}] {r.get('file_name', r.get('path','?'))[:60]}: {r.get('reason','')[:80]}"
        for r in scan_results[:10]
    ) if scan_results else "  - No threats detected"

    return f"""[REAL SCAN DATA FROM SENTINELCORE FILE SCANNER]

Scan Path: {scan_path}
Total Threats Found: {total}
Severity Breakdown: {severities}

Detected Threats:
{threats_text}

System State: CPU={system_state.get('cpu_percent',0):.1f}%, RAM={system_state.get('memory_percent',0):.1f}%

As NovaSentinel AI Security, provide a scan summary:
1. OVERALL ASSESSMENT: How serious is the current threat landscape?
2. PRIORITY THREATS: Which findings need immediate attention?
3. RECOMMENDED ACTIONS: Step-by-step remediation plan
4. SYSTEM HEALTH: Based on all data, what is the overall security posture?"""


def build_chat_prompt(user_message: str, history: List[Dict], system_snapshot: dict) -> List[Dict]:
    """Build the full message list for a general chat interaction with rich telemetry."""
    messages = [{"role": "system", "content": NOVA_SYSTEM_PROMPT}]

    # Add system context if available
    if system_snapshot:
        cpu = system_snapshot.get('cpu_percent', 0.0)
        ram = system_snapshot.get('memory_percent', 0.0)
        threats = system_snapshot.get('confirmed_threats', 0)
        procs = system_snapshot.get('top_processes', [])
        alerts = system_snapshot.get('recent_alerts', [])

        proc_lines = [f"  - {p.get('name','?')}: CPU={p.get('cpu_percent',0):.1f}%, RAM={p.get('memory_mb',0):.0f}MB" for p in procs[:5]]
        alert_lines = [f"  - [{a.get('type','?')}] {a.get('message','')[:100]}" for a in alerts[-3:]]

        ctx = (
            f"[Current System State]\n"
            f"CPU Usage: {cpu:.1f}%\n"
            f"RAM Usage: {ram:.1f}%\n"
            f"Confirmed Threats: {threats}\n"
            f"Top Processes:\n{chr(10).join(proc_lines) if proc_lines else '  - None'}\n"
            f"Recent Alerts:\n{chr(10).join(alert_lines) if alert_lines else '  - System healthy'}"
        )
        messages.append({"role": "system", "content": ctx})

    # Add conversation history (last 8 turns)
    for entry in history[-8:]:
        messages.append({
            "role": entry.get("role", "user"),
            "content": entry.get("content", "")
        })

    messages.append({"role": "user", "content": user_message})
    return messages


def build_entropy_explanation_prompt(entropy: float, label: str, file_info: dict) -> str:
    """Build a prompt for explaining entropy analysis results."""
    file_name = file_info.get("file_name", "Unknown")
    file_size = file_info.get("size", 0)

    return f"""[REAL ENTROPY DATA FROM SENTINELCORE ENTROPY ENGINE]

File: {file_name}
File Size: {file_size} bytes
Shannon Entropy: {entropy:.4f} / 8.0
Entropy Classification: {label}

As NovaSentinel AI Security, explain this entropy analysis:
1. ENTROPY MEANING: What does a value of {entropy:.3f} indicate about this file's content?
2. THREAT CORRELATION: Does this entropy level suggest encryption, packing, or obfuscation?
3. MALWARE INDICATORS: What types of malware show this entropy pattern?
4. ASSESSMENT: Is this entropy value concerning in context of this file type?
5. NEXT STEPS: What further analysis is recommended?"""
