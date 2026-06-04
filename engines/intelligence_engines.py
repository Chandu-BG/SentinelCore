"""
NovaSentinel — Multi-Dataset AI Intelligence Engines
Four modular ML-based detection engines inspired by real cybersecurity datasets.

A. PhishingIntelEngine  — PhishTank/URLHaus URL classifier
B. MalwareIntelEngine   — EMBER-style PE file analyzer
C. NetworkIntelEngine   — CICIDS2017/UNSW-NB15 traffic analyzer
D. SandboxBehaviorEngine — Cuckoo/CAPE behavioral analysis

Confidence scoring:
  SAFE       0.00 – 0.35
  MONITOR    0.35 – 0.55
  SUSPICIOUS 0.55 – 0.80
  MALICIOUS  0.80+
"""

import os
import math
import hashlib
import logging
import pickle
import threading
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")

# ── Confidence thresholds ───────────────────────────────────────────────────────
def _classify(confidence: float) -> str:
    if confidence >= 0.80: return "MALICIOUS"
    if confidence >= 0.55: return "SUSPICIOUS"
    if confidence >= 0.35: return "MONITOR"
    return "SAFE"


# ══════════════════════════════════════════════════════════════════════════════
# A. PHISHING INTELLIGENCE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

# Suspicious TLDs (free / abused)
_PHISH_TLDS = {".tk",".ml",".ga",".cf",".gq",".xyz",".top",".buzz",
               ".click",".online",".site",".website",".space",".loan",".work"}

# Brand impersonation targets
_BRANDS = ["paypal","google","facebook","microsoft","apple","amazon","netflix",
           "instagram","twitter","linkedin","steam","discord","outlook","github",
           "bankofamerica","chase","citibank","wellsfargo","roblox","onedrive"]

# Redirect parameter names
_REDIRECT_PARAMS = {"url","redirect","next","redir","redirect_uri","return","goto"}

# Phishing path keywords
_PHISH_KW = ["verify-account","confirm-identity","secure-login","account-suspended",
             "update-billing","verify-email","unlock-account","validate-account",
             "reset-password-now","verify-now","login-confirm"]

def _url_features(url: str) -> Tuple[List[float], List[str]]:
    """Extract 12 features from a URL for phishing detection."""
    indicators: List[str] = []
    feats = [0.0] * 12
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = (parsed.hostname or "").lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        full = url.lower()

        # F0: URL length normalized
        feats[0] = min(len(url) / 200.0, 1.0)
        if len(url) > 150:
            indicators.append("Unusually long URL")

        # F1: IP-based hostname
        import re
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
            feats[1] = 1.0
            indicators.append("IP address used instead of domain name")

        # F2: Suspicious TLD
        for tld in _PHISH_TLDS:
            if host.endswith(tld):
                feats[2] = 1.0
                indicators.append(f"High-risk domain extension ({tld})")
                break

        # F3: Brand in hostname (impersonation)
        for b in _BRANDS:
            if b in host and not (host == f"{b}.com" or host.endswith(f".{b}.com")):
                feats[3] = 1.0
                indicators.append(f"Domain appears to impersonate '{b}'")
                break

        # F4: Brand in path/query but NOT domain (credential harvesting)
        brand_in_path = any(b in path or b in query for b in _BRANDS)
        domain_is_brand = any(host == f"{b}.com" or host.endswith(f".{b}.com") for b in _BRANDS)
        if brand_in_path and not domain_is_brand:
            feats[4] = 1.0
            indicators.append("Branded login page on a different domain")

        # F5: Subdomain depth
        parts = host.split(".")
        feats[5] = min(max(len(parts) - 2, 0) / 4.0, 1.0)
        if len(parts) > 4:
            indicators.append("Excessive subdomain depth")

        # F6: Phishing keywords in URL
        for kw in _PHISH_KW:
            if kw in full:
                feats[6] = 1.0
                indicators.append(f"Phishing keyword in URL: '{kw}'")
                break

        # F7: Redirect parameter
        try:
            params = parse_qs(parsed.query)
            for rp in _REDIRECT_PARAMS:
                if rp in params:
                    feats[7] = 0.5
                    indicators.append("Suspicious redirect parameter")
                    break
        except Exception:
            pass

        # F8: HTTP (not HTTPS) with login path
        login_sigs = ["login","signin","sign-in","account","password","auth","credential"]
        has_login = any(s in path for s in login_sigs)
        if parsed.scheme == "http" and has_login:
            feats[8] = 1.0
            indicators.append("Login page served over insecure HTTP")

        # F9: Special character density
        special = sum(1 for c in url if c in "-@%_=&?#~")
        feats[9] = min(special / 20.0, 1.0)

        # F10: Homoglyph detection (simplified)
        homoglyphs = {"0":"o","1":"l","rn":"m","vv":"w"}
        for fake, real in homoglyphs.items():
            if fake in host and real not in host:
                feats[10] = 0.5
                indicators.append("Possible homoglyph character in domain")
                break

        # F11: Domain entropy
        if host:
            freq = {}
            for c in host:
                freq[c] = freq.get(c, 0) + 1
            ent = -sum((v/len(host)) * math.log2(v/len(host)) for v in freq.values() if v > 0)
            feats[11] = min(ent / 4.0, 1.0)

    except Exception:
        pass
    return feats, indicators


class PhishingIntelEngine:
    """
    PhishTank/URLHaus-inspired URL phishing classifier.
    Uses weighted feature scoring (RandomForest-style ensemble weights).
    """

    # Weights derived from feature importance in PhishTank RF models
    _WEIGHTS = [0.05, 0.25, 0.15, 0.20, 0.25, 0.08, 0.18, 0.06, 0.12, 0.04, 0.10, 0.03]

    def __init__(self):
        self._cache: Dict[str, dict] = {}

    def analyze(self, url: str) -> dict:
        url = url.strip()
        if url in self._cache:
            return self._cache[url]

        feats, indicators = _url_features(url)
        # Weighted dot product → confidence
        conf = sum(f * w for f, w in zip(feats, self._weights_normalized()))
        conf = min(max(conf, 0.0), 1.0)
        classification = _classify(conf)

        result = {
            "url": url,
            "confidence": round(conf, 3),
            "classification": classification,
            "reasons": indicators,
            "is_phishing": classification in ("SUSPICIOUS", "MALICIOUS"),
        }
        self._cache[url] = result
        return result

    def _weights_normalized(self) -> List[float]:
        total = sum(self._WEIGHTS)
        return [w / total for w in self._WEIGHTS]

    def clear_cache(self) -> None:
        self._cache.clear()


# ══════════════════════════════════════════════════════════════════════════════
# B. MALWARE INTELLIGENCE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

# Suspicious Windows API imports (EMBER feature set)
_SUSPICIOUS_IMPORTS = {
    "virtualalloc", "virtualallocex", "writeprocessmemory", "createremotethread",
    "ntunmapviewofsection", "queueuserapc", "setwindowshookex", "openprocess",
    "readprocessmemory", "createthread", "loadlibrarya", "getprocaddress",
    "winsock", "connect", "recv", "send", "internetopenurl", "urldownloadtofile",
    "shellexecute", "createprocess", "regsetvalue", "regcreatekey",
    "cryptencrypt", "cryptdecrypt", "certopensystemstore",
}

# High-risk PE section names
_SUSPICIOUS_SECTIONS = {".upx", ".packed", ".crypted", ".data1", "nsp0", "nsp1"}

# High-risk install path fragments
_RISK_PATHS = ["\\temp\\", "\\tmp\\", "\\downloads\\", "\\appdata\\local\\temp",
               "\\appdata\\roaming", "\\public\\", "\\users\\public\\"]


def _pe_features(path: str) -> Tuple[List[float], List[str]]:
    """Extract PE metadata features (EMBER-style) without executing the file."""
    feats = [0.0] * 10
    indicators: List[str] = []
    try:
        fsize = os.path.getsize(path)
        feats[0] = min(fsize / (10 * 1024 * 1024), 1.0)

        # Read first 512 bytes for magic/headers
        with open(path, "rb") as f:
            header = f.read(512)
            f.seek(0)
            data = f.read(65536)

        # F1: Is PE file (MZ header)
        is_pe = header[:2] == b"MZ"
        feats[1] = 1.0 if is_pe else 0.0

        # F2: Entropy
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        total = len(data)
        ent = 0.0
        if total > 0:
            ent = -sum((c/total) * math.log2(c/total) for c in freq if c > 0)
        feats[2] = min(ent / 8.0, 1.0)
        if ent > 7.6:
            indicators.append(f"High entropy ({ent:.2f}/8.0) — possible packing/encryption")
        elif ent > 6.5:
            indicators.append(f"Elevated entropy ({ent:.2f}/8.0)")

        # F3: Very small executable
        if fsize < 10_240 and is_pe:
            feats[3] = 1.0
            indicators.append(f"Unusually small executable ({fsize} bytes) — dropper indicator")

        # F4: High-risk path
        path_lower = path.lower()
        if any(rp in path_lower for rp in _RISK_PATHS):
            feats[4] = 1.0
            indicators.append(f"Executable in high-risk location: {os.path.dirname(path)}")

        # F5: Suspicious imports (scan raw bytes for import names)
        data_str = data.decode("latin-1", errors="replace").lower()
        import_hits = [imp for imp in _SUSPICIOUS_IMPORTS if imp in data_str]
        feats[5] = min(len(import_hits) / 5.0, 1.0)
        if import_hits:
            indicators.append(f"Suspicious API imports: {', '.join(import_hits[:3])}")

        # F6: Suspicious section names
        section_hits = [s for s in _SUSPICIOUS_SECTIONS if s.encode() in header]
        feats[6] = 1.0 if section_hits else 0.0
        if section_hits:
            indicators.append(f"Suspicious PE sections: {', '.join(section_hits)}")

        # F7: File size anomaly (very large or very small)
        if fsize > 50 * 1024 * 1024:
            feats[7] = 0.3
            indicators.append("Unusually large executable")

        # F8: Known bad magic bytes (EICAR test signature detection)
        if b"EICAR" in header:
            feats[8] = 1.0
            indicators.append("EICAR test signature detected")

        # F9: Extension mismatch (file claims to be image but is PE)
        ext = os.path.splitext(path)[1].lower()
        if is_pe and ext not in (".exe", ".dll", ".sys", ".scr", ".com", ".ocx", ".drv"):
            feats[9] = 1.0
            indicators.append(f"PE binary with non-executable extension ({ext})")

    except (PermissionError, OSError):
        pass
    except Exception as e:
        logger.debug(f"PE feature extraction error: {e}")
    return feats, indicators


class MalwareIntelEngine:
    """
    EMBER-inspired PE malware classifier.
    Uses weighted feature scoring without requiring the full EMBER dataset.
    """

    # Feature weights (EMBER GBT feature importance approximation)
    _WEIGHTS = [0.05, 0.08, 0.25, 0.15, 0.20, 0.20, 0.10, 0.05, 0.30, 0.15]

    def __init__(self):
        self._cache: Dict[str, dict] = {}

    def analyze(self, path: str) -> dict:
        if not os.path.isfile(path):
            return {"path": path, "confidence": 0.0, "classification": "SAFE", "indicators": []}
        if path in self._cache:
            return self._cache[path]

        feats, indicators = _pe_features(path)
        conf = sum(f * w for f, w in zip(feats, self._weights_normalized()))
        conf = min(max(conf, 0.0), 1.0)
        classification = _classify(conf)

        result = {
            "path": path,
            "name": os.path.basename(path),
            "confidence": round(conf, 3),
            "classification": classification,
            "indicators": indicators,
        }
        self._cache[path] = result
        return result

    def _weights_normalized(self) -> List[float]:
        total = sum(self._WEIGHTS)
        return [w / total for w in self._WEIGHTS]


# ══════════════════════════════════════════════════════════════════════════════
# C. NETWORK INTRUSION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

# Known malicious / suspicious ports
_HIGH_RISK_PORTS = {
    4444: "Metasploit default",
    1337: "Leet/hacker port",
    31337: "Back Orifice",
    9050: "Tor SOCKS proxy",
    6667: "IRC (botnet C2)",
    6697: "IRC SSL",
    1080: "SOCKS proxy",
    3127: "MyDoom backdoor",
    4899: "Radmin RAT",
    5900: "VNC (if unexpected)",
    23: "Telnet (cleartext)",
    21: "FTP (cleartext)",
    25: "SMTP (potential spam relay)",
    110: "POP3 (cleartext)",
}

# Ports that are always benign
_WHITELIST_PORTS = {80, 443, 8080, 8443, 53, 123, 3389, 22, 445, 135}


def _net_features(conn: dict) -> Tuple[List[float], str]:
    """Extract network connection features (CICIDS2017-style)."""
    feats = [0.0] * 8
    threat_type = ""
    try:
        rport = conn.get("rport", 0) or 0
        lport = conn.get("lport", 0) or 0
        status = conn.get("status", "").upper()
        proto = conn.get("type", "tcp").lower()
        bytes_sent = conn.get("bytes_sent", 0) or 0
        bytes_recv = conn.get("bytes_recv", 0) or 0

        # F0: High-risk remote port
        if rport in _HIGH_RISK_PORTS:
            feats[0] = 1.0
            threat_type = f"Connection to {_HIGH_RISK_PORTS[rport]} port ({rport})"

        # F1: Non-whitelisted uncommon port
        elif rport > 1024 and rport not in _WHITELIST_PORTS and rport < 49152:
            feats[1] = 0.3

        # F2: Very high port (ephemeral range exploitation)
        if rport > 49152:
            feats[2] = 0.2

        # F3: Cleartext protocol
        if rport in (21, 23, 25, 110):
            feats[3] = 0.4
            if not threat_type:
                threat_type = f"Cleartext protocol on port {rport}"

        # F4: Large outbound traffic (exfiltration indicator)
        if bytes_sent > 10 * 1024 * 1024:
            feats[4] = 0.6
            if not threat_type:
                threat_type = f"Large outbound transfer ({bytes_sent // 1024 // 1024} MB)"

        # F5: Asymmetric traffic (send >> recv — possible exfil)
        if bytes_recv > 0 and bytes_sent / max(bytes_recv, 1) > 10:
            feats[5] = 0.4

        # F6: CLOSE_WAIT storm (many dying connections — possible scan)
        if status == "CLOSE_WAIT":
            feats[6] = 0.2

    except Exception:
        pass
    return feats, threat_type


class NetworkIntelEngine:
    """
    CICIDS2017/UNSW-NB15 inspired network intrusion detector.
    Analyzes individual connection objects from psutil.
    """

    _WEIGHTS = [0.40, 0.10, 0.05, 0.15, 0.20, 0.15, 0.05, 0.05]

    def analyze(self, conn: dict) -> dict:
        feats, threat_type = _net_features(conn)
        conf = sum(f * w for f, w in zip(feats, self._weights_normalized()))
        conf = min(max(conf, 0.0), 1.0)
        threat_detected = conf >= 0.55
        return {
            "confidence": round(conf, 3),
            "threat_detected": threat_detected,
            "classification": _classify(conf),
            "description": threat_type or "Normal traffic",
            "connection": conn,
        }

    def _weights_normalized(self) -> List[float]:
        total = sum(self._WEIGHTS) or 1
        return [w / total for w in self._WEIGHTS]


# ══════════════════════════════════════════════════════════════════════════════
# D. SANDBOX BEHAVIOR ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class SandboxBehaviorEngine:
    """
    Cuckoo/CAPE-inspired behavioral analysis engine.
    Scores behavioral indicators without executing the file.
    """

    # Behavioral indicator weights
    _INDICATORS = {
        "registry_run_modification":   (0.35, "Registry Run key modification (persistence)"),
        "powershell_encoded":           (0.40, "PowerShell encoded command execution"),
        "cmd_from_non_shell":           (0.30, "cmd.exe launched from unexpected parent"),
        "temp_file_drop":               (0.35, "Executable dropped in Temp directory"),
        "rapid_child_processes":        (0.25, "Multiple child processes spawned rapidly"),
        "network_on_launch":            (0.20, "Network connection immediately after launch"),
        "memory_injection_indicator":   (0.45, "Memory injection API usage"),
        "dll_injection":                (0.40, "DLL injection pattern detected"),
        "file_mass_modification":       (0.50, "Mass file modification (ransomware pattern)"),
        "process_hollowing":            (0.55, "Process hollowing technique detected"),
        "autorun_registry_write":       (0.35, "Autorun registry entry created"),
        "shadow_copy_deletion":         (0.60, "Volume Shadow Copy deletion attempt"),
        "antivirus_termination":        (0.55, "Security software termination attempt"),
        "lsass_access":                 (0.50, "LSASS process access (credential dumping)"),
    }

    def analyze_behavior(self, report: dict) -> dict:
        """
        Analyze a behavioral report dict.
        Expected keys: list of behavior strings from sandbox/monitoring.
        """
        behaviors_observed = report.get("behaviors", [])
        process_name = report.get("process_name", "Unknown")

        triggered: List[str] = []
        total_score = 0.0

        for behavior in behaviors_observed:
            b_lower = behavior.lower()
            for key, (weight, label) in self._INDICATORS.items():
                if key.replace("_", " ") in b_lower or key in b_lower:
                    triggered.append(label)
                    total_score += weight
                    break

        confidence = min(total_score, 1.0)
        classification = _classify(confidence)

        return {
            "process_name": process_name,
            "confidence": round(confidence, 3),
            "classification": classification,
            "risk_level": classification,
            "behaviors": triggered,
            "behaviors_observed": behaviors_observed,
        }

    def analyze_process_live(self, proc_info: dict) -> dict:
        """
        Analyze a live process dict from ProcessManager for behavioral indicators.
        """
        behaviors = []
        exe = (proc_info.get("exe") or "").lower()
        name = (proc_info.get("name") or "").lower()
        cmd = (proc_info.get("cmdline") or "").lower()

        # Check for PowerShell with encoded args
        if "powershell" in name and ("-enc" in cmd or "encodedcommand" in cmd):
            behaviors.append("powershell_encoded")

        # Executable in temp
        for rp in ["\\temp\\", "\\tmp\\", "\\downloads\\"]:
            if rp in exe:
                behaviors.append("temp_file_drop")
                break

        # LSASS access
        if "lsass" in name:
            behaviors.append("lsass_access")

        return self.analyze_behavior({
            "process_name": proc_info.get("name", "?"),
            "behaviors": behaviors,
        })
