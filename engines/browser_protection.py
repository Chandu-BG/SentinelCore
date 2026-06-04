"""
SentinelCore - Browser Protection Engine
Monitors browser processes (Chrome, Edge, Firefox) network activity.
Detects:
  - Connections to suspicious / known malicious domains
  - Phishing page visits (via PhishingDetector analysis)
  - Malicious redirects
  - Connections to Tor exit nodes

Runs as a background daemon thread. CPU-safe polling interval.
"""

import time
import logging
import threading
import psutil
from typing import Callable, Optional, Set, Dict, List
from collections import deque

logger = logging.getLogger(__name__)

# Browser process names to monitor (lowercase)
BROWSER_PROCESSES = {
    "chrome.exe", "chromium.exe",
    "msedge.exe",  "microsoftedge.exe",
    "firefox.exe", "firefox",
}

# Known malicious / phishing IPs (subset — expanded by threat intel in real products)
MALICIOUS_IPS = {
    "185.220.101.55", "45.142.212.100", "91.108.4.1",
    "194.165.16.78",  "5.188.206.14",   "198.54.117.200",
    "195.78.54.10",   "212.109.196.160", "185.220.100.252",
}

# Suspicious ports browsers shouldn't normally connect to
SUSPICIOUS_BROWSER_PORTS = {
    4444, 5555, 6666, 6667, 8888, 9001, 9030, 9050,
    1337, 31337, 12345, 23456,
}

POLL_INTERVAL      = 8.0     # seconds — low CPU cost
MAX_ALERTS_PER_IP  = 2


class BrowserThreat:
    """Record of a detected browser threat."""
    def __init__(self, browser: str, threat_type: str,
                 remote_ip: str, remote_port: int,
                 description: str, url_hint: str = ""):
        self.browser     = browser
        self.threat_type = threat_type
        self.remote_ip   = remote_ip
        self.remote_port = remote_port
        self.description = description
        self.url_hint    = url_hint

    def to_dict(self) -> dict:
        return {
            "browser":     self.browser,
            "threat_type": self.threat_type,
            "remote_ip":   self.remote_ip,
            "remote_port": self.remote_port,
            "description": self.description,
            "url_hint":    self.url_hint,
        }


class BrowserProtection:
    """
    Background browser protection engine.
    Monitors Chrome, Edge, Firefox network connections for threats.
    Optionally integrates with PhishingDetector for URL analysis.
    """

    def __init__(
        self,
        on_alert:         Optional[Callable[[str, str], None]] = None,
        phishing_detector = None,
        poll_interval:    float = POLL_INTERVAL,
    ):
        self.on_alert          = on_alert
        self.phishing_detector = phishing_detector
        self.poll_interval     = poll_interval

        self._running  = False
        self._thread: Optional[threading.Thread] = None
        self._lock     = threading.Lock()

        self._seen_alerts: Dict[str, int] = {}     # key → alert count
        self._threats: List[BrowserThreat]  = []
        self._active_browsers: Set[str]     = set()

    # ──────────────────────────────────────────────────────────────────────────
    # Lifecycle
    # ──────────────────────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="BrowserProtection"
        )
        self._thread.start()
        logger.info("BrowserProtection started.")

    def stop(self) -> None:
        self._running = False
        logger.info("BrowserProtection stopped.")

    # ──────────────────────────────────────────────────────────────────────────
    # Monitor loop
    # ──────────────────────────────────────────────────────────────────────────

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._scan_browser_connections()
            except Exception as e:
                logger.debug(f"BrowserProtection loop error: {e}")
            time.sleep(self.poll_interval)

    def _scan_browser_connections(self) -> None:
        """Find browser processes and analyse their network connections."""
        active: Set[str] = set()

        try:
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    pname = (proc.info.get("name") or "").lower()
                    if pname not in BROWSER_PROCESSES:
                        continue

                    browser_label = self._normalize_browser_name(pname)
                    active.add(browser_label)

                    # Get connections for this browser process
                    try:
                        conns = proc.net_connections(kind="inet")
                    except AttributeError:
                        # psutil < 5.9 compatibility
                        conns = proc.connections(kind="inet")

                    for conn in conns:
                        if conn.status != "ESTABLISHED":
                            continue
                        if not conn.raddr:
                            continue
                        remote_ip   = conn.raddr.ip
                        remote_port = conn.raddr.port

                        # Skip private / loopback addresses
                        if self._is_private(remote_ip):
                            continue

                        self._check_connection(browser_label, remote_ip, remote_port)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        except Exception as e:
            logger.debug(f"Browser scan error: {e}")

        with self._lock:
            self._active_browsers = active

    def _check_connection(self, browser: str, ip: str, port: int) -> None:
        """Analyse a single browser connection for threats."""

        # Known malicious IP
        if ip in MALICIOUS_IPS:
            self._fire_alert(
                key=f"MALIP_{ip}",
                alert_type="BROWSER_MALICIOUS_IP",
                description=(
                    f"Your browser ({browser}) connected to a known malicious server "
                    f"({ip}:{port}). This may indicate a phishing or malware attempt."
                ),
                browser=browser,
                threat_type="BROWSER_MALICIOUS_IP",
                remote_ip=ip,
                remote_port=port,
            )
            return

        # Suspicious port
        if port in SUSPICIOUS_BROWSER_PORTS:
            self._fire_alert(
                key=f"SUSPPORT_{ip}_{port}",
                alert_type="BROWSER_SUSPICIOUS_PORT",
                description=(
                    f"Your browser ({browser}) connected to an unusual port "
                    f"({port}) on {ip}. This is uncommon and may indicate malware."
                ),
                browser=browser,
                threat_type="BROWSER_SUSPICIOUS_PORT",
                remote_ip=ip,
                remote_port=port,
            )

    # ──────────────────────────────────────────────────────────────────────────
    # URL analysis (called externally when browser URL is known)
    # ──────────────────────────────────────────────────────────────────────────

    def check_url(self, url: str, browser: str = "browser") -> Optional[str]:
        """
        Analyze a URL for phishing using the integrated PhishingDetector.
        Returns a friendly warning message if suspicious, else None.
        Called by the GUI or other modules when a URL is available.
        """
        if not self.phishing_detector:
            return None

        try:
            result = self.phishing_detector.analyze(url)
            if result.classification in ("PHISHING", "SUSPICIOUS"):
                threat = BrowserThreat(
                    browser=browser,
                    threat_type=result.classification,
                    remote_ip="",
                    remote_port=0,
                    description=result.friendly_message(),
                    url_hint=url[:120],
                )
                with self._lock:
                    self._threats.append(threat)
                return result.friendly_message()
        except Exception as e:
            logger.debug(f"BrowserProtection URL check error: {e}")

        return None

    # ──────────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _fire_alert(self, key: str, alert_type: str, description: str,
                    browser: str, threat_type: str,
                    remote_ip: str, remote_port: int) -> None:
        with self._lock:
            count = self._seen_alerts.get(key, 0)
            if count >= MAX_ALERTS_PER_IP:
                return
            self._seen_alerts[key] = count + 1
            self._threats.append(BrowserThreat(
                browser=browser,
                threat_type=threat_type,
                remote_ip=remote_ip,
                remote_port=remote_port,
                description=description,
            ))

        logger.warning(f"[BrowserProtection] {alert_type}: {description}")
        if self.on_alert:
            try:
                self.on_alert(alert_type, description)
            except Exception as e:
                logger.error(f"BrowserProtection callback error: {e}")

    def _is_private(self, ip: str) -> bool:
        private_prefixes = (
            "127.", "10.", "192.168.", "172.", "0.0.0.0", "::", "localhost"
        )
        return any(ip.startswith(p) for p in private_prefixes)

    def _normalize_browser_name(self, pname: str) -> str:
        if "chrome" in pname or "chromium" in pname:
            return "Chrome"
        if "edge" in pname:
            return "Edge"
        if "firefox" in pname:
            return "Firefox"
        return pname.capitalize()

    # ──────────────────────────────────────────────────────────────────────────
    # Status / data access
    # ──────────────────────────────────────────────────────────────────────────

    def get_active_browsers(self) -> Set[str]:
        with self._lock:
            return set(self._active_browsers)

    def get_threats(self) -> List[dict]:
        with self._lock:
            return [t.to_dict() for t in self._threats]

    def clear_threats(self) -> None:
        with self._lock:
            self._threats.clear()
            self._seen_alerts.clear()

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def threat_count(self) -> int:
        with self._lock:
            return len(self._threats)
