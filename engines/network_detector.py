"""
SentinelCore - Network Threat Detector
Monitors network connections using psutil.
Detects:
  - Unknown outbound connections
  - Suspicious ports
  - Abnormal traffic spikes
Runs in a background thread.
"""

import time
import logging
import threading
import psutil
from typing import Callable, Optional, Dict, Set, List
from collections import deque

logger = logging.getLogger(__name__)

# Ports commonly associated with malicious activity
SUSPICIOUS_PORTS = {
    31337, 1337, 4444, 5555, 6666, 6667, 6668, 6669,   # common RAT/backdoor ports
    12345, 23456, 54321, 1234, 7777, 8888,               # common malware defaults
    9001, 9030, 9050, 9051,                              # Tor
    445, 139, 135,                                        # SMB (outbound is suspicious)
    3389,                                                  # RDP outbound
    4899,                                                  # Radmin
    2222, 4747, 5247,                                     # common C2 ports
}

# Known-safe destination IP ranges (loopback, private)
PRIVATE_RANGES = [
    "127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.", "0.0.0.0", "::",
]

# Known malicious IP list (top offenders, constantly updated in real products)
KNOWN_MALICIOUS_IPS = {
    "185.220.101.55", "45.142.212.100", "91.108.4.1",
    "194.165.16.78",  "5.188.206.14",   "198.54.117.200",
    "195.78.54.10",   "212.109.196.160",
}

# Bytes-per-second spike threshold
BYTES_SPIKE_THRESHOLD  = 50 * 1024 * 1024   # 50 MB/s
WINDOW_SECONDS         = 10                  # rolling window for spike detection
MAX_ALERTS_PER_IP      = 3                   # deduplicate IP alerts


class NetworkDetector:
    """
    Background network monitoring engine.
    Emits alerts via on_alert(alert_type, description).
    """

    def __init__(
        self,
        on_alert: Optional[Callable[[str, str], None]] = None,
        poll_interval: float = 5.0,
    ):
        self.on_alert      = on_alert
        self.poll_interval = poll_interval

        self._running   = False
        self._thread: Optional[threading.Thread] = None
        self._lock      = threading.Lock()

        # Tracking
        self._seen_connections: Dict[str, int] = {}   # remote_ip → alert_count
        self._bytes_history: deque = deque()           # (timestamp, bytes_sent, bytes_recv)
        self._last_bytes_sent  = 0
        self._last_bytes_recv  = 0
        self._flagged_ips: Set[str] = set()

    # ──────────────────────────────────────────────────────────────────────────
    # Lifecycle
    # ──────────────────────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        try:
            counters = psutil.net_io_counters()
            self._last_bytes_sent = counters.bytes_sent
            self._last_bytes_recv = counters.bytes_recv
        except Exception:
            pass

        self._thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="NetworkDetector"
        )
        self._thread.start()
        logger.info("NetworkDetector started.")

    def stop(self) -> None:
        self._running = False
        logger.info("NetworkDetector stopped.")

    # ──────────────────────────────────────────────────────────────────────────
    # Monitoring loop
    # ──────────────────────────────────────────────────────────────────────────

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._check_connections()
                self._check_traffic_spike()
            except Exception as e:
                logger.debug(f"NetworkDetector loop error: {e}")
            time.sleep(self.poll_interval)

    def _check_connections(self) -> None:
        """Check active network connections for suspicious activity."""
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            return

        for conn in connections:
            if conn.status != "ESTABLISHED":
                continue
            if not conn.raddr:
                continue

            remote_ip   = conn.raddr.ip
            remote_port = conn.raddr.port

            if self._is_private_ip(remote_ip):
                continue

            # Check known malicious IPs
            if remote_ip in KNOWN_MALICIOUS_IPS:
                self._fire_alert(
                    remote_ip, "MALICIOUS_IP",
                    f"Connection to known malicious IP: {remote_ip}:{remote_port} "
                    f"(PID={conn.pid})",
                )
                continue

            # Check suspicious ports
            if remote_port in SUSPICIOUS_PORTS:
                self._fire_alert(
                    f"{remote_ip}:{remote_port}", "SUSPICIOUS_PORT",
                    f"Outbound connection to suspicious port "
                    f"{remote_port} → {remote_ip} (PID={conn.pid})",
                )

    def _check_traffic_spike(self) -> None:
        """Detect abnormal network traffic spikes."""
        try:
            counters  = psutil.net_io_counters()
            now       = time.time()
            sent_diff = counters.bytes_sent - self._last_bytes_sent
            recv_diff = counters.bytes_recv - self._last_bytes_recv

            self._last_bytes_sent = counters.bytes_sent
            self._last_bytes_recv = counters.bytes_recv

            with self._lock:
                self._bytes_history.append((now, sent_diff, recv_diff))
                # Prune old entries
                cutoff = now - WINDOW_SECONDS
                while self._bytes_history and self._bytes_history[0][0] < cutoff:
                    self._bytes_history.popleft()

                # Calculate window totals
                total_sent = sum(e[1] for e in self._bytes_history)
                total_recv = sum(e[2] for e in self._bytes_history)

            elapsed = len(self._bytes_history) * self.poll_interval or 1
            sent_rate = total_sent / elapsed
            recv_rate = total_recv / elapsed

            if sent_rate > BYTES_SPIKE_THRESHOLD:
                mb = sent_rate / (1024 * 1024)
                self._fire_alert(
                    "TRAFFIC_SPIKE_SEND", "TRAFFIC_SPIKE",
                    f"Abnormal outbound traffic spike: {mb:.1f} MB/s "
                    "(possible data exfiltration)",
                )
            if recv_rate > BYTES_SPIKE_THRESHOLD:
                mb = recv_rate / (1024 * 1024)
                self._fire_alert(
                    "TRAFFIC_SPIKE_RECV", "TRAFFIC_SPIKE",
                    f"Abnormal inbound traffic spike: {mb:.1f} MB/s",
                )

        except Exception as e:
            logger.debug(f"NetworkDetector traffic check error: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _is_private_ip(self, ip: str) -> bool:
        return any(ip.startswith(prefix) for prefix in PRIVATE_RANGES)

    def _fire_alert(self, key: str, alert_type: str, description: str) -> None:
        """Deduplicated alert firing."""
        with self._lock:
            count = self._seen_connections.get(key, 0)
            if count >= MAX_ALERTS_PER_IP:
                return
            self._seen_connections[key] = count + 1

        logger.warning(f"[NetworkDetector] {alert_type}: {description}")
        if self.on_alert:
            try:
                self.on_alert(alert_type, description)
            except Exception as e:
                logger.error(f"NetworkDetector alert callback error: {e}")

    def get_active_connections(self) -> List[dict]:
        """Return current outbound ESTABLISHED connections to public IPs."""
        result = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "ESTABLISHED" and conn.raddr:
                    ip = conn.raddr.ip
                    if not self._is_private_ip(ip):
                        result.append({
                            "remote_ip":   ip,
                            "remote_port": conn.raddr.port,
                            "local_port":  conn.laddr.port if conn.laddr else 0,
                            "pid":         conn.pid,
                            "suspicious":  ip in KNOWN_MALICIOUS_IPS
                                           or conn.raddr.port in SUSPICIOUS_PORTS,
                        })
        except Exception:
            pass
        return result

    @property
    def is_running(self) -> bool:
        return self._running
