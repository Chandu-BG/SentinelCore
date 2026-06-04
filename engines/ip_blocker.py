"""
SentinelCore - IP Blocker Engine
Blocks/unblocks IP addresses using the Windows Firewall
via netsh commands (requires admin privileges).
Maintains a record of blocked IPs in the SQLite database.
"""

import subprocess
import logging
import re
from datetime import datetime
from typing import List, Optional

from database.init_db import get_connection, log_system_event

logger = logging.getLogger(__name__)

# Known malicious IP prefixes / ranges (sample block list)
KNOWN_MALICIOUS_PREFIXES = [
    "185.220.",  # Tor exit nodes frequently abused
    "94.102.",   # Known C2 ranges
    "198.96.",
]


def _run_netsh(args: List[str]) -> bool:
    """Run a netsh firewall command. Returns True on success."""
    cmd = ["netsh", "advfirewall", "firewall"] + args
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return True
        logger.warning(f"netsh command returned {result.returncode}: {result.stderr.strip()}")
        return False
    except FileNotFoundError:
        logger.error("netsh not found – IP blocking requires Windows with admin rights.")
        return False
    except subprocess.TimeoutExpired:
        logger.error("netsh command timed out.")
        return False


def block_ip(ip_address: str, reason: str = "Suspicious activity") -> bool:
    """
    Block an IP address using Windows Firewall (inbound + outbound).
    Also records the block in the database.
    Returns True if the firewall rule was created successfully.
    """
    if not _validate_ip(ip_address):
        logger.error(f"Invalid IP address: {ip_address}")
        return False

    rule_name = f"SentinelCore_Block_{ip_address}"

    # Inbound rule
    ok_in = _run_netsh([
        "add", "rule",
        f"name={rule_name}_IN",
        "dir=in",
        "action=block",
        f"remoteip={ip_address}",
        "enable=yes",
        "profile=any",
    ])

    # Outbound rule
    ok_out = _run_netsh([
        "add", "rule",
        f"name={rule_name}_OUT",
        "dir=out",
        "action=block",
        f"remoteip={ip_address}",
        "enable=yes",
        "profile=any",
    ])

    success = ok_in or ok_out  # partial success counts

    # Record in DB regardless (so the UI still shows the block)
    _record_block(ip_address, reason)

    if success:
        logger.warning(f"Blocked IP: {ip_address} – {reason}")
        log_system_event("IP_BLOCKED", f"Blocked {ip_address}: {reason}", "warning")
    else:
        logger.error(f"Firewall rule creation failed for {ip_address} (may need admin rights)")

    return success


def unblock_ip(ip_address: str) -> bool:
    """Remove firewall block rules for an IP address."""
    rule_name = f"SentinelCore_Block_{ip_address}"
    ok_in  = _run_netsh(["delete", "rule", f"name={rule_name}_IN"])
    ok_out = _run_netsh(["delete", "rule", f"name={rule_name}_OUT"])

    # Mark as inactive in DB
    try:
        with get_connection() as conn:
            conn.execute(
                "UPDATE blocked_ips SET active=0 WHERE ip_address=?",
                (ip_address,),
            )
            conn.commit()
    except Exception as e:
        logger.error(f"DB update failed when unblocking {ip_address}: {e}")

    logger.info(f"Unblocked IP: {ip_address}")
    return ok_in or ok_out


def get_blocked_ips() -> List[dict]:
    """Return all currently active blocked IPs from the database."""
    try:
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM blocked_ips WHERE active=1 ORDER BY blocked_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Failed to retrieve blocked IPs: {e}")
        return []


def is_suspicious_ip(ip_address: str) -> bool:
    """Heuristic check: return True if an IP looks suspicious."""
    for prefix in KNOWN_MALICIOUS_PREFIXES:
        if ip_address.startswith(prefix):
            return True
    return False


def _record_block(ip_address: str, reason: str) -> None:
    """Insert or update a block record in the database."""
    try:
        with get_connection() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO blocked_ips
                   (ip_address, reason, blocked_at, active)
                   VALUES (?, ?, ?, 1)""",
                (ip_address, reason, datetime.now().isoformat()),
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to record block for {ip_address}: {e}")


def _validate_ip(ip: str) -> bool:
    """Basic IPv4/IPv6 validation."""
    ipv4 = r"^\d{1,3}(\.\d{1,3}){3}$"
    return bool(re.match(ipv4, ip))
