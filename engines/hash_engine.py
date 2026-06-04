"""
SentinelCore - Dynamic Hash Identity Engine
Implements SHA256-based identity hashing for executables.
Features:
  - Static file hash (SHA256 of file content)
  - Dynamic identity hash: SHA256(exe_hash + timestamp + random_salt)
  - Hash changes every execution to prevent replay attacks
  - Detects executable modification (hash drift)
"""

import hashlib
import os
import time
import secrets
import logging
from typing import Optional, Dict, Tuple

logger = logging.getLogger(__name__)

# In-memory registry of trusted exe hashes { exe_path: last_known_hash }
_trusted_hashes: Dict[str, str] = {}


def hash_file(file_path: str) -> Optional[str]:
    """
    Compute SHA256 hash of a file's content.
    Returns hex string, or None if the file cannot be read.
    """
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (FileNotFoundError, PermissionError, OSError) as e:
        logger.debug(f"Cannot hash file '{file_path}': {e}")
        return None


def generate_dynamic_identity(exe_hash: str) -> Tuple[str, str, str]:
    """
    Generate a dynamic identity hash that changes on every call.

    Formula:
        identity = SHA256( exe_hash + timestamp_ns + random_salt )

    Returns:
        (identity_hash, timestamp_str, salt_hex)
    """
    timestamp = str(time.time_ns())
    salt = secrets.token_hex(16)
    raw = (exe_hash + timestamp + salt).encode("utf-8")
    identity = hashlib.sha256(raw).hexdigest()
    return identity, timestamp, salt


def register_trusted(exe_path: str) -> Optional[str]:
    """
    Register an executable as trusted by storing its file hash.
    Returns the stored hash, or None on failure.
    """
    h = hash_file(exe_path)
    if h:
        _trusted_hashes[exe_path] = h
        logger.info(f"Registered trusted executable: {exe_path} [{h[:8]}…]")
    return h


def verify_executable(exe_path: str) -> Dict:
    """
    Verify an executable against its known-good hash.
    Returns a dict with: { 'trusted': bool, 'modified': bool, 'current_hash': str }
    - If not previously registered, registers it now as trusted.
    - If hash has changed since registration → modified = True
    """
    current = hash_file(exe_path)
    if current is None:
        return {"trusted": False, "modified": False, "current_hash": None}

    if exe_path not in _trusted_hashes:
        _trusted_hashes[exe_path] = current
        return {"trusted": True, "modified": False, "current_hash": current}

    known = _trusted_hashes[exe_path]
    modified = known != current
    if modified:
        logger.warning(
            f"Executable MODIFIED: {exe_path}\n"
            f"  known={known[:16]}… current={current[:16]}…"
        )
    return {"trusted": not modified, "modified": modified, "current_hash": current}


def hash_string(data: str) -> str:
    """Convenience: SHA256 hash of an arbitrary string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def generate_session_token(user_id: str) -> str:
    """
    Generate a one-time session token bound to a user ID.
    Uses dynamic identity approach (timestamp + salt).
    """
    timestamp = str(time.time_ns())
    salt = secrets.token_hex(32)
    raw = (user_id + timestamp + salt).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
