"""
SentinelCore - Permissions Engine
Manages user-controlled permission toggles for each protection module.
All other engines MUST check is_enabled() before performing any work.

Permissions are persisted to config/permissions.json so they survive restarts.
Default: all permissions OFF except core monitoring.
"""

import os
import json
import logging
import threading
from typing import Callable, Dict, Optional

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PERMISSIONS_FILE = os.path.join(BASE_DIR, "config", "permissions.json")

# All available permission modules and their safe defaults
DEFAULT_PERMISSIONS: Dict[str, bool] = {
    "file_monitoring":       True,   # File system watch & scan
    "network_protection":    True,   # Network connection monitoring & IP blocking
}


class PermissionsEngine:
    """
    Central permission registry. Each engine must call is_enabled(module)
    before performing any sensitive action.

    No hardware or OS-level access is performed by this class itself.
    It is purely a gatekeeper / configuration store.
    """

    def __init__(
        self,
        on_change: Optional[Callable[[str, bool], None]] = None,
    ):
        self._lock = threading.RLock()
        self._permissions: Dict[str, bool] = dict(DEFAULT_PERMISSIONS)
        self.on_change = on_change  # callback(module_name, new_value)
        self._load()

    # ─────────────────────────────────────────────────────────────────────────
    # Core API
    # ─────────────────────────────────────────────────────────────────────────

    def is_enabled(self, module: str) -> bool:
        """Return True if module is permitted to run. Thread-safe."""
        with self._lock:
            return self._permissions.get(module, False)

    def set_permission(self, module: str, enabled: bool) -> None:
        """Enable or disable a module. Persists immediately. Thread-safe."""
        if module not in DEFAULT_PERMISSIONS:
            logger.warning(f"PermissionsEngine: unknown module '{module}'")
            return
        with self._lock:
            old = self._permissions.get(module)
            self._permissions[module] = enabled
            self._save()
        if old != enabled:
            state = "ENABLED" if enabled else "DISABLED"
            logger.info(f"Permission: {module} -> {state}")
            if self.on_change:
                self.on_change(module, enabled)

    def toggle(self, module: str) -> bool:
        """Toggle a permission and return the new value."""
        current = self.is_enabled(module)
        self.set_permission(module, not current)
        return not current

    def get_all(self) -> Dict[str, bool]:
        """Return a snapshot of all permissions."""
        with self._lock:
            return dict(self._permissions)

    # ─────────────────────────────────────────────────────────────────────────
    # Persistence
    # ─────────────────────────────────────────────────────────────────────────

    def _load(self) -> None:
        """Load persisted permissions from disk."""
        try:
            if os.path.isfile(PERMISSIONS_FILE):
                with open(PERMISSIONS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                with self._lock:
                    for k, v in data.items():
                        if k in DEFAULT_PERMISSIONS:
                            self._permissions[k] = bool(v)
                logger.info(f"Permissions loaded from {PERMISSIONS_FILE}")
            else:
                self._save()  # write defaults on first run
        except Exception as e:
            logger.error(f"Could not load permissions: {e} — using defaults")

    def _save(self) -> None:
        """Persist current permissions to disk (must hold lock before calling)."""
        try:
            os.makedirs(os.path.dirname(PERMISSIONS_FILE), exist_ok=True)
            with open(PERMISSIONS_FILE, "w", encoding="utf-8") as f:
                json.dump(self._permissions, f, indent=2)
        except Exception as e:
            logger.error(f"Could not save permissions: {e}")
