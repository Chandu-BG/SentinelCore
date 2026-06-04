"""
SentinelCore - Privacy Engine
Detects camera and microphone access by processes on Windows.

Detection method (no kernel driver required):
  Uses the Windows Capability Access Manager registry keys:
    HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\
      CapabilityAccessManager\\ConsentStore\\webcam
    HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\
      CapabilityAccessManager\\ConsentStore\\microphone

  Each sub-key represents an app. The QWORD value 'LastUsedTimeStop = 0'
  while 'LastUsedTimeStart > 0' means the device is CURRENTLY IN USE.
  This is the same mechanism Windows Privacy Dashboard uses.

ONLY runs when the user explicitly enables camera_monitoring or
microphone_monitoring in the Permissions panel.
"""

import os
import time
import logging
import threading
import winreg
from datetime import datetime
from typing import Callable, Optional, Dict, Set

from database.init_db import log_threat, log_system_event

logger = logging.getLogger(__name__)

# Registry base path for capability access
_CAM_KEY  = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion"
    r"\CapabilityAccessManager\ConsentStore\webcam"
)
_MIC_KEY  = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion"
    r"\CapabilityAccessManager\ConsentStore\microphone"
)

# Sub-key for Win32/non-packaged apps
_NON_PACKAGED = "NonPackaged"

# Processes that legitimately access camera/mic and should not alert
KNOWN_SAFE_CAMERA_APPS: Set[str] = {
    "microsoft.windows.camera",
    "skype",
    "teams",
    "zoom",
    "obs64.exe",
    "webcamapp",
    "windowscamera",
}

KNOWN_SAFE_MIC_APPS: Set[str] = {
    "microsoft.windows.camera",
    "skype",
    "teams",
    "zoom",
    "obs64.exe",
    "audiodg.exe",
    "realtek",
    "voicerecorder",
    "cortana",
}


def _read_currently_using(base_key_path: str) -> Dict[str, str]:
    """
    Returns {app_identifier: 'currently_using'} for all apps that are
    currently accessing the device (LastUsedTimeStop == 0).
    """
    currently_using = {}
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, base_key_path,
            0, winreg.KEY_READ
        ) as base:
            # Enumerate packaged UWP apps (direct sub-keys)
            i = 0
            while True:
                try:
                    sub_name = winreg.EnumKey(base, i)
                    i += 1
                    if sub_name == _NON_PACKAGED:
                        continue
                    try:
                        with winreg.OpenKey(base, sub_name,
                                            0, winreg.KEY_READ) as app_key:
                            start  = _read_qword(app_key, "LastUsedTimeStart")
                            stop   = _read_qword(app_key, "LastUsedTimeStop")
                            if start and start > 0 and stop == 0:
                                currently_using[sub_name.lower()] = "active"
                    except OSError:
                        pass
                except OSError:
                    break

            # Enumerate non-packaged Win32 apps
            try:
                with winreg.OpenKey(base, _NON_PACKAGED,
                                    0, winreg.KEY_READ) as np_key:
                    j = 0
                    while True:
                        try:
                            app_key_name = winreg.EnumKey(np_key, j)
                            j += 1
                            try:
                                with winreg.OpenKey(np_key, app_key_name,
                                                    0, winreg.KEY_READ) as app_key:
                                    start  = _read_qword(app_key, "LastUsedTimeStart")
                                    stop   = _read_qword(app_key, "LastUsedTimeStop")
                                    if start and start > 0 and stop == 0:
                                        # app_key_name is the exec path with # delimiter
                                        app_id = app_key_name.split("#")[-1].lower()
                                        currently_using[app_id] = "active"
                            except OSError:
                                pass
                        except OSError:
                            break
            except OSError:
                pass  # NonPackaged key may not exist

    except OSError as e:
        logger.debug(f"PrivacyEngine: registry read error: {e}")

    return currently_using


def _read_qword(key, value_name: str) -> Optional[int]:
    """Read a QWORD registry value safely."""
    try:
        val, reg_type = winreg.QueryValueEx(key, value_name)
        return int(val)
    except OSError:
        return None


class PrivacyEngine:
    """
    Monitors camera and microphone access in real-time.
    ONLY operates when permissions allow.
    """

    POLL_INTERVAL = 2.0  # seconds between registry polls

    def __init__(
        self,
        permissions_engine,
        on_alert: Optional[Callable[[str, str], None]] = None,
    ):
        self._permissions = permissions_engine
        self.on_alert     = on_alert
        self._running     = False
        self._thread: Optional[threading.Thread] = None

        # Track what was in-use last tick to avoid repeated alerts
        self._last_cam_set: Set[str] = set()
        self._last_mic_set: Set[str] = set()

        self.camera_alerts:  int = 0
        self.mic_alerts:     int = 0

    # ─────────────────────────────────────────────────────────────────────────
    # Lifecycle
    # ─────────────────────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="PrivacyEngine"
        )
        self._thread.start()
        logger.info("PrivacyEngine started.")

    def stop(self) -> None:
        self._running = False
        logger.info("PrivacyEngine stopped.")

    # ─────────────────────────────────────────────────────────────────────────
    # Monitoring loop
    # ─────────────────────────────────────────────────────────────────────────

    def _loop(self) -> None:
        while self._running:
            try:
                cam_enabled = self._permissions.is_enabled("camera_monitoring")
                mic_enabled = self._permissions.is_enabled("microphone_monitoring")

                if cam_enabled:
                    self._check_device(_CAM_KEY, "Camera",
                                       KNOWN_SAFE_CAMERA_APPS,
                                       self._last_cam_set)
                if mic_enabled:
                    self._check_device(_MIC_KEY, "Microphone",
                                       KNOWN_SAFE_MIC_APPS,
                                       self._last_mic_set)

                if not cam_enabled:
                    self._last_cam_set.clear()
                if not mic_enabled:
                    self._last_mic_set.clear()

            except Exception as e:
                logger.error(f"PrivacyEngine loop error: {e}")

            time.sleep(self.POLL_INTERVAL)

    def _check_device(
        self,
        key_path: str,
        device_name: str,
        safe_set: Set[str],
        last_set: Set[str],
    ) -> None:
        """Poll registry and alert on NEW unknown processes accessing the device."""
        current = set(_read_currently_using(key_path).keys())

        # New apps accessing device since last poll
        new_apps = current - last_set

        for app_id in new_apps:
            is_safe = any(safe in app_id for safe in safe_set)
            severity = "info" if is_safe else "high"
            alert_type = f"PRIVACY_{device_name.upper()}_ACCESS"
            desc = (
                f"{device_name} accessed by: {app_id}"
                + (" [KNOWN SAFE]" if is_safe else " [UNKNOWN APP — REVIEW]")
            )
            log_threat(alert_type, desc, severity=severity)

            if not is_safe:
                if device_name == "Camera":
                    self.camera_alerts += 1
                else:
                    self.mic_alerts += 1
                if self.on_alert:
                    self.on_alert(alert_type, desc)
                logger.warning(f"[PRIVACY] {desc}")
            else:
                logger.info(f"[PRIVACY] {desc}")

        # Apps that stopped using device
        stopped = last_set - current
        for app_id in stopped:
            logger.info(f"[PRIVACY] {device_name} released by: {app_id}")

        last_set.clear()
        last_set.update(current)

    # ─────────────────────────────────────────────────────────────────────────
    # Status
    # ─────────────────────────────────────────────────────────────────────────

    def get_status(self) -> dict:
        cam_en  = self._permissions.is_enabled("camera_monitoring")
        mic_en  = self._permissions.is_enabled("microphone_monitoring")
        return {
            "running":         self._running,
            "camera_enabled":  cam_en,
            "mic_enabled":     mic_en,
            "camera_alerts":   self.camera_alerts,
            "mic_alerts":      self.mic_alerts,
            "camera_in_use":   list(self._last_cam_set) if cam_en else [],
            "mic_in_use":      list(self._last_mic_set) if mic_en else [],
        }
