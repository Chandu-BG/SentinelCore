"""
NovaSentinel — Authenticode signature verification (single WinVerifyTrust site).

Consolidates duplicate WinVerifyTrust ctypes implementations used across
SystemScanner, InstalledAppEngine, and other modules.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
import uuid
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

_WINTRUST_ACTION_GENERIC_VERIFY_V2 = "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}"

# Cache (path, mtime_ns) -> signer subject to avoid repeated PowerShell calls during scans
_subject_cache: Dict[Tuple[str, int], Optional[str]] = {}
_subject_cache_lock = threading.Lock()
_SUBJECT_CACHE_MAX = 512


class SignatureVerifier:
    """Windows Authenticode verification via WinVerifyTrust + optional signer subject."""

    @staticmethod
    def is_signed(path: str) -> bool:
        """Return True if *path* has a signature that passes WinVerifyTrust for generic verify v2."""
        if not path or not os.path.isfile(path):
            return False
        if sys.platform != "win32":
            return False
        try:
            import ctypes
            import ctypes.wintypes

            INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
            WTD_UI_NONE = 2
            WTD_CHOICE_FILE = 1
            WTD_STATEACTION_VERIFY = 0x00000001

            class WINTRUST_FILE_INFO(ctypes.Structure):
                _fields_ = [
                    ("cbStruct", ctypes.wintypes.DWORD),
                    ("pcwszFilePath", ctypes.c_wchar_p),
                    ("hFile", ctypes.c_void_p),
                    ("pgKnownSubject", ctypes.c_void_p),
                ]

            class WINTRUST_DATA(ctypes.Structure):
                _fields_ = [
                    ("cbStruct", ctypes.wintypes.DWORD),
                    ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p),
                    ("dwUIChoice", ctypes.wintypes.DWORD),
                    ("fdwRevocationChecks", ctypes.wintypes.DWORD),
                    ("dwUnionChoice", ctypes.wintypes.DWORD),
                    ("pFile", ctypes.c_void_p),
                    ("dwStateAction", ctypes.wintypes.DWORD),
                    ("hWVTStateData", ctypes.c_void_p),
                    ("pwszURLReference", ctypes.c_wchar_p),
                    ("dwProvFlags", ctypes.wintypes.DWORD),
                    ("dwUIContext", ctypes.wintypes.DWORD),
                ]

            fi = WINTRUST_FILE_INFO()
            fi.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
            fi.pcwszFilePath = path
            fi.hFile = None
            fi.pgKnownSubject = None

            wd = WINTRUST_DATA()
            wd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
            wd.pPolicyCallbackData = None
            wd.pSIPClientData = None
            wd.dwUIChoice = WTD_UI_NONE
            wd.fdwRevocationChecks = 0
            wd.dwUnionChoice = WTD_CHOICE_FILE
            wd.pFile = ctypes.cast(ctypes.pointer(fi), ctypes.c_void_p)
            wd.dwStateAction = WTD_STATEACTION_VERIFY
            wd.hWVTStateData = None
            wd.pwszURLReference = None
            wd.dwProvFlags = 0
            wd.dwUIContext = 0

            action_id = uuid.UUID(_WINTRUST_ACTION_GENERIC_VERIFY_V2)
            action_bytes = (ctypes.c_byte * 16)(*action_id.bytes_le)

            result = ctypes.windll.wintrust.WinVerifyTrust(  # type: ignore[attr-defined]
                INVALID_HANDLE_VALUE,
                ctypes.byref(action_bytes),
                ctypes.byref(wd),
            )
            # ERROR_SUCCESS (0): object trusted for the requested action.
            return int(result) == 0
        except Exception as exc:
            logger.debug("WinVerifyTrust failed for %s: %s", path, exc)
            return False

    @staticmethod
    def get_signer_subject(path: str) -> Optional[str]:
        """
        Return the signer certificate Subject DN string, or None if unavailable.

        Uses PowerShell Get-AuthenticodeSignature with the path passed via an
        environment variable to avoid shell injection. Result is cached per
        (path, mtime) to reduce overhead during large scans.
        """
        if not path or not os.path.isfile(path):
            return None
        if sys.platform != "win32":
            return None
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return None

        cache_key = (path, int(mtime * 1e9))
        with _subject_cache_lock:
            if cache_key in _subject_cache:
                return _subject_cache[cache_key]

        subject: Optional[str] = None
        try:
            env = os.environ.copy()
            env["NS_AS_CODE_SIG_PATH"] = path
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            proc = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "$s = Get-AuthenticodeSignature -LiteralPath $env:NS_AS_CODE_SIG_PATH; "
                    "if ($null -ne $s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' }",
                ],
                capture_output=True,
                text=True,
                timeout=20,
                env=env,
                creationflags=creationflags,
            )
            out = (proc.stdout or "").strip()
            subject = out if out else None
        except Exception as exc:
            logger.debug("get_signer_subject failed for %s: %s", path, exc)
            subject = None

        with _subject_cache_lock:
            if len(_subject_cache) >= _SUBJECT_CACHE_MAX:
                # Drop arbitrary oldest chunk — simple bounded cache
                for _ in range(_SUBJECT_CACHE_MAX // 4):
                    try:
                        _subject_cache.pop(next(iter(_subject_cache)))
                    except StopIteration:
                        break
            _subject_cache[cache_key] = subject

        return subject
