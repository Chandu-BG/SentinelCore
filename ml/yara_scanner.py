"""Yara rule scanning for NovaSentinel."""

from __future__ import annotations

import logging
import os
import threading
from typing import List, Optional

logger = logging.getLogger(__name__)

try:
    import yara
except ImportError:  # pragma: no cover
    yara = None  # type: ignore


class YaraScanner:
    """Loads YARA rules and scans files or raw data safely."""

    RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "yara_rules")
    SCAN_TIMEOUT = 10.0

    def __init__(self) -> None:
        self._enabled = yara is not None
        self._rules = None
        self._lock = threading.Lock()
        self._load_rules()

    def _load_rules(self) -> None:
        if not self._enabled:
            logger.warning("YaraScanner disabled because yara package is unavailable.")
            return

        rules = []
        if not os.path.isdir(self.RULES_DIR):
            logger.warning("YaraScanner rules directory missing: %s", self.RULES_DIR)
            self._rules = None
            return

        for root, _, files in os.walk(self.RULES_DIR):
            for filename in files:
                if not filename.lower().endswith((".yar", ".yara")):
                    continue
                path = os.path.join(root, filename)
                try:
                    rules.append(yara.compile(filepath=path))
                except yara.SyntaxError as exc:
                    logger.warning("Skipping invalid YARA file %s: %s", path, exc)
                except Exception as exc:
                    logger.debug("Failed to compile YARA file %s: %s", path, exc)

        if rules:
            with self._lock:
                self._rules = rules
            logger.info("YaraScanner loaded %d compiled rule files.", len(rules))
        else:
            self._rules = None
            logger.info("YaraScanner loaded no rules.")

    def scan_file(self, file_path: str) -> List[str]:
        """Scan a file with loaded YARA rules and return a list of match strings."""
        if not self._enabled or self._rules is None:
            return []

        if not file_path or not os.path.isfile(file_path):
            return []

        try:
            data = open(file_path, "rb").read()
        except (OSError, PermissionError) as exc:
            logger.debug("YaraScanner file read failed: %s", exc)
            return []

        return self.scan_data(data)

    def scan_data(self, data: bytes) -> List[str]:
        """Scan raw bytes and return rule names that matched within the timeout."""
        if not self._enabled or self._rules is None or not data:
            return []

        match_names: List[str] = []

        try:
            for compiled in list(self._rules):
                matches = compiled.match(data=data, timeout=self.SCAN_TIMEOUT)
                for match in matches:
                    match_names.append(match.rule)
        except yara.TimeoutError:
            logger.warning("YaraScanner scan timed out after %.1f seconds.", self.SCAN_TIMEOUT)
        except Exception as exc:
            logger.debug("YaraScanner scan failed: %s", exc)

        return match_names
