"""PE feature extraction for NovaSentinel.

Creates a fixed-length EMBER-style feature vector for Windows PE files.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import numpy as np
except ImportError:  # pragma: no cover
    np = None  # type: ignore

try:
    import pefile
except ImportError:  # pragma: no cover
    pefile = None  # type: ignore

FEATURE_DIMENSION = 2381


class PEFeatureExtractor:
    """Extracts a 2381-dimensional feature vector from a PE file."""

    def __init__(self) -> None:
        self._enabled = pefile is not None and np is not None

    def extract(self, file_path: str) -> Optional["np.ndarray"]:
        if not self._enabled:
            logger.warning("PEFeatureExtractor requires numpy and pefile.")
            return None

        if not file_path or not os.path.isfile(file_path):
            return None

        try:
            pe = pefile.PE(file_path, fast_load=True)
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
                ]
            )
        except (pefile.PEFormatError, PermissionError, OSError) as exc:
            logger.debug("PE feature extraction skipped: %s", exc)
            return None
        except Exception as exc:
            logger.debug("PE feature extraction failed: %s", exc)
            return None

        features = np.zeros(FEATURE_DIMENSION, dtype=np.float32)

        def set_feature(index: int, value: float) -> int:
            if 0 <= index < FEATURE_DIMENSION:
                features[index] = float(value)
            return index + 1

        idx = 0
        fh = pe.FILE_HEADER
        oh = getattr(pe, "OPTIONAL_HEADER", None)

        idx = set_feature(idx, getattr(fh, "Machine", 0))
        idx = set_feature(idx, getattr(fh, "NumberOfSections", 0))
        idx = set_feature(idx, getattr(fh, "TimeDateStamp", 0))
        idx = set_feature(idx, getattr(fh, "PointerToSymbolTable", 0))
        idx = set_feature(idx, getattr(fh, "NumberOfSymbols", 0))
        idx = set_feature(idx, getattr(fh, "SizeOfOptionalHeader", 0))
        idx = set_feature(idx, getattr(fh, "Characteristics", 0))

        if oh is not None:
            idx = set_feature(idx, getattr(oh, "MajorLinkerVersion", 0))
            idx = set_feature(idx, getattr(oh, "MinorLinkerVersion", 0))
            idx = set_feature(idx, getattr(oh, "SizeOfCode", 0))
            idx = set_feature(idx, getattr(oh, "SizeOfInitializedData", 0))
            idx = set_feature(idx, getattr(oh, "SizeOfUninitializedData", 0))
            idx = set_feature(idx, getattr(oh, "AddressOfEntryPoint", 0))
            idx = set_feature(idx, getattr(oh, "BaseOfCode", 0))
            idx = set_feature(idx, getattr(oh, "ImageBase", 0))
            idx = set_feature(idx, getattr(oh, "SectionAlignment", 0))
            idx = set_feature(idx, getattr(oh, "FileAlignment", 0))
            idx = set_feature(idx, getattr(oh, "MajorOperatingSystemVersion", 0))
            idx = set_feature(idx, getattr(oh, "MinorOperatingSystemVersion", 0))
            idx = set_feature(idx, getattr(oh, "MajorImageVersion", 0))
            idx = set_feature(idx, getattr(oh, "MinorImageVersion", 0))
            idx = set_feature(idx, getattr(oh, "MajorSubsystemVersion", 0))
            idx = set_feature(idx, getattr(oh, "MinorSubsystemVersion", 0))
            idx = set_feature(idx, getattr(oh, "SizeOfImage", 0))
            idx = set_feature(idx, getattr(oh, "SizeOfHeaders", 0))
            idx = set_feature(idx, getattr(oh, "CheckSum", 0))
            idx = set_feature(idx, getattr(oh, "Subsystem", 0))
            idx = set_feature(idx, getattr(oh, "DllCharacteristics", 0))
            idx = set_feature(idx, getattr(oh, "SizeOfStackReserve", 0))
            idx = set_feature(idx, getattr(oh, "SizeOfStackCommit", 0))
            idx = set_feature(idx, getattr(oh, "SizeOfHeapReserve", 0))
            idx = set_feature(idx, getattr(oh, "SizeOfHeapCommit", 0))
            idx = set_feature(idx, getattr(oh, "LoaderFlags", 0))
            idx = set_feature(idx, getattr(oh, "NumberOfRvaAndSizes", 0))

        idx = set_feature(idx, len(getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])))
        idx = set_feature(idx, len(getattr(pe, "DIRECTORY_ENTRY_EXPORT", [])))
        idx = set_feature(idx, len(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", [])))
        idx = set_feature(idx, len(getattr(pe, "DIRECTORY_ENTRY_DEBUG", [])))
        idx = set_feature(idx, len(getattr(pe, "DIRECTORY_ENTRY_TLS", [])))

        sections = getattr(pe, "sections", []) or []
        for section in sections[:16]:
            idx = set_feature(idx, getattr(section, "Name", b"").strip(b"\x00").decode(errors="ignore").count("."))
            idx = set_feature(idx, getattr(section, "Misc_VirtualSize", 0))
            idx = set_feature(idx, getattr(section, "VirtualAddress", 0))
            idx = set_feature(idx, getattr(section, "SizeOfRawData", 0))
            idx = set_feature(idx, getattr(section, "PointerToRawData", 0))
            idx = set_feature(idx, getattr(section, "Characteristics", 0))
            idx = set_feature(idx, getattr(section, "Entropy", 0.0))
            raw = section.get_data() if hasattr(section, "get_data") else None
            if raw is not None and raw:
                entropy = self._shannon_entropy(raw)
                idx = set_feature(idx, entropy)
            else:
                idx = set_feature(idx, 0.0)

        import_dlls = {getattr(entry, "dll", b"").decode(errors="ignore").lower() for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])}
        dll_names = sorted(import_dlls)[:64]
        for dll in dll_names:
            idx = set_feature(idx, float(len(dll)))
            idx = set_feature(idx, float(sum(ord(ch) for ch in dll) % 256))

        try:
            with open(file_path, "rb") as fh:
                data = fh.read()
            idx = set_feature(idx, float(len(data)))
            idx = set_feature(idx, float(self._shannon_entropy(data)))
        except Exception:
            idx = set_feature(idx, 0.0)
            idx = set_feature(idx, 0.0)

        if idx < FEATURE_DIMENSION:
            features[idx:] = 0.0

        return features

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        entropy = 0.0
        length = len(data)
        for count in freq.values():
            p = count / length
            entropy -= p * (0.0 if p == 0 else np.log2(p))
        return float(entropy)
