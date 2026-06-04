"""
SentinelCore - Entropy Engine
Real Shannon entropy calculation for file-based malware detection.

Formula: H = -Σ (p_i * log2(p_i))
  where p_i = frequency of byte value / total bytes

Entropy levels:
  0.0 – 4.5  → Normal         (plain text, structured data)
  4.5 – 6.5  → Compressed     (zip, gzip - benign usually)
  6.5 – 7.5  → Suspicious     (packed PE, UPX, custom packer)
  7.5 – 8.0  → Highly suspicious (encrypted payload, ransomware stage)

Uses chunked reading - never loads entire file into memory.
Hard skip for files > 500 MB to prevent hangs.
"""

import math
import os
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# ── Thresholds ────────────────────────────────────────────────────────────────
THRESHOLD_NORMAL      = 4.5
THRESHOLD_COMPRESSED  = 6.5
THRESHOLD_SUSPICIOUS  = 7.5

# Skip files larger than this (bytes)
MAX_FILE_SIZE_BYTES = 500 * 1024 * 1024   # 500 MB
CHUNK_SIZE          = 65536               # 64 KB per read


@dataclass
class EntropyResult:
    entropy:    float   # raw Shannon entropy 0.0–8.0
    label:      str     # "Normal" / "Compressed" / "Suspicious" / "Highly Suspicious"
    normalized: float   # 0.0–1.0 for use in threat scoring (linear scale against 8.0)
    skipped:    bool    # True if file was too large or unreadable
    file_size:  int     # bytes actually analyzed (0 if skipped)

    @property
    def is_suspicious(self) -> bool:
        return self.entropy >= THRESHOLD_COMPRESSED and not self.skipped

    @property
    def is_highly_suspicious(self) -> bool:
        return self.entropy >= THRESHOLD_SUSPICIOUS and not self.skipped


def _classify(entropy: float) -> str:
    if entropy < THRESHOLD_NORMAL:
        return "Normal"
    elif entropy < THRESHOLD_COMPRESSED:
        return "Compressed"
    elif entropy < THRESHOLD_SUSPICIOUS:
        return "Suspicious (packed)"
    else:
        return "Highly Suspicious (encrypted/packed)"


def analyze_file(path: str) -> EntropyResult:
    """
    Compute Shannon entropy of a file using chunked I/O.
    Returns an EntropyResult — never raises.
    """
    # Guard: file must exist and be readable
    if not os.path.isfile(path):
        return EntropyResult(entropy=0.0, label="N/A", normalized=0.0,
                             skipped=True, file_size=0)

    # Guard: skip very large files
    try:
        file_size = os.path.getsize(path)
    except OSError:
        return EntropyResult(entropy=0.0, label="N/A", normalized=0.0,
                             skipped=True, file_size=0)

    if file_size > MAX_FILE_SIZE_BYTES:
        logger.debug(f"EntropyEngine: skipping large file {path} ({file_size:,} bytes)")
        return EntropyResult(entropy=0.0, label="Skipped (>500 MB)",
                             normalized=0.0, skipped=True, file_size=file_size)

    # Accumulate byte frequencies
    freq = [0] * 256
    total = 0
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                for byte in chunk:
                    freq[byte] += 1
                total += len(chunk)
    except (OSError, PermissionError) as e:
        logger.debug(f"EntropyEngine: cannot read {path}: {e}")
        return EntropyResult(entropy=0.0, label="Unreadable",
                             normalized=0.0, skipped=True, file_size=0)

    if total == 0:
        return EntropyResult(entropy=0.0, label="Empty file",
                             normalized=0.0, skipped=False, file_size=0)

    # Shannon entropy formula
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)

    entropy = round(min(entropy, 8.0), 4)
    label   = _classify(entropy)
    norm    = round(entropy / 8.0, 4)   # linear normalise to [0, 1]

    return EntropyResult(
        entropy=entropy,
        label=label,
        normalized=norm,
        skipped=False,
        file_size=total,
    )


class EntropyEngine:
    """
    Stateless wrapper around analyze_file().
    Provides a consistent interface matching other SentinelCore engines.
    """

    def analyze(self, path: str) -> EntropyResult:
        return analyze_file(path)

    def classify(self, entropy: float) -> str:
        return _classify(entropy)

    def normalize(self, entropy: float) -> float:
        """Convert raw entropy (0–8) to 0–1 signal for threat scoring."""
        return round(min(max(entropy, 0.0), 8.0) / 8.0, 4)
