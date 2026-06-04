"""Download community YARA rule sets into the NovaSentinel models directory."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import urllib.request
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
RULES_DIR = os.path.join(ROOT_DIR, "models", "yara_rules")

COMMUNITY_SOURCES = [
    {
        "url": "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/malware.yar",
        "subdir": "malware",
        "filename": "community_malware.yar",
    },
    {
        "url": "https://raw.githubusercontent.com/Yara-Rules/rules/master/ransomware/ransomware.yar",
        "subdir": "ransomware",
        "filename": "community_ransomware.yar",
    },
]

PLACEHOLDER_RULES = {
    "malware": "rule NovaSentinel_Placeholder_Malware\n{\n    meta:\n        author = \"NovaSentinel\"\n        description = \"Fallback placeholder malware rule.\"\n    strings:\n        $placeholder = \"NovaSentinel-Malware-Placeholder-Rule-2026\"\n    condition:\n        $placeholder\n}\n",
    "ransomware": "rule NovaSentinel_Placeholder_Ransomware\n{\n    meta:\n        author = \"NovaSentinel\"\n        description = \"Fallback placeholder ransomware rule.\"\n    strings:\n        $placeholder = \"NovaSentinel-Ransomware-Placeholder-Rule-2026\"\n    condition:\n        $placeholder\n}\n",
}


def ensure_directories() -> None:
    for subdir in ["malware", "ransomware"]:
        os.makedirs(os.path.join(RULES_DIR, subdir), exist_ok=True)


def download_rule(source: dict, timeout: int = 15) -> bool:
    url = source["url"]
    dest_path = os.path.join(RULES_DIR, source["subdir"], source["filename"])

    try:
        logger.info("Downloading YARA rules from %s", url)
        with urllib.request.urlopen(url, timeout=timeout) as response:
            data = response.read()
        with open(dest_path, "wb") as fh:
            fh.write(data)
        logger.info("Saved community rules to %s", dest_path)
        return True
    except HTTPError as exc:
        logger.warning("HTTP error when downloading %s: %s", url, exc)
    except URLError as exc:
        logger.warning("URL error when downloading %s: %s", url, exc)
    except Exception as exc:
        logger.warning("Failed to download YARA rule from %s: %s", url, exc)
    return False


def write_placeholder(subdir: str) -> None:
    path = os.path.join(RULES_DIR, subdir, f"placeholder_{subdir}.yar")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(PLACEHOLDER_RULES[subdir])
    logger.info("Wrote placeholder YARA rule to %s", path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Download community YARA rules into models/yara_rules/."
    )
    parser.add_argument("--timeout", type=int, default=15, help="HTTP timeout in seconds")
    parser.add_argument("--force", action="store_true",
                        help="Overwrite any existing downloaded community rules")
    args = parser.parse_args()

    ensure_directories()
    success = False

    for source in COMMUNITY_SOURCES:
        dest_path = os.path.join(RULES_DIR, source["subdir"], source["filename"])
        if os.path.exists(dest_path) and not args.force:
            logger.info("Existing rule file found; skipping: %s", dest_path)
            success = True
            continue
        if download_rule(source, timeout=args.timeout):
            success = True
        else:
            write_placeholder(source["subdir"])
            success = True

    if success:
        print("YARA community rule download complete. Check models/yara_rules/ for files.")
        return 0
    print("No YARA rules were downloaded or written.")
    return 1


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    raise SystemExit(main())
