import os
import json
import time
import sqlite3
import logging
import threading
from datetime import datetime, timedelta
from typing import Optional, Dict

logger = logging.getLogger(__name__)

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR   = os.path.join(BASE_DIR, "cache")
CACHE_DB    = os.path.join(CACHE_DIR, "api_cache.db")
API_KEYS_FILE = os.path.join(BASE_DIR, "config", "api_keys.json")

CACHE_TTL_HOURS = 24

# Rate limiting
VT_MIN_INTERVAL    = 15.0
ABUSEIPDB_MIN_INTERVAL = 1.0


class APIResult:
    __slots__ = ("score", "source", "cached", "details")

    def __init__(self, score: float, source: str,
                 cached: bool = False, details: dict = None):
        self.score   = float(score)
        self.source  = source
        self.cached  = cached
        self.details = details or {}

    def __repr__(self):
        return (f"APIResult(score={self.score:.3f}, source={self.source!r}, "
                f"cached={self.cached})")


class APIManager:
    """
    Centralized API manager for external threat intelligence.
    Now includes URLHaus and PhishTank (as placeholders for community feeds).
    """

    def __init__(self):
        self._lock_vt    = threading.Lock()
        self._lock_abuse = threading.Lock()
        self._last_vt_time    = 0.0
        self._last_abuse_time = 0.0

        self._vt_key:    Optional[str] = None
        self._abuse_key: Optional[str] = None

        os.makedirs(CACHE_DIR, exist_ok=True)
        self._init_cache_db()
        self._load_keys()

    def lookup_hash(self, sha256: str) -> APIResult:
        if not sha256 or len(sha256) != 64:
            return APIResult(0.0, "vt", details={"error": "invalid hash"})

        cached = self._cache_get("hash", sha256)
        if cached is not None:
            return APIResult(cached["score"], "vt", cached=True, details=cached.get("details", {}))

        if not self._vt_key:
            # Check local "simulated" community feed if no key
            return self._community_hash_lookup(sha256)

        with self._lock_vt:
            elapsed = time.time() - self._last_vt_time
            if elapsed < VT_MIN_INTERVAL:
                time.sleep(min(VT_MIN_INTERVAL - elapsed, 2.0)) # Non-blocking enough
            self._last_vt_time = time.time()

        return self._vt_hash_request(sha256)

    def lookup_url(self, url: str) -> APIResult:
        """Checks URL against URLHaus and PhishTank (simulated/community)."""
        cached = self._cache_get("url", url)
        if cached is not None:
            return APIResult(cached["score"], "community", cached=True, details=cached.get("details", {}))
        
        # Simulated URLHaus/PhishTank lookup
        # In a real app, this would query their APIs or local cached blacklists
        score = 0.0
        details = {"source": "community_feeds"}
        
        low_url = url.lower()
        if any(bad in low_url for bad in [".zip", ".scr", ".pif", "login-update", "verify-account"]):
            score = 0.65
            details["matches"] = ["suspicious_pattern"]
            
        self._cache_put("url", url, score, details)
        return APIResult(score, "community", details=details)

    def lookup_ip(self, ip: str) -> APIResult:
        if not ip:
            return APIResult(0.0, "abuseipdb", details={"error": "empty IP"})

        cached = self._cache_get("ip", ip)
        if cached is not None:
            return APIResult(cached["score"], "abuseipdb", cached=True, details=cached.get("details", {}))

        if not self._abuse_key:
            return APIResult(0.0, "abuseipdb", details={"error": "no API key"})

        with self._lock_abuse:
            elapsed = time.time() - self._last_abuse_time
            if elapsed < ABUSEIPDB_MIN_INTERVAL:
                time.sleep(ABUSEIPDB_MIN_INTERVAL - elapsed)
            self._last_abuse_time = time.time()

        return self._abuseipdb_request(ip)

    def _community_hash_lookup(self, sha256: str) -> APIResult:
        """Simulated URLHaus/MalwareBazaar hash lookup for free tier users."""
        # This represents a local cache of recent community-reported hashes
        return APIResult(0.0, "community")

    def _vt_hash_request(self, sha256: str) -> APIResult:
        try:
            import urllib.request
            req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha256}")
            req.add_header("x-apikey", self._vt_key)
            req.add_header("Accept", "application/json")

            with urllib.request.urlopen(req, timeout=5) as resp:
                body = json.loads(resp.read().decode())

            stats = body.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious  = stats.get("malicious", 0)
            total      = sum(stats.values()) or 1
            score      = round(malicious / total, 4)

            details = {"malicious": malicious, "total_engines": total}
            self._cache_put("hash", sha256, score, details)
            return APIResult(score, "vt", details=details)
        except Exception as e:
            return APIResult(0.0, "vt", details={"error": str(e)})

    def _abuseipdb_request(self, ip: str) -> APIResult:
        try:
            import urllib.request
            import urllib.parse
            params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": "90"})
            req = urllib.request.Request(f"https://api.abuseipdb.com/api/v2/check?{params}")
            req.add_header("Key", self._abuse_key)
            req.add_header("Accept", "application/json")

            with urllib.request.urlopen(req, timeout=5) as resp:
                body = json.loads(resp.read().decode())

            conf = body.get("data", {}).get("abuseConfidenceScore", 0)
            score = round(conf / 100.0, 4)
            details = {"confidence": conf, "country": body.get("data", {}).get("countryCode", "")}
            self._cache_put("ip", ip, score, details)
            return APIResult(score, "abuseipdb", details=details)
        except Exception:
            return APIResult(0.0, "abuseipdb")

    def _init_cache_db(self) -> None:
        try:
            conn = sqlite3.connect(CACHE_DB)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS api_cache (
                    key_type   TEXT NOT NULL,
                    key_value  TEXT NOT NULL,
                    score      REAL NOT NULL,
                    details    TEXT,
                    cached_at  REAL NOT NULL,
                    PRIMARY KEY (key_type, key_value)
                )
            """)
            conn.commit()
            conn.close()
        except Exception: pass

    def _cache_get(self, key_type: str, key_value: str) -> Optional[Dict]:
        try:
            conn  = sqlite3.connect(CACHE_DB)
            row   = conn.execute(
                "SELECT score, details, cached_at FROM api_cache WHERE key_type=? AND key_value=?",
                (key_type, key_value),
            ).fetchone()
            conn.close()
            if not row: return None
            score, details_json, cached_at = row
            if (time.time() - cached_at) / 3600 > CACHE_TTL_HOURS: return None
            return {"score": score, "details": json.loads(details_json) if details_json else {}}
        except Exception: return None

    def _cache_put(self, key_type: str, key_value: str, score: float, details: dict) -> None:
        try:
            conn = sqlite3.connect(CACHE_DB)
            conn.execute(
                "INSERT OR REPLACE INTO api_cache (key_type, key_value, score, details, cached_at) VALUES (?, ?, ?, ?, ?)",
                (key_type, key_value, score, json.dumps(details), time.time()),
            )
            conn.commit()
            conn.close()
        except Exception: pass

    def _load_keys(self) -> None:
        try:
            if os.path.isfile(API_KEYS_FILE):
                with open(API_KEYS_FILE, "r", encoding="utf-8") as f:
                    keys = json.load(f)
                self._vt_key = keys.get("virustotal")
                self._abuse_key = keys.get("abuseipdb")
        except Exception: pass
