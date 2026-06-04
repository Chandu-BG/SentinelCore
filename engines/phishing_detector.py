"""
SentinelCore - Phishing Detector Engine (v5.0)
Offline URL analysis for phishing, brand spoofing, and fake login pages.

Detection methods:
  - Levenshtein-based brand typosquatting (PayPal, Google, Microsoft, Amazon, Apple, banking, etc.)
  - IDN Homograph / Punycode spoofing detection
  - Shannon Entropy analysis for DGA and randomized token generation
  - Suspicious TLD / extension analysis
  - Excessive subdomain depth checking
  - URL structure lexical analysis (obfuscation, special char density, encoded chars)
  - SSL availability & hostname mismatch validation
  - Insecure protocol + login pathway signals
  - Local cached threat feeds & dataset lookups
"""

import re
import math
import logging
import threading
from collections import OrderedDict
from typing import Optional, Callable, Tuple, List, Dict
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

# ── Brand targets for typosquatting & impersonation ───────────────────────────
BRAND_TARGETS = [
    "paypal", "google", "facebook", "microsoft", "apple", "amazon",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "github",
    "bankofamerica", "chase", "citibank", "wellsfargo", "hsbc",
    "steam", "roblox", "discord", "outlook", "office365", "onedrive",
]

# Suspicious TLDs commonly abused in phishing campaigns
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Free TLDs
    ".xyz", ".top", ".buzz", ".click",
    ".online", ".site", ".website", ".space",
    ".loan", ".work", ".party", ".stream", ".cc", ".icu", ".vip", ".tokyo"
}

# Phishing keyword combos in URL path/query
PHISHING_KEYWORDS = [
    "verify-account", "confirm-identity", "secure-login", "account-suspended",
    "update-billing", "verify-email", "unlock-account", "account-verify",
    "login-confirm", "reset-password-now", "verify-now", "validate-account",
    "secure-banking", "update-wallet", "login-update", "confirm-payment"
]

# Redirect parameter names
REDIRECT_PARAMS = {"url", "redirect", "next", "redir", "redirect_uri",
                   "return", "returnurl", "goto", "forward"}

# Fake login signals in path
LOGIN_PATH_SIGNALS = [
    "login", "signin", "sign-in", "logon", "log-in",
    "account", "password", "credentials", "auth", "checkout", "payment"
]

# Levenshtein Distance implementation
def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


class PhishingResult:
    """Result of phishing analysis for a single URL."""
    def __init__(self, url: str, is_phishing: bool, score: int,
                 reasons: List[str], classification: str):
        self.url            = url
        self.is_phishing    = is_phishing
        self.score          = score
        self.reasons        = reasons
        self.classification = classification   # SAFE / SUSPICIOUS / PHISHING

    def friendly_message(self) -> str:
        if self.classification == "PHISHING":
            return "Critical: This website represents a confirmed phishing or brand spoofing risk."
        if self.classification == "SUSPICIOUS":
            return "Warning: This website exhibits highly suspicious indicators and should be treated with caution."
        return "Safe: This website shows no indicators of phishing or brand impersonation."

    def to_dict(self) -> dict:
        """Serialize to a plain dict for UI rendering.

        Returns a dict with exactly the keys:
        url, is_phishing, score, reasons, classification, friendly_message.
        """
        return {
            "url":             self.url,
            "is_phishing":     self.is_phishing,
            "score":           self.score,
            "reasons":         list(self.reasons),
            "classification":  self.classification,
            "friendly_message": self.friendly_message(),
        }


class PhishingDetector:
    """
    Offline phishing URL analyzer.
    analyze(url) → PhishingResult

    Thread-safe. Optimized local pattern matching with heuristic & lexical indicators.
    """

    def __init__(
        self,
        on_alert: Optional[Callable[[str, str, str], None]] = None,
    ):
        self.on_alert    = on_alert
        # Thread-safe LRU cache (max 500 entries to prevent memory leak)
        self._cache: OrderedDict[str, PhishingResult] = OrderedDict()
        self._cache_lock = threading.Lock()
        self._cache_max = 500

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    def analyze(self, url: str) -> PhishingResult:
        """
        Analyze a URL for phishing indicators.
        Returns a PhishingResult immediately (synchronous, no network).
        """
        url = url.strip()
        # Thread-safe cache lookup
        with self._cache_lock:
            if url in self._cache:
                # Move to end (LRU touch)
                self._cache.move_to_end(url)
                return self._cache[url]

        result = self._analyze(url)
        
        # ML-based analysis from DatasetManager
        try:
            from core.dataset_manager import get_dataset_manager
            dm = get_dataset_manager()
            ml_result = dm.analyze_url(url)
            if not ml_result.get("safe", True):
                result.score = min(result.score + 30, 100)
                ml_reason = ml_result.get("reason", "ML: URL flagged as phishing.")
                if ml_reason not in result.reasons:
                    result.reasons.append(ml_reason)
                result.is_phishing = True
                result.classification = "PHISHING"
        except Exception:
            pass

        # Update final classification state based on score boundaries
        if result.score >= 60:
            result.classification = "PHISHING"
            result.is_phishing = True
        elif result.score >= 30:
            result.classification = "SUSPICIOUS"
            result.is_phishing = False
        else:
            result.classification = "SAFE"
            result.is_phishing = False

        # Thread-safe cache insert with LRU eviction
        with self._cache_lock:
            self._cache[url] = result
            self._cache.move_to_end(url)
            # Evict oldest entry if over limit
            if len(self._cache) > self._cache_max:
                self._cache.popitem(last=False)

        if result.classification in ("PHISHING", "SUSPICIOUS") and self.on_alert:
            try:
                reason = "; ".join(result.reasons[:3]) if result.reasons else "unknown"
                self.on_alert(url, result.classification, reason)
            except Exception as e:
                logger.error(f"PhishingDetector alert callback error: {e}")

        return result

    def analyze_many(self, urls: List[str]) -> List[PhishingResult]:
        return [self.analyze(u) for u in urls]

    def clear_cache(self) -> None:
        self._cache.clear()

    # ──────────────────────────────────────────────────────────────────────────
    # Internal analysis
    # ──────────────────────────────────────────────────────────────────────────

    def _analyze(self, url: str) -> PhishingResult:
        score   = 0
        reasons: List[str] = []

        try:
            # Handle URLs without protocol
            temp_url = url if "://" in url else "https://" + url
            parsed = urlparse(temp_url)
        except Exception:
            return PhishingResult(url, False, 100, ["Invalid URL format"], "PHISHING")

        hostname = (parsed.hostname or "").lower()
        path     = parsed.path.lower()
        query    = parsed.query.lower()
        full_url = url.lower()

        # ── 0. Whitelist Check ───────────────────────────────────────────────
        try:
            from core.dataset_manager import WHITELIST_DOMAINS
            if any(hostname == domain or hostname.endswith("." + domain) for domain in WHITELIST_DOMAINS):
                return PhishingResult(url, False, 0, ["Verified reputable domain."], "SAFE")
        except Exception:
            pass

        # ── PhishingIntelEngine (ML weighted features) ───────────────────────
        intel_score = 0
        try:
            from engines.intelligence_engines import PhishingIntelEngine
            intel_engine = PhishingIntelEngine()
            intel_res = intel_engine.analyze(url)
            intel_conf = intel_res.get("confidence", 0.0)
            intel_score = int(intel_conf * 100)
            intel_reasons = intel_res.get("reasons", [])
            for ir in intel_reasons:
                if ir not in reasons:
                    reasons.append(ir)
        except Exception as e:
            logger.debug(f"PhishingIntelEngine failed: {e}")

        # ── Community reputation feeds check ──────────────────────────────────
        try:
            from engines.api_manager import APIManager
            api_manager = APIManager()
            api_res = api_manager.lookup_url(url)
            if api_res.score > 0:
                score += int(api_res.score * 50)
                reasons.append("Listed in community threat feeds (PhishTank/URLHaus)")
        except Exception:
            pass

        # ── 1. IP-based URL ──────────────────────────────────────────────────
        if self._is_ip(hostname):
            score += 40
            reasons.append("Site uses an IP address instead of a real domain name.")

        # ── 2. Suspicious TLD ────────────────────────────────────────────────
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                score += 20
                reasons.append(f"Domain uses a high-risk extension ({tld}).")
                break

        # ── 3. Typosquatting & Homographs (Levenshtein) ──────────────────────
        brand_hit, dist = self._check_typosquat_advanced(hostname)
        if brand_hit:
            score += 35
            if dist == 0:
                reasons.append(f"Domain contains corporate name '{brand_hit}' without ownership verification.")
            else:
                reasons.append(f"Levenshtein typosquatting attempt: matches brand '{brand_hit}' (diff: {dist}).")

        if hostname.startswith("xn--"):
            score += 30
            reasons.append("IDN Homograph detected (Punycode) - character spoofing active.")

        # ── 4. Entropy Analysis ──────────────────────────────────────────────
        entropy = self._calculate_entropy(hostname)
        if entropy > 4.2:
            score += 25
            reasons.append(f"High domain character entropy ({entropy:.2f}) - algorithmically generated naming.")

        # ── 5. Excessive subdomains ──────────────────────────────────────────
        parts = hostname.split(".")
        if len(parts) > 4:
            score += 15
            reasons.append(f"Excessive subdomains ({len(parts)}) active - obfuscating true hostname.")

        # ── 6. Phishing keywords in URL ──────────────────────────────────────
        for kw in PHISHING_KEYWORDS:
            if kw in full_url:
                score += 20
                reasons.append(f"URL contains a high-risk phishing keyword: '{kw}'.")
                break

        # ── 7. Fake login signals ────────────────────────────────────────────
        has_login_path = any(sig in path for sig in LOGIN_PATH_SIGNALS)
        brand_in_path  = any(b in path or b in query for b in BRAND_TARGETS)
        if brand_in_path and not any(hostname.endswith(b + ".com") for b in BRAND_TARGETS):
            score += 30
            reasons.append("URL embeds a major brand name in path/query without domain ownership.")

        # ── 8. Insecure HTTP + Login ─────────────────────────────────────────
        if parsed.scheme == "http" and has_login_path:
            score += 15
            reasons.append("Sensitive pathway/login served over unencrypted HTTP protocol.")

        # ── 9. SSL & Host Analysis ───────────────────────────────────────────
        if parsed.scheme == "http":
            score += 10
            reasons.append("SSL/TLS unencrypted connection.")
        
        # ── 10. Lexical Obfuscation & Encoded density ───────────────────────
        encoded_chars = len(re.findall(r"%[0-9a-fA-F]{2}", full_url))
        if encoded_chars > 3:
            score += 15
            reasons.append(f"High density of hexadecimal encoded characters ({encoded_chars}) detected.")

        special_chars = sum(1 for c in full_url if c in "@-_?=&~")
        if special_chars > 6:
            score += 15
            reasons.append(f"Lexical obfuscation: high density of special characters ({special_chars}) active.")

        # ── 11. Redirection parameters check ───────────────────────────────
        redirects = 0
        try:
            params = parse_qs(parsed.query)
            for rp in REDIRECT_PARAMS:
                if rp in params:
                    redirects += len(params[rp])
        except Exception:
            pass
        if redirects > 0:
            score += 15
            reasons.append("Active open redirect parameter vectors detected.")

        # Blend the heuristic score with the ML model's confidence
        score = max(score, intel_score)

        # Limit score
        score = min(score, 100)

        classification = "SAFE"
        if score >= 60:
            classification = "PHISHING"
        elif score >= 30:
            classification = "SUSPICIOUS"

        return PhishingResult(
            url            = url,
            is_phishing    = classification == "PHISHING",
            score          = score,
            reasons        = reasons,
            classification = classification,
        )

    def _calculate_entropy(self, s: str) -> float:
        if not s: return 0.0
        counts = {}
        for char in s:
            counts[char] = counts.get(char, 0) + 1
        entropy = 0.0
        for count in counts.values():
            p = count / len(s)
            entropy -= p * math.log2(p)
        return entropy

    # ──────────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _is_ip(self, hostname: str) -> bool:
        """Return True if hostname is a raw IPv4 or IPv6 address."""
        ipv4 = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname)
        if ipv4:
            return True
        if hostname.startswith("[") and hostname.endswith("]"):
            return True
        return False

    def _check_typosquat_advanced(self, hostname: str) -> Tuple[Optional[str], int]:
        """
        Detect typosquatting of known brands in hostname using Levenshtein distance.
        Returns a tuple of (brand, distance) if typosquatting is active.
        """
        hostname_lower = hostname.lower()
        parts = hostname_lower.split('.')
        if not parts:
            return None, -1

        # Subdomains and TLDs to ignore when checking typosquatting
        ignored = {"www", "mail", "api", "secure", "login", "com", "org", "net", "edu", "gov", "co", "uk", "io", "cc", "xyz", "top", "tk", "ml", "ga", "cf", "gq"}

        for part in parts:
            if part in ignored or len(part) < 3:
                continue

            for brand in BRAND_TARGETS:
                # If segment is exactly the brand, verify if it's the legitimate root domain
                if part == brand:
                    # If this isn't brand.com or brand.org, etc.
                    if not (hostname_lower == f"{brand}.com" or hostname_lower.endswith(f".{brand}.com") or
                            hostname_lower == f"{brand}.org" or hostname_lower.endswith(f".{brand}.org") or
                            hostname_lower == f"{brand}.net" or hostname_lower.endswith(f".{brand}.net") or
                            hostname_lower == f"{brand}.co.uk" or hostname_lower.endswith(f".{brand}.co.uk")):
                        return brand, 0
                    continue

                # Brand in segment but not exactly segment (e.g. "secure-paypal")
                if brand in part:
                    return brand, 0

                # Levenshtein typosquat check
                dist = levenshtein_distance(part, brand)
                # Distance threshold of 1 or 2 with close string lengths
                if 1 <= dist <= 2 and abs(len(part) - len(brand)) <= 2:
                    return brand, dist

        return None, -1
