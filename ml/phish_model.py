"""Phishing URL feature extraction and model wrapper for NovaSentinel."""

from __future__ import annotations

import logging
import os
import re
import string
import urllib.parse
from typing import Dict, Optional

logger = logging.getLogger(__name__)

try:
    import numpy as np
except ImportError:  # pragma: no cover
    np = None  # type: ignore

try:
    import joblib
except ImportError:  # pragma: no cover
    joblib = None  # type: ignore

SUSPICIOUS_KEYWORDS = [
    "login", "secure", "update", "verify", "account", "password",
    "bank", "confirm", "signin", "auth", "ebay", "paypal", "wallet",
]

IP_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
HEX_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")


class URLFeatureExtractor:
    """Extracts a 30-dimensional feature vector from a URL string."""

    FEATURE_DIMENSION = 30

    @classmethod
    def extract(cls, url: str) -> Optional["np.ndarray"]:
        if not url or not isinstance(url, str):
            return None

        try:
            parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
        except Exception:
            return None

        netloc = parsed.netloc or parsed.path
        path = parsed.path or ""
        query = parsed.query or ""
        fragment = parsed.fragment or ""
        scheme = parsed.scheme or "http"
        host = netloc.lower()
        if "@" in host:
            host = host.split("@")[-1]

        url_text = url.strip()
        url_len = len(url_text)
        host_len = len(host)
        path_len = len(path)
        query_len = len(query)
        frag_len = len(fragment)
        digits = sum(ch.isdigit() for ch in url_text)
        hyphens = host.count("-") + url_text.count("-")
        dots = host.count(".")
        suspicious = sum(int(word in url_text.lower()) for word in SUSPICIOUS_KEYWORDS)
        has_ip = int(bool(IP_PATTERN.match(host)))
        has_https = int(scheme == "https")
        has_at = int("@" in url_text)
        has_www = int(host.startswith("www."))
        has_userinfo = int("@" in parsed.netloc)
        redirection = int("//" in parsed.path or "/\/" in url_text)
        path_segments = len([seg for seg in path.split("/") if seg])
        query_params = len(urllib.parse.parse_qs(query))
        file_ext = os.path.splitext(path)[1].lower()
        ext_suspicious = int(file_ext in {".exe", ".zip", ".rar", ".js", ".scr", ".cmd", ".bat", ".ps1"})
        hex_encoded = int(bool(HEX_PATTERN.search(url_text)))
        longest_run = cls._longest_repeating_sequence(url_text)
        special_ratio = sum(1 for ch in url_text if ch in string.punctuation) / max(url_len, 1)
        entropy = cls._shannon_entropy(url_text.encode("utf-8"))

        subdomains = host.split(".") if host else []
        tld_len = len(subdomains[-1]) if len(subdomains) > 1 else 0
        subdomain_count = max(0, len(subdomains) - 2)
        path_contains_login = int("login" in path.lower() or "signin" in path.lower())
        query_contains_login = int("login" in query.lower() or "signin" in query.lower())

        features = [
            float(url_len),
            float(host_len),
            float(path_len),
            float(query_len),
            float(frag_len),
            float(digits),
            float(hyphens),
            float(dots),
            float(suspicious),
            float(has_ip),
            float(has_https),
            float(has_at),
            float(has_www),
            float(has_userinfo),
            float(redirection),
            float(path_segments),
            float(query_params),
            float(ext_suspicious),
            float(hex_encoded),
            float(path_contains_login),
            float(query_contains_login),
            float(longest_run),
            float(special_ratio),
            float(entropy),
            float(tld_len),
            float(subdomain_count),
            float(len(parsed.scheme)),
            float(int(host.endswith(".zip") or host.endswith(".exe"))),
            float(int("secure" in host)),
            float(int("bank" in host)),
        ]

        if len(features) < cls.FEATURE_DIMENSION:
            features.extend([0.0] * (cls.FEATURE_DIMENSION - len(features)))
        features = features[: cls.FEATURE_DIMENSION]

        if np is not None:
            return np.array(features, dtype=np.float32)
        return features  # type: ignore

    @staticmethod
    def _longest_repeating_sequence(text: str) -> int:
        longest = 1
        current = 1
        for i in range(1, len(text)):
            current = current + 1 if text[i] == text[i - 1] else 1
            longest = max(longest, current)
        return float(longest)

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        import math

        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        entropy = 0.0
        length = len(data)
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return float(entropy)


class PhishModel:
    """Wrapper around a joblib LightGBM phishing model."""

    def __init__(self, model_path: str):
        self.model_path = model_path
        self._model = None
        self.loaded = False
        self._load_model()

    def _load_model(self) -> None:
        if joblib is None:
            logger.warning("PhishModel cannot load model: joblib is unavailable.")
            return

        if not os.path.isfile(self.model_path):
            logger.warning("PhishModel model file not found: %s", self.model_path)
            return

        try:
            self._model = joblib.load(self.model_path)
            self.loaded = True
            logger.info("PhishModel loaded model from %s", self.model_path)
        except Exception as exc:
            logger.warning("Failed to load phishing model %s: %s", self.model_path, exc)
            self.loaded = False

    def predict(self, url: str) -> Dict[str, object]:
        features = URLFeatureExtractor.extract(url)
        if features is None:
            return {
                "safe": True,
                "confidence": 0.0,
                "severity": "LOW",
                "reason": "URL could not be parsed for analysis.",
            }

        if self.loaded and self._model is not None:
            try:
                data = features.reshape(1, -1) if hasattr(features, "reshape") else [features]
                if hasattr(self._model, "predict_proba"):
                    proba = self._model.predict_proba(data)
                    score = float(proba[0][1]) if len(proba[0]) > 1 else float(proba[0][0])
                else:
                    score = float(self._model.predict(data)[0])
                score = min(max(score, 0.0), 1.0)
                severity = self._map_score_to_severity(score)
                return {
                    "safe": score < 0.5,
                    "confidence": score,
                    "severity": severity,
                    "reason": "Phishing model scored the URL based on lexical and structural features.",
                }
            except Exception as exc:
                logger.warning("PhishModel prediction failed: %s", exc)

        safe = "login" not in url.lower() and "secure" not in url.lower()
        priority = 0.85 if not safe else 0.1
        return {
            "safe": safe,
            "confidence": float(priority),
            "severity": "HIGH" if not safe else "LOW",
            "reason": "Fallback phishing analysis used lexical heuristics.",
        }

    @staticmethod
    def _map_score_to_severity(score: float) -> str:
        if score >= 0.80:
            return "HIGH"
        if score >= 0.55:
            return "MEDIUM"
        return "LOW"
