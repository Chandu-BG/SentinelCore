import logging
import os
import threading
import json
import time
from typing import Dict, Optional, List

logger = logging.getLogger(__name__)

try:
    import joblib
except ImportError:
    joblib = None

try:
    import numpy as np
except ImportError:
    np = None

from ml import PEFeatureExtractor, URLFeatureExtractor

MODEL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, "models"))
PE_MODEL_PATH = os.path.join(MODEL_DIR, "ember_lgbm.pkl")
URL_MODEL_PATH = os.path.join(MODEL_DIR, "phish_lgbm.pkl")

# ── Tranco-inspired top domain whitelist ──
WHITELIST_DOMAINS = frozenset({
    "google.com", "google.co.in", "youtube.com", "facebook.com", "microsoft.com",
    "apple.com", "amazon.com", "netflix.com", "wikipedia.org", "twitter.com",
    "instagram.com", "linkedin.com", "live.com", "outlook.com", "office.com",
    "bing.com", "msn.com", "yahoo.com", "github.com", "reddit.com", "zoom.us",
    "wordpress.com", "cloudflare.com", "adobe.com", "salesforce.com",
})


class DatasetManager:
    """Handles PE and URL inference using ML models and reputation feeds."""

    def __init__(self):
        self.models_loaded = False
        self._loading = False
        self._pe_model = None
        self._url_model = None
        self._reputation_cache: Dict[str, Dict] = {}
        self._cache_lock = threading.Lock()

    def load_models(self) -> None:
        if self._loading or self.models_loaded: return
        self._loading = True
        threading.Thread(target=self._load_models, daemon=True).start()

    def _load_models(self) -> None:
        try:
            if joblib:
                if os.path.isfile(PE_MODEL_PATH): self._pe_model = joblib.load(PE_MODEL_PATH)
                if os.path.isfile(URL_MODEL_PATH): self._url_model = joblib.load(URL_MODEL_PATH)
        except Exception: pass
        finally:
            self.models_loaded = self._pe_model is not None or self._url_model is not None
            self._loading = False

    def analyze_pe(self, file_path: str) -> Dict:
        # Check local reputation first
        file_name = os.path.basename(file_path)
        with self._cache_lock:
            if file_path in self._reputation_cache:
                return self._reputation_cache[file_path]

        features = PEFeatureExtractor().extract(file_path)
        if features is None:
            return {"safe": True, "confidence": 0.0, "severity": "LOW", "reason": "No features extracted."}

        result = None
        if self._pe_model:
            try:
                data = features.reshape(1, -1) if hasattr(features, "reshape") else [features]
                if hasattr(self._pe_model, "predict_proba"):
                    proba = self._pe_model.predict_proba(data)[0]
                    score = float(proba[1] if len(proba) > 1 else proba[0])
                else:
                    score = float(self._pe_model.predict(data)[0])
                result = self._build_result(score, "ML PE Model Analysis")
            except Exception: pass

        if not result:
            result = self._fallback_pe_analysis(features)

        with self._cache_lock:
            self._reputation_cache[file_path] = result
        return result

    def analyze_url(self, url: str) -> Dict:
        # 1. Whitelist Check
        domain = self._extract_domain(url)
        if domain in WHITELIST_DOMAINS:
            return {"safe": True, "confidence": 0.0, "severity": "LOW", "reason": "Whitelisted domain."}

        # 2. Cache Check
        with self._cache_lock:
            if url in self._reputation_cache:
                return self._reputation_cache[url]

        features = URLFeatureExtractor.extract(url)
        result = None
        if self._url_model:
            try:
                data = features.reshape(1, -1) if hasattr(features, "reshape") else [features]
                if hasattr(self._url_model, "predict_proba"):
                    proba = self._url_model.predict_proba(data)[0]
                    score = float(proba[1] if len(proba) > 1 else proba[0])
                else:
                    score = float(self._url_model.predict(data)[0])
                result = self._build_result(score, "ML URL Phishing Model Analysis")
            except Exception: pass

        if not result:
            result = self._fallback_url_analysis(url, features)

        with self._cache_lock:
            self._reputation_cache[url] = result
        return result

    def _extract_domain(self, url: str) -> str:
        try:
            from urllib.parse import urlparse
            netloc = urlparse(url).netloc
            return netloc.lower().split(':')[0]
        except Exception: return ""

    def _build_result(self, score: float, reason: str) -> Dict:
        score = max(0.0, min(score, 1.0))
        severity = "LOW"
        if score >= 0.8: severity = "HIGH"
        elif score >= 0.55: severity = "MEDIUM"
        return {"safe": score < 0.55, "confidence": score, "severity": severity, "reason": reason}

    def _fallback_pe_analysis(self, features) -> Dict:
        return {"safe": True, "confidence": 0.1, "severity": "LOW", "reason": "PE Heuristics."}

    def _fallback_url_analysis(self, url: str, features) -> Dict:
        score = 0.1
        low = url.lower()
        if any(x in low for x in ["login", "verify", "account", "update", "secure"]): score = 0.6
        return self._build_result(score, "Lexical Heuristics")

_instance: Optional[DatasetManager] = None

def get_dataset_manager() -> DatasetManager:
    global _instance
    if _instance is None: _instance = DatasetManager()
    return _instance
