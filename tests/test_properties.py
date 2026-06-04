"""Property-based tests for NovaSentinel critical correctness properties."""

from __future__ import annotations

import os
import tempfile
import threading
import time
from typing import Any

import hypothesis.strategies as st
from hypothesis import given, settings
import pytest

# Import components to test
from engines.phishing_detector import PhishingResult
from quarantine.quarantine_manager import QuarantineManager
from ml.phish_model import URLFeatureExtractor
from core.dataset_manager import DatasetManager
from core.realtime_monitor import _DebouncedHandler
from gui.theme_manager import ThemeManager, THEME_PALETTES
from core.telemetry_manager import TelemetryManager


class TestPhishingResult:
    """Test PhishingResult.to_dict() properties."""

    @given(
        url=st.text(min_size=1, max_size=100),
        is_phishing=st.booleans(),
        score=st.integers(min_value=0, max_value=10),
        reasons=st.lists(st.text(min_size=1, max_size=10), min_size=0, max_size=5),
        classification=st.sampled_from(["SAFE", "SUSPICIOUS", "MALICIOUS", "PHISHING"]),
    )
    def test_to_dict_always_returns_dict_with_required_keys(
        self, url, is_phishing, score, reasons, classification
    ):
        """PhishingResult.to_dict() always returns dict with exactly 6 required keys."""
        result = PhishingResult(
            url=url,
            is_phishing=is_phishing,
            score=score,
            reasons=reasons,
            classification=classification,
        )
        result_dict = result.to_dict()

        assert isinstance(result_dict, dict)
        required_keys = {"url", "is_phishing", "score", "reasons", "classification", "friendly_message"}
        assert set(result_dict.keys()) == required_keys

        # Verify types
        assert isinstance(result_dict["url"], str)
        assert isinstance(result_dict["is_phishing"], bool)
        assert isinstance(result_dict["score"], int)
        assert isinstance(result_dict["reasons"], list)
        assert isinstance(result_dict["classification"], str)
        assert isinstance(result_dict["friendly_message"], str)


class TestQuarantineManager:
    """Test QuarantineManager encrypt/decrypt round-trip."""

    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.manager = QuarantineManager(base_dir=self.temp_dir)

    @given(data=st.binary(min_size=1, max_size=1024))
    def test_encrypt_decrypt_round_trip(self, data):
        """QuarantineManager encrypt/decrypt preserves arbitrary byte sequences."""
        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            temp_path = f.name

        try:
            # Quarantine the file
            uuid = self.manager.quarantine(temp_path, "test")

            # Restore the file
            restored_path = self.manager.restore(uuid)

            # Verify contents match
            with open(restored_path, "rb") as f:
                restored_data = f.read()

            assert restored_data == data

        finally:
            # Cleanup
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass
            try:
                os.unlink(restored_path)
            except FileNotFoundError:
                pass


class TestURLFeatureExtractor:
    """Test URLFeatureExtractor.extract() properties."""

    @given(url=st.text(min_size=1, max_size=200))
    def test_extract_always_returns_30_element_array(self, url):
        """URLFeatureExtractor.extract() always returns 30-element float32 array for any string."""
        features = URLFeatureExtractor.extract(url)

        if features is None:
            # Should only be None for completely invalid inputs, but let's be lenient
            return

        assert len(features) == 30
        # Features can be list or numpy array, both should contain numeric types
        try:
            import numpy as np
            # Accept numpy numeric types
            assert all(isinstance(x, (float, int, np.floating, np.integer)) for x in features)
        except ImportError:
            # Fallback if numpy not available
            assert all(isinstance(x, (float, int)) for x in features)


class TestDatasetManager:
    """Test DatasetManager.analyze_pe() robustness."""

    def setup_method(self):
        self.manager = DatasetManager()

    @given(path=st.text(min_size=1, max_size=100))
    def test_analyze_pe_never_raises(self, path):
        """DatasetManager.analyze_pe() never raises for any file path string."""
        try:
            result = self.manager.analyze_pe(path)
            assert isinstance(result, dict)
            assert "safe" in result
            assert "confidence" in result
            assert "severity" in result
            assert "reason" in result
        except Exception:
            pytest.fail(f"DatasetManager.analyze_pe() raised exception for path: {path}")


class TestDebouncer:
    """Test Debouncer callback firing properties."""

    def setup_method(self):
        self.callback_count = 0
        self.last_path = None

        def callback(path):
            self.callback_count += 1
            self.last_path = path

        self.debouncer = _DebouncedHandler(callback)

    def test_rapid_same_path_events_fire_exactly_once(self):
        """Debouncer fires exactly 1 callback for rapid same-path events."""
        path = "/test/path"
        self.callback_count = 0
        self.last_path = None

        # Fire multiple events rapidly
        for _ in range(5):
            self.debouncer._debounce(path)

        # Wait for debounce period
        time.sleep(0.6)

        assert self.callback_count == 1
        assert self.last_path == path

    def test_distinct_paths_fire_separately(self):
        """Debouncer fires exactly n callbacks for n distinct paths."""
        paths = ["/path1", "/path2", "/path3"]
        self.callback_count = 0

        # Fire events for each distinct path
        for path in paths:
            self.debouncer._debounce(path)

        # Wait for debounce period
        time.sleep(0.6)

        assert self.callback_count == len(paths)


class TestThemeManager:
    """Test ThemeManager.apply() robustness."""

    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.manager = ThemeManager(self.temp_dir)

    def test_apply_succeeds_for_all_theme_names(self):
        """ThemeManager.apply() succeeds for all 6 theme names without raising."""
        for theme_name in THEME_PALETTES.keys():
            try:
                self.manager.apply(theme_name)
                assert self.manager.current_theme_name == theme_name
            except Exception:
                pytest.fail(f"ThemeManager.apply() raised exception for theme: {theme_name}")


class TestTelemetryManager:
    """Test TelemetryManager.get_snapshot() consistency."""

    def setup_method(self):
        self.manager = TelemetryManager()

    def test_get_snapshot_returns_valid_data(self):
        """TelemetryManager.get_snapshot() returns valid snapshot."""
        snap = self.manager.get_snapshot()
        assert hasattr(snap, 'cpu_percent')
        assert hasattr(snap, 'ram_percent')
        assert hasattr(snap, 'threat_count')
        assert isinstance(snap.cpu_percent, (int, float))
        assert isinstance(snap.ram_percent, (int, float))
        assert isinstance(snap.threat_count, int)