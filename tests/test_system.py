"""
SentinelCore - Test Suite
Comprehensive pytest tests covering all major engines.
Run with:  pytest tests/test_system.py -v
"""

import os
import sys
import time
import json
import sqlite3
import threading
import pytest

# Ensure project root on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

# Override DB path to an in-memory/temp DB for tests
os.environ["SENTINELCORE_TEST"] = "1"


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def init_test_db(tmp_path_factory):
    """Use a temporary DB file for all tests."""
    import database.init_db as db_mod
    tmp = tmp_path_factory.mktemp("data")
    db_mod.DB_PATH = str(tmp / "test_sentinel.db")
    db_mod.init_db()
    yield
    # Cleanup handled by tmp_path_factory


@pytest.fixture
def monitor_engine():
    from engines.monitor_engine import MonitorEngine
    engine = MonitorEngine(monitor_interval=0.2)
    yield engine
    engine.stop()


@pytest.fixture
def ai_engine():
    from engines.ai_engine import AIEngine
    engine = AIEngine()
    yield engine
    engine.stop()


@pytest.fixture
def trust_engine():
    from engines.trust_engine import TrustEngine
    return TrustEngine()


@pytest.fixture
def risk_engine():
    from engines.risk_engine import RiskEngine
    return RiskEngine()




# ─────────────────────────────────────────────────────────────────────────────
# Database Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDatabase:

    def test_tables_created(self):
        from database.init_db import get_connection
        with get_connection() as conn:
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()]
        expected = ["threat_log", "process_trust", "blocked_ips",
                    "risk_history", "file_events", "system_events"]
        for t in expected:
            assert t in tables, f"Table '{t}' is missing from DB"

    def test_log_threat(self):
        from database.init_db import log_threat, get_threat_count
        before = get_threat_count()
        log_threat("TEST_THREAT", "Unit test threat entry", severity="low")
        after = get_threat_count()
        assert after == before + 1

    def test_log_system_event(self):
        from database.init_db import log_system_event, get_connection
        log_system_event("PYTEST", "Test system event", "info")
        with get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM system_events WHERE event_type='PYTEST'"
            ).fetchone()
        assert row is not None

    def test_get_recent_threats(self):
        from database.init_db import log_threat, get_recent_threats
        log_threat("RECENT_TEST", "Recent test", severity="medium")
        threats = get_recent_threats(limit=10)
        assert isinstance(threats, list)
        assert len(threats) >= 1


# ─────────────────────────────────────────────────────────────────────────────
# Monitor Engine Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestMonitorEngine:

    def test_start_stop(self, monitor_engine):
        monitor_engine.start()
        time.sleep(0.5)
        state = monitor_engine.get_state()
        assert "cpu_percent" in state
        assert "memory_percent" in state
        assert "processes" in state
        monitor_engine.stop()

    def test_metrics_types(self, monitor_engine):
        monitor_engine.start()
        time.sleep(0.5)
        s = monitor_engine.get_state()
        assert isinstance(s["cpu_percent"], (int, float))
        assert isinstance(s["memory_percent"], (int, float))
        assert isinstance(s["processes"], list)
        monitor_engine.stop()

    def test_metrics_in_range(self, monitor_engine):
        monitor_engine.start()
        time.sleep(0.5)
        s = monitor_engine.get_state()
        assert 0.0 <= s["cpu_percent"] <= 100.0
        assert 0.0 <= s["memory_percent"] <= 100.0
        monitor_engine.stop()

    def test_simulate_high_load(self, monitor_engine):
        fake = monitor_engine.simulate_high_load()
        proc_names = [p["name"] for p in fake["processes"]]
        assert "suspicious_miner.exe" in proc_names
        assert fake["cpu_percent"] >= 90.0

    def test_alert_callback(self):
        from engines.monitor_engine import MonitorEngine
        alerts = []
        def on_alert(t, m):
            alerts.append((t, m))
        engine = MonitorEngine(monitor_interval=0.1, on_alert=on_alert)
        engine.cpu_alert_threshold    = 0.0  # force CPU alert every tick
        engine.memory_alert_threshold = 0.0  # also force memory alert (always > 0%)
        engine.start()
        time.sleep(1.5)  # wait long enough for multiple ticks to fire
        engine.stop()
        assert len(alerts) >= 1

    def test_set_interval(self, monitor_engine):
        monitor_engine.set_interval(3.5)
        assert monitor_engine.monitor_interval == 3.5
        monitor_engine.set_interval(0.0)  # clamped to 0.1
        assert monitor_engine.monitor_interval == 0.1


# ─────────────────────────────────────────────────────────────────────────────
# Hash Engine Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestHashEngine:

    def test_hash_file_returns_hex(self, tmp_path):
        from engines.hash_engine import hash_file
        f = tmp_path / "test.txt"
        f.write_bytes(b"SentinelCore test data")
        result = hash_file(str(f))
        assert result is not None
        assert len(result) == 64  # SHA256 hex = 64 chars

    def test_hash_file_consistent(self, tmp_path):
        from engines.hash_engine import hash_file
        f = tmp_path / "consistent.txt"
        f.write_bytes(b"same content")
        assert hash_file(str(f)) == hash_file(str(f))

    def test_hash_file_missing(self):
        from engines.hash_engine import hash_file
        result = hash_file("/nonexistent/path.exe")
        assert result is None

    def test_dynamic_identity_unique(self):
        from engines.hash_engine import generate_dynamic_identity
        h1, _, _ = generate_dynamic_identity("abc123")
        h2, _, _ = generate_dynamic_identity("abc123")
        assert h1 != h2  # Must differ every call

    def test_verify_executable_detects_modification(self, tmp_path):
        from engines.hash_engine import register_trusted, verify_executable
        f = tmp_path / "app.exe"
        f.write_bytes(b"original binary content")
        register_trusted(str(f))
        # Now simulate modification
        f.write_bytes(b"MODIFIED binary content")
        result = verify_executable(str(f))
        assert result["modified"] is True


# ─────────────────────────────────────────────────────────────────────────────
# AI Engine Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestAIEngine:

    def test_score_returns_float(self, ai_engine):
        metrics = {
            "cpu_percent": 20.0,
            "memory_percent": 40.0,
            "processes": [],
        }
        score = ai_engine.score(metrics)
        assert isinstance(score, float)

    def test_score_in_range(self, ai_engine):
        metrics = {"cpu_percent": 50.0, "memory_percent": 50.0, "processes": []}
        score = ai_engine.score(metrics)
        assert 0.0 <= score <= 1.0

    def test_anomaly_callback(self):
        from engines.ai_engine import AIEngine
        anomalies = []
        engine = AIEngine(on_anomaly=lambda s, d: anomalies.append(s))
        # Feed abnormal data after training
        normal = {"cpu_percent": 5.0, "memory_percent": 20.0, "processes": []}
        for _ in range(50):  # Build training data
            engine.score(normal)
        # Trigger training
        engine._train()
        # Now score something extreme
        extreme = {"cpu_percent": 99.0, "memory_percent": 99.0, "processes": []}
        engine.score(extreme)
        engine.stop()

    def test_sample_count_increases(self, ai_engine):
        before = ai_engine.sample_count
        ai_engine.score({"cpu_percent": 10.0, "memory_percent": 10.0, "processes": []})
        assert ai_engine.sample_count == before + 1


# ─────────────────────────────────────────────────────────────────────────────
# Risk Engine Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestRiskEngine:

    def test_score_range(self, risk_engine):
        score = risk_engine.compute(50, 50, 0.5, 5, 50)
        assert 0.0 <= score <= 100.0

    def test_low_risk_level(self, risk_engine):
        risk_engine.compute(5, 10, 0.01, 0, 90)
        assert risk_engine.level == "low"

    def test_high_risk_level(self, risk_engine):
        risk_engine.compute(95, 95, 0.95, 40, 5)
        assert risk_engine.level == "high"

    def test_level_change_callback(self):
        from engines.risk_engine import RiskEngine
        changes = []
        engine = RiskEngine(on_level_change=lambda o, n: changes.append((o, n)))
        engine.compute(5, 5, 0.01, 0, 90)   # low
        engine.compute(95, 95, 0.95, 40, 5)  # high
        assert len(changes) >= 1

    def test_monitor_interval_changes_with_level(self, risk_engine):
        risk_engine.compute(5, 5, 0.01, 0, 90)   # → low
        assert risk_engine.monitor_interval == 5.0
        risk_engine.compute(95, 95, 0.95, 40, 5)  # → high
        assert risk_engine.monitor_interval == 0.5


# ─────────────────────────────────────────────────────────────────────────────
# Trust Engine Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestTrustEngine:

    def test_default_trust(self, trust_engine):
        score = trust_engine.get_trust("brand_new_app.exe")
        assert score == 50

    def test_clean_run_increases_trust(self, trust_engine):
        initial = trust_engine.get_trust("growing_app.exe")
        new_score = trust_engine.report_clean_run("growing_app.exe")
        assert new_score > initial

    def test_anomaly_decreases_trust(self, trust_engine):
        initial = trust_engine.get_trust("bad_app.exe")
        new_score = trust_engine.report_anomaly("bad_app.exe")
        assert new_score < initial

    def test_trust_bounds(self, trust_engine):
        for _ in range(60):
            trust_engine.report_clean_run("loyal_app.exe")
        assert trust_engine.get_trust("loyal_app.exe") <= 100

        for _ in range(60):
            trust_engine.report_anomaly("malicious_app.exe")
        assert trust_engine.get_trust("malicious_app.exe") >= 0

    def test_average_trust(self, trust_engine):
        trust_engine.get_trust("proc_a.exe")
        trust_engine.get_trust("proc_b.exe")
        avg = trust_engine.average_trust(["proc_a.exe", "proc_b.exe"])
        assert 0 <= avg <= 100




# ─────────────────────────────────────────────────────────────────────────────
# IP Blocker Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestIPBlocker:

    def test_block_records_in_db(self):
        from engines.ip_blocker import block_ip, get_blocked_ips
        block_ip("192.168.99.1", "Unit test block")
        blocked = [b["ip_address"] for b in get_blocked_ips()]
        # netsh may fail in test env but DB record must exist
        assert "192.168.99.1" in blocked

    def test_invalid_ip_rejected(self):
        from engines.ip_blocker import block_ip
        result = block_ip("not_an_ip", "test")
        assert result is False

    def test_suspicious_ip_detection(self):
        from engines.ip_blocker import is_suspicious_ip
        assert is_suspicious_ip("185.220.101.55") is True
        assert is_suspicious_ip("8.8.8.8") is False


# ─────────────────────────────────────────────────────────────────────────────
# Config & Version Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestConfig:

    def test_version_json_valid(self):
        config_path = os.path.join(BASE_DIR, "config", "version.json")
        assert os.path.exists(config_path), "config/version.json missing"
        with open(config_path, "r") as f:
            cfg = json.load(f)
        assert cfg["name"] == "SentinelCore"
        assert "version" in cfg
        assert "risk_weights" in cfg

    def test_risk_weights_sum(self):
        config_path = os.path.join(BASE_DIR, "config", "version.json")
        with open(config_path, "r") as f:
            cfg = json.load(f)
        weights = cfg["risk_weights"]
        total = sum(weights.values())
        assert abs(total - 1.0) < 0.01, f"Risk weights should sum to 1.0, got {total}"
