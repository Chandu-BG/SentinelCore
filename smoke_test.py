"""Smoke test script (non-GUI)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def run():
    # ---- Database ----
    from database.init_db import init_db, log_threat, get_threat_count
    init_db()
    log_threat('SMOKE_TEST', 'Smoke test', severity='low')
    count = get_threat_count()
    assert count >= 1
    print(f'[OK] Database: threat_count={count}')

    # ---- Hash Engine ----
    from engines.hash_engine import generate_dynamic_identity
    h, ts, salt = generate_dynamic_identity('test_hash_input')
    h2, _, _ = generate_dynamic_identity('test_hash_input')
    assert len(h) == 64
    assert h != h2
    print('[OK] Hash Engine: unique dynamic identity verified')

    # ---- Risk Engine ----
    from engines.risk_engine import RiskEngine
    risk = RiskEngine()
    score = risk.compute(30, 40, 0.1, 2, 70)
    assert 0 <= score <= 100
    print(f'[OK] Risk Engine: score={score}, level={risk.level}')

    # ---- Trust Engine ----
    from engines.trust_engine import TrustEngine
    trust = TrustEngine()
    t0 = trust.get_trust('test_proc.exe')
    t1 = trust.report_clean_run('test_proc.exe')
    t2 = trust.report_anomaly('test_proc.exe')
    assert t1 > t0
    assert t2 < t1
    print(f'[OK] Trust Engine: {t0} -> clean={t1} -> anomaly={t2}')

    # ---- Encryption Vault ----
    from engines.encryption_engine import EncryptionEngine
    vault = EncryptionEngine()
    ok = vault.encrypt('smoke_entry', 'SentinelCore AES-256!', 'P@ssw0rd!')
    assert ok
    result = vault.decrypt('smoke_entry', 'P@ssw0rd!')
    assert result == 'SentinelCore AES-256!'
    wrong = vault.decrypt('smoke_entry', 'wrongpw')
    assert wrong is None
    print('[OK] Encryption Vault: AES-256 roundtrip OK')

    # ---- IP Blocker ----
    from engines.ip_blocker import is_suspicious_ip
    assert is_suspicious_ip('185.220.101.55') is True
    assert is_suspicious_ip('8.8.8.8') is False
    print('[OK] IP Blocker: heuristic check OK')

    # ---- Monitor Engine ----
    import time
    from engines.monitor_engine import MonitorEngine
    mon = MonitorEngine(monitor_interval=0.2)
    mon.start()
    time.sleep(0.6)
    state = mon.get_state()
    mon.stop()
    assert 'cpu_percent' in state
    assert 0 <= state['cpu_percent'] <= 100
    assert isinstance(state['processes'], list)
    print(f'[OK] Monitor Engine: cpu={state["cpu_percent"]}%, procs={state["process_count"]}')

    # ---- AI Engine ----
    from engines.ai_engine import AIEngine
    ai = AIEngine()
    s = ai.score({'cpu_percent': 20.0, 'memory_percent': 30.0, 'processes': []})
    assert 0.0 <= s <= 1.0
    ai.stop()
    print(f'[OK] AI Engine: score={s}')

    # ---- File Engine import ----
    from engines.file_engine import FileEngine
    # just import, don't start (needs watchdog observer)
    fe = FileEngine(watch_paths=[])
    print('[OK] File Engine: imported OK')

    # ---- Self-Protection Engine ----
    from engines.self_protection_engine import SelfProtectionEngine
    sp = SelfProtectionEngine()
    print('[OK] Self-Protection Engine: imported OK')

    print()
    print('=' * 50)
    print('  ALL SMOKE TESTS PASSED')
    print('=' * 50)

if __name__ == '__main__':
    run()
