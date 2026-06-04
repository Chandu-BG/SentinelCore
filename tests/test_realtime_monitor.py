"""
Tests for core/realtime_monitor.py — _DebouncedHandler debounce logic.

Requirements covered: 11.2, 11.3, 11.4
"""

import os
import sys
import time
import threading
import pytest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from core.realtime_monitor import _DebouncedHandler, RealtimeMonitor, DEBOUNCE_SECONDS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_handlers = []

@pytest.fixture(autouse=True)
def cleanup_handlers():
    yield
    for h in _handlers:
        try:
            h.stop_worker()
        except Exception:
            pass
    _handlers.clear()

def make_handler():
    """Return (handler, calls_list) where calls_list accumulates fired paths."""
    calls = []
    handler = _DebouncedHandler(lambda path: calls.append(path))
    handler.start_worker()
    _handlers.append(handler)
    return handler, calls


def _simulate_event(handler, path):
    """Directly invoke the internal _debounce method (bypasses watchdog)."""
    handler._debounce(path)


# ---------------------------------------------------------------------------
# _DebouncedHandler unit tests
# ---------------------------------------------------------------------------

class TestDebouncedHandler:

    def test_single_event_fires_once(self):
        """One event on a path → exactly 1 callback after the debounce window."""
        handler, calls = make_handler()
        _simulate_event(handler, "/tmp/file.txt")
        time.sleep(DEBOUNCE_SECONDS + 0.1)
        assert calls == ["/tmp/file.txt"]

    def test_rapid_events_same_path_fires_once(self):
        """n rapid events on the same path → exactly 1 callback (Req 11.3)."""
        handler, calls = make_handler()
        path = "/tmp/rapid.txt"
        for _ in range(10):
            _simulate_event(handler, path)
            time.sleep(0.01)  # 10 ms apart — well within 500 ms window
        # Wait for debounce to settle
        time.sleep(DEBOUNCE_SECONDS + 0.15)
        assert len(calls) == 1
        assert calls[0] == path

    def test_distinct_paths_each_fire_once(self):
        """n events on n distinct paths → exactly n callbacks (Req 11.4)."""
        handler, calls = make_handler()
        paths = [f"/tmp/file_{i}.txt" for i in range(5)]
        for p in paths:
            _simulate_event(handler, p)
        time.sleep(DEBOUNCE_SECONDS + 0.15)
        assert sorted(calls) == sorted(paths)

    def test_timer_restarted_on_repeat_event(self):
        """Repeated events keep resetting the timer; callback fires only after silence."""
        handler, calls = make_handler()
        path = "/tmp/reset.txt"
        # Fire events every 200 ms for 600 ms total — timer keeps resetting
        for _ in range(3):
            _simulate_event(handler, path)
            time.sleep(0.2)
        # At this point the last event was ~0 ms ago; wait for debounce
        time.sleep(DEBOUNCE_SECONDS + 0.15)
        assert len(calls) == 1

    def test_no_premature_callback(self):
        """Callback must NOT fire before the debounce window expires."""
        handler, calls = make_handler()
        _simulate_event(handler, "/tmp/early.txt")
        # Check immediately — should not have fired yet
        time.sleep(DEBOUNCE_SECONDS * 0.4)
        assert len(calls) == 0
        # Now wait for it to fire
        time.sleep(DEBOUNCE_SECONDS + 0.1)
        assert len(calls) == 1

    def test_independent_paths_independent_timers(self):
        """Events on different paths do not interfere with each other's timers."""
        handler, calls = make_handler()
        _simulate_event(handler, "/tmp/a.txt")
        time.sleep(0.05)
        _simulate_event(handler, "/tmp/b.txt")
        time.sleep(DEBOUNCE_SECONDS + 0.15)
        assert "/tmp/a.txt" in calls
        assert "/tmp/b.txt" in calls
        assert len(calls) == 2

    def test_callback_exception_does_not_propagate(self):
        """A callback that raises must not crash the timer thread."""
        def bad_cb(path):
            raise RuntimeError("intentional test error")

        handler = _DebouncedHandler(bad_cb)
        handler.start_worker()
        _handlers.append(handler)
        handler._debounce("/tmp/bad.txt")
        # Should not raise; just wait for the timer
        time.sleep(DEBOUNCE_SECONDS + 0.15)
        # If we reach here without exception the test passes

    def test_many_rapid_events_then_silence(self):
        """50 rapid events on one path → exactly 1 callback."""
        handler, calls = make_handler()
        path = "/tmp/storm.txt"
        for _ in range(50):
            _simulate_event(handler, path)
        time.sleep(DEBOUNCE_SECONDS + 0.2)
        assert len(calls) == 1

    def test_timer_dict_cleaned_up_after_fire(self):
        """After the callback fires, the path entry is removed from _pending_events."""
        handler, calls = make_handler()
        path = "/tmp/cleanup.txt"
        _simulate_event(handler, path)
        time.sleep(DEBOUNCE_SECONDS + 0.15)
        with handler._lock:
            assert path not in handler._pending_events

    def test_thread_safety_concurrent_paths(self):
        """Concurrent events from multiple threads all produce exactly 1 callback each."""
        handler, calls = make_handler()
        paths = [f"/tmp/thread_{i}.txt" for i in range(20)]

        def fire(p):
            for _ in range(5):
                _simulate_event(handler, p)
                time.sleep(0.01)

        threads = [threading.Thread(target=fire, args=(p,)) for p in paths]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        time.sleep(DEBOUNCE_SECONDS + 0.2)
        assert sorted(calls) == sorted(paths)


# ---------------------------------------------------------------------------
# RealtimeMonitor integration tests (no real filesystem watching needed)
# ---------------------------------------------------------------------------

class TestRealtimeMonitor:

    def test_add_callback_registered(self):
        """add_callback stores the callable."""
        monitor = RealtimeMonitor()
        cb = lambda p: None
        monitor.add_callback(cb)
        assert cb in monitor._callbacks

    def test_add_callback_no_duplicates(self):
        """Same callback added twice is stored only once."""
        monitor = RealtimeMonitor()
        cb = lambda p: None
        monitor.add_callback(cb)
        monitor.add_callback(cb)
        assert monitor._callbacks.count(cb) == 1

    def test_dispatch_calls_all_callbacks(self):
        """_dispatch forwards the path to every registered callback."""
        monitor = RealtimeMonitor()
        results = []
        monitor.add_callback(lambda p: results.append(("a", p)))
        monitor.add_callback(lambda p: results.append(("b", p)))
        monitor._dispatch("/tmp/test.txt")
        assert ("a", "/tmp/test.txt") in results
        assert ("b", "/tmp/test.txt") in results

    def test_dispatch_exception_does_not_stop_others(self):
        """If one callback raises, remaining callbacks still execute."""
        monitor = RealtimeMonitor()
        good_calls = []
        monitor.add_callback(lambda p: (_ for _ in ()).throw(RuntimeError("boom")))
        monitor.add_callback(lambda p: good_calls.append(p))
        monitor._dispatch("/tmp/test.txt")
        assert "/tmp/test.txt" in good_calls

    def test_debounce_integration_via_dispatch(self):
        """
        Simulate the full debounce → dispatch chain without starting watchdog.
        n rapid _debounce calls on the same path → exactly 1 _dispatch call.
        """
        monitor = RealtimeMonitor()
        monitor._handler.start_worker()
        _handlers.append(monitor._handler)
        calls = []
        monitor.add_callback(lambda p: calls.append(p))

        path = "/tmp/integration.txt"
        for _ in range(8):
            monitor._handler._debounce(path)
            time.sleep(0.02)

        time.sleep(DEBOUNCE_SECONDS + 0.15)
        assert len(calls) == 1
        assert calls[0] == path

    def test_debounce_integration_distinct_paths(self):
        """
        n distinct paths through the handler → exactly n _dispatch calls.
        """
        monitor = RealtimeMonitor()
        monitor._handler.start_worker()
        _handlers.append(monitor._handler)
        calls = []
        monitor.add_callback(lambda p: calls.append(p))

        paths = [f"/tmp/int_{i}.txt" for i in range(4)]
        for p in paths:
            monitor._handler._debounce(p)

        time.sleep(DEBOUNCE_SECONDS + 0.15)
        assert sorted(calls) == sorted(paths)
