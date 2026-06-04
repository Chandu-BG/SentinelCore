"""AIManager — Multi-LLM router for NovaSentinel AI assistant."""

from __future__ import annotations

import logging
import threading
import time
from typing import Optional, Callable, Dict, Any

logger = logging.getLogger(__name__)

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore


class AIManager:
    """Routes AI requests to available backends with automatic failover."""

    DISPLAY_NAME = "NovaSentinel AI"

    def __init__(self):
        self._current_backend: Optional[Any] = None
        self._backends = {}
        self._health_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()

        # Initialize backends
        if requests is not None:
            from engines.ollama_backend import OllamaBackend
            self._backends["ollama"] = OllamaBackend()
        else:
            logger.warning("Requests not available; Ollama backend disabled.")

        from engines.local_fallback import LocalFallback
        self._backends["fallback"] = LocalFallback()

        # Start health monitoring
        self._start_health_monitor()

    def _start_health_monitor(self) -> None:
        """Start daemon thread to check backend health."""
        self._running = True
        self._health_thread = threading.Thread(
            target=self._health_loop, daemon=True, name="AIMgrHealth"
        )
        self._health_thread.start()

    def _health_loop(self) -> None:
        """Ping backends every 30 seconds."""
        # Check immediately once
        self._check_backends()
        
        while self._running:
            time.sleep(30)
            if not self._running:
                break
            self._check_backends()

    def _check_backends(self) -> None:
        """Update backend availability and select best one."""
        with self._lock:
            best_backend = None
            for name, backend in self._backends.items():
                if backend.is_available():
                    best_backend = backend
                    break  # Prefer Ollama over fallback

            if best_backend != self._current_backend:
                old_name = getattr(self._current_backend, "name", "none") if self._current_backend else "none"
                new_name = getattr(best_backend, "name", "none") if best_backend else "none"
                logger.info(f"AIManager switched from {old_name} to {new_name}")
                self._current_backend = best_backend

    def is_ready(self) -> bool:
        """Return True if any backend is available."""
        with self._lock:
            return self._current_backend is not None

    def generate_response(
        self,
        prompt: str,
        stream_callback: Optional[Callable[[str], None]] = None,
        done_callback: Optional[Callable[[str], None]] = None,
        context_type: str = "chat",
    ) -> None:
        """Route request to current backend."""
        with self._lock:
            backend = self._current_backend

        if backend is None:
            if done_callback:
                done_callback("NovaSentinel AI is currently unavailable. Please try again later.")
            return

        backend.generate_response(prompt, stream_callback, done_callback, context_type)

    def chat(
        self,
        user_message: str,
        history: list,
        system_snapshot: dict,
        stream_cb=None,
        done_cb=None,
    ) -> None:
        """Handle chat requests."""
        with self._lock:
            backend = self._current_backend

        if backend is None:
            if done_cb:
                done_cb("NovaSentinel AI is currently offline. System protection remains active.")
            return

        backend.chat(user_message, history, system_snapshot, stream_cb, done_cb)

    def shutdown(self) -> None:
        """Stop health monitoring."""
        self._running = False
        for backend in self._backends.values():
            if hasattr(backend, "shutdown"):
                backend.shutdown()
