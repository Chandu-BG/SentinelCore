"""OllamaBackend — Streaming interface to Ollama API."""

from __future__ import annotations

import json
import logging
import threading
from typing import Optional, Callable, Dict, Any

logger = logging.getLogger(__name__)

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore

OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_GENERATE_URL = f"{OLLAMA_BASE_URL}/api/generate"
OLLAMA_TAGS_URL = f"{OLLAMA_BASE_URL}/api/tags"
REQUEST_TIMEOUT = 60.0


class OllamaBackend:
    """Handles streaming requests to Ollama API."""

    name = "ollama"

    def __init__(self):
        self._requests = requests
        self._available = False
        self._model_manager = OllamaModelManager(self._requests)

    def is_available(self) -> bool:
        """Check if Ollama is responding and refresh models."""
        if self._requests is None:
            return False
        try:
            resp = self._requests.get(OLLAMA_TAGS_URL, timeout=2.0)
            if resp.status_code == 200:
                self._available = True
                self._model_manager.refresh()
            else:
                self._available = False
        except Exception:
            self._available = False
        return self._available

    def generate_response(
        self,
        prompt: str,
        stream_callback: Optional[Callable[[str], None]] = None,
        done_callback: Optional[Callable[[str], None]] = None,
        context_type: str = "chat",
    ) -> None:
        """Send streaming request to Ollama."""
        if not self.is_available():
            if done_callback:
                done_callback("Ollama is not available.")
            return

        model = self._model_manager.get_best_model(context_type)
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": bool(stream_callback),
            "options": {
                "temperature": 0.3 if context_type == "threat" else 0.7,
                "num_ctx": 2048 if context_type == "threat" else 4096,
                "num_predict": 300 if context_type == "threat" else 512,
            },
        }

        def worker():
            try:
                resp = self._requests.post(
                    OLLAMA_GENERATE_URL,
                    json=payload,
                    timeout=REQUEST_TIMEOUT,
                    stream=bool(stream_callback),
                )
                resp.raise_for_status()

                full_text = ""
                if stream_callback:
                    for line in resp.iter_lines():
                        if not line:
                            continue
                        data = json.loads(line.decode("utf-8"))
                        token = data.get("response", "")
                        full_text += token
                        if token:
                            stream_callback(token)
                        if data.get("done"):
                            break
                else:
                    full_text = resp.json().get("response", "")

                if done_callback:
                    done_callback(full_text)
            except Exception as exc:
                logger.warning("Ollama request failed: %s", exc)
                if done_callback:
                    done_callback("AI analysis temporarily unavailable.")

        threading.Thread(target=worker, daemon=True).start()

    def chat(
        self,
        user_message: str,
        history: list,
        system_snapshot: dict,
        stream_cb=None,
        done_cb=None,
    ) -> None:
        """Handle chat by building prompt and calling generate_response."""
        from engines.ai_reasoning import build_chat_prompt
        messages = build_chat_prompt(user_message, history, system_snapshot)
        flattened = ""
        for msg in messages:
            role = msg["role"].upper()
            content = msg["content"]
            flattened += f"[{role}]: {content}\n"
        flattened += "[ASSISTANT]:"
        self.generate_response(flattened, stream_cb, done_cb, "chat")

    def shutdown(self) -> None:
        pass


class OllamaModelManager:
    """Manages Ollama model discovery."""

    PRIORITY_MODELS = ["redsage", "phi3", "llama3", "mistral", "gemma", "deepseek-coder", "phi"]

    def __init__(self, requests_lib):
        self._requests = requests_lib
        self.available_models = []
        self.current_model = None

    def refresh(self) -> bool:
        if not self._requests:
            return False
        try:
            resp = self._requests.get(OLLAMA_TAGS_URL, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                self.available_models = [m.get("name").split(":")[0] for m in data.get("models", [])]
                for pm in self.PRIORITY_MODELS:
                    if pm in self.available_models:
                        self.current_model = pm
                        return True
                if self.available_models:
                    self.current_model = self.available_models[0]
                    return True
        except Exception:
            pass
        return False

    def get_best_model(self, context_type: str = "chat") -> str:
        if not self.available_models:
            return "redsage"
        if context_type == "chat":
            for m in ["redsage", "phi3", "gemma", "phi", "mistral"]:
                if m in self.available_models:
                    return m
        if context_type in ["threat", "scan", "behavior", "sandbox"]:
            for m in ["redsage", "llama3", "mistral", "phi3"]:
                if m in self.available_models:
                    return m
        return self.current_model or self.available_models[0]
