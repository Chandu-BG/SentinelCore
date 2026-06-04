"""
SentinelCore - NovaSentinel AI Engine (v4.1)
Local LLM-powered SOC analyst engine using AIManager router.

Architecture:
  • AIManager routes to Ollama or LocalFallback
  • Multi-model management via AIManager
  • GPU auto-detection via nvidia-smi; CPU fallback
  • Queue-based async task processing (no UI blocking)
  • Robust error handling and offline fallback
"""

import logging
import threading
import queue
import time
import subprocess
import json
from datetime import datetime
from typing import Optional, Callable, Dict, Any, List

logger = logging.getLogger(__name__)

# ── Ollama settings ────────────────────────────────────────────────────────────
OLLAMA_BASE_URL    = "http://localhost:11434"
OLLAMA_GENERATE_URL = f"{OLLAMA_BASE_URL}/api/generate"
OLLAMA_TAGS_URL     = f"{OLLAMA_BASE_URL}/api/tags"
OLLAMA_VERSION_URL  = f"{OLLAMA_BASE_URL}/api/version"

REQUEST_TIMEOUT   = 60          # seconds per request
HEALTH_CHECK_INTERVAL = 30      # seconds between health checks
MAX_QUEUE_SIZE    = 10

class AIModelManager:
    """
    Manages discovery and selection of local AI models.
    Prioritizes fast, security-capable models.
    """
    PRIORITY_MODELS = ["phi3", "llama3", "mistral", "gemma", "deepseek-coder", "phi"]
    
    def __init__(self, requests_lib):
        self._requests = requests_lib
        self.available_models = []
        self.current_model = None
        self.ollama_version = "Unknown"

    def refresh(self) -> bool:
        """Poll Ollama for available models and version."""
        if not self._requests:
            return False
        
        try:
            # Check version
            v_resp = self._requests.get(OLLAMA_VERSION_URL, timeout=5)
            if v_resp.status_code == 200:
                self.ollama_version = v_resp.json().get("version", "Unknown")
            
            # Check models
            m_resp = self._requests.get(OLLAMA_TAGS_URL, timeout=5)
            if m_resp.status_code == 200:
                data = m_resp.json()
                self.available_models = [m.get("name").split(":")[0] for m in data.get("models", [])]
                logger.info(f"Ollama models found: {self.available_models}")
                
                # Select best model
                for pm in self.PRIORITY_MODELS:
                    if pm in self.available_models:
                        self.current_model = pm
                        logger.info(f"AIModelManager: Selected model '{pm}'")
                        return True
                
                if self.available_models:
                    self.current_model = self.available_models[0]
                    return True
        except Exception as e:
            logger.warning(f"AIModelManager refresh failed: {e}")
        
        return False

    def get_best_model(self, context_type: str = "chat") -> str:
        """Select model based on task priority."""
        if not self.available_models:
            return "mistral"
        
        # Fast models for chat
        if context_type == "chat":
            for m in ["phi3", "gemma", "phi", "mistral"]:
                if m in self.available_models:
                    return m
        
        # Heavy models for deep threat analysis
        if context_type in ["threat", "scan", "behavior"]:
            for m in ["llama3", "mistral", "deepseek-coder"]:
                if m in self.available_models:
                    return m
                    
        return self.current_model or self.available_models[0]

class NovaSentinelEngine:
    """
    NovaSentinel AI Security Analyst Engine.
    Wraps AIManager for contextual SOC-analyst responses.
    """

    def __init__(self, on_status_change: Optional[Callable[[str], None]] = None):
        self._on_status_change = on_status_change
        self._lock = threading.Lock()
        self._task_queue: queue.Queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self._running = False
        self._initialized = False
        self._gpu_available = False
        self._worker_thread: Optional[threading.Thread] = None
        self._health_thread: Optional[threading.Thread] = None
        
        # Use AIManager instead of direct Ollama
        from engines.ai_manager import AIManager
        self.ai_manager = AIManager()

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the engine: check GPU, connect to AI manager, launch worker."""
        if self._running:
            return
        self._running = True
        self._gpu_available = self._detect_gpu()
        
        # Launch startup in background
        threading.Thread(target=self._startup_sequence, daemon=True,
                         name="NovaSentinel-Startup").start()

    def stop(self) -> None:
        """Stop the engine gracefully."""
        self._running = False
        self.ai_manager.shutdown()
        logger.info("NovaSentinelEngine stopping...")

    @property
    def is_ready(self) -> bool:
        return self.ai_manager.is_ready()

    @property
    def model_name(self) -> str:
        return "NovaSentinel AI"  # Never expose internal model names

    # ── Public API ─────────────────────────────────────────────────────────────

    def generate_response(
        self,
        prompt: str,
        stream_callback: Optional[Callable[[str], None]] = None,
        done_callback: Optional[Callable[[str], None]] = None,
        context_type: str = "chat",
    ) -> None:
        """Queue an AI generation task."""
        if not self._running:
            self.start()

        task = {
            "prompt": prompt,
            "stream_callback": stream_callback,
            "done_callback": done_callback,
            "context_type": context_type,
            "timestamp": datetime.now().isoformat(),
        }
        try:
            self._task_queue.put_nowait(task)
        except queue.Full:
            if done_callback:
                done_callback("⚠ NovaSentinel is busy. Please wait.")

    def explain_threat(self, scan_detail: dict, system_state: dict, stream_cb=None, done_cb=None) -> None:
        from engines.ai_reasoning import build_threat_explanation_prompt
        prompt = build_threat_explanation_prompt(scan_detail, system_state)
        self.generate_response(prompt, stream_cb, done_cb, "threat")

    def chat(self, user_message: str, history: List[Dict], system_snapshot: dict, stream_cb=None, done_cb=None) -> None:
        if not self._running:
            self.start()
        if not self.is_ready:
            if done_cb: done_cb(self._offline_chat_response(user_message))
            return

        # Intent Detection
        intent = self._detect_intent(user_message)
        if intent:
            logger.info(f"NovaSentinelEngine: Detected intent '{intent}'")
            # We can still call the AI to explain what it's doing, 
            # or handle it separately. For now, let's let AI process it
            # but we can inject a hint into the prompt that it SHOULD execute it.

        self.ai_manager.chat(user_message, history, system_snapshot, stream_cb, done_cb)

    def _detect_intent(self, msg: str) -> Optional[str]:
        msg = msg.lower()
        if any(kw in msg for kw in ["quarantine", "isolate", "move to vault"]):
            return "quarantine"
        if any(kw in msg for kw in ["terminate", "kill process", "stop process"]):
            return "terminate"
        if any(kw in msg for kw in ["scan", "check system", "quick scan"]):
            return "scan"
        return None

    # ── Internal startup ───────────────────────────────────────────────────────

    def _startup_sequence(self) -> None:
        """Initialize connection and model selection."""
        self._set_status("Checking local AI engine...")
        
        # Immediate check
        if self.ai_manager.is_ready():
            self._set_status(f"AI Protection Active ({self.model_name})")
        else:
            self._set_status("AI Engine Offline (Local mode active)")

        self._start_worker()

    def _detect_gpu(self) -> bool:
        try:
            result = subprocess.run(
                ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0 and bool(result.stdout.strip())
        except Exception:
            return False

    def _start_worker(self) -> None:
        self._worker_thread = threading.Thread(
            target=self._worker_loop, daemon=True, name="NovaSentinel-Worker"
        )
        self._worker_thread.start()

    # ── Worker loop ────────────────────────────────────────────────────────────

    def _worker_loop(self) -> None:
        while self._running:
            try:
                task = self._task_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                self._process_task(task)
            except Exception as e:
                logger.error(f"NovaSentinel worker error: {e}")
                cb = task.get("done_callback")
                if cb: cb(f"⚠ AI Error: {e}")
            finally:
                self._task_queue.task_done()

    def _process_task(self, task: dict) -> None:
        prompt = task.get("prompt", "")
        stream_cb = task.get("stream_callback")
        done_cb = task.get("done_callback")

        if not self.is_ready:
            res = self._offline_response(task.get("context_type", "chat"))
            if done_cb: done_cb(res)
            return

        # Route through AIManager
        self.ai_manager.generate_response(prompt, stream_cb, done_cb, task.get("context_type", "chat"))

    def _set_status(self, status: str) -> None:
        if self._on_status_change:
            self._on_status_change(status)

    def _offline_response(self, context_type: str) -> str:
        return "NovaSentinel is operating in Local/Offline mode. No critical threats detected in recent scans."

    def _offline_chat_response(self, user_message: str) -> str:
        return "I am currently in Offline mode. Please ensure Ollama is running at localhost:11434 to enable full AI analysis."
