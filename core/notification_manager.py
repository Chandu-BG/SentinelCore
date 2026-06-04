import logging
import threading
from typing import List, Dict, Callable
from datetime import datetime

logger = logging.getLogger(__name__)

class NotificationManager:
    """
    Centralized notification manager.
    Responsible for deduplicating alerts and preventing UI spam.
    Only allows REAL events to pass through to the GUI.
    """
    
    def __init__(self):
        self._lock = threading.Lock()
        self._recent_events: List[Dict] = []
        self._callbacks: List[Callable[[str, str, str], None]] = []
        # A dictionary mapping message content to last seen time to avoid duplicate spam
        self._seen_messages: Dict[str, float] = {}

    def add_callback(self, callback: Callable[[str, str, str], None]) -> None:
        """Add a callback to be triggered when a valid notification is fired."""
        with self._lock:
            if callback not in self._callbacks:
                self._callbacks.append(callback)

    def fire_alert(self, alert_type: str, severity: str, description: str) -> None:
        """
        Fires an alert if it is not a recent duplicate.
        """
        import time
        now = time.time()
        
        with self._lock:
            # Basic deduplication (5 seconds cooldown for exact same message)
            if description in self._seen_messages:
                if now - self._seen_messages[description] < 5.0:
                    return # Skip spam
            self._seen_messages[description] = now
            
            # Clean up old seen messages
            keys_to_delete = [k for k, v in self._seen_messages.items() if now - v > 60.0]
            for k in keys_to_delete:
                del self._seen_messages[k]
                
            event = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "type": alert_type,
                "severity": severity,
                "description": description
            }
            self._recent_events.append(event)
            if len(self._recent_events) > 100:
                self._recent_events = self._recent_events[-100:]
                
            for cb in self._callbacks:
                try:
                    cb(alert_type, severity, description)
                except Exception as e:
                    logger.debug(f"Notification callback error: {e}")

_instance = None

def get_notification_manager() -> NotificationManager:
    global _instance
    if _instance is None:
        _instance = NotificationManager()
    return _instance
