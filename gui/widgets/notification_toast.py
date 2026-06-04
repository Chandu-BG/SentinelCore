from __future__ import annotations

import os
from typing import List, Dict, Any
from PyQt6.QtCore import QEasingCurve, QPropertyAnimation, QPoint, Qt, QTimer, pyqtSlot, QRect
from PyQt6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget, QGraphicsDropShadowEffect, QHBoxLayout, QPushButton
from PyQt6.QtGui import QColor, QGuiApplication

# Global registry of active toast windows
_ACTIVE_TOASTS: List[ToastCardWidget] = []


class ToastCardWidget(QWidget):
    """An individual frameless notification window that slides and fades seamlessly."""

    def __init__(self, alert: dict, parent=None):
        super().__init__(parent, Qt.WindowType.ToolTip | Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating, True)
        self.setFixedWidth(360)
        self.setWindowOpacity(0.0)

        sev = str(alert.get("severity", "info")).lower()
        msg = str(alert.get("message", ""))

        colors = {
            "critical": "#ef4444",
            "high": "#f87171",
            "warning": "#f59e0b",
            "medium": "#fbbf24",
            "danger": "#ef4444",
            "success": "#10b981",
            "info": "#3b82f6",
        }
        color = colors.get(sev, "#3b82f6")

        # Visual Card Container
        card = QFrame(self)
        card.setObjectName("toastCard")
        card.setStyleSheet(f"""
            QFrame#toastCard {{
                background-color: rgba(15, 23, 42, 0.95);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-left: 4px solid {color};
                border-radius: 12px;
            }}
        """)
        
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.addWidget(card)

        cl = QVBoxLayout(card)
        cl.setContentsMargins(15, 12, 15, 15)
        cl.setSpacing(5)

        title_bar = QHBoxLayout()
        title_map = {
            "critical": "󰈸 CRITICAL THREAT",
            "high": "󰈸 HIGH RISK",
            "warning": " SECURITY WARNING",
            "danger": "󰈸 DANGER DETECTED",
            "success": "󰄬 SUCCESS",
            "info": "󰋼 SYSTEM NOTIFICATION"
        }
        title_text = title_map.get(sev, "󰋼 NOTIFICATION")
        
        title = QLabel(title_text)
        title.setStyleSheet(f"color: {color}; font-weight: 900; font-size: 11px; letter-spacing: 1.5px;")
        title_bar.addWidget(title)
        title_bar.addStretch()

        close_btn = QPushButton("✕")
        close_btn.setFixedSize(16, 16)
        close_btn.setStyleSheet("""
            QPushButton { 
                color: #64748b; 
                border: none; 
                font-size: 10px; 
                background: transparent;
            } 
            QPushButton:hover { color: white; }
        """)
        close_btn.clicked.connect(self.close_smooth)
        title_bar.addWidget(close_btn)

        cl.addLayout(title_bar)

        content = QLabel(msg)
        content.setWordWrap(True)
        content.setStyleSheet("color: #e2e8f0; font-size: 13px; font-weight: 500; line-height: 1.4;")
        cl.addWidget(content)

        # Drop shadow for a premium elevated look
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(20)
        shadow.setXOffset(0)
        shadow.setYOffset(8)
        shadow.setColor(QColor(0, 0, 0, 150))
        card.setGraphicsEffect(shadow)

        self.adjustSize()

        # Life cycle timers
        self._dismiss_timer = QTimer(self)
        self._dismiss_timer.setSingleShot(True)
        self._dismiss_timer.timeout.connect(self.close_smooth)
        self._dismiss_timer.start(8000)

        self._pos_anim = None
        self._opacity_anim = None
        self._is_closing = False

    def start_entry_animation(self, target_pos: QPoint) -> None:
        """Lightweight GPU-accelerated entry transition combining opacity fade + slide upward."""
        self.move(target_pos.x(), target_pos.y() + 30)  # Start 30px below
        self.show()

        # Slide Upwards Animation
        self._pos_anim = QPropertyAnimation(self, b"pos")
        self._pos_anim.setDuration(400)
        self._pos_anim.setStartValue(QPoint(target_pos.x(), target_pos.y() + 30))
        self._pos_anim.setEndValue(target_pos)
        self._pos_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._pos_anim.start()

        # Opacity Fade-In Animation
        self._opacity_anim = QPropertyAnimation(self, b"windowOpacity")
        self._opacity_anim.setDuration(350)
        self._opacity_anim.setStartValue(0.0)
        self._opacity_anim.setEndValue(1.0)
        self._opacity_anim.start()

    def update_position_smooth(self, target_pos: QPoint) -> None:
        """Gently transition the toast position when preceding alerts exit."""
        if self._is_closing:
            return
        if self._pos_anim and self._pos_anim.state() == QPropertyAnimation.State.Running:
            self._pos_anim.stop()
            
        self._pos_anim = QPropertyAnimation(self, b"pos")
        self._pos_anim.setDuration(300)
        self._pos_anim.setStartValue(self.pos())
        self._pos_anim.setEndValue(target_pos)
        self._pos_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._pos_anim.start()

    def close_smooth(self) -> None:
        """Silk smooth fade-out and destruction transition."""
        if self._is_closing:
            return
        self._is_closing = True
        
        # Stop entry timers
        self._dismiss_timer.stop()
        if self._pos_anim and self._pos_anim.state() == QPropertyAnimation.State.Running:
            self._pos_anim.stop()

        # Opacity Fade-Out Animation
        self._opacity_anim = QPropertyAnimation(self, b"windowOpacity")
        self._opacity_anim.setDuration(300)
        self._opacity_anim.setStartValue(self.windowOpacity())
        self._opacity_anim.setEndValue(0.0)
        
        # Slide Downward on exit
        self._pos_anim = QPropertyAnimation(self, b"pos")
        self._pos_anim.setDuration(300)
        self._pos_anim.setStartValue(self.pos())
        self._pos_anim.setEndValue(QPoint(self.x(), self.y() + 20))
        self._pos_anim.setEasingCurve(QEasingCurve.Type.InCubic)

        self._opacity_anim.finished.connect(self._finalize_close)
        self._opacity_anim.start()
        self._pos_anim.start()

    def _finalize_close(self) -> None:
        if self in _ACTIVE_TOASTS:
            _ACTIVE_TOASTS.remove(self)
        self.hide()
        self.deleteLater()
        _rearrange_toasts()


def _rearrange_toasts() -> None:
    """Animate all remaining notifications cleanly to their new stacked coordinates."""
    screen = QGuiApplication.primaryScreen()
    if not screen: 
        return
        
    avail = screen.availableGeometry()
    spacing = 12
    margin_bottom = 20
    margin_right = 20
    
    current_y = avail.y() + avail.height() - margin_bottom
    
    for toast in list(_ACTIVE_TOASTS):
        current_y -= toast.height()
        target_pos = QPoint(avail.x() + avail.width() - toast.width() - margin_right, current_y)
        toast.update_position_smooth(target_pos)
        current_y -= spacing


class NotificationToast(QWidget):
    """A lightweight async manager interface that queues and spawns ToastCardWidgets safely."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.hide()

    @pyqtSlot(dict)
    def show_alert(self, alert: dict) -> None:
        """Dynamically queue and show new alerts without blocking the render thread."""
        def spawn():
            try:
                screen = QGuiApplication.primaryScreen()
                if not screen: 
                    return
                
                avail = screen.availableGeometry()
                spacing = 12
                margin_bottom = 20
                margin_right = 20

                # Instantiate new Toast Window
                toast = ToastCardWidget(alert)
                _ACTIVE_TOASTS.insert(0, toast)  # Prepend newest

                # Position the new toast, sliding existing ones up
                current_y = avail.y() + avail.height() - margin_bottom
                
                for idx, t in enumerate(_ACTIVE_TOASTS):
                    current_y -= t.height()
                    target_pos = QPoint(avail.x() + avail.width() - t.width() - margin_right, current_y)
                    
                    if idx == 0:
                        # Newest slides and fades in
                        t.start_entry_animation(target_pos)
                    else:
                        # Rest shift up smoothly
                        t.update_position_smooth(target_pos)
                        
                    current_y -= spacing
            except Exception:
                pass
                
        # Non-blocking dispatch to event loop
        QTimer.singleShot(0, spawn)
