"""
NovaSentinel Splash Screen — shown during SecurityCore initialization.

Features:
  - Animated progress bar with pulsing glow
  - Rotating status messages
  - Smooth fade-in on show, fade-out before close
  - Uses only PyQt6 (no Pillow required at runtime)
  - Runs on main thread; SecurityCore loads in worker thread
"""

from __future__ import annotations

import math
import os
import sys

from PyQt6.QtCore import (
    Qt, QTimer, QPropertyAnimation, QEasingCurve, pyqtSignal, QThread, pyqtSlot
)
from PyQt6.QtGui import (
    QColor, QFont, QLinearGradient, QPainter, QPen, QBrush, QPixmap, QIcon
)
from PyQt6.QtWidgets import QSplashScreen, QApplication, QWidget, QProgressBar, QVBoxLayout, QLabel

import logging
logger = logging.getLogger(__name__)


class NovaSentinelSplash(QSplashScreen):
    """
    Premium animated splash screen for NovaSentinel.

    Usage:
        splash = NovaSentinelSplash()
        splash.show()
        splash.set_status("Loading ML Models...")
        splash.set_progress(50)
        # ... when ready:
        splash.finish(main_window)
    """

    def __init__(self):
        # Create the pixmap for splash background
        pixmap = self._build_pixmap(800, 420)
        super().__init__(pixmap, Qt.WindowType.WindowStaysOnTopHint)
        self.setWindowFlags(
            Qt.WindowType.SplashScreen |
            Qt.WindowType.FramelessWindowHint |
            Qt.WindowType.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)

        self._progress = 0
        self._status_text = "Initializing NovaSentinel..."
        self._pulse_angle = 0.0

        # Pulse animation timer (60 FPS feel, 16ms)
        self._pulse_timer = QTimer(self)
        self._pulse_timer.setInterval(33)   # ~30 FPS for the animated bar
        self._pulse_timer.timeout.connect(self._tick_pulse)
        self._pulse_timer.start()

    # ── Static pixmap (background) ───────────────────────────────────────────

    def _build_pixmap(self, w: int, h: int) -> QPixmap:
        pixmap = QPixmap(w, h)
        pixmap.fill(QColor("#0F0A0A"))

        p = QPainter(pixmap)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Hex grid pattern
        self._paint_hex_grid(p, w, h)

        # Left glow zone
        glow = QLinearGradient(0, 0, w // 2, 0)
        glow.setColorAt(0.0, QColor(255, 62, 62, 20))
        glow.setColorAt(1.0, QColor(0, 0, 0, 0))
        p.fillRect(0, 0, w, h, glow)

        # Shield icon area (left side) — simple geometric
        self._paint_shield(p, 120, h // 2, 80)

        # Title text
        p.setPen(QColor("#F5E6E6"))
        font = QFont("Segoe UI", 38, QFont.Weight.Bold)
        p.setFont(font)
        p.drawText(230, 160, "NovaSentinel")

        # Subtitle
        p.setPen(QColor("#FF3E3E"))
        font2 = QFont("Segoe UI", 14, QFont.Weight.Normal)
        p.setFont(font2)
        p.drawText(232, 190, "AI-Powered Cybersecurity Platform")

        # Version badge
        p.setPen(QColor("#8B6060"))
        font3 = QFont("Segoe UI", 10)
        p.setFont(font3)
        p.drawText(232, 215, "v4.1  ·  Windows Edition")

        # Separator line
        pen = QPen(QColor(255, 62, 62, 60))
        pen.setWidth(1)
        p.setPen(pen)
        p.drawLine(210, 100, 210, 320)

        p.end()
        return pixmap

    def _paint_hex_grid(self, p: QPainter, w: int, h: int):
        pen = QPen(QColor(80, 15, 15, 22))
        pen.setWidth(1)
        p.setPen(pen)
        spacing = 40
        for row in range(-1, h // spacing + 2):
            for col in range(-1, w // spacing + 2):
                cx = col * spacing * 1.732
                cy = row * spacing * 2 + (col % 2) * spacing
                pts = []
                for i in range(6):
                    angle = math.radians(60 * i - 30)
                    pts.append((
                        int(cx + spacing * 0.9 * math.cos(angle)),
                        int(cy + spacing * 0.9 * math.sin(angle))
                    ))
                from PyQt6.QtCore import QPoint
                from PyQt6.QtGui import QPolygon
                poly = QPolygon([QPoint(x, y) for x, y in pts])
                p.drawPolygon(poly)

    def _paint_shield(self, p: QPainter, cx: int, cy: int, size: int):
        """Draw a simple shield on the painter."""
        s = size
        pts_outer = [
            (cx, cy - int(s * 0.85)),
            (cx + int(s * 0.75), cy - int(s * 0.4)),
            (cx + int(s * 0.75), cy + int(s * 0.25)),
            (cx, cy + int(s * 0.90)),
            (cx - int(s * 0.75), cy + int(s * 0.25)),
            (cx - int(s * 0.75), cy - int(s * 0.4)),
        ]
        from PyQt6.QtCore import QPoint
        from PyQt6.QtGui import QPolygon
        poly = QPolygon([QPoint(x, y) for x, y in pts_outer])
        p.setBrush(QBrush(QColor(30, 10, 10)))
        pen = QPen(QColor("#FF3E3E"))
        pen.setWidth(2)
        p.setPen(pen)
        p.drawPolygon(poly)

        # Eye
        er = int(s * 0.30)
        p.setBrush(QBrush(QColor("#FF3E3E")))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(cx - er // 2, cy - er // 2, er, er)

        # Pupil
        pr = int(er * 0.4)
        p.setBrush(QBrush(QColor(10, 5, 5)))
        p.drawEllipse(cx - pr // 2, cy - pr // 2, pr, pr)

    # ── Dynamic paint (progress bar, status, pulse) ───────────────────────────

    def drawContents(self, painter: QPainter):
        """Called every repaint — draws the animated progress bar and status."""
        w = self.width()
        h = self.height()

        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Status text
        painter.setPen(QColor("#8B6060"))
        font = QFont("Segoe UI", 10)
        painter.setFont(font)
        painter.drawText(40, h - 38, self._status_text)

        # Progress bar track
        bar_y = h - 20
        bar_x = 40
        bar_w = w - 80
        bar_h = 5

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(QColor(40, 20, 20)))
        painter.drawRoundedRect(bar_x, bar_y, bar_w, bar_h, 2, 2)

        # Filled portion
        fill_w = int(bar_w * self._progress / 100)
        if fill_w > 0:
            grad = QLinearGradient(bar_x, 0, bar_x + fill_w, 0)
            grad.setColorAt(0.0, QColor("#C81E1E"))
            grad.setColorAt(1.0, QColor("#FF3E3E"))
            painter.setBrush(QBrush(grad))
            painter.drawRoundedRect(bar_x, bar_y, fill_w, bar_h, 2, 2)

            # Pulsing glow at the leading edge
            pulse_alpha = int(80 + 60 * math.sin(self._pulse_angle))
            glow_color = QColor(255, 62, 62, pulse_alpha)
            glow_pen = QPen(glow_color)
            glow_pen.setWidth(3)
            painter.setPen(glow_pen)
            painter.drawLine(bar_x + fill_w, bar_y - 2, bar_x + fill_w, bar_y + bar_h + 2)

    def _tick_pulse(self):
        self._pulse_angle += 0.15
        if self._pulse_angle > math.pi * 2:
            self._pulse_angle = 0.0
        self.repaint()

    # ── Public API ────────────────────────────────────────────────────────────

    def set_status(self, text: str) -> None:
        self._status_text = text
        self.repaint()

    def set_progress(self, value: int) -> None:
        self._progress = max(0, min(100, value))
        self.repaint()

    def stop(self):
        self._pulse_timer.stop()
