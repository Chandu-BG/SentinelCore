from __future__ import annotations

import logging
import os
import json
from datetime import datetime
from typing import Dict, Optional

from PyQt6.QtCore import Qt, pyqtSlot, QTimer, pyqtSignal

logger = logging.getLogger(__name__)
from PyQt6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QPushButton,
    QVBoxLayout,
    QWidget,
    QScrollArea,
    QGraphicsDropShadowEffect,
    QLineEdit,
    QTextBrowser,
)
from PyQt6.QtGui import QColor, QFont

from core.telemetry_manager import get_telemetry


class DashboardCard(QFrame):
    def __init__(self, title: str, value: str, icon: str = "", color: str = "#2563EB", parent=None):
        super().__init__(parent)
        self.setObjectName("dashboardCard")
        self._color = color

        # Premium styling for the card
        self.setStyleSheet(f"""
            QFrame#dashboardCard {{
                background: rgba(13, 20, 38, 0.6);
                border-radius: 16px;
                border: 1px solid rgba(255, 255, 255, 0.05);
            }}
            QFrame#dashboardCard:hover {{
                border: 1px solid {color}40;
                background: rgba(13, 20, 38, 0.8);
            }}
        """)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(8)

        header_lay = QHBoxLayout()
        self._title = QLabel(title)
        self._title.setStyleSheet("color: #94a3b8; font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: 1.2px;")
        header_lay.addWidget(self._title, 1)

        if icon:
            self._icon_lbl = QLabel(icon)
            self._icon_lbl.setStyleSheet(f"font-size: 18px; color: {color};")
            header_lay.addWidget(self._icon_lbl)
        lay.addLayout(header_lay)

        self._value = QLabel(value)
        self._value.setStyleSheet(f"font-size: 28px; font-weight: 900; color: #f8fafc;")
        lay.addWidget(self._value)

        self._footer = QLabel("Stable")
        self._footer.setStyleSheet("color: #475569; font-size: 11px; font-weight: 600;")
        lay.addWidget(self._footer)

    def set_value(self, val: str):
        self._value.setText(val)

    def set_footer(self, text: str):
        self._footer.setText(text)


class DashboardView(QWidget):
    ai_message_sent = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._chat_history = (
            "<span style='color: #3b82f6;'><b>NovaSentinel Analyst:</b></span> "
            "Online and ready. Ask me anything about quarantined items, process threads, URL security, or threat remediations.<br>"
        )
        self._is_ai_responding = False
        self._current_ai_response = ""
        # AI token batch buffer — accumulate tokens and flush at 20 FPS max
        self._ai_token_buffer = ""
        self._ai_flush_timer = None  # created lazily on first token

        # Telemetry feed dedup: skip rebuild if content hash unchanged
        self._feed_last_hash: int = -1

        # Load persisted scan info
        self._persisted_scan_path = os.path.join("config", "last_scan.json")

        main_v_lay = QVBoxLayout(self)
        main_v_lay.setContentsMargins(0, 0, 0, 0)
        main_v_lay.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("background: transparent; border: none;")

        container = QWidget()
        container.setObjectName("dashboardScrollContainer")
        container.setStyleSheet("#dashboardScrollContainer { background: #0b1220; }")
        main_lay = QVBoxLayout(container)
        main_lay.setContentsMargins(30, 30, 30, 30)
        main_lay.setSpacing(25)
        scroll.setWidget(container)
        main_v_lay.addWidget(scroll)

        # ── Hero Section ──
        self._hero_card = QFrame()
        self._hero_card.setObjectName("heroCard")
        self._hero_card.setFixedHeight(160)
        self._hero_card.setStyleSheet("""
            QFrame#heroCard {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #1e40af, stop:1 #1e3a8a);
                border-radius: 24px;
                border: 1px solid rgba(255, 255, 255, 0.1);
            }
        """)

        hero_shadow = QGraphicsDropShadowEffect()
        hero_shadow.setBlurRadius(15)  # PERF: 30→15 halves GPU compositing cost
        hero_shadow.setYOffset(4)
        hero_shadow.setColor(QColor(0, 0, 0, 60))
        self._hero_card.setGraphicsEffect(hero_shadow)

        hero_lay = QHBoxLayout(self._hero_card)
        hero_lay.setContentsMargins(40, 0, 40, 0)
        hero_lay.setSpacing(25)

        self._hero_icon = QLabel("🛡️")
        self._hero_icon.setStyleSheet("font-size: 64px; background: transparent;")
        hero_lay.addWidget(self._hero_icon)

        hero_text_lay = QVBoxLayout()
        hero_text_lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hero_text_lay.setSpacing(3)

        self._hero_title = QLabel("System Fully Protected")
        self._hero_title.setStyleSheet("font-size: 28px; font-weight: 800; color: white; background: transparent;")
        hero_text_lay.addWidget(self._hero_title)

        self._hero_subtitle = QLabel("AI-driven neural guard is active. Monitoring for threats across all subsystems.")
        self._hero_subtitle.setStyleSheet("color: rgba(255,255,255,0.7); font-size: 13px; background: transparent;")
        hero_text_lay.addWidget(self._hero_subtitle)
        hero_lay.addLayout(hero_text_lay, 1)

        self._quick_scan_btn = QPushButton("Quick System Scan")
        self._quick_scan_btn.setFixedSize(170, 46)
        self._quick_scan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._quick_scan_btn.setStyleSheet("""
            QPushButton {
                background: #ffffff; 
                color: #1e40af; 
                font-weight: 900; 
                border-radius: 23px; 
                font-size: 13px;
                border: none;
            }
            QPushButton:hover { background: #f1f5f9; }
        """)
        hero_lay.addWidget(self._quick_scan_btn)

        main_lay.addWidget(self._hero_card)

        # ── Stats Grid ──
        stats_grid = QGridLayout()
        stats_grid.setSpacing(20)

        self._cpu_card = DashboardCard("CPU LOAD", "0.0%", "⚡", "#3b82f6")
        self._ram_card = DashboardCard("MEMORY", "0.0%", "🧠", "#8b5cf6")
        self._disk_card = DashboardCard("STORAGE I/O", "0.0%", "💾", "#eab308")
        self._net_card = DashboardCard("NETWORK", "0.0 Mbps", "🌐", "#10b981")

        self._threat_card = DashboardCard("THREATS FOUND", "0", "🚨", "#ef4444")
        self._last_scan_card = DashboardCard("LAST SCAN", "Never", "🔍", "#6366f1")
        self._protection_card = DashboardCard("SHIELD STATUS", "Active", "🛡️", "#10b981")
        self._health_card = DashboardCard("SYSTEM INTEGRITY", "100%", "🩺", "#06b6d4")

        stats_grid.addWidget(self._cpu_card, 0, 0)
        stats_grid.addWidget(self._ram_card, 0, 1)
        stats_grid.addWidget(self._disk_card, 0, 2)
        stats_grid.addWidget(self._net_card, 0, 3)

        stats_grid.addWidget(self._threat_card, 1, 0)
        stats_grid.addWidget(self._last_scan_card, 1, 1)
        stats_grid.addWidget(self._protection_card, 1, 2)
        stats_grid.addWidget(self._health_card, 1, 3)

        main_lay.addLayout(stats_grid)

        # ── Lower Row: Telemetry Feed (Left) + Interactive AI Chatbot (Right) ──
        lower_row = QHBoxLayout()
        lower_row.setSpacing(20)

        # Security Telemetry Feed Panel
        timeline_container = QFrame()
        timeline_container.setObjectName("dashboardCard")
        timeline_container.setFixedHeight(350)
        timeline_container.setStyleSheet("QFrame#dashboardCard { background: rgba(13, 20, 38, 0.6); border-radius: 16px; border: 1px solid rgba(255, 255, 255, 0.05); }")
        timeline_lay = QVBoxLayout(timeline_container)
        timeline_lay.setContentsMargins(20, 20, 20, 20)

        timeline_header = QHBoxLayout()
        timeline_title = QLabel("SECURITY TELEMETRY FEED")
        timeline_title.setStyleSheet("font-size: 11px; font-weight: 800; color: #f8fafc; letter-spacing: 1px;")
        timeline_header.addWidget(timeline_title, 1)

        self._ai_btn = QPushButton("✨ Focus AI")
        self._ai_btn.setFixedSize(100, 30)
        self._ai_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._ai_btn.setStyleSheet("""
            QPushButton {
                background: rgba(59, 130, 246, 0.15); 
                color: #3b82f6; 
                border: 1px solid rgba(59, 130, 246, 0.3); 
                border-radius: 15px; 
                font-size: 10px; 
                font-weight: bold;
            }
            QPushButton:hover { background: rgba(59, 130, 246, 0.25); }
        """)
        timeline_header.addWidget(self._ai_btn)
        timeline_lay.addLayout(timeline_header)

        self._feed = QListWidget()
        self._feed.setFrameShape(QFrame.Shape.NoFrame)
        self._feed.setStyleSheet("""
            QListWidget { background: transparent; border: none; font-size: 12px; color: #94a3b8; outline: none; }
            QListWidget::item { padding: 8px; border-bottom: 1px solid rgba(255,255,255,0.02); }
        """)
        self._feed.setAlternatingRowColors(True)
        timeline_lay.addWidget(self._feed)
        lower_row.addWidget(timeline_container, 4)

        # Interactive AI Assistant Card
        ai_info_container = QFrame()
        ai_info_container.setObjectName("dashboardCard")
        ai_info_container.setFixedHeight(350)
        ai_info_container.setStyleSheet("QFrame#dashboardCard { background: rgba(13, 20, 38, 0.6); border-radius: 16px; border: 1px solid rgba(255, 255, 255, 0.05); }")
        ai_info_lay = QVBoxLayout(ai_info_container)
        ai_info_lay.setContentsMargins(20, 20, 20, 20)
        ai_info_lay.setSpacing(10)

        ai_info_title = QLabel("✨ INTERACTIVE NOVASENTINEL SOC ANALYST")
        ai_info_title.setStyleSheet("font-size: 11px; font-weight: 800; color: #3b82f6; letter-spacing: 1px;")
        ai_info_lay.addWidget(ai_info_title)

        # Chat history scroll area
        self._chat_scroll = QScrollArea()
        self._chat_scroll.setWidgetResizable(True)
        self._chat_scroll.setStyleSheet("background: #020617; border-radius: 8px; border: 1px solid rgba(255,255,255,0.03);")
        
        self._chat_output = QTextBrowser()
        self._chat_output.setOpenExternalLinks(True)
        self._chat_output.setStyleSheet("QTextBrowser { background: #020617; color: #94a3b8; font-size: 12px; border: none; padding: 5px; line-height: 1.4; }")
        self._chat_output.setHtml(self._chat_history)
        self._chat_scroll.setWidget(self._chat_output)
        ai_info_lay.addWidget(self._chat_scroll, 1)

        # Input field + send button
        inp_lay = QHBoxLayout()
        inp_lay.setSpacing(8)

        self._chat_input = QLineEdit()
        self._chat_input.setPlaceholderText("Ask NovaSentinel AI...")
        self._chat_input.setStyleSheet("""
            QLineEdit {
                background: #090d16;
                color: white;
                border: 1px solid #1f2a40;
                border-radius: 16px;
                padding: 6px 15px;
                font-size: 12px;
            }
            QLineEdit:focus {
                border: 1px solid #3b82f6;
            }
        """)
        self._chat_input.returnPressed.connect(self._send_chat)
        inp_lay.addWidget(self._chat_input, 1)

        self._chat_send = QPushButton("Send")
        self._chat_send.setFixedSize(70, 32)
        self._chat_send.setCursor(Qt.CursorShape.PointingHandCursor)
        self._chat_send.setStyleSheet("""
            QPushButton { background: #2563eb; color: white; border-radius: 16px; font-weight: bold; font-size: 11px; border: none; }
            QPushButton:hover { background: #1d4ed8; }
        """)
        self._chat_send.clicked.connect(self._send_chat)
        inp_lay.addWidget(self._chat_send)
        ai_info_lay.addLayout(inp_lay)

        lower_row.addWidget(ai_info_container, 3)
        main_lay.addLayout(lower_row)

        self._threat_count = 0
        self._module_status_map = {}
        
        # Connect internal button to focus input
        self._ai_btn.clicked.connect(self._chat_input.setFocus)

        # Populate cache
        self._load_persisted_scan()

    def _load_persisted_scan(self):
        try:
            if os.path.exists(self._persisted_scan_path):
                with open(self._persisted_scan_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                info = data.get("last_scan", "Never")
                self._last_scan_card.set_value(info)
        except Exception as e:
            logger.debug(f"Failed to load persisted last scan: {e}")

    def _send_chat(self) -> None:
        text = self._chat_input.text().strip()
        if not text or self._is_ai_responding:
            return

        self._chat_input.clear()
        self._chat_history += f"<br><b>You:</b> <span style='color: #f8fafc;'>{text}</span><br>"
        self._chat_output.setHtml(self._chat_history)
        
        # Set text to bottom
        scrollbar = self._chat_scroll.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

        # Emit the message back to MainWindow which routes it to SecurityCore AI
        self._chat_input.setEnabled(False)
        self._chat_send.setEnabled(False)
        self.ai_message_sent.emit(text)

    # Slots for AI Token Streaming
    def append_ai_token(self, token: str):
        """Buffer tokens and flush to DOM at max 20 FPS to eliminate per-token setHtml stutter."""
        if not self._is_ai_responding:
            self._is_ai_responding = True
            self._current_ai_response = ""
            self._ai_token_buffer = ""
            self._chat_history += "<br><span style='color: #3b82f6;'><b>NovaSentinel Analyst:</b></span> "
            # Start flush timer (50ms = 20 FPS max DOM updates)
            if self._ai_flush_timer is None:
                from PyQt6.QtCore import QTimer as _QT
                self._ai_flush_timer = _QT(self)
                self._ai_flush_timer.setInterval(50)
                self._ai_flush_timer.timeout.connect(self._flush_ai_tokens)
            self._ai_flush_timer.start()

        self._ai_token_buffer += token
        self._current_ai_response += token

    def _flush_ai_tokens(self) -> None:
        """Flush buffered tokens to the DOM — called by timer at 20 FPS max."""
        if not self._ai_token_buffer:
            return
        self._ai_token_buffer = ""
        formatted = self._current_ai_response.replace("\n", "<br>")
        self._chat_output.setHtml(self._chat_history + formatted)
        scrollbar = self._chat_scroll.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def on_ai_response_complete(self, full_response: str):
        # Stop flush timer; do one final DOM write with the complete response
        if self._ai_flush_timer is not None:
            self._ai_flush_timer.stop()
        self._is_ai_responding = False
        self._ai_token_buffer = ""
        formatted = full_response.replace("\n", "<br>")
        self._chat_history += formatted + "<br>"
        self._chat_output.setHtml(self._chat_history)

        self._chat_input.setEnabled(True)
        self._chat_send.setEnabled(True)
        self._chat_input.setFocus()

        # Auto-scroll to bottom
        scrollbar = self._chat_scroll.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    @pyqtSlot(float, float, float, float, int)
    def update_metrics(self, cpu: float, ram: float, disk: float, net: float, threats: int):
        self._cpu_card.set_value(f"{cpu:.1f}%")
        self._ram_card.set_value(f"{ram:.1f}%")
        self._disk_card.set_value(f"{disk:.1f}%")
        self._net_card.set_value(f"{net:.2f} Mbps")

        self._threat_count = threats
        self._threat_card.set_value(str(threats))

        health = max(0, 100 - (threats * 10))
        self._health_card.set_value(f"{health}%")
        if health < 80:
            self._health_card._value.setStyleSheet("font-size: 28px; font-weight: 900; color: #ef4444;")
        else:
            self._health_card._value.setStyleSheet("font-size: 28px; font-weight: 900; color: #f8fafc;")

        # Populate real-time Security Telemetry Feed
        self._refresh_telemetry_feed()

    def _refresh_telemetry_feed(self) -> None:
        """Rebuild the feed ONLY when content has actually changed (hash guard)."""
        if not self._feed.isVisible():
            return
        try:
            telemetry = get_telemetry()
            logs = telemetry.get_recent_alerts(20)

            # Fast content-hash check: skip full rebuild if nothing changed
            content_hash = hash(tuple(
                (l.get("timestamp", ""), l.get("message", "")) for l in logs
            ))
            if content_hash == self._feed_last_hash:
                return
            self._feed_last_hash = content_hash

            # --- Content changed: do a single batched rebuild ---
            _EMOJI = {
                "SCAN": "🔍", "PHISH": "🌐", "SAND": "🧪",
                "QUAR": "📦", "AI": "🧠", "THREAT": "🚨",
            }
            items_text = []
            items_color = []
            for l in reversed(logs):
                msg = l.get("message", "")
                mod = l.get("module", "").upper()
                sev = l.get("severity", "info").lower()
                ts  = l.get("timestamp", "")
                try:
                    time_part = ts.split(" ")[1][:5]
                except Exception:
                    time_part = ts
                emoji = next((v for k, v in _EMOJI.items() if k in mod), "🛡️")
                items_text.append(f"{emoji} [{time_part}] [{mod}] {msg}")
                if sev in ("critical", "high"):
                    items_color.append(QColor("#ff4d4d"))
                elif sev == "warning":
                    items_color.append(QColor("#fbbf24"))
                elif sev == "alert":
                    items_color.append(QColor("#f97316"))
                else:
                    items_color.append(QColor("#cbd5e1"))

            self._feed.setUpdatesEnabled(False)
            self._feed.clear()
            for text, color in zip(items_text, items_color):
                from PyQt6.QtWidgets import QListWidgetItem
                item = QListWidgetItem(text)
                item.setForeground(color)
                self._feed.addItem(item)
            self._feed.setUpdatesEnabled(True)

        except Exception as e:
            import logging as _log
            _log.getLogger(__name__).debug(f"Telemetry feed refresh error: {e}")

    def set_hero_status(self, status: str) -> None:
        if status == "protected":
            self._hero_card.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #1e40af, stop:1 #1e3a8a); border-radius: 24px; border: 1px solid rgba(255, 255, 255, 0.1);")
            self._hero_title.setText("System Fully Protected")
            self._hero_icon.setText("🛡️")
            self._protection_card.set_value("Active")
            self._protection_card._value.setStyleSheet("font-size: 28px; font-weight: 900; color: #10b981;")
        else:
            self._hero_card.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #991b1b, stop:1 #7f1d1d); border-radius: 24px; border: 1px solid rgba(255, 255, 255, 0.1);")
            self._hero_title.setText("Protection Disabled")
            self._hero_icon.setText("⚠️")
            self._protection_card.set_value("Disabled")
            self._protection_card._value.setStyleSheet("font-size: 28px; font-weight: 900; color: #ef4444;")

    def set_module_status(self, module: str, status: str) -> None:
        self._module_status_map[module] = status
        get_telemetry().push_log("PROTECTION", f"{module} module status is now {status}", "info")

    def on_threat(self, alert: dict) -> None:
        msg = str(alert.get("message", "Threat detected"))
        severity = str(alert.get("severity", "low")).lower()
        get_telemetry().push_log("THREAT", msg, severity)

        self._threat_count += 1
        self._threat_card.set_value(str(self._threat_count))
        health = max(0, 100 - (self._threat_count * 10))
        self._health_card.set_value(f"{health}%")
        if health < 80:
            self._health_card._value.setStyleSheet("font-size: 28px; font-weight: 900; color: #ef4444;")
        else:
            self._health_card._value.setStyleSheet("font-size: 28px; font-weight: 900; color: #f8fafc;")

    def update_scan_info(self, last_scan: str):
        self._last_scan_card.set_value(last_scan)
        try:
            os.makedirs(os.path.dirname(self._persisted_scan_path), exist_ok=True)
            with open(self._persisted_scan_path, "w", encoding="utf-8") as f:
                json.dump({"last_scan": last_scan}, f, indent=2)
        except Exception as e:
            logger.debug(f"Failed to persist last scan: {e}")
