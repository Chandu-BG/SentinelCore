from __future__ import annotations

from typing import Callable, Dict, List

from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QHBoxLayout,
    QFrame,
    QWidget,
    QPushButton,
)
from PyQt6.QtGui import QFont


class SettingsView(QWidget):
    theme_picked = pyqtSignal(str)

    def __init__(self, theme_names: List[str], get_perms: Callable, set_perm: Callable, parent=None):
        super().__init__(parent)
        self._get_perms = get_perms
        self._set_perm = set_perm
        self._perm_checkboxes: Dict[str, QCheckBox] = {}

        # Outer scroll area so settings work on any screen size
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        outer.addWidget(scroll)

        container = QWidget()
        container.setObjectName("settingsContainer")
        container.setStyleSheet("#settingsContainer { background: #070b19; }")
        scroll.setWidget(container)

        lay = QVBoxLayout(container)
        lay.setContentsMargins(30, 30, 30, 30)
        lay.setSpacing(20)

        # ── Page Title ──
        title_row = QHBoxLayout()
        title = QLabel("Settings")
        title.setStyleSheet("font-size: 26px; font-weight: 800; color: #f8fafc;")
        subtitle = QLabel("Configure NovaSentinel to match your security workflow.")
        subtitle.setStyleSheet("color: #64748b; font-size: 13px; margin-top: 2px;")
        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title_col.addWidget(title)
        title_col.addWidget(subtitle)
        title_row.addLayout(title_col)
        title_row.addStretch()
        lay.addLayout(title_row)

        # ── Appearance ──
        appearance_box = self._make_group("🎨  Appearance & Personalization")
        appearance_lay = QFormLayout(appearance_box)
        appearance_lay.setSpacing(12)
        appearance_lay.addRow(self._row_label("UI Theme"), self._build_theme_picker(theme_names))
        lay.addWidget(appearance_box)

        # ── Protection Permissions ──
        permissions_box = self._make_group("🛡️  Protection Modules")
        permissions_layout = QVBoxLayout(permissions_box)
        permissions_layout.setSpacing(8)
        info = QLabel("Toggle protection modules on or off. Changes take effect immediately.")
        info.setStyleSheet("color: #64748b; font-size: 12px;")
        permissions_layout.addWidget(info)
        self._perm_container = QVBoxLayout()
        permissions_layout.addLayout(self._perm_container)
        refresh = QPushButton("↻  Reload Permissions")
        refresh.setFixedHeight(34)
        refresh.setFixedWidth(180)
        refresh.setCursor(Qt.CursorShape.PointingHandCursor)
        refresh.setStyleSheet("""
            QPushButton {
                background: #1e293b; color: #94a3b8;
                border: 1px solid #334155; border-radius: 17px;
                font-size: 11px; font-weight: bold;
            }
            QPushButton:hover { background: #334155; color: #f8fafc; }
        """)
        refresh.clicked.connect(self._load_permissions)
        permissions_layout.addWidget(refresh)
        lay.addWidget(permissions_box)

        # ── Notifications ──
        notify_box = self._make_group("🔔  Notifications & Alerts")
        notify_lay = QVBoxLayout(notify_box)
        notify_lay.setSpacing(10)
        self.toast_toggle = self._make_toggle("Enable on-screen threat notifications (toasts)")
        self.toast_toggle.setChecked(True)
        notify_lay.addWidget(self.toast_toggle)
        self.alert_toggle = self._make_toggle("Show module status messages in toasts")
        self.alert_toggle.setChecked(True)
        notify_lay.addWidget(self.alert_toggle)
        lay.addWidget(notify_box)

        # ── Keyboard Shortcuts ──
        kb_box = self._make_group("⌨️  Keyboard Shortcuts")
        kb_lay = QVBoxLayout(kb_box)
        kb_lay.setSpacing(6)
        shortcuts = [
            ("F1", "Dashboard"),
            ("F2", "Scan"),
            ("F3", "Phishing Intelligence"),
            ("F4", "Performance Monitor"),
            ("F5", "Quarantine Vault"),
            ("F6", "Application Audit"),
            ("F7", "Sandbox"),
            ("F8", "Event Logs"),
            ("F9", "Settings"),
        ]
        for key, desc in shortcuts:
            row = QHBoxLayout()
            key_badge = QLabel(key)
            key_badge.setFixedSize(38, 22)
            key_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            key_badge.setStyleSheet("""
                background: #1e293b;
                color: #38bdf8;
                border: 1px solid #334155;
                border-radius: 5px;
                font-size: 10px;
                font-weight: 800;
                font-family: 'Courier New', monospace;
            """)
            desc_lbl = QLabel(desc)
            desc_lbl.setStyleSheet("color: #94a3b8; font-size: 12px;")
            row.addWidget(key_badge)
            row.addWidget(desc_lbl)
            row.addStretch()
            kb_lay.addLayout(row)
        lay.addWidget(kb_box)

        # ── About NovaSentinel ──
        about_box = self._make_group("ℹ️  About NovaSentinel")
        about_lay = QVBoxLayout(about_box)
        about_lay.setSpacing(12)

        # Hero badge
        hero = QFrame()
        hero.setStyleSheet("""
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #0f172a, stop:1 #1e293b);
            border: 1px solid rgba(37,99,235,0.2);
            border-radius: 12px;
        """)
        hero_lay = QHBoxLayout(hero)
        hero_lay.setContentsMargins(20, 16, 20, 16)
        hero_lay.setSpacing(16)

        shield = QLabel("🛡️")
        shield.setStyleSheet("font-size: 40px; background: transparent;")
        hero_lay.addWidget(shield)

        text_col = QVBoxLayout()
        text_col.setSpacing(3)
        app_name = QLabel("NovaSentinel")
        app_name.setStyleSheet("font-size: 20px; font-weight: 900; color: #f8fafc; background: transparent;")
        text_col.addWidget(app_name)
        app_version = QLabel("Version 4.1  ·  Windows Edition  ·  PyQt6 Build")
        app_version.setStyleSheet("color: #64748b; font-size: 12px; background: transparent;")
        text_col.addWidget(app_version)
        app_desc = QLabel("AI-Powered Cybersecurity Platform — Real-time threat detection, phishing analysis,\nsandbox isolation, and intelligent process management.")
        app_desc.setWordWrap(True)
        app_desc.setStyleSheet("color: #94a3b8; font-size: 11px; background: transparent; line-height: 1.5;")
        text_col.addWidget(app_desc)
        hero_lay.addLayout(text_col, 1)
        about_lay.addWidget(hero)

        # Feature grid
        features = [
            ("🔍", "Real-Time Scanner", "Heuristic + ML + YARA multi-engine scanning"),
            ("🌐", "Phishing Intelligence", "Lexical + entropy + brand-spoofing detection"),
            ("🧪", "Sandbox Isolation", "Behavioral analysis in isolated container"),
            ("📦", "AES-256 Quarantine", "Encrypted threat vault with full restore"),
            ("⚡", "Performance Monitor", "Live process tree with Task Manager-style graphs"),
            ("✨", "NovaSentinel AI", "SOC analyst chatbot powered by local LLM"),
        ]
        grid_widget = QWidget()
        from PyQt6.QtWidgets import QGridLayout
        grid = QGridLayout(grid_widget)
        grid.setSpacing(10)
        for i, (icon, feat, desc) in enumerate(features):
            card = QFrame()
            card.setStyleSheet("background: rgba(30,41,59,0.4); border: 1px solid rgba(255,255,255,0.04); border-radius: 10px;")
            cl = QVBoxLayout(card)
            cl.setContentsMargins(12, 10, 12, 10)
            cl.setSpacing(3)
            hl = QHBoxLayout()
            ic = QLabel(icon)
            ic.setStyleSheet("font-size: 18px; background: transparent;")
            fn = QLabel(feat)
            fn.setStyleSheet("font-size: 12px; font-weight: 800; color: #e2e8f0; background: transparent;")
            hl.addWidget(ic)
            hl.addWidget(fn, 1)
            cl.addLayout(hl)
            fd = QLabel(desc)
            fd.setWordWrap(True)
            fd.setStyleSheet("font-size: 10px; color: #64748b; background: transparent;")
            cl.addWidget(fd)
            grid.addWidget(card, i // 2, i % 2)
        about_lay.addWidget(grid_widget)

        # Tech stack
        tech_lbl = QLabel("Built with: Python 3.11 · PyQt6 · pyqtgraph · scikit-learn · cryptography · psutil · watchdog · SQLite")
        tech_lbl.setStyleSheet("color: #334155; font-size: 10px;")
        tech_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_lay.addWidget(tech_lbl)
        lay.addWidget(about_box)

        lay.addStretch(1)
        self._load_permissions()

    def _make_group(self, title: str) -> QGroupBox:
        box = QGroupBox(title)
        box.setStyleSheet("""
            QGroupBox {
                font-size: 13px;
                font-weight: 800;
                color: #f8fafc;
                border: 1px solid rgba(255,255,255,0.06);
                border-radius: 14px;
                margin-top: 8px;
                padding: 16px;
                background: rgba(13, 20, 38, 0.5);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 8px;
                left: 12px;
                color: #94a3b8;
            }
        """)
        return box

    def _row_label(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet("color: #94a3b8; font-size: 12px; font-weight: bold;")
        return lbl

    def _make_toggle(self, text: str) -> QCheckBox:
        cb = QCheckBox(text)
        cb.setStyleSheet("""
            QCheckBox { color: #cbd5e1; font-size: 12px; spacing: 8px; }
            QCheckBox::indicator { width: 16px; height: 16px; border-radius: 4px; border: 1px solid #334155; background: #0f172a; }
            QCheckBox::indicator:checked { background: #2563eb; border-color: #2563eb; }
            QCheckBox::indicator:hover { border-color: #3b82f6; }
        """)
        return cb

    def _build_theme_picker(self, theme_names: List[str]) -> QComboBox:
        self._theme = QComboBox()
        self._theme.setFixedHeight(34)
        self._theme.setStyleSheet("""
            QComboBox {
                background: #1e293b; color: #f8fafc;
                border: 1px solid #334155; border-radius: 8px;
                padding: 0 12px; font-size: 12px;
            }
            QComboBox:hover { border-color: #3b82f6; }
            QComboBox::drop-down { border: none; width: 20px; }
        """)
        for n in theme_names:
            self._theme.addItem(n)
        self._theme.currentTextChanged.connect(self.theme_picked.emit)
        return self._theme

    def _load_permissions(self) -> None:
        for i in reversed(range(self._perm_container.count())):
            item = self._perm_container.takeAt(i)
            if item is not None and item.widget() is not None:
                item.widget().deleteLater()
        perms = self._get_perms() or {}
        for module, enabled in perms.items():
            checkbox = self._make_toggle(module.replace("_", " ").title())
            checkbox.setChecked(bool(enabled))
            checkbox.toggled.connect(lambda value, mod=module: self._set_perm(mod, value))
            self._perm_checkboxes[module] = checkbox
            self._perm_container.addWidget(checkbox)
