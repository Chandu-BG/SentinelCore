from __future__ import annotations

from typing import List, Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class Sidebar(QFrame):
    """220px navigation rail with module buttons and controls."""

    navigate = pyqtSignal(int)
    theme_changed = pyqtSignal(str)
    protection_toggled = pyqtSignal(bool)

    NAV_LABELS: List[str] = [
        "Dashboard", "Scan", "Phishing", "Performance", "Quarantine",
        "Apps", "Sandbox", "Logs", "Settings"
    ]
    NAV_ICONS: List[str] = [
        "📊", "🔍", "🎣", "📈", "🛡️", "📱", "🧪", "📋", "⚙️"
    ]

    def __init__(self, theme_names: List[str], parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("sidebar")
        self.setFixedWidth(240)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 20, 10, 20)
        layout.setSpacing(8)

        title_container = QWidget()
        title_lay = QHBoxLayout(title_container)
        title_icon = QLabel("✦")
        title_icon.setStyleSheet("font-size: 24px; color: #2f81f7;")
        title_lay.addWidget(title_icon)
        
        title = QLabel("NOVASENTINEL")
        title.setObjectName("sidebarTitle")
        title.setStyleSheet("font-size: 16px; font-weight: 900; letter-spacing: 1px; color: #f8fafc;")
        title_lay.addWidget(title)
        layout.addWidget(title_container)
        layout.addSpacing(20)

        self._nav_buttons: List[QPushButton] = []
        for idx, label in enumerate(self.NAV_LABELS):
            icon = self.NAV_ICONS[idx] if idx < len(self.NAV_ICONS) else "•"
            btn = QPushButton(f"{icon}  {label}")
            btn.setObjectName("navButton")
            btn.setProperty("active", "false")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _=False, i=idx: self._on_nav(i))
            layout.addWidget(btn)
            self._nav_buttons.append(btn)

        layout.addSpacing(30)
        
        # Protection Switch
        # ── TEMPORARILY HIDDEN ──────────────────────────────────────────────
        # To restore: comment out self._protection.hide() and uncomment
        #             layout.addWidget(self._protection)
        self._protection = QCheckBox("REAL-TIME PROTECTION")
        self._protection.setStyleSheet("padding: 10px; font-weight: 800; font-size: 10px; color: #94a3b8;")
        self._protection.setChecked(False)
        self._protection.toggled.connect(self.protection_toggled.emit)
        self._protection.hide()          # hides from UI — backend fully intact
        # layout.addWidget(self._protection)  # ← uncomment to restore button

        layout.addSpacing(10)
        theme_lbl = QLabel("  APPEARANCE")
        theme_lbl.setStyleSheet("color: #4b5563; font-size: 10px; font-weight: 800; letter-spacing: 0.5px;")
        layout.addWidget(theme_lbl)
        
        self._theme = QComboBox()
        self._theme.setStyleSheet("")
        for name in theme_names:
            self._theme.addItem(name)
        self._theme.currentTextChanged.connect(self.theme_changed.emit)
        layout.addWidget(self._theme)

        layout.addStretch(1)

        version = QLabel("v4.0.1 PRO ENTERPRISE")
        version.setStyleSheet("color: #1f2a40; font-size: 9px; font-weight: 900; margin-left: 15px;")
        layout.addWidget(version)

    def _on_nav(self, index: int) -> None:
        for i, b in enumerate(self._nav_buttons):
            b.setProperty("active", "true" if i == index else "false")
            b.style().unpolish(b)
            b.style().polish(b)
        self.navigate.emit(index)

    def set_active(self, index: int) -> None:
        for i, b in enumerate(self._nav_buttons):
            b.setProperty("active", "true" if i == index else "false")
            b.style().unpolish(b)
            b.style().polish(b)

    def set_protection_checked(self, on: bool) -> None:
        self._protection.blockSignals(True)
        self._protection.setChecked(on)
        self._protection.blockSignals(False)

    def set_theme_selection(self, name: str) -> None:
        idx = self._theme.findText(name)
        if idx >= 0:
            self._theme.blockSignals(True)
            self._theme.setCurrentIndex(idx)
            self._theme.blockSignals(False)
