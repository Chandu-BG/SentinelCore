"""
ThemeManager — six QSS themes with palette token substitution and persistence.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QApplication

logger = logging.getLogger(__name__)

THEME_PALETTES: Dict[str, Dict[str, str]] = {
    "Cyber Blue": {
        "bg": "#0b1220",
        "surface": "#121a2b",
        "sidebar": "#0f1726",
        "accent": "#2f81f7",
        "text": "#f8fafc",
        "text_secondary": "#94a3b8",
        "danger": "#ff4d4d",
        "warning": "#fbbf24",
        "success": "#22c55e",
        "border": "#1f2a40",
    },
    "Emerald Dark": {
        "bg": "#0D1117",
        "surface": "#161B22",
        "accent": "#2ECC71",
        "text": "#E6EDF3",
        "danger": "#F85149",
        "warning": "#D29922",
        "success": "#3FB950",
        "border": "#30363D",
    },
    "Royal Purple": {
        "bg": "#120B1A",
        "surface": "#1D1529",
        "accent": "#9D50FF",
        "text": "#F0E6FF",
        "danger": "#FF4D4D",
        "warning": "#FFB800",
        "success": "#00E676",
        "border": "#2C233D",
    },
    "Crimson Night": {
        "bg": "#0F0A0A",
        "surface": "#1A1414",
        "accent": "#FF3E3E",
        "text": "#F5E6E6",
        "danger": "#FF2D2D",
        "warning": "#FF8800",
        "success": "#00C853",
        "border": "#2E2323",
    },
    "Graphite Gray": {
        "bg": "#121212",
        "surface": "#1E1E1E",
        "accent": "#757575",
        "text": "#FFFFFF",
        "danger": "#CF6679",
        "warning": "#FBC02D",
        "success": "#4CAF50",
        "border": "#333333",
    },
    "Minimal Light": {
        "bg": "#F8F9FA",
        "surface": "#FFFFFF",
        "accent": "#007BFF",
        "text": "#212529",
        "danger": "#DC3545",
        "warning": "#FFC107",
        "success": "#28A745",
        "border": "#DEE2E6",
    },
}

_THEME_FILE = {k: "base.qss" for k in THEME_PALETTES.keys()}


class ThemeManager(QObject):
    theme_changed = pyqtSignal(str, dict)

    def __init__(self, config_dir: str):
        super().__init__()
        self._config_dir = config_dir
        self._themes_dir = os.path.join(config_dir, "themes")
        self._version_path = os.path.join(config_dir, "version.json")
        self._current = self._load_saved_theme()

    def _load_saved_theme(self) -> str:
        try:
            with open(self._version_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            name = data.get("ui_theme")
            if isinstance(name, str) and name in THEME_PALETTES:
                return name
        except Exception:
            pass
        return "Cyber Blue"

    def _save_theme(self, theme_name: str) -> None:
        try:
            data: Dict[str, Any] = {}
            if os.path.isfile(self._version_path):
                with open(self._version_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            data["ui_theme"] = theme_name
            with open(self._version_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as exc:
            logger.warning("Could not persist theme: %s", exc)

    def apply(self, theme_name: str) -> None:
        if theme_name not in THEME_PALETTES:
            theme_name = "Cyber Blue"
        palette = THEME_PALETTES[theme_name]
        fname = _THEME_FILE[theme_name]
        qss_path = os.path.join(self._themes_dir, fname)
        qss = ""
        if os.path.isfile(qss_path):
            with open(qss_path, "r", encoding="utf-8") as f:
                qss = f.read()
        else:
            qss = (
                "QMainWindow, QWidget { background-color: {{COLOR_BG}}; color: {{COLOR_TEXT}}; }\n"
                "QPushButton { background-color: {{COLOR_SURFACE}}; "
                "border: 1px solid {{COLOR_BORDER}}; padding: 6px 12px; border-radius: 4px; }\n"
                "QPushButton:hover { border-color: {{COLOR_ACCENT}}; }\n"
            )
        for key, value in palette.items():
            qss = qss.replace("{{COLOR_%s}}" % key.upper(), value)
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(qss)
        self._current = theme_name
        self._save_theme(theme_name)
        self.theme_changed.emit(theme_name, dict(palette))

    def current_palette(self) -> dict:
        return dict(THEME_PALETTES[self._current])

    @property
    def current_theme_name(self) -> str:
        return self._current


def format_markdown_to_html(md: str) -> str:
    """
    A premium markdown-to-cyber-HTML parser that formats headers, lists, 
    code blocks, and custom severity badges (CRITICAL, MALICIOUS, WARNING, SAFE).
    """
    lines = md.split("\n")
    html_lines = []
    in_list = False
    
    for line in lines:
        line_stripped = line.strip()
        if not line_stripped:
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append("<br>")
            continue
            
        # Headers
        if line_stripped.startswith("### "):
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append(f"<h4 style='color: #60a5fa; font-size: 13px; margin-top: 12px; font-weight: 800; text-transform: uppercase;'>{line_stripped[4:]}</h4>")
        elif line_stripped.startswith("## "):
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append(f"<h3 style='color: #ef4444; font-size: 14px; margin-top: 16px; font-weight: 900; text-transform: uppercase; border-bottom: 1px solid rgba(239,68,68,0.2); padding-bottom: 4px;'>{line_stripped[3:]}</h3>")
        elif line_stripped.startswith("# "):
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append(f"<h2 style='color: #ffffff; font-size: 16px; margin-top: 18px; font-weight: 900; border-bottom: 2px solid #ef4444; padding-bottom: 6px;'>{line_stripped[2:]}</h2>")
        
        # Bullet list
        elif line_stripped.startswith("- ") or line_stripped.startswith("* "):
            if not in_list:
                html_lines.append("<ul style='margin-left: 15px; padding-left: 10px; color: #cbd5e1; list-style-type: square;'>")
                in_list = True
            content = line_stripped[2:]
            
            # Format bold text
            while "**" in content:
                content = content.replace("**", "<b>", 1).replace("**", "</b>", 1)
                
            # Colored tags
            content = content.replace("CRITICAL", "<span style='background: rgba(239, 68, 68, 0.25); color: #f87171; border: 1px solid rgba(239,68,68,0.4); border-radius: 4px; padding: 1px 5px; font-weight: bold;'>CRITICAL</span>")
            content = content.replace("MALICIOUS", "<span style='background: rgba(239, 68, 68, 0.25); color: #f87171; border: 1px solid rgba(239,68,68,0.4); border-radius: 4px; padding: 1px 5px; font-weight: bold;'>MALICIOUS</span>")
            content = content.replace("WARNING", "<span style='background: rgba(245, 158, 11, 0.25); color: #fbbf24; border: 1px solid rgba(245,158,11,0.4); border-radius: 4px; padding: 1px 5px; font-weight: bold;'>WARNING</span>")
            content = content.replace("SUSPICIOUS", "<span style='background: rgba(245, 158, 11, 0.25); color: #fbbf24; border: 1px solid rgba(245,158,11,0.4); border-radius: 4px; padding: 1px 5px; font-weight: bold;'>SUSPICIOUS</span>")
            content = content.replace("SAFE", "<span style='background: rgba(16, 185, 129, 0.25); color: #34d399; border: 1px solid rgba(16,185,129,0.4); border-radius: 4px; padding: 1px 5px; font-weight: bold;'>SAFE</span>")
            content = content.replace("CLEAN", "<span style='background: rgba(16, 185, 129, 0.25); color: #34d399; border: 1px solid rgba(16,185,129,0.4); border-radius: 4px; padding: 1px 5px; font-weight: bold;'>CLEAN</span>")
            
            html_lines.append(f"<li style='margin-bottom: 5px; line-height: 1.4;'>{content}</li>")
            
        else:
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            content = line_stripped
            
            # Format bold text
            while "**" in content:
                content = content.replace("**", "<b>", 1).replace("**", "</b>", 1)
                
            # Colored tags in text
            content = content.replace("CRITICAL", "<span style='background: rgba(239, 68, 68, 0.25); color: #f87171; border: 1px solid rgba(239,68,68,0.4); border-radius: 4px; padding: 1px 5px; font-weight: bold;'>CRITICAL</span>")
            content = content.replace("MALICIOUS", "<span style='background: rgba(239, 68, 68, 0.25); color: #f87171; border: 1px solid rgba(239,68,68,0.4); border-radius: 4px; padding: 1px 5px; font-weight: bold;'>MALICIOUS</span>")
            content = content.replace("WARNING", "<span style='background: rgba(245, 158, 11, 0.25); color: #fbbf24; border: 1px solid rgba(245,158,11,0.4); border-radius: 4px; padding: 1px 5px; font-weight: bold;'>WARNING</span>")
            content = content.replace("SUSPICIOUS", "<span style='background: rgba(245, 158, 11, 0.25); color: #fbbf24; border: 1px solid rgba(245,158,11,0.4); border-radius: 4px; padding: 1px 5px; font-weight: bold;'>SUSPICIOUS</span>")
            content = content.replace("SAFE", "<span style='background: rgba(16, 185, 129, 0.25); color: #34d399; border: 1px solid rgba(16,185,129,0.4); border-radius: 4px; padding: 1px 5px; font-weight: bold;'>SAFE</span>")
            content = content.replace("CLEAN", "<span style='background: rgba(16, 185, 129, 0.25); color: #34d399; border: 1px solid rgba(16,185,129,0.4); border-radius: 4px; padding: 1px 5px; font-weight: bold;'>CLEAN</span>")
            
            html_lines.append(f"<p style='color: #e2e8f0; margin-bottom: 6px; line-height: 1.4;'>{content}</p>")
            
    if in_list:
        html_lines.append("</ul>")
        
    return "".join(html_lines)

