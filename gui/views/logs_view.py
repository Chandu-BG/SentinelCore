from __future__ import annotations

import logging
import csv
import os
from typing import List, Optional, Dict
from datetime import datetime

from PyQt6.QtCore import Qt, pyqtSlot, QTimer
from PyQt6.QtGui import QColor, QIcon, QFont
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QLineEdit,
    QComboBox,
    QFileDialog,
    QFrame,
)

from core.telemetry_manager import get_telemetry

logger = logging.getLogger(__name__)

class LogsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._telemetry = get_telemetry()
        self._filter_text = ""
        self._filter_severity = "All"
        self._filter_category = "All Categories"
        self._last_log_count = -1
        self._last_filter_key = ""
        
        self._setup_ui()
        
        # Refresh timer — 2s is plenty for logs (was 1s, saved 50% timer overhead)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(2000)

        # Row-content hash cache for incremental updates: {row_index: hash_of_cells}
        self._row_hash_cache: dict = {}

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(15)

        # ── Header & Toolbar ──
        toolbar = QHBoxLayout()
        
        title = QLabel("SYSTEM EVENT LOGS")
        title.setStyleSheet("font-size: 18px; font-weight: 800; color: #f8fafc;")
        toolbar.addWidget(title)
        
        toolbar.addStretch()
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Search logs...")
        self.search_input.setFixedWidth(200)
        self.search_input.setFixedHeight(35)
        self.search_input.textChanged.connect(self._on_search_changed)
        toolbar.addWidget(self.search_input)
        
        self.category_filter = QComboBox()
        self.category_filter.addItems(["All Categories", "Scans", "Phishing", "Quarantine", "Sandbox", "AI Audits", "Protection"])
        self.category_filter.setFixedWidth(140)
        self.category_filter.setFixedHeight(35)
        self.category_filter.currentTextChanged.connect(self._on_category_changed)
        toolbar.addWidget(self.category_filter)
        
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All Severities", "Info", "Warning", "High", "Critical"])
        self.severity_filter.setFixedWidth(120)
        self.severity_filter.setFixedHeight(35)
        self.severity_filter.currentTextChanged.connect(self._on_severity_changed)
        toolbar.addWidget(self.severity_filter)
        
        self.btn_export = QPushButton("Export CSV")
        self.btn_export.setFixedHeight(35)
        self.btn_export.setFixedWidth(100)
        self.btn_export.setStyleSheet("""
            QPushButton { background: #1f2a40; color: white; border-radius: 8px; font-weight: bold; border: 1px solid #374151; }
            QPushButton:hover { background: #374151; }
        """)
        self.btn_export.clicked.connect(self.export_logs)
        toolbar.addWidget(self.btn_export)
        
        root.addLayout(toolbar)

        # ── Table ──
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["#", "Timestamp", "Module", "Message", "Severity"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch) # Message stretches
        self.table.setColumnWidth(0, 50)  # Fixed-width stable count column
        self.table.setColumnWidth(1, 160) # Timestamp
        self.table.setColumnWidth(2, 120) # Module
        self.table.setColumnWidth(4, 100) # Severity
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False) # Hide default vertical headers to prevent numbering alignment issues
        self.table.setStyleSheet("""
            QTableWidget {
                background: #0b1220;
                border: 1px solid #1f2a40;
                border-radius: 8px;
                gridline-color: #1e293b;
                color: #cbd5e1;
            }
            QTableWidget::item {
                padding: 6px 10px;
                border-bottom: 1px solid #1f2a40;
                font-family: Outfit, 'Segoe UI', sans-serif;
                font-size: 11px;
            }
            QHeaderView::section {
                background: #1e293b;
                color: #94a3b8;
                padding: 8px 10px;
                border: none;
                font-family: Outfit, 'Segoe UI', sans-serif;
                font-weight: bold;
                font-size: 10px;
                text-transform: uppercase;
            }
        """)
        root.addWidget(self.table)

    def refresh(self):
        # PERF: bail immediately when not visible — moved BEFORE the filter loop
        if not self.isVisible():
            return

        logs = self._telemetry.get_all_logs()

        # Filtering
        filtered = []
        for l in logs:
            msg = l.get("message", "").lower()
            mod = l.get("module", "").lower()
            sev = l.get("severity", "info").lower()

            if self._filter_text and (self._filter_text not in msg and self._filter_text not in mod):
                continue

            # Severity filter check
            if self._filter_severity != "All Severities" and self._filter_severity != "All":
                if self._filter_severity.lower() != sev:
                    continue

            # Category module filter check
            if self._filter_category != "All Categories":
                cat_map = {
                    "Scans": "scanner",
                    "Phishing": "phishing",
                    "Quarantine": "quarantine",
                    "Sandbox": "sandbox",
                    "AI Audits": "ai_audits",
                    "Protection": "protection"
                }
                target_mod = cat_map.get(self._filter_category, "")
                if target_mod and target_mod != mod:
                    continue

            filtered.append(l)

        # Caching check: only repaint if new logs arrived or filter parameters changed
        filter_key = f"{self._filter_text}|{self._filter_severity}|{self._filter_category}"
        if len(filtered) == self._last_log_count and filter_key == self._last_filter_key:
            return

        self._last_log_count = len(filtered)
        self._last_filter_key = filter_key

        # Cap the live render queue to 250 most recent logs
        if len(filtered) > 250:
            filtered = filtered[-250:]

        # —— INCREMENTAL TABLE UPDATE ——
        # Grow/shrink row count without destroying existing rows
        new_count = len(filtered)
        old_count = self.table.rowCount()

        self.table.setUpdatesEnabled(False)

        # Add missing rows (append only — no destroy)
        if new_count > old_count:
            self.table.setRowCount(new_count)

        # Newest-first ordering
        rows = list(reversed(filtered))

        _BOLD = QFont("Outfit", 9, QFont.Weight.Bold)
        _SEV_COLORS = {
            "CRITICAL": QColor("#ff4d4d"), "HIGH": QColor("#ff4d4d"),
            "WARNING": QColor("#fbbf24"), "ALERT": QColor("#fbbf24"),
            "INFO": QColor("#10b981"), "SUCCESS": QColor("#10b981"),
        }

        for i, l in enumerate(rows):
            ts  = l.get("timestamp", "")
            mod = l.get("module", "").upper()
            msg = l.get("message", "")
            sev = l.get("severity", "info").upper()

            # Per-row hash: only update cells if content changed
            row_hash = hash((ts, mod, msg, sev))
            if self._row_hash_cache.get(i) == row_hash:
                continue
            self._row_hash_cache[i] = row_hash

            index_str = str(i + 1)

            idx_item = QTableWidgetItem(index_str)
            idx_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            idx_item.setFont(_BOLD)
            idx_item.setForeground(QColor("#64748b"))
            self.table.setItem(i, 0, idx_item)

            self.table.setItem(i, 1, QTableWidgetItem(ts))
            self.table.setItem(i, 2, QTableWidgetItem(mod))
            self.table.setItem(i, 3, QTableWidgetItem(msg))

            sev_item = QTableWidgetItem(sev)
            sev_color = _SEV_COLORS.get(sev, QColor("#cbd5e1"))
            sev_item.setForeground(sev_color)
            if sev in ("CRITICAL", "HIGH", "WARNING", "ALERT"):
                sev_item.setFont(_BOLD)
            self.table.setItem(i, 4, sev_item)

        # Remove stale rows at the bottom (shrink without full clear)
        if new_count < old_count:
            # Invalidate hash cache for removed rows
            for i in range(new_count, old_count):
                self._row_hash_cache.pop(i, None)
            self.table.setRowCount(new_count)

        self.table.setUpdatesEnabled(True)

    def _on_search_changed(self, text: str):
        self._filter_text = text.lower()
        self.refresh()

    def _on_category_changed(self, text: str):
        self._filter_category = text
        self.refresh()

    def _on_severity_changed(self, text: str):
        self._filter_severity = text
        self.refresh()

    def export_logs(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Logs", f"NovaSentinel_Logs_{datetime.now().strftime('%Y%m%d')}.csv", "CSV Files (*.csv)")
        if not path:
            return
        
        try:
            logs = self._telemetry.get_all_logs()
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=["timestamp", "module", "message", "severity"])
                writer.writeheader()
                writer.writerows(logs)
            logger.info(f"Exported {len(logs)} logs to {path}")
        except Exception as e:
            logger.error(f"Failed to export logs: {e}")
