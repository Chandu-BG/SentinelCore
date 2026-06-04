from __future__ import annotations

from PyQt6.QtWidgets import QFrame, QHBoxLayout, QLabel, QWidget
from PyQt6.QtCore import Qt


class MetricsBar(QFrame):
    """Compact header metrics bar with premium styling."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("metricsBar")
        self.setFixedHeight(40)
        
        self.setStyleSheet("""
            QFrame#metricsBar {
                background: rgba(15, 23, 42, 0.4);
                border-radius: 20px;
                border: 1px solid rgba(255, 255, 255, 0.05);
                padding: 0 15px;
            }
            QLabel {
                color: #94a3b8;
                font-size: 11px;
                font-weight: 800;
                letter-spacing: 0.5px;
            }
            QLabel#metricValue {
                color: #f8fafc;
                font-weight: 900;
                margin-left: 4px;
            }
            QLabel#statusLabel {
                color: #10b981;
                font-weight: 900;
                text-transform: uppercase;
            }
        """)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(15, 0, 15, 0)
        layout.setSpacing(20)
        
        self._cpu = self._create_metric("CPU")
        self._ram = self._create_metric("RAM")
        self._thr = self._create_metric("THREATS", color="#ef4444")
        
        layout.addStretch()
        
        # Status indicator
        status_box = QHBoxLayout()
        status_box.setSpacing(8)
        dot = QLabel("●")
        dot.setStyleSheet("color: #10b981; font-size: 14px;")
        self._status = QLabel("SYSTEM SECURE")
        self._status.setObjectName("statusLabel")
        status_box.addWidget(dot)
        status_box.addWidget(self._status)
        
        layout.addLayout(status_box)

    def _create_metric(self, label: str, color: str = None) -> QLabel:
        container = QWidget()
        lay = QHBoxLayout(container)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(2)
        
        lbl = QLabel(label + ":")
        val = QLabel("—")
        val.setObjectName("metricValue")
        if color:
            val.setStyleSheet(f"color: {color};")
            
        lay.addWidget(lbl)
        lay.addWidget(val)
        self.layout().addWidget(container)
        return val

    def set_metrics(self, cpu: float, ram: float, disk: float, net: float, threats: int) -> None:
        self._cpu.setText(f"{cpu:.1f}%")
        self._ram.setText(f"{ram:.1f}%")
        self._thr.setText(str(threats))

    def set_status(self, status: str) -> None:
        """Set the status indicator text."""
        self._status.setText(status.upper())
