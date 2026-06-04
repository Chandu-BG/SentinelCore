from __future__ import annotations

from PyQt6.QtCore import QEasingCurve, QPoint, QPropertyAnimation, Qt, pyqtSignal, QSize, QRect, QTimer
from PyQt6.QtGui import QMouseEvent, QColor, QPainter, QLinearGradient, QIcon
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QStackedWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QGraphicsDropShadowEffect,
    QSizeGrip,
    QFrame,
)

class FloatingAI(QWidget):
    message_sent = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(None, Qt.WindowType.Window | Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setWindowTitle("NovaSentinel AI Assistant")
        
        self._expanded = True
        self._drag_pos = QPoint()
        self._is_typing = False
        self._main_win = parent

        self.setMinimumSize(380, 500)
        self.resize(420, 600)

        # Main Layout
        self.root_lay = QVBoxLayout(self)
        self.root_lay.setContentsMargins(10, 10, 10, 10)
        
        # Main Container (Glass Effect)
        self.container = QFrame()
        self.container.setObjectName("aiContainer")
        self.container.setStyleSheet("""
            QFrame#aiContainer {
                background-color: rgba(13, 20, 38, 0.98);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 20px;
            }
        """)
        
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(30)
        shadow.setXOffset(0)
        shadow.setYOffset(10)
        shadow.setColor(QColor(0, 0, 0, 180))
        self.container.setGraphicsEffect(shadow)
        
        self.container_lay = QVBoxLayout(self.container)
        self.container_lay.setContentsMargins(0, 0, 0, 0)
        self.container_lay.setSpacing(0)
        self.root_lay.addWidget(self.container)

        # ── Title Bar ──
        self.title_bar = QFrame()
        self.title_bar.setFixedHeight(65)
        self.title_bar.setStyleSheet("background: rgba(255,255,255,0.03); border-bottom: 1px solid rgba(255,255,255,0.05); border-top-left-radius: 20px; border-top-right-radius: 20px;")
        th = QHBoxLayout(self.title_bar)
        th.setContentsMargins(20, 0, 15, 0)
        
        icon_lbl = QLabel("✦")
        icon_lbl.setStyleSheet("font-size: 22px; color: #3b82f6; font-weight: bold;")
        th.addWidget(icon_lbl)
        
        title_v = QVBoxLayout()
        title_v.setSpacing(0)
        title_v.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        t1 = QLabel("NOVASENTINEL")
        t1.setStyleSheet("font-weight: 900; font-size: 11px; letter-spacing: 2px; color: #3b82f6;")
        title_v.addWidget(t1)
        
        t2 = QLabel("Neural Security Assistant")
        t2.setStyleSheet("font-size: 10px; color: #94a3b8; font-weight: 600;")
        title_v.addWidget(t2)
        
        th.addLayout(title_v, 1)
        
        # Action Buttons
        self.btn_clear = QPushButton("↺")
        self.btn_clear.setFixedSize(32, 32)
        self.btn_clear.setToolTip("Clear Conversation")
        self.btn_clear.setStyleSheet("QPushButton { background: transparent; color: #64748b; font-size: 18px; border: none; } QPushButton:hover { color: white; background: rgba(255,255,255,0.05); border-radius: 16px; }")
        self.btn_clear.clicked.connect(self.clear_chat)
        th.addWidget(self.btn_clear)
        
        self.btn_min = QPushButton("─")
        self.btn_min.setFixedSize(32, 32)
        self.btn_min.setStyleSheet("QPushButton { background: transparent; color: #64748b; font-size: 14px; border: none; font-weight: bold; } QPushButton:hover { color: white; background: rgba(255,255,255,0.05); border-radius: 16px; }")
        self.btn_min.clicked.connect(self._toggle_minimize)
        th.addWidget(self.btn_min)
        
        self.btn_close = QPushButton("✕")
        self.btn_close.setFixedSize(32, 32)
        self.btn_close.setStyleSheet("QPushButton { background: transparent; color: #64748b; font-size: 14px; border: none; } QPushButton:hover { color: #ef4444; background: rgba(239, 68, 68, 0.1); border-radius: 16px; }")
        self.btn_close.clicked.connect(self.hide)
        th.addWidget(self.btn_close)
        
        self.container_lay.addWidget(self.title_bar)

        # ── Chat Area ──
        self.chat_widget = QWidget()
        cv = QVBoxLayout(self.chat_widget)
        cv.setContentsMargins(0, 0, 0, 0)
        cv.setSpacing(0)
        
        self._chat = QTextEdit()
        self._chat.setReadOnly(True)
        self._chat.setFrameStyle(QFrame.Shape.NoFrame)
        self._chat.setStyleSheet("""
            QTextEdit {
                background: transparent;
                border: none;
                padding: 25px;
                font-size: 14px;
                line-height: 1.6;
                color: #e2e8f0;
            }
        """)
        cv.addWidget(self._chat, 1)

        self._typing_lbl = QLabel("Generating intelligence...")
        self._typing_lbl.setStyleSheet("color: #3b82f6; font-size: 11px; font-style: italic; padding: 10px 25px; font-weight: bold;")
        self._typing_lbl.hide()
        cv.addWidget(self._typing_lbl)

        # ── Input Area ──
        input_frame = QFrame()
        input_frame.setStyleSheet("background: rgba(0,0,0,0.2); border-top: 1px solid rgba(255,255,255,0.05); border-bottom-left-radius: 20px; border-bottom-right-radius: 20px;")
        ih = QHBoxLayout(input_frame)
        ih.setContentsMargins(20, 15, 20, 20)
        
        self._input = QLineEdit()
        self._input.setPlaceholderText("Ask me anything about your system...")
        self._input.setStyleSheet("""
            QLineEdit {
                background: #0f172a;
                color: #f8fafc;
                border-radius: 22px;
                padding: 12px 20px;
                border: 1px solid rgba(255,255,255,0.1);
                font-size: 13px;
            }
            QLineEdit:focus {
                border: 1px solid #3b82f6;
            }
        """)
        self._input.returnPressed.connect(self._send)
        ih.addWidget(self._input, 1)
        
        self.send_btn = QPushButton("➤")
        self.send_btn.setFixedSize(44, 44)
        self.send_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.send_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #3b82f6, stop:1 #2563eb);
                color: white;
                border-radius: 22px;
                font-size: 20px;
                border: none;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #60a5fa, stop:1 #3b82f6);
            }
        """)
        self.send_btn.clicked.connect(self._send)
        ih.addWidget(self.send_btn)
        cv.addWidget(input_frame)
        
        self.container_lay.addWidget(self.chat_widget)
        
        # Size Grip
        self.grip = QSizeGrip(self)
        self.grip.setFixedSize(24, 24)
        self.grip.setStyleSheet("background: transparent;")
        self.root_lay.addWidget(self.grip, 0, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignBottom)

        self._append_welcome()

    def _append_welcome(self):
        self._append_message("ASSISTANT", 
            "Hello, I am NovaSentinel. I have direct access to your system telemetry, "
            "running processes, and threat logs. How can I help secure your environment today?", 
            "#3b82f6")

    def clear_chat(self):
        self._chat.clear()
        self._append_welcome()

    def _toggle_minimize(self):
        self._expanded = not self._expanded
        self.chat_widget.setVisible(self._expanded)
        self.btn_min.setText("▢" if not self._expanded else "─")
        
        if not self._expanded:
            self.setMinimumHeight(65 + 20) # Title bar + margins
            self.resize(self.width(), 85)
        else:
            self.setMinimumHeight(500)
            self.resize(self.width(), 600)

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if event.buttons() & Qt.MouseButton.LeftButton:
            self.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()

    def _send(self) -> None:
        text = self._input.text().strip()
        if not text or self._is_typing:
            return
        self._input.clear()
        self._append_message("USER", text, "#3b82f6")
        self._set_typing(True)
        self.message_sent.emit(text)

    def _set_typing(self, typing: bool) -> None:
        self._is_typing = typing
        self._typing_lbl.setVisible(typing)

    def append_token(self, token: str) -> None:
        self._set_typing(False)
        self._chat.moveCursor(self._chat.textCursor().MoveOperation.End)
        
        if self._chat.toPlainText().endswith("\n") or not self._chat.toPlainText() or "USER" in self._chat.toPlainText().splitlines()[-1]:
             if not self._chat.toPlainText().endswith("ASSISTANT:"):
                self._chat.insertHtml("<br><b style='color: #3b82f6; font-size: 10px;'>ASSISTANT</b><br>")
            
        self._chat.insertPlainText(token)
        self._chat.ensureCursorVisible()

    def on_response_complete(self, _full: str) -> None:
        self._set_typing(False)
        self._chat.append("")
        self._chat.ensureCursorVisible()

    def _append_message(self, who: str, text: str, color: str) -> None:
        align = "right" if who == "USER" else "left"
        bg = "rgba(59, 130, 246, 0.15)" if who == "USER" else "rgba(255, 255, 255, 0.05)"
        border = "1px solid rgba(59, 130, 246, 0.3)" if who == "USER" else "1px solid rgba(255, 255, 255, 0.1)"
        
        html = f"""
            <div style='margin-bottom: 20px;'>
                <div style='text-align: {align};'>
                    <b style='color: {color}; font-size: 10px; letter-spacing: 1px;'>{who}</b>
                </div>
                <div style='background: {bg}; border: {border}; border-radius: 12px; padding: 15px; margin-top: 5px; color: #f1f5f9;'>
                    {text}
                </div>
            </div>
        """
        self._chat.append(html)
        self._chat.ensureCursorVisible()

    def show(self) -> None:
        super().show()
        if self._main_win:
            g = self._main_win.geometry()
            # Position at bottom right
            target_x = g.x() + g.width() - self.width() - 30
            target_y = g.y() + g.height() - self.height() - 30
            self.move(target_x, target_y)
