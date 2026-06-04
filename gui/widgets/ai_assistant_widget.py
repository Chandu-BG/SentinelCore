from __future__ import annotations

from PyQt6.QtCore import QEasingCurve, QPoint, QPropertyAnimation, Qt, QTimer, pyqtSignal, QSize
from PyQt6.QtGui import QMouseEvent, QColor, QIcon
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
)


class AIAssistantWidget(QWidget):
    message_sent = pyqtSignal(str)

    COLLAPSED_SIZE = QSize(65, 65)
    EXPANDED_SIZE = QSize(420, 600)

    def __init__(self, parent: QWidget | None = None):
        # We use Qt.WindowType.Window | Qt.WindowType.FramelessWindowHint to make it float above everything
        super().__init__(None, Qt.WindowType.Window | Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setWindowTitle("NovaSentinel AI")
        
        self._expanded = False
        self._drag_pos = QPoint()
        self._is_typing = False
        self._main_win = parent

        self.setFixedSize(self.COLLAPSED_SIZE)

        # Main Layout
        self.root_lay = QVBoxLayout(self)
        self.root_lay.setContentsMargins(10, 10, 10, 10)
        
        self.container = QWidget()
        self.container.setObjectName("aiContainer")
        self.container_lay = QVBoxLayout(self.container)
        self.container_lay.setContentsMargins(0, 0, 0, 0)
        self.container_lay.setSpacing(0)
        
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(20)
        shadow.setXOffset(0)
        shadow.setYOffset(5)
        shadow.setColor(QColor(0, 0, 0, 80))
        self.container.setGraphicsEffect(shadow)
        
        self.root_lay.addWidget(self.container)

        self._stack = QStackedWidget()
        self.container_lay.addWidget(self._stack)

        # ── Collapsed View ──
        self._collapsed = QWidget()
        cl = QVBoxLayout(self._collapsed)
        cl.setContentsMargins(0, 0, 0, 0)
        self._collapsed_btn = QPushButton("✦")
        self._collapsed_btn.setFixedSize(55, 55)
        self._collapsed_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._collapsed_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #7C3AED, stop:1 #2563EB);
                color: white;
                border-radius: 27px;
                font-size: 28px;
                border: 2px solid rgba(255,255,255,0.2);
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #8B5CF6, stop:1 #3B82F6);
            }
        """)
        self._collapsed_btn.clicked.connect(self.toggle)
        cl.addWidget(self._collapsed_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        # ── Expanded View ──
        self._panel = QWidget()
        self._panel.setStyleSheet("background: white; border-radius: 12px;")
        pv = QVBoxLayout(self._panel)
        pv.setContentsMargins(0, 0, 0, 0)
        pv.setSpacing(0)

        # Custom Title Bar
        self.title_bar = QWidget()
        self.title_bar.setFixedHeight(55)
        self.title_bar.setStyleSheet("background: #F9FAFB; border-top-left-radius: 12px; border-top-right-radius: 12px; border-bottom: 1px solid #E5E7EB;")
        th = QHBoxLayout(self.title_bar)
        th.setContentsMargins(15, 0, 10, 0)
        
        avatar = QLabel("✨")
        avatar.setStyleSheet("font-size: 20px;")
        th.addWidget(avatar)
        
        title_lbl = QLabel("NovaSentinel Assistant")
        title_lbl.setStyleSheet("font-weight: 700; font-size: 14px; color: #1F2937;")
        th.addWidget(title_lbl, 1)
        
        self.min_btn = QPushButton("─")
        self.min_btn.setFixedSize(28, 28)
        self.min_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.min_btn.setStyleSheet("QPushButton { background: transparent; border-radius: 14px; font-weight: bold; } QPushButton:hover { background: #E5E7EB; }")
        self.min_btn.clicked.connect(self.toggle)
        th.addWidget(self.min_btn)
        
        self.close_btn = QPushButton("✕")
        self.close_btn.setFixedSize(28, 28)
        self.close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.close_btn.setStyleSheet("QPushButton { background: transparent; border-radius: 14px; font-weight: bold; } QPushButton:hover { background: #FEE2E2; color: #EF4444; }")
        self.close_btn.clicked.connect(self.hide)
        th.addWidget(self.close_btn)
        pv.addWidget(self.title_bar)

        # Chat Area
        self._chat = QTextEdit()
        self._chat.setReadOnly(True)
        self._chat.setStyleSheet("""
            QTextEdit {
                background: white;
                border: none;
                padding: 15px;
                font-size: 13px;
                line-height: 1.5;
                color: #374151;
            }
        """)
        pv.addWidget(self._chat, 1)

        # Typing Indicator
        self._typing_lbl = QLabel("NovaSentinel is typing...")
        self._typing_lbl.setStyleSheet("color: #6B7280; font-size: 11px; font-style: italic; padding: 5px 20px; background: white;")
        self._typing_lbl.hide()
        pv.addWidget(self._typing_lbl)

        # Input Area
        input_container = QWidget()
        input_container.setStyleSheet("background: white; border-bottom-left-radius: 12px; border-bottom-right-radius: 12px; border-top: 1px solid #E5E7EB;")
        ih = QHBoxLayout(input_container)
        ih.setContentsMargins(15, 12, 15, 12)
        
        self._input = QLineEdit()
        self._input.setPlaceholderText("Ask me about processes or threats...")
        self._input.setStyleSheet("background: #F3F4F6; border-radius: 18px; padding: 8px 15px; border: 1px solid transparent;")
        self._input.returnPressed.connect(self._send)
        ih.addWidget(self._input, 1)
        
        send = QPushButton("➤")
        send.setFixedSize(36, 36)
        send.setCursor(Qt.CursorShape.PointingHandCursor)
        send.setStyleSheet("""
            QPushButton {
                background: #2563EB;
                color: white;
                border-radius: 18px;
                font-size: 16px;
                border: none;
            }
            QPushButton:hover {
                background: #1D4ED8;
            }
        """)
        send.clicked.connect(self._send)
        ih.addWidget(send)
        pv.addWidget(input_container)
        
        # Size Grip for resizing
        self.size_grip = QSizeGrip(self._panel)
        pv.addWidget(self.size_grip, 0, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignBottom)

        self._stack.addWidget(self._collapsed)
        self._stack.addWidget(self._panel)
        self._stack.setCurrentWidget(self._collapsed)

    def attach_bottom_right(self, host: QWidget) -> None:
        """Position the widget initially relative to the host."""
        margin = 30
        g = host.geometry()
        size = self.EXPANDED_SIZE if self._expanded else self.COLLAPSED_SIZE
        
        # Global position calculation
        pos = host.mapToGlobal(QPoint(g.width() - size.width() - margin, g.height() - size.height() - margin))
        self.setGeometry(pos.x(), pos.y(), size.width(), size.height())

    def toggle(self) -> None:
        self._expanded = not self._expanded
        self._stack.setCurrentWidget(self._panel if self._expanded else self._collapsed)
        
        target_size = self.EXPANDED_SIZE if self._expanded else self.COLLAPSED_SIZE
        
        # Animate size change
        self._anim = QPropertyAnimation(self, b"size")
        self._anim.setDuration(300)
        self._anim.setEasingCurve(QEasingCurve.Type.OutQuart)
        self._anim.setEndValue(target_size)
        
        # Adjust position so it expands upwards/leftwards from bottom right
        if self._expanded:
            self.move(self.pos().x() - (self.EXPANDED_SIZE.width() - self.COLLAPSED_SIZE.width()), 
                      self.pos().y() - (self.EXPANDED_SIZE.height() - self.COLLAPSED_SIZE.height()))
        else:
            self.move(self.pos().x() + (self.EXPANDED_SIZE.width() - self.COLLAPSED_SIZE.width()), 
                      self.pos().y() + (self.EXPANDED_SIZE.height() - self.COLLAPSED_SIZE.height()))
            
        self._anim.start()
        
        if not self._expanded:
            self.setFixedSize(self.COLLAPSED_SIZE)
        else:
            self.setMinimumSize(350, 450)
            self.setMaximumSize(800, 900)

    def _send(self) -> None:
        text = self._input.text().strip()
        if not text or self._is_typing:
            return
        self._input.clear()
        self._append_message("You", text, "#2563EB")
        self._set_typing(True)
        self.message_sent.emit(text)

    def _set_typing(self, typing: bool) -> None:
        self._is_typing = typing
        self._typing_lbl.setVisible(typing)

    def append_token(self, token: str) -> None:
        self._set_typing(False)
        self._chat.moveCursor(self._chat.textCursor().MoveOperation.End)
        
        if self._chat.toPlainText().endswith("\n") or not self._chat.toPlainText():
            self._chat.insertHtml("<br><b style='color: #7C3AED;'>NovaSentinel:</b> ")
            
        self._chat.insertPlainText(token)
        self._chat.ensureCursorVisible()

    def on_response_complete(self, _full: str) -> None:
        self._set_typing(False)
        self._chat.append("")
        self._chat.ensureCursorVisible()

    def _append_message(self, who: str, text: str, color: str) -> None:
        align = "left" if who == "NovaSentinel" else "right"
        bg = "#F3F4F6" if who == "NovaSentinel" else "#DBEAFE"
        
        html = f"""
            <div style='margin-bottom: 10px;'>
                <b style='color: {color};'>{who}:</b><br>
                <div style='background: {bg}; border-radius: 8px; padding: 10px; margin-top: 5px;'>
                    {text}
                </div>
            </div>
        """
        self._chat.append(html)
        self._chat.ensureCursorVisible()

    # ── Mouse Events for Dragging ──
    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if event.buttons() & Qt.MouseButton.LeftButton:
            self.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()

    def show(self) -> None:
        super().show()
        if self._main_win:
            self.attach_bottom_right(self._main_win)
