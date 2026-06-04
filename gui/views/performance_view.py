from __future__ import annotations

import os
from collections import deque
from typing import Any, List, Optional, Dict

from PyQt6.QtCore import Qt, pyqtSlot, pyqtSignal, QSize, QTimer, QFileInfo
from PyQt6.QtGui import QColor, QIcon, QAction
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QSplitter,
    QVBoxLayout,
    QWidget,
    QLineEdit,
    QPushButton,
    QMenu,
    QMessageBox,
    QLabel,
    QComboBox,
    QTreeWidget,
    QTreeWidgetItem,
    QFrame,
    QFileIconProvider,
)

try:
    import pyqtgraph as pg
    _HAS_PG = True
except Exception:
    pg = None
    _HAS_PG = False

HISTORY_LEN = 120


class ProcessTreeWidgetItem(QTreeWidgetItem):
    """Custom QTreeWidgetItem that sorts columns numerically or alphabetically as appropriate."""

    def __lt__(self, other: QTreeWidgetItem) -> bool:
        column = self.treeWidget().sortColumn() if self.treeWidget() else 0
        t1 = self.text(column)
        t2 = other.text(column)

        # Numeric sorting for PID and Threads
        if column in (1, 7):
            try:
                return int(t1) < int(t2)
            except ValueError:
                pass

        # Float sorting for CPU, RAM, Disk, GPU (stripping symbols & units)
        if column in (3, 4, 5, 6):
            try:
                v1 = float(t1.replace("%", "").replace("MB", "").replace("KB/s", "").strip())
                v2 = float(t2.replace("%", "").replace("MB", "").replace("KB/s", "").strip())
                return v1 < v2
            except ValueError:
                pass

        # Case-insensitive alphabetic sorting for other columns
        return t1.lower() < t2.lower()


class PerformanceView(QWidget):
    terminate_process_requested = pyqtSignal(int, str)

    def __init__(self, theme_manager: Any = None, parent=None):
        super().__init__(parent)
        self._tm = theme_manager
        
        # Historical metric buffers
        self._cpu_hist = deque([0.0] * HISTORY_LEN, maxlen=HISTORY_LEN)
        self._ram_hist = deque([0.0] * HISTORY_LEN, maxlen=HISTORY_LEN)
        self._disk_hist = deque([0.0] * HISTORY_LEN, maxlen=HISTORY_LEN)
        self._net_hist = deque([0.0] * HISTORY_LEN, maxlen=HISTORY_LEN)

        # Target and current interpolation values for 30 FPS smooth graph flow
        self._target_cpu = 0.0
        self._target_ram = 0.0
        self._target_disk = 0.0
        self._target_net = 0.0

        self._current_cpu = 0.0
        self._current_ram = 0.0
        self._current_disk = 0.0
        self._current_net = 0.0

        self._all_processes: List[Dict] = []
        self._filter_text = ""
        self._filter_group = "All"
        self._process_states: Dict[int, str] = {}

        # Sorting state
        self._sort_column = 3  # Default to CPU %
        self._sort_order = Qt.SortOrder.DescendingOrder
        self._sort_dirty = False  # PERF: only sort when data actually changed

        # Icon cache (LRU-capped at 200 entries) + batch load queue
        self._icon_cache: Dict[str, QIcon] = {}
        self._icon_load_queue: List[tuple] = []  # list of (path, item_ref) pending
        self._default_app_icon = QFileIconProvider().icon(QFileIconProvider.IconType.File)

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(15)

        # Header with Search and Stats
        header = QHBoxLayout()
        self._search = QLineEdit()
        self._search.setPlaceholderText("🔍 Search processes (name, PID, user)...")
        self._search.setFixedHeight(35)
        self._search.setStyleSheet("""
            QLineEdit {
                padding: 0 15px;
                font-size: 13px;
            }
        """)
        self._search.textChanged.connect(self._on_search_changed)
        header.addWidget(self._search, 2)

        self._group_filter = QComboBox()
        self._group_filter.setFixedHeight(35)
        self._group_filter.addItems(["All", "Apps", "Background Processes", "Windows Processes"])
        self._group_filter.currentTextChanged.connect(self._on_group_changed)
        header.addWidget(self._group_filter, 1)

        self._btn_terminate = QPushButton("End Task")
        self._btn_terminate.setFixedHeight(35)
        self._btn_terminate.setEnabled(False)
        self._btn_terminate.setStyleSheet("""
            QPushButton {
                background: #EF4444; 
                color: white; 
                font-weight: bold; 
                border-radius: 8px; 
                padding: 0 20px;
            }
            QPushButton:hover { background: #DC2626; }
            QPushButton:disabled { background: #FCA5A5; }
        """)
        self._btn_terminate.clicked.connect(self._on_terminate_click)
        header.addWidget(self._btn_terminate)
        
        root.addLayout(header)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # ── Graphs Section ──
        graphs_container = QFrame()
        graphs_container.setObjectName("performanceCard")
        gh = QHBoxLayout(graphs_container)
        gh.setContentsMargins(15, 15, 15, 15)
        gh.setSpacing(10)
        
        if _HAS_PG:
            pg.setConfigOption("background", "#0b1220")
            pg.setConfigOption("foreground", "#94a3b8")
            
            self._cpu_plot = pg.PlotWidget()
            self._ram_plot = pg.PlotWidget()
            self._disk_plot = pg.PlotWidget()
            self._net_plot = pg.PlotWidget()
            
            # Windows Task Manager Styles and Colors
            plots_info = [
                (self._cpu_plot, "CPU UTILIZATION", "#00d2ff"),   # Blue/Cyan
                (self._ram_plot, "MEMORY USAGE", "#a855f7"),      # Purple/Violet
                (self._disk_plot, "DISK ACTIVITY", "#22c55e"),    # Green
                (self._net_plot, "NETWORK TRAFFIC", "#ef4444")    # Orange/Red
            ]
            
            for pw, title, color in plots_info:
                pw.setBackground("transparent")
                pw.setTitle(title, color="#94a3b8", size="8pt")
                pw.showGrid(x=True, y=True, alpha=0.05)
                pw.setMouseEnabled(x=False, y=False)
                pw.hideAxis("bottom")
                pw.setMinimumHeight(150)
            
            self._cpu_plot.setYRange(0, 100, padding=0)
            self._ram_plot.setYRange(0, 100, padding=0)
            
            # --- 1. CPU Layers (Bars -> Translucent Fill -> Thick Glow -> Fore Curve) ---
            self._cpu_bars = pg.BarGraphItem(x=[], height=[], width=0.5, brush=QColor(0, 210, 255, 6), pen=None)
            self._cpu_plot.addItem(self._cpu_bars)
            self._cpu_fill = pg.PlotDataItem(fillLevel=0.0, fillBrush=QColor(0, 210, 255, 12), pen=None)
            self._cpu_plot.addItem(self._cpu_fill)
            self._cpu_glow = self._cpu_plot.plot(pen=pg.mkPen(QColor(0, 210, 255, 30), width=6))
            self._cpu_curve = self._cpu_plot.plot(pen=pg.mkPen("#00d2ff", width=2))
            
            # --- 2. Memory Layers (Bars -> Translucent Fill -> Thick Glow -> Fore Curve) ---
            self._ram_bars = pg.BarGraphItem(x=[], height=[], width=0.5, brush=QColor(168, 85, 247, 6), pen=None)
            self._ram_plot.addItem(self._ram_bars)
            self._ram_fill = pg.PlotDataItem(fillLevel=0.0, fillBrush=QColor(168, 85, 247, 12), pen=None)
            self._ram_plot.addItem(self._ram_fill)
            self._ram_glow = self._ram_plot.plot(pen=pg.mkPen(QColor(168, 85, 247, 30), width=6))
            self._ram_curve = self._ram_plot.plot(pen=pg.mkPen("#a855f7", width=2))
            
            # --- 3. Disk Layers (Bars -> Translucent Fill -> Thick Glow -> Fore Curve) ---
            self._disk_bars = pg.BarGraphItem(x=[], height=[], width=0.5, brush=QColor(34, 197, 94, 6), pen=None)
            self._disk_plot.addItem(self._disk_bars)
            self._disk_fill = pg.PlotDataItem(fillLevel=0.0, fillBrush=QColor(34, 197, 94, 12), pen=None)
            self._disk_plot.addItem(self._disk_fill)
            self._disk_glow = self._disk_plot.plot(pen=pg.mkPen(QColor(34, 197, 94, 30), width=6))
            self._disk_curve = self._disk_plot.plot(pen=pg.mkPen("#22c55e", width=2))
            
            # --- 4. Network Layers (Bars -> Translucent Fill -> Thick Glow -> Fore Curve) ---
            self._net_bars = pg.BarGraphItem(x=[], height=[], width=0.5, brush=QColor(239, 68, 68, 6), pen=None)
            self._net_plot.addItem(self._net_bars)
            self._net_fill = pg.PlotDataItem(fillLevel=0.0, fillBrush=QColor(239, 68, 68, 12), pen=None)
            self._net_plot.addItem(self._net_fill)
            self._net_glow = self._net_plot.plot(pen=pg.mkPen(QColor(239, 68, 68, 30), width=6))
            self._net_curve = self._net_plot.plot(pen=pg.mkPen("#ef4444", width=2))
            
            gh.addWidget(self._cpu_plot)
            gh.addWidget(self._ram_plot)
            gh.addWidget(self._disk_plot)
            gh.addWidget(self._net_plot)
        else:
            gh.addWidget(QLabel("Graphs unavailable (pyqtgraph missing)"))
            
        splitter.addWidget(graphs_container)

        # ── Tree Section (Grouped Task Manager) ──
        self._tree = QTreeWidget()
        self._tree.setHeaderLabels([
            "Name", "PID", "User", "CPU %", "RAM MB", "Disk KB/s", "GPU %", "Threads", "Status", "Path"
        ])
        self._tree.setColumnCount(10)
        self._tree.setColumnWidth(0, 180)
        self._tree.setColumnWidth(1, 60)
        self._tree.setColumnWidth(2, 80)
        self._tree.setColumnWidth(3, 60)
        self._tree.setColumnWidth(4, 80)
        self._tree.setColumnWidth(5, 90)
        self._tree.setColumnWidth(6, 60)
        self._tree.setColumnWidth(7, 70)
        self._tree.setColumnWidth(8, 80)
        
        self._tree.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self._tree.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self._tree.header().setStretchLastSection(True)
        
        # Configure Custom Headers & Interaction Sorting
        self._tree.setSortingEnabled(False)
        self._tree.header().setSectionsClickable(True)
        self._tree.header().sectionClicked.connect(self._on_header_clicked)
        self._tree.header().setSortIndicator(self._sort_column, self._sort_order)
        
        self._tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        self._tree.setAlternatingRowColors(True)
        self._tree.itemSelectionChanged.connect(self._on_selection_changed)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._on_context_menu)
        
        splitter.addWidget(self._tree)

        root.addWidget(splitter, 1)

        # Initialize group items
        self._groups = {
            "Apps": QTreeWidgetItem(self._tree, ["Apps"]),
            "Background Processes": QTreeWidgetItem(self._tree, ["Background Processes"]),
            "Windows Processes": QTreeWidgetItem(self._tree, ["Windows Processes"]),
        }
        for g in self._groups.values():
            g.setExpanded(True)
            g.setBackground(0, QColor("#1f2a40"))
            g.setForeground(0, QColor("#94a3b8"))
            font = g.font(0)
            font.setBold(True)
            g.setFont(0, font)

        # Setup 15 FPS Graph Refresh Timer (was 30 FPS — halved CPU overhead)
        # Timer is STOPPED when this view is hidden (see showEvent/hideEvent)
        self._smooth_timer = QTimer(self)
        self._smooth_timer.setInterval(66)  # ~15 FPS (was 33ms/30 FPS)
        self._smooth_timer.timeout.connect(self._update_graph_smooth)
        # Do NOT start here — started in showEvent to avoid burning CPU on other tabs

        # Batch icon loader: one icon per 100ms tick (replaces per-process QTimer flood)
        self._icon_batch_timer = QTimer(self)
        self._icon_batch_timer.setInterval(100)
        self._icon_batch_timer.timeout.connect(self._process_icon_queue)
        self._icon_batch_timer.start()

    def showEvent(self, event) -> None:  # noqa: N802
        """Start graph timer only when this view is actually visible."""
        super().showEvent(event)
        self._smooth_timer.start()

    def hideEvent(self, event) -> None:  # noqa: N802
        """Stop graph timer when hidden — eliminates background 30 FPS CPU burn."""
        super().hideEvent(event)
        self._smooth_timer.stop()

    @pyqtSlot(list, float, float, float, float)
    def set_metrics(self, processes: list, cpu: float, ram: float, net_mbps: float, disk_kbps: float = 0.0) -> None:
        self._all_processes = processes
        
        # Record new target telemetry values
        self._target_cpu = float(cpu)
        self._target_ram = float(ram)
        self._target_net = float(net_mbps)
        self._target_disk = float(disk_kbps)

        # Perform optimized incremental refresh of the process tree
        self._refresh_tree()

    def _process_icon_queue(self) -> None:
        """Process one pending icon load per timer tick (100ms) — replaces QTimer flood."""
        if not self._icon_load_queue:
            return
        path, item_ref = self._icon_load_queue.pop(0)
        try:
            if item_ref is None or not path:
                return
            if path in self._icon_cache:
                item_ref.setIcon(0, self._icon_cache[path])
                return
            icon = QFileIconProvider().icon(QFileInfo(path))
            if not icon.isNull():
                # LRU eviction: cap at 200 entries
                if len(self._icon_cache) >= 200:
                    try:
                        oldest_key = next(iter(self._icon_cache))
                        del self._icon_cache[oldest_key]
                    except StopIteration:
                        pass
                self._icon_cache[path] = icon
                item_ref.setIcon(0, icon)
        except Exception:
            pass

    def _update_graph_smooth(self) -> None:
        """Gently interpolate values to render buttery smooth graph waves."""
        alpha = 0.08
        self._current_cpu += (self._target_cpu - self._current_cpu) * alpha
        self._current_ram += (self._target_ram - self._current_ram) * alpha
        self._current_disk += (self._target_disk - self._current_disk) * alpha
        self._current_net += (self._target_net - self._current_net) * alpha

        # Round values to fix strange float precision residues
        self._current_cpu = round(self._current_cpu, 1)
        self._current_ram = round(self._current_ram, 1)
        self._current_disk = round(self._current_disk, 1)
        self._current_net = round(self._current_net, 1)

        # Append intermediate interpolated metrics into deques
        self._cpu_hist.append(self._current_cpu)
        self._ram_hist.append(self._current_ram)
        self._disk_hist.append(self._current_disk)
        self._net_hist.append(self._current_net)

        if _HAS_PG:
            x = list(range(len(self._cpu_hist)))
            cpu_y = list(self._cpu_hist)
            ram_y = list(self._ram_hist)
            disk_y = list(self._disk_hist)
            net_y = list(self._net_hist)

            # Update CPU Layers
            self._cpu_curve.setData(x, cpu_y)
            self._cpu_glow.setData(x, cpu_y)
            self._cpu_fill.setData(x, cpu_y)
            self._cpu_bars.setOpts(x=x, height=cpu_y)

            # Update RAM Layers
            self._ram_curve.setData(x, ram_y)
            self._ram_glow.setData(x, ram_y)
            self._ram_fill.setData(x, ram_y)
            self._ram_bars.setOpts(x=x, height=ram_y)

            # Update Disk Layers
            self._disk_curve.setData(x, disk_y)
            self._disk_glow.setData(x, disk_y)
            self._disk_fill.setData(x, disk_y)
            self._disk_bars.setOpts(x=x, height=disk_y)

            # Update Network Layers
            self._net_curve.setData(x, net_y)
            self._net_glow.setData(x, net_y)
            self._net_fill.setData(x, net_y)
            self._net_bars.setOpts(x=x, height=net_y)

            # Dynamically scale disk and network Y-ranges to prevent clipping & jumps
            max_disk = max(10.0, max(disk_y))
            self._disk_plot.setYRange(0, max_disk * 1.1, padding=0)

            max_net = max(10.0, max(net_y))
            self._net_plot.setYRange(0, max_net * 1.1, padding=0)

            # Update Windows Task Manager style dynamic labels & units
            self._cpu_plot.setTitle(f"CPU UTILIZATION — {self._current_cpu:.1f}%", color="#94a3b8", size="8pt")
            self._ram_plot.setTitle(f"MEMORY USAGE — {self._current_ram:.1f}%", color="#94a3b8", size="8pt")
            
            if self._current_disk < 1024.0:
                disk_text = f"{self._current_disk:.1f} KB/s"
            else:
                disk_text = f"{self._current_disk/1024.0:.1f} MB/s"
            self._disk_plot.setTitle(f"DISK ACTIVITY — {disk_text}", color="#94a3b8", size="8pt")
            
            self._net_plot.setTitle(f"NETWORK TRAFFIC — {self._current_net:.1f} Mbps", color="#94a3b8", size="8pt")

    def _refresh_tree(self):
        # 1. Capture and preserve current user selections
        selected_pids = set()
        for item in self._tree.selectedItems():
            pid_str = item.text(1)
            if pid_str.isdigit():
                selected_pids.add(int(pid_str))

        # Track existing items by PID
        existing_items: Dict[int, QTreeWidgetItem] = {}
        for g_name, g_item in self._groups.items():
            for i in range(g_item.childCount()):
                child = g_item.child(i)
                pid_str = child.text(1)
                if pid_str.isdigit():
                    existing_items[int(pid_str)] = child

        active_pids = set()
        
        for p in self._all_processes:
            p_dict = p.to_dict() if hasattr(p, "to_dict") else p
            pid = p_dict.get("pid", 0)
            name = str(p_dict.get("display_name", p_dict.get("name", "")))
            group_name = p_dict.get("group", "Background Processes")
            user = p_dict.get("user", "System")
            cpu = p_dict.get("cpu_percent", 0.0)
            ram = p_dict.get("ram_mb", 0.0)
            disk = p_dict.get("disk_read_kbps", 0.0) + p_dict.get("disk_write_kbps", 0.0)
            gpu = p_dict.get("gpu_percent", 0.0)
            threads = p_dict.get("num_threads", 0)
            
            status = self._process_states.get(pid)
            if not status:
                status = "Suspicious" if p_dict.get("risk_flag") else ("Safe" if p_dict.get("trusted") else "Running")
                
            path = p_dict.get("exe", "")

            # Filter logic
            if self._filter_text and self._filter_text not in name.lower() and self._filter_text not in str(pid) and self._filter_text not in user.lower():
                continue
            if self._filter_group != "All" and self._filter_group != group_name:
                continue

            active_pids.add(pid)
            
            values = [
                name, str(pid), user, f"{cpu:.1f}%", f"{ram:.1f} MB", 
                f"{disk:.1f} KB/s", f"{gpu:.1f}%", str(threads), status, path
            ]

            # Optimized Incremental Update: setText only if values changed
            if pid in existing_items:
                item = existing_items[pid]
                for i, v in enumerate(values):
                    if item.text(i) != v:
                        item.setText(i, v)
                # Re-parent if group changed
                target_parent = self._groups.get(group_name, self._groups["Background Processes"])
                if item.parent() != target_parent:
                    item.parent().removeChild(item)
                    target_parent.addChild(item)
            else:
                # Create as type-aware custom QTreeWidgetItem subclass
                item = ProcessTreeWidgetItem(self._groups.get(group_name, self._groups["Background Processes"]), values)

                # Queue icon load (one per 100ms batch tick, not per-process QTimer flood)
                if path:
                    if path in self._icon_cache:
                        item.setIcon(0, self._icon_cache[path])
                    else:
                        item.setIcon(0, self._default_app_icon)
                        self._icon_load_queue.append((path, item))
                else:
                    item.setIcon(0, self._default_app_icon)
            
            # Apply dynamic colors to status cell (column 8)
            color_map = {
                "Suspicious": QColor("#EF4444"),
                "Safe": QColor("#10B981"),
                "Terminating...": QColor("#fbbf24"),
                "Terminated": QColor("#10B981"),
                "Failed": QColor("#EF4444"),
                "Access Denied": QColor("#EF4444"),
                "Protected Process": QColor("#EF4444")
            }
            c = color_map.get(status)
            if c:
                item.setForeground(8, c)

            # Mark that sort data changed (only sort when actually needed)
            self._sort_dirty = True
            
        # Clean up dead processes
        for pid, item in existing_items.items():
            if pid not in active_pids:
                if item.parent():
                    item.parent().removeChild(item)
                self._sort_dirty = True

        # Sort children ONLY when data actually changed (sort_dirty flag)
        if self._sort_dirty:
            for g_item in self._groups.values():
                g_item.sortChildren(self._sort_column, self._sort_order)
            self._sort_dirty = False

        # Restore Selection without triggering event loops
        self._tree.blockSignals(True)
        for g_item in self._groups.values():
            for i in range(g_item.childCount()):
                child = g_item.child(i)
                pid_str = child.text(1)
                if pid_str.isdigit() and int(pid_str) in selected_pids:
                    child.setSelected(True)
        self._tree.blockSignals(False)

    def _on_header_clicked(self, logical_index: int) -> None:
        """Trigger sorted order updates when clicking columns."""
        if logical_index == self._sort_column:
            self._sort_order = (
                Qt.SortOrder.AscendingOrder 
                if self._sort_order == Qt.SortOrder.DescendingOrder 
                else Qt.SortOrder.DescendingOrder
            )
        else:
            self._sort_column = logical_index
            self._sort_order = Qt.SortOrder.DescendingOrder
        
        self._tree.header().setSortIndicator(self._sort_column, self._sort_order)
        
        # Force re-sort instantly
        for g_item in self._groups.values():
            g_item.sortChildren(self._sort_column, self._sort_order)

    def _on_search_changed(self, text: str):
        self._filter_text = text.lower()
        self._refresh_tree()

    def _on_group_changed(self, text: str):
        self._filter_group = text
        self._refresh_tree()

    def _on_selection_changed(self):
        valid_items = []
        for i in self._tree.selectedItems():
            pid_str = i.text(1)
            if pid_str.isdigit():
                pid = int(pid_str)
                state = self._process_states.get(pid, "")
                if state not in ("Terminating...", "Terminated", "Failed", "Access Denied", "Protected Process"):
                    valid_items.append(i)
        self._btn_terminate.setEnabled(len(valid_items) > 0)

    def _on_terminate_click(self):
        items = self._tree.selectedItems()
        if not items: 
            return
        
        for item in items:
            pid_str = item.text(1)
            if not pid_str.isdigit(): 
                continue
            
            pid = int(pid_str)
            name = item.text(0)
            
            reply = QMessageBox.question(
                self, "Terminate Process",
                f"Are you sure you want to terminate {name} (PID: {pid})?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.set_process_status(pid, "Terminating...")
                self.terminate_process_requested.emit(pid, name)

    def set_process_status(self, pid: int, status: str) -> None:
        """Instantly register custom process state and update cell text/color."""
        self._process_states[pid] = status
        
        for g_item in self._groups.values():
            for i in range(g_item.childCount()):
                child = g_item.child(i)
                pid_str = child.text(1)
                if pid_str.isdigit() and int(pid_str) == pid:
                    child.setText(8, status)
                    color_map = {
                        "Terminating...": QColor("#fbbf24"),
                        "Terminated": QColor("#10B981"),
                        "Failed": QColor("#EF4444"),
                        "Access Denied": QColor("#EF4444"),
                        "Protected Process": QColor("#EF4444")
                    }
                    c = color_map.get(status)
                    if c:
                        child.setForeground(8, c)
                    break
        
        self._on_selection_changed()

    def _on_context_menu(self, pos):
        item = self._tree.itemAt(pos)
        if not item or not item.text(1).isdigit(): 
            return
        
        menu = QMenu()
        term_action = menu.addAction("End Task")
        open_action = menu.addAction("Open File Location")
        
        action = menu.exec(self._tree.viewport().mapToGlobal(pos))
        if action == term_action:
            self._on_terminate_click()
        elif action == open_action:
            path = item.text(9)
            if path:
                try: 
                    os.startfile(os.path.dirname(path))
                except Exception: 
                    pass
