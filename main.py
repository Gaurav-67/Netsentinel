import sys
from collections import Counter, deque

from PyQt5.QtCore import QTimer, Qt, QAbstractTableModel, QModelIndex, QSortFilterProxyModel
from PyQt5.QtGui import QFontDatabase
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QComboBox, QTabWidget, QTableWidget, QTableWidgetItem, QTableView, QPlainTextEdit,
    QMessageBox, QSplitter, QAbstractItemView, QHeaderView, QLabel, QLineEdit,
    QFileDialog)
from scapy.all import rdpcap
from scapy.utils import hexdump

from sniffer import PacketSniffer, parse, rebuild, write_pcap
from detector import Detector
from flows import FlowTable
from dashboard import Dashboard, service_of

APP_NAME = "NetSentinel"
APP_VERSION = "v0.2"
MAX_ROWS = 100000         # packets kept in memory / table (1 lakh)
BATCH = 500               # max packets added to the table per refresh
PROTOS = ["TCP", "UDP", "ICMP", "Other"]

# ------------------------------------------------------------------ themes
DARK = dict(bg="#0d1117", panel="#161b22", alt="#1b2129", btn="#21262d", hover="#30363d",
            border="#30363d", text="#e6edf3", muted="#8b949e", header="#1f2630", accent="#1f6feb")
LIGHT = dict(bg="#f6f8fa", panel="#ffffff", alt="#f3f5f7", btn="#eaeef2", hover="#d8dee4",
             border="#d0d7de", text="#1f2328", muted="#656d76", header="#eaeef2", accent="#0969da")


def make_style(c):
    return f"""
    QWidget {{ background:{c['bg']}; color:{c['text']}; font-family:'Segoe UI','Inter','Arial'; font-size:13px; }}
    QPushButton {{ background:{c['btn']}; border:1px solid {c['border']}; border-radius:6px; padding:7px 14px; }}
    QPushButton:hover {{ background:{c['hover']}; border-color:{c['accent']}; }}
    QPushButton:pressed {{ background:{c['accent']}; color:#ffffff; padding-top:9px; padding-bottom:5px; }}
    QPushButton:checked {{ background:{c['accent']}; color:#ffffff; border-color:{c['accent']}; }}
    QPushButton:disabled {{ background:{c['bg']}; color:{c['muted']}; border-color:{c['border']}; }}
    QPushButton#startBtn {{ background:#238636; border-color:#2ea043; color:#ffffff; font-weight:600; }}
    QPushButton#startBtn:hover {{ background:#2ea043; }}
    QPushButton#startBtn:pressed {{ background:#196c2e; }}
    QPushButton#stopBtn {{ background:#da3633; border-color:#f85149; color:#ffffff; font-weight:600; }}
    QPushButton#stopBtn:hover {{ background:#f85149; }}
    QPushButton#stopBtn:pressed {{ background:#a62522; }}
    QPushButton#startBtn:disabled, QPushButton#stopBtn:disabled {{ background:{c['bg']}; color:{c['muted']}; border-color:{c['border']}; }}
    QComboBox, QLineEdit, QPlainTextEdit {{ background:{c['panel']}; border:1px solid {c['border']}; border-radius:6px; padding:6px; }}
    QComboBox:hover, QLineEdit:focus {{ border-color:{c['accent']}; }}
    QComboBox QAbstractItemView {{ background:{c['panel']}; selection-background-color:{c['accent']}; selection-color:#ffffff; }}
    QTableView, QTableWidget {{ background:{c['panel']}; alternate-background-color:{c['alt']}; gridline-color:{c['border']};
        border:1px solid {c['border']}; selection-background-color:{c['accent']}; selection-color:#ffffff; }}
    QHeaderView::section {{ background:{c['header']}; color:{c['text']}; padding:7px; border:none;
        border-right:1px solid {c['border']}; border-bottom:1px solid {c['border']}; font-weight:600; }}
    QTabWidget::pane {{ border:1px solid {c['border']}; border-radius:6px; top:-1px; }}
    QTabBar::tab {{ background:{c['btn']}; color:{c['muted']}; padding:8px 18px; border:1px solid {c['border']};
        border-bottom:none; border-top-left-radius:6px; border-top-right-radius:6px; margin-right:2px; }}
    QTabBar::tab:selected {{ background:{c['panel']}; color:{c['text']}; border-bottom:2px solid {c['accent']}; }}
    QTabBar::tab:hover {{ color:{c['text']}; }}
    QScrollBar:vertical {{ width:11px; background:transparent; }}
    QScrollBar::handle:vertical {{ background:{c['border']}; border-radius:5px; min-height:30px; }}
    QScrollBar:horizontal {{ height:11px; background:transparent; }}
    QScrollBar::handle:horizontal {{ background:{c['border']}; border-radius:5px; min-width:30px; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ width:0; height:0; }}
    QLabel#title {{ font-size:20px; font-weight:700; }}
    QLabel#subtitle {{ color:{c['muted']}; font-size:12px; padding-top:6px; }}
    QLabel#status {{ color:{c['muted']}; padding:4px 2px; }}
    QLabel#dashTitle {{ font-size:17px; font-weight:700; }}
    QFrame#card {{ background:{c['panel']}; border:1px solid {c['border']}; border-radius:10px; }}
    QFrame#card QLabel {{ background:transparent; }}
    QLabel#cardTitle {{ color:{c['muted']}; font-size:11px; font-weight:700; letter-spacing:1px; }}
    QLabel#kpiValue {{ font-size:28px; font-weight:700; }}
    QLabel#cardNote {{ color:{c['muted']}; font-size:11px; }}
    QSplitter::handle {{ background:{c['border']}; height:2px; }}
    """


def table(headers):
    """Small table for low-volume data (alerts, flows)."""
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setSelectionMode(QAbstractItemView.SingleSelection)
    t.setAlternatingRowColors(True)
    t.verticalHeader().setVisible(False)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
    return t


def mono_box():
    b = QPlainTextEdit()
    b.setReadOnly(True)
    b.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
    return b


class PacketModel(QAbstractTableModel):
    """Fast model for the packet table (adds rows in batches)."""
    HEAD = ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Information"]
    KEYS = ["no", "time", "src", "dst", "proto", "len", "info"]

    def __init__(self):
        super().__init__()
        self.rows = []

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.KEYS)

    def data(self, index, role=Qt.DisplayRole):
        if role == Qt.DisplayRole:
            return str(self.rows[index.row()][self.KEYS[index.column()]])
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.HEAD[section]
        return None

    def append(self, batch):
        n = len(self.rows)
        self.beginInsertRows(QModelIndex(), n, n + len(batch) - 1)
        self.rows.extend(batch)
        self.endInsertRows()

    def trim(self, keep):
        extra = len(self.rows) - keep
        if extra > 0:
            self.beginRemoveRows(QModelIndex(), 0, extra - 1)
            del self.rows[:extra]
            self.endRemoveRows()

    def reset(self):
        self.beginResetModel()
        self.rows = []
        self.endResetModel()


class PacketFilter(QSortFilterProxyModel):
    """Protocol buttons + search box filtering."""

    def __init__(self):
        super().__init__()
        self.protos = {"TCP", "UDP", "ICMP"}
        self.text = ""

    def filterAcceptsRow(self, row, parent):
        p = self.sourceModel().rows[row]
        if p["proto"] in ("TCP", "UDP", "ICMP") and p["proto"] not in self.protos:
            return False
        if self.text:
            hay = f"{p['src']} {p['dst']} {p['proto']} {p['app']} {p['info']}".lower()
            return self.text in hay
        return True


class Main(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {APP_VERSION} - Network Packet Analyzer & Intrusion Detection")
        self.resize(1250, 760)
        self.alerts, self.counts = [], Counter()
        self.colors = DARK
        self.idle_secs = 0
        self.pkt_no = 0
        self.total_bytes, self.last_total = 0, 0
        self.talkers, self.services = Counter(), Counter()
        self.pps_hist = deque([0] * 60, maxlen=60)
        self.sniffer, self.detector, self.flows = PacketSniffer(), Detector(), FlowTable()
        self.model = PacketModel()
        self.proxy = PacketFilter()
        self.proxy.setSourceModel(self.model)

        root = QWidget()
        self.setCentralWidget(root)
        lay = QVBoxLayout(root)
        lay.setContentsMargins(14, 10, 14, 8)
        lay.setSpacing(8)

        # ---- header ----
        head = QHBoxLayout()
        title = QLabel(APP_NAME)
        title.setObjectName("title")
        sub = QLabel("Network Packet Analyzer & Intrusion Detection System")
        sub.setObjectName("subtitle")
        self.b_theme = QPushButton("Switch Theme (Dark / Light)")
        self.b_theme.clicked.connect(self.toggle_theme)
        head.addWidget(title)
        head.addWidget(sub)
        head.addStretch()
        head.addWidget(self.b_theme)
        lay.addLayout(head)

        # ---- toolbar ----
        bar = QHBoxLayout()
        self.b_start = QPushButton("▶  Start Capture")
        self.b_stop = QPushButton("■  Stop Capture")
        self.b_clear = QPushButton("Clear All")
        self.b_save = QPushButton("Save PCAP")
        self.b_open = QPushButton("Open PCAP")
        self.b_start.setObjectName("startBtn")
        self.b_stop.setObjectName("stopBtn")
        self.iface = QComboBox()
        self.iface.setMinimumWidth(340)
        self.load_ifaces()
        self.b_stop.setEnabled(False)
        self.b_start.clicked.connect(self.start)
        self.b_stop.clicked.connect(self.stop)
        self.b_clear.clicked.connect(self.clear)
        self.b_save.clicked.connect(self.save_pcap)
        self.b_open.clicked.connect(self.open_pcap)
        for w in (self.b_start, self.b_stop, self.b_clear, self.b_save, self.b_open,
                  QLabel("Network Interface:"), self.iface):
            bar.addWidget(w)
        bar.addStretch()
        lay.addLayout(bar)

        self.tabs = QTabWidget()
        lay.addWidget(self.tabs, 1)
        self.tabs.addTab(self.packets_tab(), "Packets")
        self.tabs.addTab(self.flows_tab(), "Flows")
        self.tabs.addTab(self.alerts_tab(), "Alerts")
        self.dash = Dashboard()
        self.tabs.addTab(self.dash, "Dashboard")
        self.tabs.currentChanged.connect(lambda _: self.refresh_dashboard())

        # ---- status row ----
        srow = QHBoxLayout()
        self.status = QLabel("Ready. Choose a network interface and press Start Capture.")
        self.status.setObjectName("status")
        self.state_lbl = QLabel()
        self.set_state("● Idle", "muted")
        srow.addWidget(self.status, 1)
        srow.addWidget(self.state_lbl)
        lay.addLayout(srow)

        # packets are pulled from the capture queue in small batches
        self.drain_timer = QTimer(self)
        self.drain_timer.timeout.connect(self.drain)
        self.drain_timer.start(100)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.start(1000)
        self.apply_theme()

    # ---------- theme ----------
    def apply_theme(self):
        c = self.colors
        self.setStyleSheet(make_style(c))
        self.dash.set_theme(c)

    def toggle_theme(self):
        self.colors = LIGHT if self.colors is DARK else DARK
        self.apply_theme()

    def set_state(self, text, kind):
        color = {"green": "#3fb950", "red": "#f85149", "muted": "#8b949e"}[kind]
        self.state_lbl.setText(text)
        self.state_lbl.setStyleSheet(f"color:{color}; font-weight:700; padding:4px 6px;")

    # ---------- tabs ----------
    def packets_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        row = QHBoxLayout()
        self.filters = {}
        for p in ("TCP", "UDP", "ICMP"):
            b = QPushButton(p)
            b.setCheckable(True)
            b.setChecked(True)
            b.setToolTip(f"Show / hide {p} packets")
            b.clicked.connect(self.apply_filter)
            self.filters[p] = b
            row.addWidget(b)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search by IP address, domain or keyword (e.g. google, 8.8.8.8, HTTP)")
        self.search.textChanged.connect(self.apply_filter)
        row.addWidget(self.search, 1)
        v.addLayout(row)

        split = QSplitter(Qt.Vertical)
        self.ptable = QTableView()
        self.ptable.setModel(self.proxy)
        self.ptable.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.ptable.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.ptable.setSelectionMode(QAbstractItemView.SingleSelection)
        self.ptable.setAlternatingRowColors(True)
        self.ptable.setShowGrid(False)
        self.ptable.verticalHeader().setVisible(False)
        self.ptable.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.ptable.verticalHeader().setDefaultSectionSize(24)
        self.ptable.horizontalHeader().setStretchLastSection(True)
        for c, wd in enumerate([75, 90, 160, 160, 90, 80]):
            self.ptable.setColumnWidth(c, wd)
        self.ptable.selectionModel().selectionChanged.connect(self.show_detail)

        bottom = QTabWidget()
        self.detail, self.hex = mono_box(), mono_box()
        self.detail.setPlaceholderText("Select a packet to see its layer-by-layer details")
        self.hex.setPlaceholderText("Select a packet to see its hexadecimal and ASCII view")
        bottom.addTab(self.detail, "Packet Details")
        bottom.addTab(self.hex, "Hex View")
        split.addWidget(self.ptable)
        split.addWidget(bottom)
        split.setSizes([430, 220])
        v.addWidget(split)
        return w

    def flows_tab(self):
        self.ftable = table(["Protocol", "Endpoint A", "Endpoint B", "Application",
                             "Packets", "Bytes", "Duration (seconds)"])
        return self.ftable

    def alerts_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        row = QHBoxLayout()
        self.t_scan = self.toggle_btn("Port Scan Detection", "scan")
        self.t_syn = self.toggle_btn("SYN Flood Detection", "syn")
        b_det = QPushButton("Alert Details")
        b_clr = QPushButton("Clear Alerts")
        b_det.clicked.connect(self.alert_details)
        b_clr.clicked.connect(self.clear_alerts)
        for b in (self.t_scan, self.t_syn, b_det, b_clr):
            row.addWidget(b)
        row.addStretch()
        v.addLayout(row)
        self.atable = table(["Time", "Severity", "Attack Name", "Source IP Address", "MITRE ATT&CK ID"])
        v.addWidget(self.atable)
        return w

    def toggle_btn(self, label, key):
        b = QPushButton(f"{label}: ON")
        b.setCheckable(True)
        b.setChecked(True)

        def flip(on):
            self.detector.enabled[key] = on
            b.setText(f"{label}: {'ON' if on else 'OFF'}")
        b.clicked.connect(flip)
        return b

    # ---------- capture buttons ----------
    def load_ifaces(self):
        """Friendly interface names (Wi-Fi, Ethernet...) with IP, active ones first."""
        from scapy.all import conf
        items = []
        for i in conf.ifaces.values():
            net = getattr(i, "network_name", None) or i.name
            ip = getattr(i, "ip", "") or ""
            ok = ip not in ("", "0.0.0.0")
            items.append((ok, f"{i.name} - {ip}" if ok else f"{i.name} (no IP)", net))
        items.sort(key=lambda x: not x[0])
        for _, label, net in items:
            self.iface.addItem(label, net)
        default = getattr(conf.iface, "network_name", None) or str(conf.iface)
        idx = self.iface.findData(default)
        if idx >= 0:
            self.iface.setCurrentIndex(idx)

    def start(self):
        try:
            self.sniffer.start(self.iface.currentData())
        except Exception as e:
            QMessageBox.warning(self, "Start Capture", f"Could not start capture:\n{e}")
            return
        self.idle_secs = 0
        self.b_start.setEnabled(False)
        self.b_stop.setEnabled(True)
        self.iface.setEnabled(False)
        self.set_state("● Capturing", "green")
        self.status.setText("Capturing packets...")

    def stop(self):
        self.sniffer.stop()
        self.b_start.setEnabled(True)
        self.b_stop.setEnabled(False)
        self.iface.setEnabled(True)
        self.drain()
        self.set_state("● Stopped", "red")
        self.status.setText(f"Stopped. Total packets: {sum(self.counts.values()):,} | Alerts: {len(self.alerts)}")

    def clear(self):
        self.sniffer.queue.clear()
        self.model.reset()
        self.counts.clear()
        self.flows.clear()
        self.pkt_no = 0
        self.total_bytes, self.last_total = 0, 0
        self.talkers.clear()
        self.services.clear()
        self.pps_hist.extend([0] * 60)
        self.ftable.setRowCount(0)
        self.detail.clear()
        self.hex.clear()
        self.status.setText("Cleared. All packets and flows removed.")

    def clear_alerts(self):
        self.atable.setRowCount(0)
        self.alerts.clear()

    # ---------- PCAP ----------
    def save_pcap(self):
        if not self.model.rows:
            QMessageBox.information(self, "Save PCAP", "There are no packets to save yet.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save PCAP", "capture.pcap", "PCAP (*.pcap)")
        if path:
            write_pcap(path, self.model.rows)
            self.status.setText(f"Saved {len(self.model.rows):,} packets to {path}")

    def open_pcap(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open PCAP", "", "Capture files (*.pcap *.pcapng)")
        if not path:
            return
        if self.b_stop.isEnabled():
            self.stop()
        try:
            pkts = rdpcap(path)
        except Exception as e:
            QMessageBox.warning(self, "Open PCAP", f"Could not read the file:\n{e}")
            return
        self.clear()
        self.clear_alerts()
        self.detector.reset()
        limit = min(len(pkts), MAX_ROWS)
        self.add_batch([parse(p) for p in pkts[:limit]], live=False)
        extra = f" (first {limit:,} of {len(pkts):,} packets shown)" if len(pkts) > limit else ""
        self.status.setText(f"Loaded {path}{extra} | Alerts: {len(self.alerts)}")
        self.last_total = sum(self.counts.values())
        self.set_state("● File loaded", "muted")
        self.refresh_flows()

    # ---------- filters / search ----------
    def apply_filter(self, *_):
        self.proxy.protos = {k for k, b in self.filters.items() if b.isChecked()}
        self.proxy.text = self.search.text().strip().lower()
        self.proxy.invalidateFilter()

    # ---------- packet flow (batched) ----------
    def drain(self):
        q = self.sniffer.queue
        batch = []
        while q and len(batch) < BATCH:
            batch.append(q.popleft())
        if batch:
            self.add_batch(batch, live=True)

    def add_batch(self, batch, live=True):
        sb = self.ptable.verticalScrollBar()
        at_bottom = sb.value() >= sb.maximum() - 2
        for p in batch:
            self.pkt_no += 1
            p["no"] = self.pkt_no
            self.counts[p["proto"] if p["proto"] in PROTOS else "Other"] += 1
            self.flows.update(p)
            self.total_bytes += p["len"]
            if p["src"] != "-":
                self.talkers[p["src"]] += p["len"]
            svc = service_of(p)
            if svc:
                self.services[svc] += 1
            for a in self.detector.check(p):
                self.add_alert(a)
        if len(self.talkers) > 5000:
            self.talkers = Counter(dict(self.talkers.most_common(1000)))
        self.model.append(batch)
        self.model.trim(MAX_ROWS)
        if live and at_bottom:
            self.ptable.scrollToBottom()
        if live:
            self.status.setText(f"Capturing... Total packets: {sum(self.counts.values()):,} | Alerts: {len(self.alerts)}")

    def add_alert(self, a):
        self.alerts.append(a)
        r = self.atable.rowCount()
        self.atable.insertRow(r)
        for c, k in enumerate(["time", "severity", "name", "src", "mitre"]):
            self.atable.setItem(r, c, QTableWidgetItem(a[k]))

    def show_detail(self, *_):
        rows = self.ptable.selectionModel().selectedRows()
        if not rows:
            return
        src = self.proxy.mapToSource(rows[0]).row()
        if 0 <= src < len(self.model.rows):
            raw = rebuild(self.model.rows[src])
            self.detail.setPlainText(raw.show(dump=True))
            self.hex.setPlainText(hexdump(raw, dump=True))

    def alert_details(self):
        rows = self.atable.selectionModel().selectedRows()
        if not rows:
            QMessageBox.information(self, "Alert Details", "Please select an alert first.")
            return
        a = self.alerts[rows[0].row()]
        QMessageBox.information(
            self, a["name"],
            f"Severity: {a['severity']}\nMITRE ATT&CK ID: {a['mitre']}\n\n"
            f"{a['desc']}\n\nRecommended action:\n{a['action']}")

    # ---------- periodic refresh ----------
    def tick(self):
        total = sum(self.counts.values())
        self.pps_hist.append(max(0, total - self.last_total))
        self.last_total = total
        if self.b_stop.isEnabled() and sum(self.counts.values()) == 0:
            self.idle_secs += 1
            if self.idle_secs >= 5:
                self.status.setText("Capturing, but no packets yet. Press Stop Capture and try a different network interface.")
        if self.tabs.currentWidget() is self.ftable:
            self.refresh_flows()
        elif self.tabs.currentWidget() is self.dash:
            self.refresh_dashboard()

    def refresh_dashboard(self):
        self.dash.update_data(sum(self.counts.values()), self.pps_hist, self.total_bytes,
                              len(self.flows.flows), self.alerts, self.counts,
                              self.talkers, self.services)

    def refresh_flows(self):
        rows = self.flows.top(200)
        self.ftable.setRowCount(len(rows))
        for r, f in enumerate(rows):
            vals = [f["proto"], f"{f['a'][0]}:{f['a'][1]}", f"{f['b'][0]}:{f['b'][1]}",
                    f["app"], f["pkts"], f["bytes"], f"{f['last'] - f['start']:.1f}"]
            for c, v in enumerate(vals):
                self.ftable.setItem(r, c, QTableWidgetItem(str(v)))

    def closeEvent(self, e):
        self.sniffer.stop()
        e.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = Main()
    win.show()
    sys.exit(app.exec_())
