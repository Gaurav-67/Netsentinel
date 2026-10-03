import time

import pyqtgraph as pg
from PyQt5.QtCore import Qt, QRectF
from PyQt5.QtGui import QPainter, QColor, QPen, QFont, QFontMetrics
from PyQt5.QtWidgets import QWidget, QFrame, QVBoxLayout, QHBoxLayout, QLabel

PROTOS = ["TCP", "UDP", "ICMP", "Other"]
PROTO_COLORS = {"TCP": "#1f6feb", "UDP": "#2ea043", "ICMP": "#d29922", "Other": "#8957e5"}
SEVERITY_COLORS = {"High": "#f85149", "Medium": "#d29922", "Low": "#3fb950"}

SERVICES = {
    80: "HTTP (80)", 443: "HTTPS / QUIC (443)", 53: "DNS (53)", 22: "SSH (22)",
    21: "FTP (21)", 23: "Telnet (23)", 25: "SMTP (25)", 110: "POP3 (110)",
    123: "NTP (123)", 143: "IMAP (143)", 445: "SMB (445)", 3389: "RDP (3389)",
    5353: "mDNS (5353)", 1900: "SSDP (1900)", 67: "DHCP (67)", 68: "DHCP (68)",
    8080: "HTTP-Alt (8080)",
}


def human_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def service_of(p):
    """Name of the service a packet belongs to (used for 'Top Services')."""
    if p["proto"] in ("ICMP", "ARP"):
        return p["proto"]
    if p["dport"] is None:
        return None
    for port in (p["dport"], p["sport"]):
        if port in SERVICES:
            return SERVICES[port]
    return "Other / dynamic ports"


class HBarWidget(QWidget):
    """Horizontal bar list: label | bar | value."""

    def __init__(self, empty_text="No data yet"):
        super().__init__()
        self.items, self.c, self.empty_text = [], None, empty_text
        self.setMinimumHeight(200)

    def set_data(self, items):
        self.items = items          # (label, value, value_text, color or None)
        self.update()

    def set_colors(self, c):
        self.c = c
        self.update()

    def paintEvent(self, _):
        if not self.c:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        if not self.items:
            p.setPen(QColor(self.c["muted"]))
            p.drawText(self.rect(), Qt.AlignCenter, self.empty_text)
            return
        n = len(self.items)
        row_h = min(34.0, h / n)
        label_w, value_w = min(150, int(w * 0.36)), 60
        bar_x, bar_w = label_w + 8, max(20, w - label_w - value_w - 20)
        mx = max(v for _, v, _, _ in self.items) or 1
        fm = QFontMetrics(p.font())
        for i, (label, val, vtxt, color) in enumerate(self.items):
            y = i * row_h
            cy = y + row_h / 2
            p.setPen(QColor(self.c["text"]))
            p.drawText(QRectF(0, y, label_w, row_h), Qt.AlignVCenter | Qt.AlignLeft,
                       fm.elidedText(label, Qt.ElideRight, label_w))
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(self.c["border"]))
            p.drawRoundedRect(QRectF(bar_x, cy - 6, bar_w, 12), 6, 6)
            if val > 0:
                p.setBrush(QColor(color or self.c["accent"]))
                p.drawRoundedRect(QRectF(bar_x, cy - 6, max(8.0, bar_w * val / mx), 12), 6, 6)
            p.setPen(QColor(self.c["muted"]))
            p.drawText(QRectF(w - value_w, y, value_w, row_h), Qt.AlignVCenter | Qt.AlignRight, vtxt)


class DonutWidget(QWidget):
    """Protocol distribution ring with a legend."""

    def __init__(self):
        super().__init__()
        self.data, self.c = {}, None
        self.setMinimumHeight(200)

    def set_data(self, data):
        self.data = data
        self.update()

    def set_colors(self, c):
        self.c = c
        self.update()

    def paintEvent(self, _):
        if not self.c:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        side = max(60, min(h - 10, int(w * 0.5)))
        th = max(14, side // 7)
        left, top = 8, (h - side) / 2
        rect = QRectF(left + th / 2, top + th / 2, side - th, side - th)
        total = sum(self.data.values())

        pen = QPen(QColor(self.c["border"]), th)
        p.setPen(pen)
        p.drawArc(rect, 0, 360 * 16)
        if total:
            start = 90 * 16
            for name in PROTOS:
                n = self.data.get(name, 0)
                if n:
                    span = -int(round(n / total * 360 * 16))
                    p.setPen(QPen(QColor(PROTO_COLORS[name]), th, Qt.SolidLine, Qt.FlatCap))
                    p.drawArc(rect, start, span)
                    start += span

        big = QFont(self.font())
        big.setPointSize(15)
        big.setBold(True)
        p.setFont(big)
        p.setPen(QColor(self.c["text"]))
        p.drawText(QRectF(left, top, side, side / 2 + 6), Qt.AlignCenter | Qt.AlignBottom, f"{total:,}")
        small = QFont(self.font())
        small.setPointSize(9)
        p.setFont(small)
        p.setPen(QColor(self.c["muted"]))
        p.drawText(QRectF(left, top + side / 2 + 6, side, side / 2), Qt.AlignHCenter | Qt.AlignTop, "packets")

        lx = left + side + 34
        row = 32
        y0 = (h - row * len(PROTOS)) / 2
        p.setFont(self.font())
        for i, name in enumerate(PROTOS):
            n = self.data.get(name, 0)
            pct = (n / total * 100) if total else 0
            y = y0 + i * row
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(PROTO_COLORS[name]))
            p.drawRoundedRect(QRectF(lx, y + 9, 12, 12), 3, 3)
            p.setPen(QColor(self.c["text"]))
            p.drawText(QRectF(lx + 22, y, 70, row), Qt.AlignVCenter, name)
            p.setPen(QColor(self.c["muted"]))
            p.drawText(QRectF(lx + 92, y, max(60, w - lx - 100), row), Qt.AlignVCenter,
                       f"{pct:.1f}%   ({n:,})")


class Dashboard(QWidget):
    def __init__(self):
        super().__init__()
        self.c = None
        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(12)

        # header
        head = QHBoxLayout()
        t = QLabel("Security Operations Dashboard")
        t.setObjectName("dashTitle")
        s = QLabel("Live overview of network traffic and security alerts")
        s.setObjectName("subtitle")
        self.updated = QLabel("")
        self.updated.setObjectName("subtitle")
        head.addWidget(t)
        head.addWidget(s)
        head.addStretch()
        head.addWidget(self.updated)
        root.addLayout(head)

        # KPI row
        kpis = QHBoxLayout()
        kpis.setSpacing(12)
        self.k_total = self._kpi(kpis, "TOTAL PACKETS", "captured in this session")
        self.k_pps = self._kpi(kpis, "PACKETS / SECOND", "current traffic rate")
        self.k_bytes = self._kpi(kpis, "DATA TRANSFERRED", "total volume observed")
        self.k_flows = self._kpi(kpis, "ACTIVE FLOWS", "unique conversations")
        self.k_alerts = self._kpi(kpis, "SECURITY ALERTS", "see the Alerts tab")
        root.addLayout(kpis)

        # middle row: traffic graph + protocol donut
        mid = QHBoxLayout()
        mid.setSpacing(12)
        f1, l1 = self._card("TRAFFIC RATE  (packets per second, last 60 seconds)")
        self.plot = pg.PlotWidget()
        self.plot.setMouseEnabled(False, False)
        self.plot.setMenuEnabled(False)
        self.plot.hideButtons()
        self.plot.showGrid(x=False, y=True, alpha=0.15)
        self.plot.setLabel("bottom", "seconds ago", **{"font-size": "9pt"})
        small = QFont()
        small.setPointSize(8)
        for ax in ("bottom", "left"):
            self.plot.getAxis(ax).setStyle(tickFont=small)
        self.plot.getAxis("left").setWidth(40)
        self.plot.setXRange(-59, 0, padding=0)
        self.curve = self.plot.plot([], [], pen=pg.mkPen("#1f6feb", width=2),
                                    fillLevel=0, brush=(31, 111, 235, 55))
        l1.addWidget(self.plot)
        f2, l2 = self._card("PROTOCOL DISTRIBUTION")
        self.donut = DonutWidget()
        l2.addWidget(self.donut)
        mid.addWidget(f1, 3)
        mid.addWidget(f2, 2)
        root.addLayout(mid, 3)

        # bottom row: top talkers, services, alerts by severity
        bot = QHBoxLayout()
        bot.setSpacing(12)
        f3, l3 = self._card("TOP TALKERS  (source IP by data volume)")
        self.talkers = HBarWidget("Waiting for traffic...")
        l3.addWidget(self.talkers)
        f4, l4 = self._card("TOP SERVICES  (packets)")
        self.services = HBarWidget("Waiting for traffic...")
        l4.addWidget(self.services)
        f5, l5 = self._card("ALERTS BY SEVERITY")
        self.severity = HBarWidget("No alerts detected")
        l5.addWidget(self.severity)
        bot.addWidget(f3, 3)
        bot.addWidget(f4, 3)
        bot.addWidget(f5, 2)
        root.addLayout(bot, 3)

    # ---- builders ----
    def _card(self, title):
        f = QFrame()
        f.setObjectName("card")
        lay = QVBoxLayout(f)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(8)
        lbl = QLabel(title)
        lbl.setObjectName("cardTitle")
        lay.addWidget(lbl)
        return f, lay

    def _kpi(self, parent, title, note):
        f, lay = self._card(title)
        val = QLabel("0")
        val.setObjectName("kpiValue")
        n = QLabel(note)
        n.setObjectName("cardNote")
        lay.addWidget(val)
        lay.addWidget(n)
        parent.addWidget(f, 1)
        return val

    # ---- theme / data ----
    def set_theme(self, c):
        self.c = c
        self.plot.setBackground(c["panel"])
        for ax in ("bottom", "left"):
            self.plot.getAxis(ax).setPen(c["border"])
            self.plot.getAxis(ax).setTextPen(c["muted"])
        for w in (self.donut, self.talkers, self.services, self.severity):
            w.set_colors(c)

    def update_data(self, total, pps_hist, total_bytes, flows, alerts, counts, talkers, services):
        self.k_total.setText(f"{total:,}")
        self.k_pps.setText(f"{pps_hist[-1]:,}")
        self.k_bytes.setText(human_bytes(total_bytes))
        self.k_flows.setText(f"{flows:,}")
        self.k_alerts.setText(f"{len(alerts):,}")
        self.k_alerts.setStyleSheet("color:#f85149;" if alerts else "")
        self.curve.setData(list(range(-len(pps_hist) + 1, 1)), list(pps_hist))
        self.plot.setYRange(0, max(10, max(pps_hist) * 1.2), padding=0)
        self.donut.set_data({p: counts.get(p, 0) for p in PROTOS})
        self.talkers.set_data([(ip, b, human_bytes(b), None) for ip, b in talkers.most_common(8)])
        self.services.set_data([(name, n, f"{n:,}", None) for name, n in services.most_common(8)])
        sev = {"High": 0, "Medium": 0, "Low": 0}
        for a in alerts:
            sev[a["severity"]] = sev.get(a["severity"], 0) + 1
        self.severity.set_data([(k, v, str(v), SEVERITY_COLORS.get(k)) for k, v in sev.items()] if alerts else [])
        self.updated.setText("Last updated: " + time.strftime("%H:%M:%S"))
