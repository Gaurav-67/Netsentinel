import struct
import time
from collections import deque
from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP, ICMP, ARP, Raw, DNS, DNSQR

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ")


def http_info(payload):
    """Return (info, host) if payload looks like an HTTP request/response."""
    if not (payload.startswith(HTTP_METHODS) or payload.startswith(b"HTTP/1.")):
        return None, ""
    head = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1", "ignore")
    lines = head.split("\r\n")
    host = next((l[5:].strip() for l in lines[1:] if l.lower().startswith("host:")), "")
    info = "HTTP " + lines[0][:80] + (f" | Host: {host}" if host else "")
    return info, host


def rebuild(p):
    """Rebuild the full scapy packet from stored bytes (only when needed)."""
    pkt = p["cls"](p["raw"])
    pkt.time = p["ts"]
    return pkt


def write_pcap(path, rows):
    """Fast PCAP writer straight from stored bytes (works for 1 lakh+ packets)."""
    from scapy.all import conf
    link = conf.l2types.layer2num.get(rows[0]["cls"], 1)
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link))
        for p in rows:
            sec = int(p["ts"])
            usec = int((p["ts"] - sec) * 1_000_000)
            b = p["raw"]
            f.write(struct.pack("<IIII", sec, usec, len(b), len(b)))
            f.write(b)


def parse(pkt):
    """Scapy packet -> simple dict used by GUI, flows and detector."""
    ts = float(pkt.time)
    d = {
        "ts": ts, "time": time.strftime("%H:%M:%S", time.localtime(ts)),
        "src": "-", "dst": "-", "proto": "OTHER", "len": len(pkt),
        "sport": None, "dport": None, "flags": "", "info": "",
        "app": "", "dns": "", "http_host": "", "raw": bytes(pkt), "cls": pkt.__class__,
    }
    if pkt.haslayer(IP):
        d["src"], d["dst"] = pkt[IP].src, pkt[IP].dst
    elif pkt.haslayer(IPv6):
        d["src"], d["dst"] = pkt[IPv6].src, pkt[IPv6].dst
    elif pkt.haslayer(ARP):
        d["src"], d["dst"], d["proto"] = pkt[ARP].psrc, pkt[ARP].pdst, "ARP"
        d["info"] = "ARP request" if pkt[ARP].op == 1 else "ARP reply"

    if pkt.haslayer(TCP):
        t = pkt[TCP]
        d.update(proto="TCP", sport=t.sport, dport=t.dport, flags=str(t.flags))
        d["info"] = f"{t.sport} -> {t.dport} [{t.flags}]"
        if pkt.haslayer(Raw):
            info, host = http_info(bytes(pkt[Raw].load))
            if info:
                d.update(app="HTTP", info=info, http_host=host)
    elif pkt.haslayer(UDP):
        u = pkt[UDP]
        d.update(proto="UDP", sport=u.sport, dport=u.dport)
        d["info"] = f"{u.sport} -> {u.dport}"
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            q = pkt[DNSQR].qname
            q = (q.decode("utf-8", "ignore") if isinstance(q, bytes) else str(q)).rstrip(".")
            kind = "response" if pkt[DNS].qr else "query"
            d.update(app="DNS", dns=q, info=f"DNS {kind}: {q}")
    elif pkt.haslayer(ICMP):
        d["proto"] = "ICMP"
        d["info"] = f"type {pkt[ICMP].type}"
    return d


class PacketSniffer:
    """Captures in a background thread and puts parsed packets in a queue.
    The GUI drains the queue in batches, so it never freezes."""

    def __init__(self):
        self._sniffer = None
        self.queue = deque(maxlen=50000)

    def _on_packet(self, pkt):
        try:
            self.queue.append(parse(pkt))
        except Exception:
            pass

    def start(self, iface=None):
        self._sniffer = AsyncSniffer(iface=iface or None, store=False, prn=self._on_packet)
        self._sniffer.start()

    def stop(self):
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
