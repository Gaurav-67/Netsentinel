import time
from collections import defaultdict, deque

# Thresholds (tune these later; v0.2 will move them to rules.yaml)
SCAN_PORTS, SCAN_WINDOW = 15, 10      # 15 distinct ports in 10 s
SYN_COUNT, SYN_WINDOW = 100, 5        # 100 SYNs in 5 s
COOLDOWN = 30                         # don't repeat same alert for 30 s


class Detector:
    def __init__(self):
        self.enabled = {"scan": True, "syn": True}
        self.ports = defaultdict(deque)   # src -> (time, dport)
        self.syns = defaultdict(deque)    # src -> time
        self.last = {}

    def reset(self):
        self.ports.clear()
        self.syns.clear()
        self.last.clear()

    def _ok(self, kind, src, now):
        if now - self.last.get((kind, src), 0) < COOLDOWN:
            return False
        self.last[(kind, src)] = now
        return True

    def check(self, p):
        if p["proto"] != "TCP":
            return []
        now, src, flags, out = p.get("ts", time.time()), p["src"], p["flags"], []

        # Port scan: many SYNs to different ports from one source
        if self.enabled["scan"] and "S" in flags and "A" not in flags:
            q = self.ports[src]
            q.append((now, p["dport"]))
            while q and now - q[0][0] > SCAN_WINDOW:
                q.popleft()
            n = len({port for _, port in q})
            if n >= SCAN_PORTS and self._ok("scan", src, now):
                out.append(self._alert(
                    "Port Scan", "Medium", src, "T1046",
                    f"{src} probed {n} different ports in {SCAN_WINDOW}s.",
                    "Verify if the source is an authorised scanner; "
                    "if not, block the IP and review exposed services."))

        # SYN flood: very many bare SYNs from one source
        if self.enabled["syn"] and flags == "S":
            q = self.syns[src]
            q.append(now)
            while q and now - q[0] > SYN_WINDOW:
                q.popleft()
            if len(q) >= SYN_COUNT and self._ok("syn", src, now):
                out.append(self._alert(
                    "SYN Flood", "High", src, "T1498",
                    f"{src} sent {len(q)} SYN packets in {SYN_WINDOW}s.",
                    "Enable SYN cookies / rate limiting and block the source."))
        return out

    @staticmethod
    def _alert(name, sev, src, mitre, desc, action):
        return {"time": time.strftime("%H:%M:%S"), "name": name,
                "severity": sev, "src": src, "mitre": mitre,
                "desc": desc, "action": action}
