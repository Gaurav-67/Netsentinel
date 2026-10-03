MAX_FLOWS = 100000


class FlowTable:
    """Groups packets into bidirectional conversations (flows)."""

    def __init__(self):
        self.flows = {}

    def clear(self):
        self.flows.clear()

    def update(self, p):
        if p["src"] == "-":
            return
        a = (p["src"], p["sport"] or 0)
        b = (p["dst"], p["dport"] or 0)
        key = (p["proto"],) + tuple(sorted([a, b]))
        f = self.flows.get(key)
        if f is None:
            if len(self.flows) >= MAX_FLOWS:
                self.flows.pop(next(iter(self.flows)))
            f = self.flows[key] = {
                "proto": p["proto"], "a": a, "b": b, "pkts": 0, "bytes": 0,
                "start": p["ts"], "last": p["ts"], "app": "",
            }
        f["pkts"] += 1
        f["bytes"] += p["len"]
        f["last"] = p["ts"]
        if p.get("app"):
            f["app"] = p["app"]

    def top(self, n=200):
        return sorted(self.flows.values(), key=lambda f: f["last"], reverse=True)[:n]
