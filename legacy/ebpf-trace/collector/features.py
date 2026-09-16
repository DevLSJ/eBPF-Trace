import math
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Snapshot:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    pkt_cnt: int
    byte_cnt: int
    syn_cnt: int
    first_seen_ns: int
    last_seen_ns: int

    @property
    def key(self):
        return self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol


def entropy(counts):
    total = sum(counts)
    return (
        -sum((count / total) * math.log2(count / total) for count in counts if count)
        if total
        else 0.0
    )


@dataclass
class SourceWindow:
    """Incremental 10s port distribution and 1s source rates.

    Re-scanning the whole 10s packet history for every flow made dense capture
    replay quadratic. Each snapshot now enters and expires just once.
    """

    ports: Counter = field(default_factory=Counter)
    history: deque = field(default_factory=deque)
    recent: deque = field(default_factory=deque)
    total: int = 0
    weighted_logs: float = 0.0
    packets: int = 0
    syns: int = 0

    def change_port(self, port, count):
        old = self.ports[port]
        new = old + count
        self.weighted_logs += (new * math.log2(new) if new else 0) - (
            old * math.log2(old) if old else 0
        )
        self.total += count
        if new:
            self.ports[port] = new
        else:
            self.ports.pop(port, None)
        if not self.total:
            self.weighted_logs = 0.0

    def add(self, now, port, packets, syns):
        while self.history and self.history[0][0] <= now - 10:
            _, expired_port, count = self.history.popleft()
            self.change_port(expired_port, -count)
        while self.recent and self.recent[0][0] <= now - 1:
            _, count, syn_count = self.recent.popleft()
            self.packets -= count
            self.syns -= syn_count
        self.history.append((now, port, packets))
        self.recent.append((now, packets, syns))
        self.change_port(port, packets)
        self.packets += packets
        self.syns += syns

    @property
    def entropy(self):
        # Floating-point cancellation can leave a tiny negative residue.
        return max(0.0, min(math.log2(len(self.ports)),
                            math.log2(self.total) - self.weighted_logs / self.total))


class FeatureCalculator:
    """Cumulative kernel counters → one-second deltas; source ports span ten seconds."""

    def __init__(self, max_flows=65536):
        self.flows = OrderedDict()
        self.sources = OrderedDict()
        self.max_flows = max_flows

    def compute(self, snapshot: Snapshot, now: float):
        previous, window = self.flows.get(snapshot.key, (None, deque()))
        if previous and previous.first_seen_ns == snapshot.first_seen_ns:
            if snapshot.pkt_cnt <= previous.pkt_cnt:
                return None
            delta = (
                snapshot.pkt_cnt - previous.pkt_cnt,
                snapshot.byte_cnt - previous.byte_cnt,
                snapshot.syn_cnt - previous.syn_cnt,
            )
        else:
            window = deque()
            delta = snapshot.pkt_cnt, snapshot.byte_cnt, snapshot.syn_cnt
        window.append((now, *delta))
        while window and window[0][0] <= now - 1:
            window.popleft()
        self.flows[snapshot.key] = (snapshot, window)
        self.flows.move_to_end(snapshot.key)
        while len(self.flows) > self.max_flows:
            self.flows.popitem(last=False)

        if snapshot.src_ip not in self.sources:
            self.sources[snapshot.src_ip] = SourceWindow()
        source = self.sources[snapshot.src_ip]
        self.sources.move_to_end(snapshot.src_ip)
        source.add(now, snapshot.dst_port, delta[0], delta[2])
        while len(self.sources) > self.max_flows:
            self.sources.popitem(last=False)
        packets = sum(row[1] for row in window)
        byte_count = sum(row[2] for row in window)
        syns = sum(row[3] for row in window)
        return {
            "pkt_rate": float(packets),
            "byte_rate": float(byte_count),
            "syn_ratio": syns / packets if packets else 0.0,
            "port_entropy": source.entropy,
            "port_cnt": len(source.ports),
            "flow_duration": max(0, snapshot.last_seen_ns - snapshot.first_seen_ns) / 1e6,
            "avg_pkt_size": byte_count / packets if packets else 0.0,
            "source_pkt_rate": float(source.packets),
            "source_syn_rate": float(source.syns),
        }
