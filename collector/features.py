import math
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass


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

        source = self.sources.setdefault(snapshot.src_ip, deque())
        self.sources.move_to_end(snapshot.src_ip)
        source.append((now, snapshot.dst_port, delta[0], delta[2]))
        while source and source[0][0] <= now - 10:
            source.popleft()
        while len(self.sources) > self.max_flows:
            self.sources.popitem(last=False)
        ports = Counter()
        source_packets = source_syns = 0
        for ts, port, packets, syns in source:
            ports[port] += packets
            if ts > now - 1:
                source_packets += packets
                source_syns += syns
        packets = sum(row[1] for row in window)
        byte_count = sum(row[2] for row in window)
        syns = sum(row[3] for row in window)
        return {
            "pkt_rate": float(packets),
            "byte_rate": float(byte_count),
            "syn_ratio": syns / packets if packets else 0.0,
            "port_entropy": entropy(ports.values()),
            "port_cnt": len(ports),
            "flow_duration": max(0, snapshot.last_seen_ns - snapshot.first_seen_ns) / 1e6,
            "avg_pkt_size": byte_count / packets if packets else 0.0,
            "source_pkt_rate": float(source_packets),
            "source_syn_rate": float(source_syns),
        }
