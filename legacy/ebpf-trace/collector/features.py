import math
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field

from collector.feature_schema import FEATURE_SCHEMA_VERSION


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


@dataclass(slots=True)
class RateWindow:
    """Each counter delta enters/expires once, including reverse-flow lookups."""

    history: deque = field(default_factory=deque)
    packets: int = 0
    bytes: int = 0
    syns: int = 0

    def expire(self, now):
        while self.history and self.history[0][0] <= now - 1:
            _, packets, byte_count, syns = self.history.popleft()
            self.packets -= packets
            self.bytes -= byte_count
            self.syns -= syns

    def add(self, now, packets, byte_count, syns):
        self.expire(now)
        self.history.append((now, packets, byte_count, syns))
        self.packets += packets
        self.bytes += byte_count
        self.syns += syns


@dataclass(slots=True)
class DestinationWindow:
    rate: RateWindow = field(default_factory=RateWindow)
    history: deque = field(default_factory=deque)
    peers: Counter = field(default_factory=Counter)
    packets: int = 0

    def add(self, now, peer, packets, byte_count, syns):
        while self.history and self.history[0][0] <= now - 10:
            _, expired_peer, count = self.history.popleft()
            self.packets -= count
            self.peers[expired_peer] -= 1
            if not self.peers[expired_peer]:
                del self.peers[expired_peer]
        self.history.append((now, peer, packets))
        self.peers[peer] += 1
        self.packets += packets
        self.rate.add(now, packets, byte_count, syns)


class FeatureCalculator:
    """Causal 1s rates, 10s diversity and observed reverse-direction context.

    Reverse absence is not proof of a failed handshake: ingress-only sensors
    may not see replies. All context tables are bounded independently.
    """

    def __init__(self, max_flows=65536):
        self.flows = OrderedDict()
        self.sources = OrderedDict()
        self.destinations = OrderedDict()
        self.services = OrderedDict()
        self.max_flows = max_flows

    def destination(self, table, key, snapshot, now, delta):
        value = table.get(key)
        if value is None:
            value = table[key] = DestinationWindow()
        table.move_to_end(key)
        value.add(now, snapshot.src_ip, *delta)
        while len(table) > self.max_flows:
            table.popitem(last=False)
        return value

    def compute(self, snapshot: Snapshot, now: float):
        previous, window = self.flows.get(snapshot.key, (None, None))
        if previous and previous.first_seen_ns == snapshot.first_seen_ns:
            if snapshot.pkt_cnt <= previous.pkt_cnt:
                return None
            delta = (
                snapshot.pkt_cnt - previous.pkt_cnt,
                snapshot.byte_cnt - previous.byte_cnt,
                snapshot.syn_cnt - previous.syn_cnt,
            )
            if min(delta) < 0:
                return None  # Ignore torn/stale cumulative snapshots.
        else:
            window = RateWindow()
            delta = snapshot.pkt_cnt, snapshot.byte_cnt, snapshot.syn_cnt
        window.add(now, *delta)
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
        destination = self.destination(self.destinations, snapshot.dst_ip, snapshot, now, delta)
        service = self.destination(
            self.services, (snapshot.dst_ip, snapshot.dst_port, snapshot.protocol),
            snapshot, now, delta)
        reverse_key = (snapshot.dst_ip, snapshot.src_ip, snapshot.dst_port,
                       snapshot.src_port, snapshot.protocol)
        reverse = self.flows.get(reverse_key) if reverse_key != snapshot.key else None
        if reverse:
            reverse[1].expire(now)
        reverse_packets = reverse[1].packets if reverse else 0
        reverse_bytes = reverse[1].bytes if reverse else 0
        reverse_syns = reverse[1].syns if reverse else 0
        packets, byte_count, syns = window.packets, window.bytes, window.syns
        bidirectional_packets = packets + reverse_packets
        return {
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "pkt_rate": float(packets),
            "byte_rate": float(byte_count),
            "syn_ratio": syns / packets if packets else 0.0,
            "port_entropy": source.entropy,
            "port_cnt": len(source.ports),
            "flow_duration": max(0, snapshot.last_seen_ns - snapshot.first_seen_ns) / 1e6,
            "avg_pkt_size": byte_count / packets if packets else 0.0,
            "source_pkt_rate": float(source.packets),
            "source_syn_rate": float(source.syns),
            "destination_pkt_rate": float(destination.rate.packets),
            "destination_byte_rate": float(destination.rate.bytes),
            "destination_syn_rate": float(destination.rate.syns),
            "destination_source_count": len(destination.peers),
            "service_pkt_rate": float(service.rate.packets),
            "service_byte_rate": float(service.rate.bytes),
            "service_syn_rate": float(service.rate.syns),
            "service_source_count": len(service.peers),
            "reverse_pkt_rate": float(reverse_packets),
            "reverse_byte_rate": float(reverse_bytes),
            "bidirectional_pkt_rate": float(bidirectional_packets),
            "bidirectional_byte_rate": float(byte_count + reverse_bytes),
            "reverse_packet_fraction": reverse_packets / bidirectional_packets if bidirectional_packets else 0.0,
            "bidirectional_syn_ratio": (syns + reverse_syns) / bidirectional_packets if bidirectional_packets else 0.0,
            "source_pkt_rate_10s": source.total / 10.0,
            "destination_pkt_rate_10s": destination.packets / 10.0,
        }
