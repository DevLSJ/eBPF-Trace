import random
from collections import Counter, deque
from dataclasses import replace

import pytest

from collector.features import FeatureCalculator, Snapshot, SourceWindow, entropy


def snapshot(**kwargs):
    return replace(
        Snapshot(
            "192.168.64.1", "192.168.64.2", 5000, 80, 6, 10, 600, 2, 1_000_000_000, 2_000_000_000
        ),
        **kwargs,
    )


def test_delta_not_lifetime_and_expiration():
    calculator = FeatureCalculator()
    first = calculator.compute(snapshot(), 1)
    assert first["pkt_rate"] == 10
    assert first["syn_ratio"] == 0.2
    assert first["flow_duration"] == 1000
    assert calculator.compute(snapshot(), 1.1) is None
    second = calculator.compute(snapshot(pkt_cnt=15, byte_cnt=900, syn_cnt=3), 1.5)
    assert second["pkt_rate"] == 15
    third = calculator.compute(snapshot(pkt_cnt=20, byte_cnt=1200, syn_cnt=4), 2.01)
    assert third["pkt_rate"] == 10


def test_scan_across_twenty_five_tuples_and_expiry():
    calculator = FeatureCalculator()
    for port in range(1, 21):
        features = calculator.compute(
            snapshot(dst_port=port, src_port=5000 + port, pkt_cnt=1, byte_cnt=60, syn_cnt=1),
            1 + port / 100,
        )
    assert features["port_cnt"] == 20
    assert features["port_entropy"] == pytest.approx(entropy([1] * 20))
    assert features["source_syn_rate"] == 20
    expired = calculator.compute(snapshot(dst_port=21, pkt_cnt=1), 12)
    assert expired["port_cnt"] == 1


def test_eviction_and_counter_generation_reset():
    calculator = FeatureCalculator(max_flows=2)
    for port in (80, 81, 82):
        calculator.compute(snapshot(dst_port=port), port)
    assert len(calculator.flows) == 2
    fresh = calculator.compute(
        snapshot(dst_port=82, first_seen_ns=3_000_000_000, pkt_cnt=1, byte_cnt=60, syn_cnt=1), 83
    )
    assert fresh["pkt_rate"] == 1


def test_incremental_source_window_matches_full_history():
    rng, history, window = random.Random(42), deque(), SourceWindow()
    now = 0
    for _ in range(3000):
        now += rng.choice([0, 0.001, 0.1, 1, 11])
        port, count, syns = rng.randrange(500), rng.randrange(1, 100), rng.randrange(2)
        history.append((now, port, count, syns))
        while history[0][0] <= now - 10:
            history.popleft()
        window.add(now, port, count, syns)
        ports = Counter()
        for _, p, n, _ in history:
            ports[p] += n
        assert window.ports == ports
        assert window.entropy == pytest.approx(entropy(ports.values()), abs=1e-10)
        assert window.packets == sum(n for ts, _, n, _ in history if ts > now - 1)
        assert window.syns == sum(s for ts, _, _, s in history if ts > now - 1)


def test_destination_fan_in_service_isolation_and_reverse_expiry():
    from backend.core.schemas import Features
    from ml.rule_engine import RuleEngine

    calculator = FeatureCalculator()
    first = snapshot(src_ip="192.0.2.1", dst_ip="192.0.2.9", pkt_cnt=600, syn_cnt=600)
    calculator.compute(first, 1)
    second = calculator.compute(replace(first, src_ip="192.0.2.2"), 1.1)
    assert second["pkt_rate"] == 600
    assert second["service_pkt_rate"] == second["service_syn_rate"] == 1200
    assert second["service_source_count"] == 2
    assert RuleEngine().detect(second) == "SYN_FLOOD"
    assert Features(**second).feature_schema_version == 2
    other = calculator.compute(replace(first, dst_port=443, pkt_cnt=1, syn_cnt=1), 1.2)
    assert other["service_pkt_rate"] == 1 and other["destination_pkt_rate"] == 1201
    reply = replace(first, src_ip=first.dst_ip, dst_ip=first.src_ip,
                    src_port=first.dst_port, dst_port=first.src_port, pkt_cnt=10, syn_cnt=0)
    paired = calculator.compute(reply, 1.3)
    assert paired["reverse_pkt_rate"] == 600 and paired["bidirectional_pkt_rate"] == 610
    assert paired["reverse_packet_fraction"] == pytest.approx(600 / 610)
    expired = calculator.compute(replace(reply, pkt_cnt=11, byte_cnt=660), 2.4)
    assert expired["reverse_pkt_rate"] == 0 and expired["bidirectional_pkt_rate"] == 1
    reset = calculator.compute(replace(first, pkt_cnt=601, syn_cnt=601, byte_cnt=660), 12)
    assert reset["destination_source_count"] == reset["service_source_count"] == 1


def test_context_tables_are_bounded_and_stale_counter_snapshot_is_ignored():
    calculator = FeatureCalculator(max_flows=2)
    for index in range(5):
        calculator.compute(snapshot(src_ip=f"192.0.2.{index}", dst_ip=f"198.51.100.{index}"), index)
    assert all(len(table) <= 2 for table in (calculator.sources, calculator.destinations, calculator.services, calculator.flows))
    sample = snapshot(src_ip="192.0.2.99")
    calculator.compute(sample, 10)
    assert calculator.compute(replace(sample, pkt_cnt=11, byte_cnt=1), 10.1) is None
