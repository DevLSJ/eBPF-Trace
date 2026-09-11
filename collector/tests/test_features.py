from dataclasses import replace

import pytest

from collector.features import FeatureCalculator, Snapshot, entropy


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
