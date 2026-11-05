from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from backend.services.risk_gate import MIN_OBSERVATIONS, assess, proximity

NOW = datetime(2026, 9, 23, 9, 0, tzinfo=timezone.utc)


def asset(**overrides):
    values = {
        "address": "198.51.100.20",
        "protected_cidrs": ["127.0.0.0/8", "10.0.0.0/8"],
        "criticality": "standard",
    }
    return SimpleNamespace(**{**values, **overrides})


def observations(count, *, syn_ratio, port_cnt=1, reverse=None, gap=1.0):
    features = {"port_cnt": port_cnt}
    if reverse is not None:
        features["reverse_packet_fraction"] = reverse
    return [
        SimpleNamespace(
            detected_at=NOW - timedelta(seconds=gap * (count - index)),
            syn_ratio=syn_ratio,
            raw_features=dict(features),
        )
        for index in range(count)
    ]


def test_pure_flood_is_low_risk_with_traceable_signals():
    result = assess(
        source_ip="192.0.2.10",
        asset=asset(),
        events=observations(3, syn_ratio=0.98),
        threshold=0.4,
        now=NOW,
    )
    assert result["level"] == "low" and result["route"] == "automatic"
    assert result["hard_stop"] is None and 0 <= result["score"] < 0.4
    assert set(result["signals"]) == {"normal_fraction", "port_diversity", "observation", "proximity"}
    assert pytest.approx(sum(s["weight"] for s in result["signals"].values())) == 1
    assert any("완료된 연결이 거의 없어" in reason for reason in result["reasons"])


def test_mixed_traffic_source_is_routed_to_approval():
    result = assess(
        source_ip="192.0.2.77",
        asset=asset(),
        events=observations(3, syn_ratio=0.2, port_cnt=48),
        threshold=0.4,
        now=NOW,
    )
    assert result["level"] == "high" and result["route"] == "approval"
    assert result["hard_stop"] is None and result["score"] >= 0.4
    assert any("공유 NAT" in reason for reason in result["reasons"])


def test_reverse_traffic_counts_as_normal_sessions():
    quiet = assess(source_ip="192.0.2.5", asset=asset(), events=observations(3, syn_ratio=0.95), threshold=0.4, now=NOW)
    talkative = assess(
        source_ip="192.0.2.5",
        asset=asset(),
        events=observations(3, syn_ratio=0.95, reverse=0.6),
        threshold=0.4,
        now=NOW,
    )
    assert talkative["score"] > quiet["score"] and talkative["level"] == "high"


def test_single_observation_never_passes():
    result = assess(
        source_ip="192.0.2.10",
        asset=asset(),
        events=observations(MIN_OBSERVATIONS - 1, syn_ratio=1.0),
        threshold=0.99,
        now=NOW,
    )
    assert result["hard_stop"] == "insufficient_evidence" and result["level"] == "high"


def test_protected_neighbourhood_and_critical_assets_need_a_person():
    neighbour = assess(
        source_ip="10.0.0.9",
        asset=asset(),
        events=observations(4, syn_ratio=1.0),
        threshold=0.99,
        now=NOW,
    )
    assert neighbour["hard_stop"] == "protected_neighbourhood"
    critical = assess(
        source_ip="192.0.2.10",
        asset=asset(criticality="critical"),
        events=observations(4, syn_ratio=0.6),
        threshold=0.99,
        now=NOW,
    )
    assert critical["hard_stop"] == "critical_asset_mixed_traffic"
    clear = assess(
        source_ip="192.0.2.10",
        asset=asset(criticality="critical"),
        events=observations(4, syn_ratio=0.98),
        threshold=0.4,
        now=NOW,
    )
    assert clear["hard_stop"] is None and clear["level"] == "low"


def test_proximity_is_graded_by_prefix():
    assert proximity("198.51.100.77", asset()) == 1.0
    assert proximity("198.51.7.7", asset()) == 0.5
    assert proximity("192.0.2.10", asset()) == 0.0
    assert proximity("2001:db8::1", asset()) == 0.0
