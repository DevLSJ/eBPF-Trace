"""Explainable collateral-damage gate: it splits automatic from approved responses, never decides alone.

The score estimates how likely blocking `source -> service` also cuts legitimate sessions. Hard
stops override the weighted score. Every output carries the observations it was computed from.
"""

import ipaddress
from datetime import timezone

from sqlalchemy import select

from backend.db.models import DetectionEvent, IncidentEvent

VERSION = 1
WEIGHTS = {"normal_fraction": 0.4, "port_diversity": 0.2, "observation": 0.2, "proximity": 0.2}
MIN_OBSERVATIONS = 2


def _aware(value):
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _mean(values):
    values = [v for v in values if v is not None]
    return sum(values) / len(values) if values else None


def proximity(source_ip, asset):
    """0 = unrelated network, 0.5 = shares a /16, 1 = shares a /24 with a protected address."""
    address = ipaddress.ip_address(source_ip)
    if address.version != 4:
        return 0.0
    networks = [ipaddress.ip_network(c, strict=False) for c in asset.protected_cidrs]
    networks.append(ipaddress.ip_network(f"{asset.address}/32"))
    for prefix, weight in ((24, 1.0), (16, 0.5)):
        neighbourhood = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
        if any(n.version == 4 and n.overlaps(neighbourhood) for n in networks):
            return weight
    return 0.0


def assess(*, source_ip, asset, events, threshold, now):
    """Return the assessment for one source. `events` are this source's linked detection events."""
    syn_ratios = [e.syn_ratio for e in events]
    reverse = [e.raw_features.get("reverse_packet_fraction") for e in events]
    port_counts = [e.raw_features.get("port_cnt", 1) for e in events]
    mean_syn, mean_reverse, mean_ports = _mean(syn_ratios), _mean(reverse), _mean(port_counts)
    completed = 1 - mean_syn if mean_syn is not None else 0.0
    normal_fraction = max(completed, mean_reverse or 0.0)
    times = sorted(_aware(e.detected_at) for e in events)
    span = (times[-1] - times[0]).total_seconds() if len(times) > 1 else 0.0
    near = proximity(source_ip, asset)

    signals = {
        "normal_fraction": {"value": round(normal_fraction, 3), "risk": normal_fraction},
        "port_diversity": {
            "value": mean_ports,
            "risk": 0.1 if (mean_ports or 0) >= 20 else 0.3 if (mean_ports or 0) >= 5 else 0.5,
        },
        "observation": {
            "value": {"count": len(events), "span_seconds": round(span, 1)},
            "risk": 0.5 if len(events) < 6 or span < 5 else 0.2,
        },
        "proximity": {"value": near, "risk": near},
    }
    for name, signal in signals.items():
        signal["weight"] = WEIGHTS[name]
    score = round(sum(s["risk"] * s["weight"] for s in signals.values()), 3)

    reasons = []
    if normal_fraction < 0.15:
        reasons.append(
            f"SYN 비율 {mean_syn:.0%} — 완료된 연결이 거의 없어 정상 세션 영향이 낮습니다."
        )
    elif normal_fraction >= 0.5:
        reasons.append(
            f"관측의 {normal_fraction:.0%}가 완료 연결·응답 트래픽입니다 — 정상 사용자가 섞인 출발지(공유 NAT·프록시)일 가능성이 높습니다."
        )
    else:
        reasons.append(f"완료 연결 비율 {normal_fraction:.0%} — 정상 트래픽이 일부 섞여 있습니다.")
    if (mean_ports or 0) >= 20:
        reasons.append(f"목적지 포트 {mean_ports:.0f}개 — 탐색 지문이 뚜렷해 대상이 특정됩니다.")
    elif (mean_ports or 0) <= 4:
        reasons.append("단일 서비스 집중 유입 — 포트 분포만으로는 출발지 성격을 가리지 못합니다.")
    reasons.append(f"이 출발지를 {len(events)}회, {span:.0f}초에 걸쳐 관측했습니다.")
    if near >= 1.0:
        reasons.append("보호 대상 주소와 같은 /24 네트워크의 출발지입니다.")
    elif near >= 0.5:
        reasons.append("보호 대상 주소와 같은 /16 네트워크의 출발지입니다 — 내부 장비일 수 있습니다.")

    hard_stop = None
    if len(events) < MIN_OBSERVATIONS:
        hard_stop = "insufficient_evidence"
        reasons.append(f"관측이 {len(events)}건뿐입니다 — 최소 {MIN_OBSERVATIONS}회 관측 후 판단합니다.")
    elif near >= 1.0:
        hard_stop = "protected_neighbourhood"
    elif asset.criticality == "critical" and normal_fraction >= 0.3:
        hard_stop = "critical_asset_mixed_traffic"
        reasons.append("중요 자산이며 정상 트래픽이 섞여 있어 사람의 판단이 필요합니다.")

    level = "high" if hard_stop or score >= threshold else "low"
    return {
        "version": VERSION,
        "score": score,
        "threshold": threshold,
        "level": level,
        "hard_stop": hard_stop,
        "reasons": reasons,
        "signals": signals,
        "evaluated_at": now.isoformat(),
        "route": "automatic" if level == "low" else "approval",
    }


async def source_evidence(session, incident, source_ip, limit=100):
    return list(
        await session.scalars(
            select(DetectionEvent)
            .join(IncidentEvent, IncidentEvent.event_id == DetectionEvent.id)
            .where(IncidentEvent.incident_id == incident.id, DetectionEvent.src_ip == source_ip)
            .order_by(DetectionEvent.id.desc())
            .limit(limit)
        )
    )
