"""Approval-bound commands; an agent receipt and health evidence drive recovery."""

import hashlib
import ipaddress
import json
from datetime import timedelta
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import select

from backend.core.operator_auth import aware
from backend.db.models import (
    ActionRequest,
    ActionRun,
    Asset,
    EnforcementPoint,
    Incident,
    OpsControl,
    ServiceObservation,
    utcnow,
)
from backend.services.incidents import (
    ACTIVE_ACTIONS,
    CLOSED,
    audit,
    change_incident,
    lock_key,
    queue_notifications,
)


def policy_digest(policy):
    return hashlib.sha256(
        json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


async def response_gate(session, incident, point, settings, source_ip=None):
    reasons = []
    asset = await session.get(Asset, point.asset_id) if point else None
    control = await session.get(OpsControl, 1)
    if control and control.kill_switch:
        reasons.append("전체 대응 중지 상태입니다.")
    if not point or not point.enabled:
        reasons.append("활성화된 대응 지점이 없습니다.")
    if not asset or incident.asset_id != asset.id:
        reasons.append("사건 자산과 대응 지점이 일치하지 않습니다.")
    if point and (
        not point.last_seen_at
        or aware(point.last_seen_at)
        < utcnow() - timedelta(seconds=settings.response_freshness_seconds)
    ):
        reasons.append("에이전트 관측이 오래되었습니다.")
    if point and (
        not point.health.get("healthy", False) or point.health.get("success_rate", 0) < 0.99
    ):
        reasons.append("정상 서비스 상태를 확인하지 못했습니다.")
    if point and point.mode == "nftables" and not settings.response_live_enabled:
        reasons.append("실제 네트워크 대응이 운영 설정에서 비활성화되어 있습니다.")
    if point and incident.source == "simulation" and point.mode != "lab":
        reasons.append("훈련 사건은 실제 네트워크 대응을 실행할 수 없습니다.")
    if point and incident.source == "live" and point.mode == "lab":
        reasons.append("실제 사건을 모의 에이전트로 대응할 수 없습니다.")
    if asset and (
        asset.address != incident.dst_ip
        or asset.service_port != incident.dst_port
        or asset.protocol != incident.protocol
    ):
        reasons.append("등록된 서비스와 관측 대상이 일치하지 않습니다.")
    if source_ip and asset:
        address = ipaddress.ip_address(source_ip)
        protected = [*asset.protected_cidrs, f"{asset.address}/32"]
        if (
            address.is_loopback
            or address.is_multicast
            or address.is_unspecified
            or any(address in ipaddress.ip_network(c, strict=False) for c in protected)
        ):
            reasons.append("보호 대상 주소에는 대응 정책을 적용할 수 없습니다.")
        if source_ip not in incident.summary.get("sources", []):
            reasons.append("사건 증거에 없는 출발지입니다.")
    if incident.status not in {"acknowledged", "investigating"}:
        reasons.append("담당자 인수 후 조사 중인 사건에서 대응을 요청하세요.")
    if not incident.owner_id:
        reasons.append("담당자 인수가 필요합니다.")
    return reasons, asset


async def preview(session, incident, actor, body, settings):
    existing = await session.get(ActionRequest, str(body.request_id))
    point = await session.get(EnforcementPoint, str(body.point_id))
    policy = {
        "version": 1,
        "action": body.action,
        "source_ip": str(body.source_ip),
        "destination_ip": incident.dst_ip,
        "destination_port": incident.dst_port,
        "protocol": incident.protocol,
        "ttl_seconds": body.ttl_seconds,
        "rate_pps": body.rate_pps,
        "point_id": str(body.point_id),
        "source": incident.source,
    }
    if existing:
        if (
            existing.incident_id != incident.id
            or existing.requester_id != actor.id
            or existing.policy_hash != policy_digest(policy)
        ):
            raise HTTPException(409, "Request ID already used for another policy")
        return existing
    if incident.version != body.version:
        raise HTTPException(409, "Incident changed; refresh before creating a preview")
    reasons, asset = await response_gate(session, incident, point, settings, str(body.source_ip))
    if body.ttl_seconds > settings.response_max_ttl_seconds:
        reasons.append("정책 기한이 서버의 최대 허용 시간을 초과합니다.")
    if point and body.action not in point.capabilities:
        reasons.append("이 대응 지점에서 지원하지 않는 조치입니다.")
    active = await session.scalar(
        select(ActionRun.id).where(
            ActionRun.point_id == str(body.point_id), ActionRun.status.in_(ACTIVE_ACTIONS)
        )
    )
    if active:
        reasons.append("이미 실행 중인 대응을 먼저 확인하세요.")
    if reasons:
        raise HTTPException(409, " ".join(reasons))
    snapshot = {
        "mode": point.mode,
        "asset": asset.name,
        "point": point.name,
        "protected_cidrs": asset.protected_cidrs,
        "health": point.health,
        "affected_sessions": None,
        "impact": "모의 훈련: 실제 패킷은 변경되지 않습니다."
        if point.mode == "lab"
        else "출발지별 정상 세션 영향은 미확인입니다. 공유 NAT 여부를 검토하고 승인하세요.",
        "automatic_approval": False,
        "requires_separate_approver": True,
        "expires_locally": True,
        "policy_version": 1,
    }
    row = ActionRequest(
        id=str(body.request_id),
        incident_id=incident.id,
        requester_id=actor.id,
        point_id=point.id,
        status="preview",
        incident_version=incident.version,
        policy=policy,
        policy_hash=policy_digest(policy),
        preview=snapshot,
        reason=body.reason,
        expires_at=utcnow() + timedelta(minutes=5),
    )
    session.add(row)
    audit(
        session,
        "response.previewed",
        {
            "request_id": row.id,
            "policy": policy,
            "policy_hash": row.policy_hash,
            "reason": body.reason,
        },
        incident_id=incident.id,
        actor=actor,
    )
    await session.flush()
    return row


async def approve(session, row, actor, body, settings):
    await lock_key(session, "global-response-control")
    await lock_key(session, f"action:{row.id}")
    await session.refresh(row)
    if row.requester_id == actor.id:
        raise HTTPException(403, "A different operator must approve this response")
    if row.policy_hash != body.policy_hash:
        raise HTTPException(409, "Policy changed; review the current preview")
    existing = await session.scalar(select(ActionRun).where(ActionRun.request_id == row.id))
    if existing:
        return existing
    if row.status != "preview" or aware(row.expires_at) <= utcnow():
        raise HTTPException(409, "Preview expired; create a new preview")
    incident = await session.get(Incident, row.incident_id)
    point = await session.get(EnforcementPoint, row.point_id)
    reasons, _ = await response_gate(session, incident, point, settings, row.policy["source_ip"])
    if incident.version != row.incident_version:
        reasons.append("사건이 변경되어 새로운 미리보기가 필요합니다.")
    if row.policy["action"] not in point.capabilities:
        reasons.append("에이전트 기능이 변경되었습니다.")
    if row.policy["ttl_seconds"] > settings.response_max_ttl_seconds:
        reasons.append("현재 운영 설정의 최대 대응 시간을 초과합니다.")
    await lock_key(session, f"incident-action:{incident.id}")
    if await session.scalar(
        select(ActionRun.id).where(
            ActionRun.point_id == row.point_id, ActionRun.status.in_(ACTIVE_ACTIONS)
        )
    ):
        reasons.append("실행 중인 대응이 있습니다.")
    if reasons:
        raise HTTPException(409, " ".join(reasons))
    row.status, row.approver_id, row.approved_at = "approved", actor.id, utcnow()
    run = ActionRun(
        id=str(uuid4()),
        request_id=row.id,
        incident_id=row.incident_id,
        point_id=row.point_id,
        status="queued",
        policy=row.policy,
        policy_hash=row.policy_hash,
        command_expires_at=utcnow() + timedelta(seconds=30),
    )
    session.add(run)
    await change_incident(
        session,
        incident,
        row.incident_version,
        {"status": "action_pending"},
        "response.approved",
        actor,
        body.reason,
    )
    audit(
        session,
        "response.queued",
        {"run_id": run.id, "policy_hash": run.policy_hash, "requester_id": row.requester_id},
        incident_id=incident.id,
        actor=actor,
    )
    await session.flush()
    return run


async def revoke(session, run, actor=None, reason="Requested"):
    if run.status in {"released", "failed", "expired"}:
        return run
    run.status, run.revoke_requested_at = "revoke_requested", utcnow()
    audit(
        session,
        "response.revoke_requested",
        {"run_id": run.id, "reason": reason},
        incident_id=run.incident_id,
        actor=actor,
    )
    await session.flush()
    return run


async def agent_report(session, point, run, body, settings):
    await lock_key(session, f"run:{run.id}")
    await session.refresh(run)
    if run.point_id != point.id or run.policy_hash != body.policy_hash:
        raise HTTPException(403, "Command does not belong to this agent or policy")
    if body.sequence <= run.last_report_seq:
        return run
    if run.status in {"released", "failed", "expired"}:
        raise HTTPException(409, "Command is terminal")
    incident = await session.get(Incident, run.incident_id)
    now = utcnow()
    if body.status == "applied":
        if run.status not in {"queued", "applying", "applied", "revoke_requested", "unknown"}:
            raise HTTPException(409, "Unexpected apply receipt")
        if run.applied_at is None:
            run.applied_at = now
            # A conservative upper bound; the agent's kernel timeout starts at application.
            run.expires_at = now + timedelta(seconds=run.policy["ttl_seconds"])
        if run.status != "revoke_requested":
            run.status = "applied"
    elif body.status == "released":
        run.status, run.released_at = "released", now
    elif body.status == "failed":
        if run.applied_at:
            raise HTTPException(409, "Applied policy must report release or release_failed")
        run.status, run.last_error = "failed", body.detail or "Agent rejected command"
        if incident.status == "action_pending":
            incident.status, incident.version = "investigating", incident.version + 1
    else:
        run.status, run.last_error = "release_failed", body.detail or "Policy release failed"
        audit(
            session,
            "response.recovery_failure",
            {"run_id": run.id, "error": run.last_error},
            incident_id=incident.id,
        )
        incident.priority = "P1"
        await queue_notifications(session, incident, settings, "recovery_failed")
    run.last_report_seq = body.sequence
    run.agent_result = {
        "policy_handle": body.policy_handle,
        "detail": body.detail,
        "received_at": now.isoformat(),
        "mode": point.mode,
    }
    audit(
        session,
        f"response.{body.status}",
        {"run_id": run.id, **run.agent_result},
        incident_id=incident.id,
    )
    await session.flush()
    return run


async def verify_transition(session, incident, target, settings):
    allowed = {
        "acknowledged": {"investigating", "false_positive", "duplicate", "accepted_risk"},
        "investigating": {"contained", "false_positive", "duplicate", "accepted_risk"},
        "action_pending": {"contained", "investigating"},
        "contained": {"recovering", "investigating"},
        "recovering": {"resolved", "investigating"},
    }
    if target not in allowed.get(incident.status, set()):
        raise HTTPException(409, f"Cannot move from {incident.status} to {target}")
    runs = list(
        await session.scalars(select(ActionRun).where(ActionRun.incident_id == incident.id))
    )
    if target in CLOSED and any(r.status in ACTIVE_ACTIONS for r in runs):
        raise HTTPException(409, "Release all active or unverified policies before closing")
    if target not in {"contained", "recovering", "resolved"}:
        return
    run = max(runs, key=lambda r: aware(r.created_at)) if runs else None
    if run is None:
        raise HTTPException(409, "Verified response evidence is required")
    if target == "contained" and (not run.applied_at or run.status not in {"applied", "released"}):
        raise HTTPException(409, "An agent apply receipt is required")
    if target == "recovering" and run.status != "released":
        raise HTTPException(409, "An agent release receipt is required before recovery")
    point = await session.get(EnforcementPoint, run.point_id)
    if not point.last_seen_at or aware(point.last_seen_at) < utcnow() - timedelta(
        seconds=settings.response_freshness_seconds
    ):
        raise HTTPException(409, "Agent evidence is stale")
    since = run.applied_at if target == "contained" else run.released_at
    if target == "resolved":
        since = incident.recovering_at
        if (
            not since
            or (utcnow() - aware(since)).total_seconds() < settings.recovery_observation_seconds
        ):
            raise HTTPException(409, "Recovery observation period has not completed")
    if since is None:
        raise HTTPException(409, "Required response timestamp is missing")
    observations = list(
        await session.scalars(
            select(ServiceObservation)
            .where(ServiceObservation.point_id == point.id, ServiceObservation.observed_at >= since)
            .order_by(ServiceObservation.observed_at.desc())
            .limit(5000)
        )
    )
    if len(observations) < 2 or not all(o.healthy and o.success_rate >= 0.99 for o in observations):
        raise HTTPException(
            409, "At least two healthy service observations (success ≥99%) are required"
        )
    checkpoints = [aware(since), *[aware(o.observed_at) for o in reversed(observations)], utcnow()]
    if any(
        (later - earlier).total_seconds() > settings.response_freshness_seconds
        for earlier, later in zip(checkpoints, checkpoints[1:])
    ):
        raise HTTPException(409, "Continuous service observations are required; evidence has a gap")
    peak = incident.summary.get("peak_pps", 0)
    if target == "contained" and (peak <= 0 or observations[0].ingress_pps > peak * 0.5):
        raise HTTPException(409, "No measured traffic reduction; containment is not verified")


async def sweep_responses(session, settings):
    now = utcnow()
    runs = list(
        await session.scalars(select(ActionRun).where(ActionRun.status.in_(ACTIVE_ACTIONS)))
    )
    for run in runs:
        point = await session.get(EnforcementPoint, run.point_id)
        if run.status == "queued" and aware(run.command_expires_at) < now:
            run.status, run.last_error = "expired", "Command was not accepted before its deadline"
            incident = await session.get(Incident, run.incident_id)
            if incident.status == "action_pending":
                incident.status, incident.version = "investigating", incident.version + 1
            audit(session, "response.expired", {"run_id": run.id}, incident_id=run.incident_id)
        elif (
            run.status == "applied"
            and point
            and (
                not point.health.get("healthy", False)
                or point.health.get("success_rate", 0) < 0.99
                or not point.last_seen_at
                or aware(point.last_seen_at)
                < now - timedelta(seconds=settings.response_freshness_seconds)
            )
        ):
            await revoke(session, run, reason="Service health degraded; automatic rollback")
        elif run.status in {"applied", "applying", "revoke_requested"}:
            deadline = run.expires_at or run.command_expires_at + timedelta(
                seconds=run.policy["ttl_seconds"]
            )
            if aware(deadline) + timedelta(seconds=settings.response_freshness_seconds) < now:
                run.status, run.last_error = (
                    "unknown",
                    "Local expiry expected; agent release not yet verified",
                )
                audit(
                    session,
                    "response.release_unverified",
                    {"run_id": run.id},
                    incident_id=run.incident_id,
                )


async def set_kill_switch(session, enabled, actor, reason):
    await lock_key(session, "global-response-control")
    row = await session.get(OpsControl, 1)
    if row is None:
        row = OpsControl(id=1, kill_switch=enabled, version=1, updated_at=utcnow())
        session.add(row)
    else:
        row.kill_switch, row.version, row.updated_at = enabled, row.version + 1, utcnow()
    if enabled:
        runs = await session.scalars(select(ActionRun).where(ActionRun.status.in_(ACTIVE_ACTIONS)))
        for run in runs:
            await revoke(session, run, actor, "Global kill switch: " + reason)
    audit(session, "response.kill_switch", {"enabled": enabled, "reason": reason}, actor=actor)
    await session.flush()
    return row
