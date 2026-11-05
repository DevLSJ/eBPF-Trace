"""Automatic path. Closed by default; every failure falls back to the two-person approval route.

Order of checks mirrors the SRS: separate switch and kill switch (F-ML08, F-R19), asset opt-in
(F-R17), hourly ceiling (F-R18), then the gate (F-R13/F-R14). A gate error is a decline, never a
pass (F-R15). An automatic policy is shorter-lived than an approved one (F-R16).
"""

import logging
from datetime import timedelta
from uuid import uuid4

from sqlalchemy import func, select

from backend.db.models import (
    ActionRequest,
    ActionRun,
    Asset,
    EnforcementPoint,
    OpsControl,
    utcnow,
)
from backend.services.incidents import ACTIVE_ACTIONS, audit, lock_key, queue_notifications
from backend.services.response import policy_digest, response_gate
from backend.services.risk_gate import assess, source_evidence

logger = logging.getLogger(__name__)


async def automatic_usage(session, settings):
    since = utcnow() - timedelta(hours=1)
    used = await session.scalar(
        select(func.count())
        .select_from(ActionRequest)
        .where(ActionRequest.origin == "automatic", ActionRequest.created_at >= since)
    )
    return {"used": used or 0, "limit": settings.response_auto_hourly_limit}


def _record(incident, source_ip, status, **detail):
    incident.summary = {
        **(incident.summary or {}),
        "automatic": {"status": status, "source_ip": source_ip, "at": utcnow().isoformat(), **detail},
    }


async def consider(session, app, incident, event):
    """Apply without approval only when every precondition holds and the gate rates the source low."""
    settings = app.state.settings
    control = await session.get(OpsControl, 1)
    if not control or not control.auto_response or control.kill_switch:
        return None
    if incident.status != "open" or not incident.asset_id or event.severity not in {"critical", "high"}:
        return None
    asset = await session.get(Asset, incident.asset_id)
    if not asset or not asset.auto_response:
        return None
    evidence = event.raw_features.get("model_evidence") or {}
    if evidence.get("used_for_detection") and evidence.get("stage") != "production":
        return None
    source_ip = str(event.src_ip)
    previous = (incident.summary or {}).get("automatic") or {}
    if previous.get("source_ip") == source_ip:
        return None  # One automatic decision per source; humans take it from here.
    point = await session.scalar(
        select(EnforcementPoint).where(
            EnforcementPoint.asset_id == asset.id,
            EnforcementPoint.enabled.is_(True),
            EnforcementPoint.mode == ("lab" if incident.source == "simulation" else "nftables"),
        )
    )
    if point is None or "block_source" not in point.capabilities:
        return None
    await lock_key(session, "global-response-control")
    await lock_key(session, f"incident-action:{incident.id}")
    if await session.scalar(
        select(ActionRun.id).where(
            ActionRun.point_id == point.id, ActionRun.status.in_(ACTIVE_ACTIONS)
        )
    ):
        return None
    usage = await automatic_usage(session, settings)
    if usage["used"] >= usage["limit"]:
        control.auto_response, control.version, control.updated_at = False, control.version + 1, utcnow()
        audit(
            session,
            "response.auto_limit_reached",
            {**usage, "action": "automatic path closed; further responses need approval"},
            incident_id=incident.id,
        )
        _record(incident, source_ip, "limit_reached", **usage)
        return None
    try:
        events = await source_evidence(session, incident, source_ip)
        assessment = assess(
            source_ip=source_ip,
            asset=asset,
            events=events,
            threshold=settings.response_risk_threshold,
            now=utcnow(),
        )
    except Exception:
        logger.exception("Risk gate failed; falling back to approval for incident %s", incident.id)
        audit(session, "response.auto_gate_error", {"source_ip": source_ip}, incident_id=incident.id)
        _record(incident, source_ip, "gate_error")
        return None
    if assessment["hard_stop"] == "insufficient_evidence":
        return None  # Not a decision yet: the next observation of this source re-evaluates.
    reasons, _ = await response_gate(
        session, incident, point, settings, source_ip, require_owner=False
    )
    if reasons or assessment["level"] != "low":
        audit(
            session,
            "response.auto_declined",
            {"source_ip": source_ip, "gate": assessment, "blocked_by": reasons},
            incident_id=incident.id,
        )
        _record(incident, source_ip, "declined", gate=assessment, blocked_by=reasons)
        return None
    now = utcnow()
    policy = {
        "version": 1,
        "action": "block_source",
        "source_ip": source_ip,
        "destination_ip": incident.dst_ip,
        "destination_port": incident.dst_port,
        "protocol": incident.protocol,
        "ttl_seconds": min(settings.response_auto_ttl_seconds, settings.response_max_ttl_seconds),
        "rate_pps": 100,
        "point_id": point.id,
        "source": incident.source,
    }
    request = ActionRequest(
        id=str(uuid4()),
        incident_id=incident.id,
        requester_id=None,
        approver_id=None,
        point_id=point.id,
        origin="automatic",
        status="approved",
        incident_version=incident.version,
        policy=policy,
        policy_hash=policy_digest(policy),
        preview={
            "mode": point.mode,
            "asset": asset.name,
            "point": point.name,
            "protected_cidrs": asset.protected_cidrs,
            "health": point.health,
            "affected_sessions": None,
            "impact": "게이트 저위험 판정으로 승인 없이 적용됩니다. 커널 TTL이 정책을 자동 만료시킵니다.",
            "automatic_approval": True,
            "requires_separate_approver": False,
            "expires_locally": True,
            "policy_version": 1,
            "gate": assessment,
        },
        reason=f"자동 경로 · 위험 점수 {assessment['score']:.2f} < {assessment['threshold']:.2f}",
        expires_at=now,
        approved_at=now,
    )
    run = ActionRun(
        id=str(uuid4()),
        request_id=request.id,
        incident_id=incident.id,
        point_id=point.id,
        origin="automatic",
        status="queued",
        policy=policy,
        policy_hash=request.policy_hash,
        command_expires_at=now + timedelta(seconds=30),
    )
    session.add_all([request, run])
    _record(incident, source_ip, "applied", run_id=run.id, gate=assessment)
    audit(
        session,
        "response.auto_approved",
        {
            "run_id": run.id,
            "request_id": request.id,
            "policy": policy,
            "policy_hash": run.policy_hash,
            "gate": assessment,
            "model_id": evidence.get("model_id"),
            "usage": {**usage, "used": usage["used"] + 1},
        },
        incident_id=incident.id,
    )
    await queue_notifications(session, incident, settings, "auto_response")
    await session.flush()
    return run
