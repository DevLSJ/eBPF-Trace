"""Transactional incident correlation, audit history and outcome metrics."""

import hashlib
import json
from datetime import timedelta
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import func, select, update

from backend.core.operator_auth import aware
from backend.db.crud import event_dict, utc_iso
from backend.db.models import (
    ActionRun,
    Asset,
    AuditEntry,
    CorrelationKey,
    DetectionEvent,
    Incident,
    IncidentEvent,
    NotificationDelivery,
    Operator,
    utcnow,
)

CLOSED = {"resolved", "false_positive", "duplicate", "accepted_risk"}
ACK_SECONDS = {"P1": 120, "P2": 600, "P3": 3600, "P4": 86400}
ACTIVE_ACTIONS = {"queued", "applying", "applied", "revoke_requested", "release_failed", "unknown"}


def serialize(row, exclude=()):
    return {
        column.name: utc_iso(value) if hasattr(value, "tzinfo") else value
        for column in row.__table__.columns
        if column.name not in exclude
        for value in [getattr(row, column.name)]
    }


def audit(session, kind, detail, *, incident_id=None, actor=None):
    entry = AuditEntry(
        id=str(uuid4()),
        incident_id=incident_id,
        actor_id=actor.id if actor else None,
        actor_name=actor.name if actor else "System",
        kind=kind,
        detail=detail,
    )
    session.add(entry)
    return entry


async def lock_key(session, key):
    """A durable per-key lock works across workers, including SQLite test deployments."""
    key = hashlib.sha256(key.encode()).hexdigest()  # PostgreSQL column is exactly 64 characters.
    if session.bind.dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        from sqlalchemy.dialects.sqlite import insert
    await session.execute(
        insert(CorrelationKey).values(id=key, touched_at=utcnow()).on_conflict_do_nothing()
    )
    await session.execute(
        update(CorrelationKey).where(CorrelationKey.id == key).values(touched_at=utcnow())
    )


async def queue_notifications(session, incident, settings, kind="opened"):
    payload = {
        "title": incident.title,
        "priority": incident.priority,
        "source": incident.source,
        "incident_id": incident.id,
        "asset": incident.asset_name,
        "url": f"{settings.public_base_url.rstrip('/')}#incidents?id={incident.id}",
        "kind": kind,
        "event_count": incident.event_count,
    }
    destinations = [("in_app", "workspace", "provider_accepted")]
    if incident.source == "live" and incident.priority in {"P1", "P2"}:
        slack = settings.slack_escalation_channel if kind == "escalated" else settings.slack_channel
        slack = slack or settings.slack_channel
        destinations.append(
            (
                "slack",
                slack,
                "queued"
                if settings.ops_notifications_enabled
                and settings.slack_bot_token.get_secret_value()
                and slack
                else "not_configured",
            )
        )
        if incident.priority == "P1" or kind == "escalated":
            destinations.append(
                (
                    "email",
                    settings.notification_email,
                    "queued"
                    if settings.ops_notifications_enabled
                    and settings.smtp_host
                    and settings.smtp_from
                    and settings.notification_email
                    else "not_configured",
                )
            )
    for channel, destination, status in destinations:
        key = f"{incident.id}:{kind}:{channel}:{incident.version if kind != 'opened' else 1}"
        if await session.scalar(
            select(NotificationDelivery.id).where(NotificationDelivery.dedupe_key == key)
        ):
            continue
        session.add(
            NotificationDelivery(
                id=str(uuid4()),
                incident_id=incident.id,
                dedupe_key=key,
                kind=kind,
                channel=channel,
                destination=destination,
                status=status,
                payload=payload,
                accepted_at=utcnow() if channel == "in_app" else None,
            )
        )


async def correlate(session, event, settings):
    linked = await session.scalar(select(IncidentEvent).where(IncidentEvent.event_id == event.id))
    if linked:
        return await session.get(Incident, linked.incident_id)
    # Scans span destination ports; floods span source addresses. Never merge training and live.
    identity = [
        event.source,
        event.scenario_run_id,
        str(event.dst_ip),
        event.protocol,
        event.attack_type,
    ]
    identity += [str(event.src_ip)] if event.attack_type == "PORT_SCAN" else [event.dst_port]
    if event.attack_type in {"LARGE_FLOW", "TRAFFIC_SPIKE", "ANOMALY"}:
        identity.append(str(event.src_ip))
    key = hashlib.sha256(json.dumps(identity).encode()).hexdigest()
    await lock_key(session, key)
    incident = await session.scalar(
        select(Incident).where(Incident.active_key == key).with_for_update()
    )
    if incident and aware(incident.last_seen_at) < utcnow() - timedelta(
        seconds=settings.incident_window_seconds
    ):
        incident.active_key = (
            None  # Keep the older investigation open, but start a separate episode.
        )
        await session.flush()
        incident = None
    asset = await session.scalar(
        select(Asset).where(
            Asset.address == str(event.dst_ip),
            Asset.service_port == event.dst_port,
            Asset.protocol == event.protocol,
            Asset.environment == ("simulation" if event.source == "simulation" else "production"),
        )
    )
    if asset is None and event.source == "live":
        asset = await session.scalar(
            select(Asset).where(
                Asset.address == str(event.dst_ip),
                Asset.service_port == event.dst_port,
                Asset.protocol == event.protocol,
                Asset.environment == "lab",
            )
        )
    priority = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}[event.severity]
    if asset and asset.criticality == "critical" and priority == "P2":
        priority = "P1"
    now = utcnow()
    if incident is None:
        incident = Incident(
            id=str(uuid4()),
            active_key=key,
            title=f"{event.attack_type.replace('_', ' ')} · {asset.name if asset else str(event.dst_ip)}",
            attack_type=event.attack_type,
            priority=priority,
            status="open",
            source=event.source,
            scenario_run_id=event.scenario_run_id,
            asset_id=asset.id if asset else None,
            asset_name=asset.name if asset else f"{event.dst_ip}:{event.dst_port}",
            dst_ip=str(event.dst_ip),
            dst_port=event.dst_port,
            protocol=event.protocol,
            version=1,
            event_count=1,
            created_at=now,
            last_seen_at=now,
            ack_due_at=now + timedelta(seconds=ACK_SECONDS[priority]),
            summary={},
        )
        session.add(incident)
        await session.flush()
        audit(
            session,
            "incident.opened",
            {
                "priority": priority,
                "event_id": event.id,
                "priority_reason": "rule severity and registered asset criticality",
            },
            incident_id=incident.id,
        )
        await queue_notifications(session, incident, settings)
    else:
        incident.event_count += 1
        incident.last_seen_at = now
        if priority < incident.priority:
            incident.priority = priority
            incident.version += 1
            incident.ack_due_at = min(
                aware(incident.ack_due_at), now + timedelta(seconds=ACK_SECONDS[priority])
            )
            audit(
                session, "incident.priority_raised", {"priority": priority}, incident_id=incident.id
            )
            await queue_notifications(session, incident, settings, "priority_raised")
    prior = incident.summary or {}
    model_evidence = event.raw_features.get("model_evidence") or {}
    incident.summary = {
        **prior,
        "latest_event_id": event.id,
        "schema_version": event.raw_features.get("feature_schema_version", 1),
        "evidence": "validated_model"
        if model_evidence.get("used_for_detection")
        else ("rules" if event.anomaly_score is None else "rules_and_validated_model"),
        "model_evidence": model_evidence or None,
        "sources": list(dict.fromkeys([*prior.get("sources", []), str(event.src_ip)]))[:50],
        "peak_pps": max(prior.get("peak_pps", 0), event.pkt_rate),
        "latest_pps": event.pkt_rate,
        "latest_byte_rate": event.byte_rate,
        "asset_registered": asset is not None,
    }
    session.add(IncidentEvent(incident_id=incident.id, event_id=event.id))
    await session.flush()
    return incident


async def get_incident(session, incident_id):
    row = await session.get(Incident, incident_id)
    if row is None:
        raise HTTPException(404, "Incident not found")
    return row


async def change_incident(session, row, version, values, kind, actor, reason):
    if row.version != version:
        raise HTTPException(409, "Incident changed; refresh and review the latest evidence")
    result = await session.execute(
        update(Incident)
        .where(Incident.id == row.id, Incident.version == version)
        .values(**values, version=version + 1)
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        raise HTTPException(409, "Another operator updated this incident")
    audit(
        session,
        kind,
        {
            **{k: utc_iso(v) if hasattr(v, "tzinfo") else v for k, v in values.items()},
            "reason": reason,
            "from_status": row.status,
            "version": version + 1,
        },
        incident_id=row.id,
        actor=actor,
    )
    await session.refresh(row)
    return row


async def acknowledge(session, row, actor, version):
    if row.owner_id == actor.id and row.acknowledged_at:
        return row
    if row.status != "open" or row.owner_id:
        raise HTTPException(409, "Incident already owned; use an explicit handoff")
    await change_incident(
        session,
        row,
        version,
        {"owner_id": actor.id, "status": "acknowledged", "acknowledged_at": utcnow()},
        "incident.acknowledged",
        actor,
        "Accepted responsibility",
    )
    await session.execute(
        update(NotificationDelivery)
        .where(NotificationDelivery.incident_id == row.id)
        .values(acknowledged_at=utcnow())
    )
    return row


async def detail(session, row):
    evidence = list(
        await session.scalars(
            select(DetectionEvent)
            .join(IncidentEvent, IncidentEvent.event_id == DetectionEvent.id)
            .where(IncidentEvent.incident_id == row.id)
            .order_by(DetectionEvent.id.desc())
            .limit(100)
        )
    )
    history = await session.scalars(
        select(AuditEntry)
        .where(AuditEntry.incident_id == row.id)
        .order_by(AuditEntry.created_at, AuditEntry.id)
        .limit(300)
    )
    deliveries = await session.scalars(
        select(NotificationDelivery)
        .where(NotificationDelivery.incident_id == row.id)
        .order_by(NotificationDelivery.created_at.desc())
        .limit(100)
    )
    runs = await session.scalars(
        select(ActionRun)
        .where(ActionRun.incident_id == row.id)
        .order_by(ActionRun.created_at.desc())
    )
    owner = await session.get(Operator, row.owner_id) if row.owner_id else None
    return {
        **serialize(row),
        "owner_name": owner.name if owner else None,
        "events": [event_dict(e) for e in evidence],
        "events_truncated": row.event_count > len(evidence),
        "timeline": [serialize(e) for e in history],
        "notifications": [serialize(e, ("lease_token",)) for e in deliveries],
        "actions": [serialize(e) for e in runs],
    }


async def metrics(session, source="live", days=7):
    start = utcnow() - timedelta(days=days)
    rows = list(
        await session.scalars(
            select(Incident).where(Incident.source == source, Incident.created_at >= start)
        )
    )

    def elapsed(end, begin):
        values = sorted(
            (aware(getattr(r, end)) - aware(getattr(r, begin))).total_seconds()
            for r in rows
            if getattr(r, end) and getattr(r, begin)
        )
        if not values:
            return {"mean_seconds": None, "p95_seconds": None, "samples": 0}
        import math

        return {
            "mean_seconds": round(sum(values) / len(values), 2),
            "p95_seconds": round(values[max(0, math.ceil(len(values) * 0.95) - 1)], 2),
            "samples": len(values),
        }

    active = [r for r in rows if r.status not in CLOSED]
    notifications = list(
        await session.scalars(
            select(NotificationDelivery)
            .join(Incident)
            .where(Incident.source == source, NotificationDelivery.created_at >= start)
        )
    )
    external = [n for n in notifications if n.channel != "in_app" and n.status != "not_configured"]
    failures = sum(n.status in {"failed", "unknown"} for n in external)
    action_counts = dict(
        (
            await session.execute(
                select(ActionRun.status, func.count())
                .join(Incident)
                .where(Incident.source == source, ActionRun.created_at >= start)
                .group_by(ActionRun.status)
            )
        ).all()
    )
    return {
        "source": source,
        "window_days": days,
        "window_start": utc_iso(start),
        "incidents": len(rows),
        "open": len(active),
        "unacknowledged_urgent": sum(
            r.priority in {"P1", "P2"} and not r.acknowledged_at for r in active
        ),
        "overdue": sum(not r.acknowledged_at and aware(r.ack_due_at) < utcnow() for r in active),
        "false_positive_incidents": sum(r.status == "false_positive" for r in rows),
        "mtta": elapsed("acknowledged_at", "created_at"),
        "mttc": elapsed("contained_at", "created_at"),
        "mttr": elapsed("resolved_at", "created_at"),
        "mttd": {
            "mean_seconds": None,
            "samples": 0,
            "reason": "Independent attack start time required",
        },
        "external_notification_attempts": len(external),
        "notification_failures": failures,
        "notification_failure_rate": failures / len(external) if external else None,
        "notifications_not_configured": sum(n.status == "not_configured" for n in notifications),
        "active_actions": sum(action_counts.get(s, 0) for s in ACTIVE_ACTIONS),
        "recovery_failures": action_counts.get("release_failed", 0),
        "action_states": action_counts,
    }
