"""Explicit SIMULATION adapter. Exercises the same approval/receipt/recovery services."""

import secrets
from uuid import uuid4

from sqlalchemy import select

from backend.core.operations_schemas import AgentReport
from backend.core.operator_auth import digest
from backend.db.models import ActionRun, Asset, EnforcementPoint, ServiceObservation, utcnow
from backend.services.incidents import audit, lock_key
from backend.services.response import agent_report


async def prepare(session, actor):
    await lock_key(session, "rehearsal-assets")
    asset = await session.scalar(
        select(Asset).where(Asset.address == "198.51.100.20", Asset.environment == "simulation")
    )
    if asset is None:
        asset = Asset(
            id=str(uuid4()),
            name="훈련용 결제 API",
            address="198.51.100.20",
            service_port=443,
            protocol=6,
            environment="simulation",
            criticality="critical",
            protected_cidrs=["127.0.0.0/8"],
            owner_id=actor.id,
        )
        session.add(asset)
        await session.flush()
    point = await session.scalar(
        select(EnforcementPoint).where(
            EnforcementPoint.asset_id == asset.id, EnforcementPoint.mode == "lab"
        )
    )
    if point is None:
        point = EnforcementPoint(
            id=str(uuid4()),
            asset_id=asset.id,
            name="격리 훈련 어댑터",
            mode="lab",
            token_hash=digest(secrets.token_urlsafe(32)),
            enabled=True,
            capabilities=["block_source", "rate_limit"],
            health={},
            last_seen_at=utcnow(),
        )
        session.add(point)
    audit(
        session,
        "rehearsal.prepared",
        {
            "asset_id": asset.id,
            "point_id": point.id,
            "network_effect": "none",
            "external_notifications": False,
        },
        actor=actor,
    )
    await session.flush()
    return asset


async def tick(session, settings):
    points = list(
        await session.scalars(
            select(EnforcementPoint).where(
                EnforcementPoint.mode == "lab", EnforcementPoint.enabled.is_(True)
            )
        )
    )
    for point in points:
        runs = list(
            await session.scalars(
                select(ActionRun).where(
                    ActionRun.point_id == point.id,
                    ActionRun.status.in_(
                        ["queued", "applying", "applied", "revoke_requested", "unknown"]
                    ),
                )
            )
        )
        active = False
        for run in runs:
            from backend.core.operator_auth import aware

            target = None
            if run.status in {"queued", "applying"} and aware(run.command_expires_at) > utcnow():
                target = "applied"
            elif run.status in {"revoke_requested", "unknown"} or (
                run.expires_at and aware(run.expires_at) <= utcnow()
            ):
                target = "released"
            if target:
                await agent_report(
                    session,
                    point,
                    run,
                    AgentReport(
                        sequence=run.last_report_seq + 1,
                        status=target,
                        policy_hash=run.policy_hash,
                        policy_handle=f"simulation:{run.id}",
                        detail="Synthetic lab adapter; no network policy changed",
                    ),
                    settings,
                )
            active |= run.status == "applied"
        point.last_seen_at = utcnow()
        point.health = {
            "healthy": True,
            "success_rate": 1.0,
            "latency_ms": 12.0,
            "normal_sessions": 8,
            "mode": "lab",
            "ingress_pps": 35.0,
            "policy_hits": 4000 if active else 0,
        }
        session.add(
            ServiceObservation(
                id=str(uuid4()),
                point_id=point.id,
                source="simulation",
                **{k: v for k, v in point.health.items() if k != "mode"},
            )
        )
