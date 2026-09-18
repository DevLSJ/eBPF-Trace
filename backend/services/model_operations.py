import asyncio
import math
from datetime import timedelta
from uuid import UUID, uuid4

from sqlalchemy import func, select

from backend.core.operator_auth import aware
from backend.db.models import ModelDeployment, ShadowPrediction, utcnow
from backend.services.incidents import audit, serialize
from ml.shadow import promotion_gates


async def register_model(app):
    model = app.state.shadow_model
    if model.status != "ready":
        return
    manifest = model.manifest
    async with app.state.db.sessions() as session:
        row = await session.get(ModelDeployment, manifest["id"])
        if row and (row.artifact_hash != manifest["sha256"] or row.manifest != manifest):
            model.model, model.status = None, "immutable_version_conflict"
            return
        if row is None:
            session.add(
                ModelDeployment(
                    id=manifest["id"],
                    artifact_hash=manifest["sha256"],
                    manifest=manifest,
                    enabled=False,
                    stage="offline",
                )
            )
            audit(
                session,
                "model.registered",
                {"model_id": manifest["id"], "sha256": manifest["sha256"]},
            )
            await session.commit()


async def observe(app, session, message, result, source):
    model = app.state.shadow_model
    if model.status != "ready":
        return
    # Deterministic bounded sampling includes normal traffic, and is deduplicated on replay.
    row = await session.get(ModelDeployment, model.manifest["id"])
    if not row or not row.enabled or row.stage not in {"shadow", "advisory", "production"}:
        return
    sampled = UUID(str(message.message_id)).int % app.state.settings.shadow_sample_modulus == 0
    if not sampled and row.stage != "production":
        return
    prediction = await asyncio.to_thread(model.predict, message.features.model_dump())
    rule_attack = bool(result["severity"])
    production = row.stage == "production" and source == "live"
    evidence = {
        **prediction,
        "decision_threshold": model.manifest.get("threshold"),
        "model_id": row.id,
        "artifact_hash": row.artifact_hash,
        "stage": row.stage,
        "used_for_detection": False,
    }
    if production and prediction["status"] != "ok":
        row.stage, row.updated_at = "shadow", utcnow()
        audit(
            session,
            "model.automatic_fallback",
            {"model_id": row.id, "reason": prediction["status"], "stage": "shadow"},
        )
    if (
        production
        and prediction["status"] == "ok"
        and prediction["predicted_attack"]
        and not rule_attack
    ):
        result.update(attack_type="ANOMALY", severity="medium")
        evidence["used_for_detection"] = True
        # Keep the legacy IF score empty: the new estimator's score has a different contract.
        # Evidence, model version and score remain in shadow_predictions by message_id.
    if not sampled and not production:
        return evidence
    if await session.scalar(
        select(ShadowPrediction.id).where(
            ShadowPrediction.model_id == row.id,
            ShadowPrediction.message_id == str(message.message_id),
        )
    ):
        return evidence
    session.add(
        ShadowPrediction(
            id=str(uuid4()),
            model_id=row.id,
            message_id=str(message.message_id),
            source=source,
            rule_attack=rule_attack,
            feature_schema_version=message.features.feature_schema_version,
            **prediction,
        )
    )
    return evidence


async def runtime_mode(app, session):
    model = app.state.shadow_model
    if model.status == "ready":
        row = await session.get(ModelDeployment, model.manifest["id"])
        if row and row.enabled and row.stage == "production":
            return "hybrid"
    return app.state.detector.mode


async def statistics(session, model_id, source="live"):
    start = utcnow() - timedelta(days=14)
    conditions = [
        ShadowPrediction.model_id == model_id,
        ShadowPrediction.source == source,
        ShadowPrediction.observed_at >= start,
    ]
    total = await session.scalar(
        select(func.count()).select_from(ShadowPrediction).where(*conditions)
    )
    good = await session.scalar(
        select(func.count())
        .select_from(ShadowPrediction)
        .where(*conditions, ShadowPrediction.status == "ok")
    )
    disagreement = await session.scalar(
        select(func.count())
        .select_from(ShadowPrediction)
        .where(
            *conditions,
            ShadowPrediction.status == "ok",
            ShadowPrediction.predicted_attack != ShadowPrediction.rule_attack,
        )
    )
    first = await session.scalar(select(func.min(ShadowPrediction.observed_at)).where(*conditions))
    last = await session.scalar(select(func.max(ShadowPrediction.observed_at)).where(*conditions))
    # Percentile is bounded to the latest 10,000 successful observations, labelled in the API.
    recent = list(
        await session.scalars(
            select(ShadowPrediction)
            .where(*conditions, ShadowPrediction.status == "ok")
            .order_by(ShadowPrediction.observed_at.desc())
            .limit(10000)
        )
    )
    latency = sorted(r.latency_ms for r in recent)
    scores = [r.score for r in recent if r.score is not None]
    newest = scores[: len(scores) // 2]
    older = scores[len(scores) // 2 :]
    shift = abs(sum(newest) / len(newest) - sum(older) / len(older)) if newest and older else None
    return {
        "source": source,
        "samples": total,
        "successful": good,
        "window_days": 14,
        "observed_days": (aware(last) - aware(first)).total_seconds() / 86400
        if first and last
        else 0,
        "failure_rate": (total - good) / total if total else None,
        "disagreement_rate": disagreement / good if good else None,
        "p95_latency_ms": latency[math.ceil(len(latency) * 0.95) - 1] if latency else None,
        "latency_sample_count": len(latency),
        "score_mean_shift": shift,
        "drift_status": "insufficient_data"
        if len(scores) < 200
        else "review"
        if shift > 0.15
        else "stable",
        "drift_method": "absolute mean score difference between recent halves; diagnostic, not a validation test",
        "false_positive_rate": None,
        "false_positive_reason": "Operator-reviewed ground truth not yet available",
    }


async def model_overview(app, session):
    models = list(
        await session.scalars(select(ModelDeployment).order_by(ModelDeployment.updated_at.desc()))
    )
    items = []
    for row in models:
        stats = await statistics(session, row.id)
        gates = promotion_gates(row.manifest, stats)
        items.append(
            {
                **serialize(row),
                "statistics": stats,
                "gates": gates,
                "promotion_ready": all(g["passed"] for g in gates),
            }
        )
    return {
        "runtime": await runtime_mode(app, session),
        "shadow_status": app.state.shadow_model.status,
        "sample_modulus": app.state.settings.shadow_sample_modulus,
        "collector_schema": app.state.collector_feature_schema_version,
        "items": items,
        "automatic_response_enabled": False,
    }
