"""Authenticated incident workspace, outbox, approvals, response-agent and model APIs."""

import asyncio
import hashlib
import hmac
import json
import secrets
import time
from datetime import timedelta
from urllib.parse import parse_qs
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from sqlalchemy import delete, func, or_, select
from sqlalchemy.exc import IntegrityError

from backend.core import operations_schemas as schema
from backend.core.operator_auth import (
    COOKIE,
    authorize,
    aware,
    check_origin,
    check_password,
    check_transport,
    current_operator,
    digest,
    new_session,
    operator_dict,
    password_hash,
)
from backend.db.models import (
    ActionRequest,
    ActionRun,
    Asset,
    EnforcementPoint,
    Incident,
    LoginThrottle,
    ModelDeployment,
    NotificationDelivery,
    Operator,
    OperatorSession,
    OpsControl,
    ServiceObservation,
    utcnow,
)
from backend.services.incidents import (
    CLOSED,
    acknowledge,
    audit,
    change_incident,
    detail,
    get_incident,
    lock_key,
    metrics,
    serialize,
)
from backend.services.model_operations import model_overview, statistics
from backend.services.response import (
    agent_report,
    approve,
    preview,
    revoke,
    set_kill_switch,
    verify_transition,
)
from ml.shadow import promotion_gates

router = APIRouter(prefix="/api/ops", tags=["operations"])
integration_router = APIRouter(tags=["integrations"])
_DUMMY_HASH = password_hash(secrets.token_urlsafe(32))


@router.post("/rehearsals", status_code=201)
async def start_rehearsal(request: Request, actor=Depends(current_operator)):
    authorize(actor, "investigate")
    from backend.core.schemas import ScenarioRequest
    from backend.services.rehearsal import prepare, tick

    async with request.app.state.db.sessions() as session:
        await prepare(session, actor)
        await tick(session, request.app.state.settings)
        await session.commit()
    return await request.app.state.scenarios.start(
        ScenarioRequest(scenario_id="syn_flood", request_id=uuid4())
    )


@router.post("/login")
async def login(body: schema.Login, request: Request, response: Response):
    check_transport(request)
    check_origin(request)
    key = digest(f"{request.client.host if request.client else 'unknown'}:{body.username.lower()}")
    async with request.app.state.db.sessions() as session:
        await lock_key(session, f"login:{key}")
        throttle = await session.get(LoginThrottle, key)
        now = utcnow()
        if throttle is None:
            throttle = LoginThrottle(key=key, attempts=0, window_start=now)
            session.add(throttle)
        if aware(throttle.window_start) < now - timedelta(minutes=15):
            throttle.attempts, throttle.window_start = 0, now
        if throttle.attempts >= 10:
            raise HTTPException(429, "Too many sign-in attempts; try again in 15 minutes")
        throttle.attempts += 1
        await session.commit()
        actor = await session.scalar(select(Operator).where(Operator.username == body.username))
        valid = await asyncio.to_thread(
            check_password, body.password, actor.password_hash if actor else _DUMMY_HASH
        )
        if not valid or not actor or not actor.active:
            raise HTTPException(401, "Invalid username or password")
        throttle.attempts = 0
        token, csrf = await new_session(
            session, actor, request.app.state.settings.ops_session_hours
        )
        audit(session, "operator.signed_in", {}, actor=actor)
        await session.commit()
        response.set_cookie(
            COOKIE,
            token,
            httponly=True,
            secure=request.url.scheme == "https",
            samesite="strict",
            max_age=request.app.state.settings.ops_session_hours * 3600,
            path="/",
        )
        response.headers["Cache-Control"] = "no-store"
        return {"operator": operator_dict(actor), "csrf_token": csrf}


@router.get("/me")
async def me(request: Request, response: Response, actor=Depends(current_operator)):
    response.headers["Cache-Control"] = "no-store"
    return {
        "operator": operator_dict(actor),
        "csrf_token": digest(request.cookies[COOKIE] + ":csrf"),
    }


@router.post("/logout")
async def logout(request: Request, response: Response, actor=Depends(current_operator)):
    async with request.app.state.db.sessions() as session:
        await session.execute(
            delete(OperatorSession).where(
                OperatorSession.token_hash == digest(request.cookies[COOKIE])
            )
        )
        audit(session, "operator.signed_out", {}, actor=actor)
        await session.commit()
    response.delete_cookie(
        COOKIE, path="/", secure=request.url.scheme == "https", httponly=True, samesite="strict"
    )
    return {"ok": True}


@router.get("/operators")
async def operators(request: Request, actor=Depends(current_operator)):
    async with request.app.state.db.sessions() as session:
        rows = await session.scalars(
            select(Operator).where(Operator.active.is_(True)).order_by(Operator.name)
        )
        return {"items": [operator_dict(r) for r in rows]}


@router.get("/incidents")
async def incident_list(
    request: Request,
    source: str = Query(default="live", pattern="^(live|simulation)$"),
    status: str = "active",
    priority: str = "",
    owner: str = "",
    q: str = Query(default="", max_length=120),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=30, ge=1, le=100),
    scenario_run_id: UUID | None = None,
    actor=Depends(current_operator),
):
    conditions = [Incident.source == source]
    if scenario_run_id:
        conditions.append(Incident.scenario_run_id == str(scenario_run_id))
    if status == "active":
        conditions.append(Incident.status.not_in(CLOSED))
    elif status != "all":
        conditions.append(Incident.status == status)
    if priority:
        conditions.append(Incident.priority == priority)
    if owner == "mine":
        conditions.append(Incident.owner_id == actor.id)
    elif owner == "unassigned":
        conditions.append(Incident.owner_id.is_(None))
    if q:
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        conditions.append(
            or_(Incident.title.ilike(f"%{escaped}%", escape="\\"), Incident.dst_ip == q)
        )
    async with request.app.state.db.sessions() as session:
        count = await session.scalar(select(func.count()).select_from(Incident).where(*conditions))
        rows = await session.execute(
            select(Incident, Operator.name)
            .outerjoin(Operator, Operator.id == Incident.owner_id)
            .where(*conditions)
            .order_by(Incident.priority, Incident.ack_due_at, Incident.id)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        return {
            "items": [{**serialize(r), "owner_name": name} for r, name in rows],
            "total": count,
            "page": page,
            "page_size": page_size,
        }


@router.get("/metrics")
async def outcome_metrics(
    request: Request,
    source: str = Query(default="live", pattern="^(live|simulation)$"),
    days: int = Query(default=7, ge=1, le=90),
    actor=Depends(current_operator),
):
    async with request.app.state.db.sessions() as session:
        return await metrics(session, source, days)


@router.get("/incidents/{incident_id}")
async def incident_detail(incident_id: UUID, request: Request, actor=Depends(current_operator)):
    async with request.app.state.db.sessions() as session:
        return await detail(session, await get_incident(session, str(incident_id)))


@router.get("/incidents/{incident_id}/report")
async def incident_report(incident_id: UUID, request: Request, actor=Depends(current_operator)):
    async with request.app.state.db.sessions() as session:
        row = await get_incident(session, str(incident_id))
        value = await detail(session, row)
        return {
            "report_version": 1,
            "generated_at": utcnow().isoformat(),
            "incident": value,
            "limitations": [
                "LIVE and SIMULATION outcomes must be reported separately",
                "Traffic reduction alone is not proof of attack eradication",
                "Evidence is bounded to 100 events and 300 timeline entries; original records retained",
            ],
            "closed": row.status in CLOSED,
            "recovery_verified": row.status == "resolved",
        }


@router.post("/incidents/{incident_id}/ack")
async def ack(
    incident_id: UUID, body: schema.Mutation, request: Request, actor=Depends(current_operator)
):
    authorize(actor, "investigate")
    async with request.app.state.db.sessions() as session:
        row = await get_incident(session, str(incident_id))
        await acknowledge(session, row, actor, body.version)
        await session.commit()
        return await detail(session, row)


@router.post("/incidents/{incident_id}/assign")
async def assign(
    incident_id: UUID, body: schema.Assignment, request: Request, actor=Depends(current_operator)
):
    authorize(actor, "investigate")
    async with request.app.state.db.sessions() as session:
        row = await get_incident(session, str(incident_id))
        if row.owner_id != actor.id and actor.role != "admin":
            raise HTTPException(403, "Only the current owner or admin can hand off this incident")
        other = await session.get(Operator, str(body.operator_id))
        if not other or not other.active or other.role == "viewer":
            raise HTTPException(422, "An active investigating operator is required")
        if row.status in CLOSED:
            raise HTTPException(409, "Closed incidents cannot be assigned")
        await change_incident(
            session,
            row,
            body.version,
            {"owner_id": other.id},
            "incident.assigned",
            actor,
            body.reason,
        )
        await session.commit()
        return await detail(session, row)


@router.post("/incidents/{incident_id}/transition")
async def transition(
    incident_id: UUID, body: schema.Transition, request: Request, actor=Depends(current_operator)
):
    authorize(actor, "investigate")
    if len(body.reason.strip()) < 3:
        raise HTTPException(422, "Record the evidence supporting this transition")
    async with request.app.state.db.sessions() as session:
        row = await get_incident(session, str(incident_id))
        await verify_transition(session, row, body.status, request.app.state.settings)
        values = {"status": body.status}
        if body.status in {"contained", "recovering", "resolved"}:
            values[
                {
                    "contained": "contained_at",
                    "recovering": "recovering_at",
                    "resolved": "resolved_at",
                }[body.status]
            ] = utcnow()
        if body.status in CLOSED:
            values.update(active_key=None, resolution=body.reason)
            if body.status != "resolved":
                # Do not turn false positives into MTTR recovery samples.
                values["resolved_at"] = None
        await change_incident(
            session, row, body.version, values, "incident." + body.status, actor, body.reason
        )
        await session.commit()
        return await detail(session, row)


@router.post("/incidents/{incident_id}/notes")
async def note(
    incident_id: UUID, body: schema.Note, request: Request, actor=Depends(current_operator)
):
    authorize(actor, "investigate")
    async with request.app.state.db.sessions() as session:
        row = await get_incident(session, str(incident_id))
        audit(session, "incident.note", {"text": body.reason}, incident_id=row.id, actor=actor)
        await session.commit()
        return {"ok": True}


@router.get("/assets")
async def assets(request: Request, actor=Depends(current_operator)):
    async with request.app.state.db.sessions() as session:
        return {
            "items": [
                serialize(r) for r in await session.scalars(select(Asset).order_by(Asset.name))
            ],
            "points": [
                serialize(r, ("token_hash",))
                for r in await session.scalars(select(EnforcementPoint))
            ],
        }


@router.post("/assets", status_code=201)
async def create_asset(body: schema.AssetInput, request: Request, actor=Depends(current_operator)):
    authorize(actor, "admin")
    async with request.app.state.db.sessions() as session:
        if body.owner_id and not await session.get(Operator, str(body.owner_id)):
            raise HTTPException(422, "Asset owner not found")
        row = Asset(id=str(uuid4()), **body.model_dump(mode="json"))
        session.add(row)
        audit(session, "asset.created", {"asset_id": row.id, "name": row.name}, actor=actor)
        try:
            await session.commit()
        except IntegrityError:
            raise HTTPException(
                409, "This address, service and environment are already registered"
            ) from None
        await session.refresh(row)
        return serialize(row)


@router.post("/points", status_code=201)
async def create_point(body: schema.PointInput, request: Request, actor=Depends(current_operator)):
    authorize(actor, "admin")
    async with request.app.state.db.sessions() as session:
        asset = await session.get(Asset, str(body.asset_id))
        if not asset:
            raise HTTPException(404, "Asset not found")
        if (asset.environment == "simulation") != (body.mode == "lab"):
            raise HTTPException(
                422, "Simulation assets require a lab adapter; network assets require nftables"
            )
        token = secrets.token_urlsafe(32)
        row = EnforcementPoint(
            id=str(uuid4()),
            asset_id=asset.id,
            name=body.name,
            mode=body.mode,
            enabled=True,
            token_hash=digest(token),
            capabilities=[],
            health={},
        )
        session.add(row)
        audit(session, "point.registered", {"point_id": row.id, "mode": row.mode}, actor=actor)
        await session.commit()
        await session.refresh(row)
        return {**serialize(row, ("token_hash",)), "token": token, "token_visibility": "shown_once"}


@router.get("/actions")
async def actions(
    request: Request,
    source: str = Query(default="live", pattern="^(live|simulation)$"),
    actor=Depends(current_operator),
):
    async with request.app.state.db.sessions() as session:
        rows = await session.scalars(
            select(ActionRun)
            .join(Incident)
            .where(Incident.source == source)
            .order_by(ActionRun.created_at.desc())
            .limit(100)
        )
        pending = await session.scalars(
            select(ActionRequest)
            .join(Incident)
            .where(
                Incident.source == source,
                ActionRequest.status == "preview",
                ActionRequest.expires_at > utcnow(),
            )
            .order_by(ActionRequest.created_at.desc())
            .limit(100)
        )
        control = await session.get(OpsControl, 1)
        return {
            "items": [serialize(r) for r in rows],
            "pending": [serialize(r) for r in pending],
            "kill_switch": control.kill_switch if control else False,
        }


@router.get("/incidents/{incident_id}/response-context")
async def response_context(incident_id: UUID, request: Request, actor=Depends(current_operator)):
    async with request.app.state.db.sessions() as session:
        row = await get_incident(session, str(incident_id))
        points = (
            list(
                await session.scalars(
                    select(EnforcementPoint).where(EnforcementPoint.asset_id == row.asset_id)
                )
            )
            if row.asset_id
            else []
        )
        observations = await session.scalars(
            select(ServiceObservation)
            .where(ServiceObservation.point_id.in_([p.id for p in points]))
            .order_by(ServiceObservation.observed_at.desc())
            .limit(120)
        )
        previews = await session.scalars(
            select(ActionRequest)
            .where(ActionRequest.incident_id == row.id)
            .order_by(ActionRequest.created_at.desc())
            .limit(30)
        )
        return {
            "points": [serialize(p, ("token_hash",)) for p in points],
            "observations": [serialize(o) for o in observations],
            "previews": [serialize(p) for p in previews],
            "max_ttl_seconds": request.app.state.settings.response_max_ttl_seconds,
            "recovery_observation_seconds": request.app.state.settings.recovery_observation_seconds,
        }


@router.post("/incidents/{incident_id}/action-previews", status_code=201)
async def action_preview(
    incident_id: UUID, body: schema.PreviewInput, request: Request, actor=Depends(current_operator)
):
    authorize(actor, "respond")
    async with request.app.state.db.sessions() as session:
        row = await preview(
            session,
            await get_incident(session, str(incident_id)),
            actor,
            body,
            request.app.state.settings,
        )
        await session.commit()
        return serialize(row)


@router.post("/action-requests/{request_id}/approve")
async def approval(
    request_id: UUID, body: schema.Approval, request: Request, actor=Depends(current_operator)
):
    authorize(actor, "approve")
    async with request.app.state.db.sessions() as session:
        row = await session.get(ActionRequest, str(request_id))
        if row is None:
            raise HTTPException(404, "Response request not found")
        run = await approve(session, row, actor, body, request.app.state.settings)
        await session.commit()
        return serialize(run)


@router.post("/actions/{run_id}/revoke")
async def revocation(
    run_id: UUID, body: schema.Note, request: Request, actor=Depends(current_operator)
):
    authorize(actor, "respond")
    async with request.app.state.db.sessions() as session:
        run = await session.get(ActionRun, str(run_id))
        if run is None:
            raise HTTPException(404, "Response run not found")
        await revoke(session, run, actor, body.reason)
        await session.commit()
        return serialize(run)


@router.post("/kill-switch")
async def kill_switch(body: schema.KillSwitch, request: Request, actor=Depends(current_operator)):
    authorize(actor, "admin")
    async with request.app.state.db.sessions() as session:
        row = await set_kill_switch(session, body.enabled, actor, body.reason)
        await session.commit()
        return serialize(row)


@router.get("/notifications")
async def notifications(
    request: Request,
    source: str = Query(default="live", pattern="^(live|simulation)$"),
    status: str = "",
    actor=Depends(current_operator),
):
    async with request.app.state.db.sessions() as session:
        conditions = [Incident.source == source]
        if status:
            conditions.append(NotificationDelivery.status == status)
        rows = await session.scalars(
            select(NotificationDelivery)
            .join(Incident)
            .where(*conditions)
            .order_by(NotificationDelivery.created_at.desc())
            .limit(100)
        )
        return {
            "items": [serialize(r, ("lease_token",)) for r in rows],
            "external_enabled": request.app.state.settings.ops_notifications_enabled,
        }


@router.post("/notifications/{delivery_id}/retry")
async def retry(
    delivery_id: UUID, body: schema.Note, request: Request, actor=Depends(current_operator)
):
    authorize(actor, "investigate")
    async with request.app.state.db.sessions() as session:
        await lock_key(session, f"delivery:{delivery_id}")
        row = await session.get(NotificationDelivery, str(delivery_id))
        if row is None:
            raise HTTPException(404, "Delivery not found")
        if row.status not in {"failed", "unknown"}:
            raise HTTPException(409, "Only failed or unconfirmed deliveries can be retried")
        if not request.app.state.settings.ops_notifications_enabled:
            raise HTTPException(409, "External notifications are disabled")
        row.status, row.next_attempt_at = "queued", utcnow()
        row.attempts = 0
        audit(
            session,
            "notification.manual_retry",
            {"delivery_id": row.id, "reason": body.reason, "duplicate_risk_accepted": True},
            incident_id=row.incident_id,
            actor=actor,
        )
        await session.commit()
        return serialize(row, ("lease_token",))


@router.get("/models")
async def models(request: Request, actor=Depends(current_operator)):
    async with request.app.state.db.sessions() as session:
        return await model_overview(request.app, session)


@router.post("/models/{model_id}/stage")
async def model_stage(
    model_id: str, body: schema.ModelStage, request: Request, actor=Depends(current_operator)
):
    authorize(actor, "admin")
    async with request.app.state.db.sessions() as session:
        row = await session.get(ModelDeployment, model_id)
        if not row:
            raise HTTPException(404, "Model not registered")
        if body.stage != "offline" and (
            request.app.state.shadow_model.status != "ready"
            or request.app.state.shadow_model.manifest.get("id") != model_id
        ):
            raise HTTPException(409, "This model is not loaded in the current runtime")
        if body.stage in {"advisory", "production"}:
            gates = promotion_gates(row.manifest, await statistics(session, model_id))
            missing = [g["label"] for g in gates if not g["passed"]]
            if missing:
                raise HTTPException(409, "승격 조건 미충족: " + ", ".join(missing))
        row.stage, row.enabled, row.updated_at = body.stage, body.stage != "offline", utcnow()
        audit(
            session,
            "model.stage_changed",
            {
                "model_id": row.id,
                "stage": body.stage,
                "reason": body.reason,
                "automatic_response": False,
            },
            actor=actor,
        )
        await session.commit()
        return serialize(row)


async def agent_identity(point_id, request, authorization):
    token = authorization.removeprefix("Bearer ")
    async with request.app.state.db.sessions() as session:
        point = await session.get(EnforcementPoint, str(point_id))
        if (
            not point
            or not point.enabled
            or not authorization.startswith("Bearer ")
            or not secrets.compare_digest(point.token_hash, digest(token))
        ):
            raise HTTPException(401, "Agent authentication required")
        if request.url.scheme != "https" and not (
            request.app.state.settings.ops_allow_insecure_local
            and request.url.hostname in {"127.0.0.1", "localhost", "testserver"}
        ):
            raise HTTPException(
                403, "Agent transport requires HTTPS or explicit loopback development"
            )
        return point


@router.post("/agents/{point_id}/heartbeat")
async def heartbeat(
    point_id: UUID,
    body: schema.Heartbeat,
    request: Request,
    authorization: str = Header(default=""),
):
    await agent_identity(point_id, request, authorization)
    async with request.app.state.db.sessions() as session:
        point = await session.get(EnforcementPoint, str(point_id))
        if point.mode != body.mode:
            raise HTTPException(409, "Agent adapter does not match registration")
        point.last_seen_at, point.capabilities, point.health = (
            utcnow(),
            body.capabilities,
            body.model_dump(),
        )
        session.add(
            ServiceObservation(
                id=str(uuid4()),
                point_id=point.id,
                source="simulation" if point.mode == "lab" else "live",
                **body.model_dump(exclude={"capabilities", "mode"}),
            )
        )
        await session.commit()
        return {"ok": True, "server_time": utcnow().isoformat()}


@router.get("/agents/{point_id}/commands")
async def commands(point_id: UUID, request: Request, authorization: str = Header(default="")):
    point = await agent_identity(point_id, request, authorization)
    async with request.app.state.db.sessions() as session:
        await lock_key(session, "global-response-control")
        rows = await session.scalars(
            select(ActionRun)
            .where(
                ActionRun.point_id == point.id,
                ActionRun.status.in_(
                    ["queued", "applying", "revoke_requested", "unknown", "release_failed"]
                ),
            )
            .order_by(ActionRun.created_at)
            .limit(100)
        )
        items = []
        for run in rows:
            operation = (
                "revoke"
                if run.status in {"revoke_requested", "unknown", "release_failed"}
                else "apply"
            )
            if operation == "apply" and aware(run.command_expires_at) <= utcnow():
                continue
            payload = {
                "run_id": run.id,
                "operation": operation,
                "policy": run.policy,
                "policy_hash": run.policy_hash,
                "command_expires_at": run.command_expires_at.isoformat(),
                "point_id": point.id,
            }
            signature = hmac.new(
                authorization.removeprefix("Bearer ").encode(),
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
                hashlib.sha256,
            ).hexdigest()
            items.append({"payload": payload, "signature": signature})
            if run.status == "queued":
                run.status = "applying"
        await session.commit()
        return {"items": items}


@router.post("/agents/{point_id}/actions/{run_id}/report")
async def report(
    point_id: UUID,
    run_id: UUID,
    body: schema.AgentReport,
    request: Request,
    authorization: str = Header(default=""),
):
    point = await agent_identity(point_id, request, authorization)
    async with request.app.state.db.sessions() as session:
        run = await session.get(ActionRun, str(run_id))
        if run is None:
            raise HTTPException(404, "Response command not found")
        await agent_report(session, point, run, body, request.app.state.settings)
        await session.commit()
        return serialize(run)


@integration_router.post("/api/integrations/slack/interactions")
async def slack_interaction(request: Request):
    settings = request.app.state.settings
    secret = settings.slack_signing_secret.get_secret_value()
    raw = await request.body()
    if len(raw) > 65536:
        raise HTTPException(413, "Interaction body too large")
    timestamp = request.headers.get("x-slack-request-timestamp", "")
    try:
        fresh = abs(time.time() - int(timestamp)) <= 300
    except ValueError:
        fresh = False
    expected = (
        "v0="
        + hmac.new(
            secret.encode(), b"v0:" + timestamp.encode() + b":" + raw, hashlib.sha256
        ).hexdigest()
    )
    if (
        not secret
        or not fresh
        or not hmac.compare_digest(expected, request.headers.get("x-slack-signature", ""))
    ):
        raise HTTPException(401, "Invalid Slack signature or timestamp")
    try:
        payload = json.loads(parse_qs(raw.decode())["payload"][0])
        action = payload["actions"][0]
        incident_id = str(UUID(action["value"]))
        team, slack_user = payload["team"]["id"], payload["user"]["id"]
    except (ValueError, KeyError, IndexError, TypeError):
        raise HTTPException(422, "Malformed interaction") from None
    if (
        not settings.slack_team_id
        or team != settings.slack_team_id
        or action["action_id"] != "incident_ack"
    ):
        raise HTTPException(403, "Unsupported workspace or action")
    async with request.app.state.db.sessions() as session:
        actor = await session.scalar(
            select(Operator).where(Operator.slack_user_id == slack_user, Operator.active.is_(True))
        )
        if actor is None:
            raise HTTPException(403, "Slack user is not mapped to an active operator")
        authorize(actor, "investigate")
        row = await get_incident(session, incident_id)
        if row.source != "live":
            raise HTTPException(403, "Training incidents cannot be owned through production Slack")
        await acknowledge(session, row, actor, row.version)
        await session.commit()
        return {"text": f"{actor.name} 담당자가 사건을 인수했습니다.", "replace_original": False}
