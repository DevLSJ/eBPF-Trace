from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select, text

from backend.core.auth import require_admin
from backend.core.schemas import EventQuery, EventReview, ScenarioRequest, Thresholds
from backend.db import crud
from backend.db.models import RuntimeConfig, ScenarioRun, SystemMetric, utcnow
from backend.services.analysis import capture_reports, model_evaluation
from backend.services.event_summary import summarize
from backend.services.scenarios import catalog, run_detail, run_dict

router = APIRouter()


@router.get("/health")
async def health(request: Request):
    try:
        async with request.app.state.db.sessions() as session:
            await session.execute(text("SELECT 1"))
    except Exception:
        raise HTTPException(503, "Database unavailable") from None
    return {
        "status": "ok",
        "database": "ok",
        "redis": "ok" if request.app.state.redis_available else "degraded",
        "detection_mode": request.app.state.detector.mode,
        "collector_connected": request.app.state.collector_connections > 0,
        "model_status": request.app.state.detector.model_status,
        "model_validation_threshold": (
            request.app.state.detector.metadata.get("validation_threshold")
            if request.app.state.detector.metadata else None
        ),
    }


@router.get("/api/analysis/pcap")
def pcap_report():
    reports = capture_reports()
    if not reports:
        raise HTTPException(404, "No offline capture report available")
    return {"items": reports}


@router.get("/api/analysis/model")
def analysis_model(request: Request):
    detector = request.app.state.detector
    return {
        "runtime": {"mode": detector.mode, "status": detector.model_status},
        "evaluation": model_evaluation(),
    }


@router.get("/api/events")
async def events(request: Request, query: Annotated[EventQuery, Query()]):
    if query.start_time and query.end_time and query.start_time > query.end_time:
        raise HTTPException(400, "start_time must not exceed end_time")
    async with request.app.state.db.sessions() as session:
        return await crud.get_events(session, query)


@router.get("/api/events/summary")
async def events_summary(request: Request, query: Annotated[EventQuery, Query()]):
    if query.start_time and query.end_time and query.start_time > query.end_time:
        raise HTTPException(400, "start_time must not exceed end_time")
    async with request.app.state.db.sessions() as session:
        return await summarize(session, query)


@router.patch("/api/events/{event_id}/review", dependencies=[Depends(require_admin)])
async def review_event(request: Request, event_id: int, body: EventReview):
    async with request.app.state.db.sessions() as session:
        row = await crud.get_event_by_id(session, event_id)
        if row is None:
            raise HTTPException(404, "Event not found")
        row.is_confirmed, row.note, row.reviewed_at = body.is_confirmed, body.note, utcnow()
        await session.commit()
        await session.refresh(row)
        return crud.event_dict(row)


@router.get("/api/scenarios")
def scenarios():
    return {"items": catalog()}


@router.get("/api/scenarios/runs")
async def scenario_runs(request: Request, limit: int = Query(default=20, ge=1, le=100)):
    async with request.app.state.db.sessions() as session:
        rows = await session.scalars(select(ScenarioRun).order_by(ScenarioRun.started_at.desc()).limit(limit))
        return {"items": [run_dict(row) for row in rows]}


@router.post("/api/scenarios/runs", status_code=201, dependencies=[Depends(require_admin)])
async def start_scenario(request: Request, body: ScenarioRequest):
    return await request.app.state.scenarios.start(body)


@router.get("/api/scenarios/runs/{run_id}")
async def scenario_run(request: Request, run_id: UUID):
    async with request.app.state.db.sessions() as session:
        return await run_detail(session, str(run_id))


@router.post("/api/scenarios/runs/{run_id}/stop", dependencies=[Depends(require_admin)])
async def stop_scenario(request: Request, run_id: UUID):
    await request.app.state.scenarios.stop(str(run_id))
    async with request.app.state.db.sessions() as session:
        return await run_detail(session, str(run_id))


@router.get("/api/events/{event_id}")
async def event(request: Request, event_id: int):
    async with request.app.state.db.sessions() as session:
        row = await crud.get_event_by_id(session, event_id)
        if row is None:
            raise HTTPException(404, "Event not found")
        return crud.event_dict(row)


@router.get("/api/metrics")
async def metrics(request: Request):
    async with request.app.state.db.sessions() as session:
        row = await crud.get_latest_metric(session)
        return crud.metric_dict(row) if row else None


@router.get("/api/metrics/history")
async def metric_history(request: Request, minutes: int = Query(default=5, ge=1, le=1440)):
    async with request.app.state.db.sessions() as session:
        rows = await session.scalars(
            select(SystemMetric)
            .where(
                SystemMetric.collected_at >= datetime.now(timezone.utc) - timedelta(minutes=minutes)
            )
            .order_by(SystemMetric.collected_at.desc())
            .limit(8640)
        )
        return {"items": list(reversed([crud.metric_dict(row) for row in rows]))}


@router.get("/api/config/thresholds")
async def get_thresholds(request: Request):
    return request.app.state.detector.rules.thresholds.model_dump()


@router.put("/api/config/thresholds", dependencies=[Depends(require_admin)])
async def update_thresholds(
    request: Request, thresholds: Thresholds
):
    async with request.app.state.db.sessions() as session:
        row = await session.get(RuntimeConfig, 1)
        if row is None:
            row = RuntimeConfig(id=1)
            session.add(row)
        row.thresholds = thresholds.model_dump()
        await session.commit()
    request.app.state.detector.rules.thresholds = thresholds
    return thresholds.model_dump()
