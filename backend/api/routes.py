import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Query, Request
from sqlalchemy import select, text

from backend.core.schemas import EventQuery, Thresholds
from backend.db import crud
from backend.db.models import RuntimeConfig, SystemMetric

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
    }


@router.get("/api/events")
async def events(request: Request, query: Annotated[EventQuery, Query()]):
    if query.start_time and query.end_time and query.start_time > query.end_time:
        raise HTTPException(400, "start_time must not exceed end_time")
    async with request.app.state.db.sessions() as session:
        return await crud.get_events(session, query)


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


@router.put("/api/config/thresholds")
async def update_thresholds(
    request: Request, thresholds: Thresholds, authorization: str = Header(default="")
):
    expected = request.app.state.settings.admin_token.get_secret_value()
    if not expected or not secrets.compare_digest(authorization, f"Bearer {expected}"):
        raise HTTPException(401, "Administrator token required")
    async with request.app.state.db.sessions() as session:
        row = await session.get(RuntimeConfig, 1)
        if row is None:
            row = RuntimeConfig(id=1)
            session.add(row)
        row.thresholds = thresholds.model_dump()
        await session.commit()
    request.app.state.detector.rules.thresholds = thresholds
    return thresholds.model_dump()
