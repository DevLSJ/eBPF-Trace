"""Administrator-only: this host's interfaces, local inspections and the defense-line check."""

import asyncio
import platform
import sys
from uuid import UUID

from fastapi import APIRouter, Depends, Request

from backend.core.auth import require_admin
from backend.core.schemas import InspectionRequest
from backend.services.live_inspection import capabilities, defense_check, list_interfaces

router = APIRouter(prefix="/api/live", dependencies=[Depends(require_admin)])


@router.get("/interfaces")
async def interfaces():
    return {"items": await asyncio.to_thread(list_interfaces), "capabilities": capabilities(),
            "host": platform.node(), "platform": sys.platform}


@router.post("/check")
async def check(request: Request):
    return await defense_check(request.app)


@router.get("/inspections")
async def inspections(request: Request):
    return {"items": await request.app.state.live.list()}


@router.post("/inspections", status_code=201)
async def start_inspection(request: Request, body: InspectionRequest):
    return await request.app.state.live.start(body)


@router.get("/inspections/{run_id}")
async def inspection(request: Request, run_id: UUID):
    return await request.app.state.live.detail(str(run_id))


@router.post("/inspections/{run_id}/stop")
async def stop_inspection(request: Request, run_id: UUID):
    return await request.app.state.live.stop(str(run_id))
