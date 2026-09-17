import asyncio
import json
import logging
import secrets
from urllib.parse import urlparse

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError

from backend.core.schemas import FlowMessage
from backend.services.alert import send_alert
from backend.services.detection import process_flow, traffic_message

router = APIRouter()
logger = logging.getLogger(__name__)


@router.websocket("/ws/dashboard")
async def dashboard(ws: WebSocket):
    origin = ws.headers.get("origin")
    allowed = ws.app.state.settings.allowed_origins.split(",")
    if origin and origin not in allowed and urlparse(origin).netloc != ws.headers.get("host"):
        await ws.close(code=1008)
        return
    await ws.app.state.manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        ws.app.state.manager.disconnect(ws)


@router.websocket("/ws/collector")
async def collector(ws: WebSocket):
    expected = ws.app.state.settings.collector_token.get_secret_value()
    if not expected or not secrets.compare_digest(
        ws.headers.get("authorization", ""), f"Bearer {expected}"
    ):
        await ws.close(code=1008)
        return
    await ws.accept()
    ws.app.state.collector_connections += 1
    try:
        while True:
            try:
                message = FlowMessage.model_validate_json(await ws.receive_text())
            except (ValidationError, json.JSONDecodeError):
                await ws.send_json({"type": "error", "code": "VALIDATION_ERROR"})
                continue
            try:
                async with ws.app.state.db.sessions() as session:
                    result, event = await process_flow(ws.app, session, message)
                    await session.commit()
            except SQLAlchemyError:
                logger.exception("Event persistence failed; collector will replay unacknowledged data")
                await ws.close(code=1013)
                return
            if event:
                await ws.app.state.manager.broadcast(event)
                if ws.app.state.settings.slack_enabled:
                    task = asyncio.create_task(
                        send_alert(ws.app.state.settings.slack_webhook_url.get_secret_value(), event)
                    )
                    ws.app.state.alert_tasks.add(task)
                    task.add_done_callback(ws.app.state.alert_tasks.discard)
            await ws.app.state.manager.broadcast(traffic_message(message, result))
            await ws.send_json({"type": "ack", "message_id": str(message.message_id)})
    except WebSocketDisconnect:
        pass
    finally:
        ws.app.state.collector_connections -= 1
