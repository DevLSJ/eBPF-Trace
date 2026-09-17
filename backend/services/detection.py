"""One detection/persistence path for collectors and explicitly marked rehearsals."""
import asyncio

from sqlalchemy import select

from backend.db.crud import create_event, event_dict
from backend.db.models import DetectionEvent


async def process_flow(app, session, message, *, detector=None, source='live',
                       run_id=None, expected_label=None, use_ml=None):
    result = await asyncio.to_thread(
        (detector or app.state.detector).analyze,
        message.features.model_dump(), app.state.redis_available if use_ml is None else use_ml)
    event = None
    if result['severity']:
        existing = await session.scalar(select(DetectionEvent).where(
            DetectionEvent.message_id == str(message.message_id)))
        if existing is None:
            event = event_dict(await create_event(
                session, message, result, source=source, scenario_run_id=run_id,
                expected_label=expected_label, commit=False))
    return result, event


def traffic_message(message, result, *, source='live', run_id=None):
    return {'type': 'traffic', 'timestamp': message.timestamp,
            'flow': message.flow.model_dump(mode='json'),
            'features': message.features.model_dump(), 'anomaly_score': result['anomaly_score'],
            'source': source, 'scenario_run_id': run_id}
