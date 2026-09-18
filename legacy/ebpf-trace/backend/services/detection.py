"""One detection/persistence path for collectors and explicitly marked rehearsals."""
import asyncio

from sqlalchemy import select

from backend.db.crud import create_event, event_dict
from backend.db.models import DetectionEvent
from backend.services.incidents import correlate
from backend.services.model_operations import observe


async def process_flow(app, session, message, *, detector=None, source='live',
                       run_id=None, expected_label=None, use_ml=None):
    result = await asyncio.to_thread(
        (detector or app.state.detector).analyze,
        message.features.model_dump(), app.state.redis_available if use_ml is None else use_ml)
    event = None
    model_evidence = await observe(app, session, message, result, source)
    if result['severity']:
        existing = await session.scalar(select(DetectionEvent).where(
            DetectionEvent.message_id == str(message.message_id)))
        if existing is None:
            row = await create_event(
                session, message, result, source=source, scenario_run_id=run_id,
                expected_label=expected_label, commit=False, model_evidence=model_evidence)
            await correlate(session, row, app.state.settings)
            event = event_dict(row)
    return result, event


def traffic_message(message, result, *, source='live', run_id=None):
    return {'type': 'traffic', 'timestamp': message.timestamp,
            'flow': message.flow.model_dump(mode='json'),
            'features': message.features.model_dump(), 'anomaly_score': result['anomaly_score'],
            'source': source, 'scenario_run_id': run_id}
