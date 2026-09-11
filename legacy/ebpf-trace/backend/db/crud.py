from sqlalchemy import func, select

from backend.db.models import DetectionEvent, SystemMetric


def event_dict(event):
    return {
        "type": "detection_event",
        "event_id": event.id,
        "detected_at": event.detected_at.isoformat(),
        "attack_type": event.attack_type,
        "severity": event.severity,
        "anomaly_score": event.anomaly_score,
        "flow": {
            key: str(getattr(event, key)) if key.endswith("ip") else getattr(event, key)
            for key in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")
        },
        "features": event.raw_features,
    }


def metric_dict(metric):
    return {
        key: value.isoformat() if key == "collected_at" else value
        for key in (column.name for column in SystemMetric.__table__.columns)
        if (value := getattr(metric, key)) is not None
    }


async def create_event(session, message, result):
    features = message.features.model_dump()
    event = DetectionEvent(
        message_id=str(message.message_id),
        **message.flow.model_dump(mode="json"),
        **result,
        **{
            key: features[key]
            for key in ("pkt_rate", "byte_rate", "syn_ratio", "port_entropy", "flow_duration")
        },
        raw_features=features,
    )
    session.add(event)
    await session.commit()
    await session.refresh(event)
    return event


async def get_events(session, query):
    conditions = []
    for key in ("severity", "attack_type"):
        if value := getattr(query, key):
            conditions.append(getattr(DetectionEvent, key) == value)
    if query.start_time:
        conditions.append(DetectionEvent.detected_at >= query.start_time)
    if query.end_time:
        conditions.append(DetectionEvent.detected_at <= query.end_time)
    total = await session.scalar(
        select(func.count()).select_from(DetectionEvent).where(*conditions)
    )
    rows = await session.scalars(
        select(DetectionEvent)
        .where(*conditions)
        .order_by(DetectionEvent.detected_at.desc(), DetectionEvent.id.desc())
        .offset((query.page - 1) * query.page_size)
        .limit(query.page_size)
    )
    return {
        "items": [event_dict(row) for row in rows],
        "total": total,
        "page": query.page,
        "page_size": query.page_size,
    }


async def get_event_by_id(session, event_id):
    return await session.get(DetectionEvent, event_id)


async def create_metric(session, values):
    metric = SystemMetric(**values)
    session.add(metric)
    await session.commit()
    await session.refresh(metric)
    return metric


async def get_latest_metric(session):
    return await session.scalar(
        select(SystemMetric).order_by(SystemMetric.collected_at.desc()).limit(1)
    )
