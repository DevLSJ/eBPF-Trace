from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from backend.db.crud import event_conditions
from backend.db.models import DetectionEvent as Event


async def summarize(session, query):
    conditions = event_conditions(query)
    result = {}
    for name in ('severity', 'attack_type', 'source', 'is_confirmed'):
        column = getattr(Event, name)
        rows = await session.execute(select(column, func.count()).where(*conditions).group_by(column))
        result[name] = {('pending' if key is None else 'confirmed' if key is True else
                        'false_positive' if key is False else key): count for key, count in rows}
    end = min(query.end_time or datetime.now(timezone.utc), datetime.now(timezone.utc))
    start = max(query.start_time or end - timedelta(hours=24), end - timedelta(hours=24))
    # Group in the database: no arbitrary row cap that could distort graph totals.
    minute = (func.strftime('%Y-%m-%dT%H:%M:00', Event.detected_at)
              if session.bind.dialect.name == 'sqlite' else func.date_trunc('minute', Event.detected_at))
    rows = await session.execute(select(minute, func.count()).where(
        *conditions, Event.detected_at >= start, Event.detected_at <= end).group_by(minute).order_by(minute))
    timeline = []
    for ts, count in rows:
        stamp = datetime.fromisoformat(ts) if isinstance(ts, str) else ts
        timeline.append({'timestamp': stamp.replace(tzinfo=timezone.utc).isoformat(), 'count': count})
    return {**result, 'total': sum(result['source'].values()), 'timeline': timeline,
            'timeline_start': start.isoformat(), 'timeline_end': end.isoformat(),
            'timeline_scope': 'Last 24 hours within filters; one-minute database aggregates'}
