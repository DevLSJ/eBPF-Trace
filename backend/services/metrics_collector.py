import asyncio
import logging

import psutil
from sqlalchemy import func, select

from backend.db.crud import create_metric, metric_dict
from backend.db.models import DetectionEvent

logger = logging.getLogger(__name__)


async def collect_metrics(app):
    psutil.cpu_percent()
    while True:
        try:
            try:
                app.state.redis_available = bool(await app.state.redis.ping())
            except Exception:
                app.state.redis_available = False
            async with app.state.db.sessions() as session:
                count = await session.scalar(select(func.count()).select_from(DetectionEvent))
                metric = await create_metric(
                    session,
                    {
                        "cpu_percent": psutil.cpu_percent(),
                        "memory_percent": psutil.virtual_memory().percent,
                        "event_total": count,
                    },
                )
                await app.state.manager.broadcast(
                    {"type": "system_metrics", "metric": metric_dict(metric)}
                )
        except Exception:
            logger.exception("Metrics collection failed; retrying at next interval")
        await asyncio.sleep(app.state.settings.metrics_collect_interval_sec)
