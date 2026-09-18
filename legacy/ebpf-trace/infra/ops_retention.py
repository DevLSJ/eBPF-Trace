"""Prune only transient operational telemetry. Dry-run unless --apply is supplied.

Incidents, source events, approvals, deliveries and audit history are never deleted here.
"""

import argparse
import asyncio
from datetime import timedelta

from sqlalchemy import delete, func, select

from backend.core.config import Settings
from backend.db.database import Database
from backend.db.models import (
    LoginThrottle,
    OperatorSession,
    ServiceObservation,
    ShadowPrediction,
    utcnow,
)


async def prune(session, days, apply=False):
    cutoff = utcnow() - timedelta(days=days)
    targets = [
        (ShadowPrediction, ShadowPrediction.observed_at < cutoff),
        (ServiceObservation, ServiceObservation.observed_at < cutoff),
        (OperatorSession, OperatorSession.expires_at < utcnow()),
        (LoginThrottle, LoginThrottle.window_start < cutoff),
    ]
    counts = {}
    for model, predicate in targets:
        counts[model.__tablename__] = await session.scalar(
            select(func.count()).select_from(model).where(predicate)
        )
        if apply:
            await session.execute(delete(model).where(predicate))
    if apply:
        await session.commit()
    return counts


async def main(apply):
    settings = Settings()
    db = Database(settings.database_url)
    try:
        async with db.sessions() as session:
            counts = await prune(session, settings.ops_retention_days, apply)
            print({"applied": apply, "retention_days": settings.ops_retention_days, "rows": counts})
    finally:
        await db.engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    asyncio.run(main(parser.parse_args().apply))
