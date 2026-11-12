"""Durable demo jobs. No timers that invent success, no operational writes."""

import asyncio
import logging
from uuid import uuid4

from sqlalchemy import select, update

from backend.db.models import DemoActivity, DemoScan, DemoSession, DemoVersion, utcnow
from backend.services.demo_fixtures import evaluate

logger = logging.getLogger(__name__)


def record(db, visitor, kind, title, detail=None):
    row = DemoActivity(
        id=str(uuid4()), session_id=visitor.id, kind=kind, title=title, detail=detail or {}
    )
    db.add(row)
    return row


async def lock_visitor(db, visitor_id):
    # A real write serializes both SQLite and PostgreSQL callers; no in-memory lock.
    await db.execute(
        update(DemoSession)
        .where(DemoSession.id == visitor_id)
        .values(revision=DemoSession.revision + 1)
    )
    return await db.get(DemoSession, visitor_id, populate_existing=True)


class DemoJobs:
    def __init__(self, app):
        self.app = app
        self.tasks = {}
        self.limit = asyncio.Semaphore(4)

    async def recover(self):
        async with self.app.state.db.sessions() as db:
            rows = (
                await db.scalars(select(DemoScan).where(DemoScan.status.in_(["queued", "running"])))
            ).all()
            for scan in rows:
                scan.status, scan.error = (
                    "failed",
                    "서버가 다시 시작되어 검사가 중단되었습니다. 같은 버전을 다시 검사하세요.",
                )
                scan.finished_at = utcnow()
                visitor = await db.get(DemoSession, scan.session_id)
                record(
                    db,
                    visitor,
                    "scan_failed",
                    "검사가 중단되었습니다",
                    {"scan_id": scan.id, "reason": scan.error},
                )
            await db.commit()

    def start(self, scan_id):
        if scan_id not in self.tasks:
            task = asyncio.create_task(self.run(scan_id))
            self.tasks[scan_id] = task
            task.add_done_callback(lambda _: self.tasks.pop(scan_id, None))

    async def run(self, scan_id):
        try:
            async with self.limit:
                async with self.app.state.db.sessions() as db:
                    scan = await db.get(DemoScan, scan_id)
                    if not scan:
                        return
                    visitor = await lock_visitor(db, scan.session_id)
                    await db.refresh(scan)
                    if not visitor or scan.status != "queued":
                        return
                    version = await db.get(DemoVersion, scan.version_id)
                    scan.status, scan.stage = "running", "사용 부품 확인"
                    await db.commit()
                    checks, findings = evaluate(version)
                for index, check in enumerate(checks):
                    async with self.app.state.db.sessions() as db:
                        scan = await db.get(DemoScan, scan_id)
                        if not scan:
                            return  # This visitor explicitly reset their demo.
                        visitor = await lock_visitor(db, scan.session_id)
                        await db.refresh(scan)
                        scan.checks = checks[: index + 1]
                        scan.stage = (
                            checks[index + 1]["title"] if index + 1 < len(checks) else "검사 완료"
                        )
                        if index == len(checks) - 1:
                            scan.status, scan.findings, scan.finished_at = (
                                "completed",
                                findings,
                                utcnow(),
                            )
                            visitor.stage = max(
                                visitor.stage,
                                3 if version.number == 1 else 5 if not findings else 4,
                            )
                            record(
                                db,
                                visitor,
                                "scan_completed",
                                "보안 검사 완료" if version.number == 1 else "새 버전 재검사 완료",
                                {
                                    "scan_id": scan.id,
                                    "version_id": version.id,
                                    "passed": not findings,
                                    "findings": len(findings),
                                    "digest": version.digest,
                                },
                            )
                        await db.commit()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Demo scan failed")
            async with self.app.state.db.sessions() as db:
                scan = await db.get(DemoScan, scan_id)
                if scan:
                    visitor = await lock_visitor(db, scan.session_id)
                    scan.status, scan.error, scan.finished_at = (
                        "failed",
                        "검사를 완료하지 못했습니다. 이전 버전은 보존되어 있습니다. 다시 검사하세요.",
                        utcnow(),
                    )
                    record(
                        db,
                        visitor,
                        "scan_failed",
                        "검사 실패",
                        {"scan_id": scan.id, "reason": scan.error},
                    )
                    await db.commit()

    async def close(self):
        tasks = list(self.tasks.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
