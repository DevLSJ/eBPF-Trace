"""Anonymous, visitor-isolated educational supply-chain workflow."""

import hashlib
import hmac
import json
from datetime import timedelta
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, func, select, update

from backend.core.operator_auth import aware, check_origin, check_transport, digest
from backend.core.schemas import Thresholds
from backend.db.models import (
    DemoAction,
    DemoActivity,
    DemoDeployment,
    DemoRateLimit,
    DemoScan,
    DemoSession,
    DemoVersion,
    utcnow,
)
from backend.services.demo_fixtures import (
    POLICY_REVISION,
    PROJECT,
    REPLAY_FEATURES,
    artifact,
    evaluate,
    file_digest,
    signature,
)
from backend.services.supply_demo import lock_visitor, record
from ml.rule_engine import RuleEngine

router = APIRouter(prefix="/api/demo", tags=["isolated supply-chain demo"])
COOKIE = "supply_demo"
KINDS = Literal["scan", "fix", "deploy", "replay", "finish", "help", "feedback"]


class Start(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: UUID


class Command(Start):
    version_id: UUID | None = None
    scan_id: UUID | None = None
    artifact_digest: str = Field(default="", max_length=71)
    step: int = Field(default=1, ge=1, le=6)
    topic: Literal["guide", "risk", "evidence", "component", "changes", "deployment"] = "guide"
    needed_help: bool = False
    hardest_step: int = Field(default=1, ge=1, le=6)
    misclicks: int = Field(default=0, ge=0, le=50)


def data(row):
    return {
        column.name: value.isoformat() if hasattr(value, "isoformat") else value
        for column in row.__table__.columns
        if column.name not in {"session_id", "token_hash"}
        for value in [getattr(row, column.name)]
    }


def token(request):
    return request.cookies.get(COOKIE, "")


def csrf(value):
    return digest(value + ":supply-demo-csrf")


def guard(request, *, mutation=False, bootstrap=False):
    check_transport(request)
    if mutation:
        check_origin(request)
        if not bootstrap and (
            not token(request)
            or not hmac.compare_digest(request.headers.get("X-Demo-CSRF", ""), csrf(token(request)))
        ):
            raise HTTPException(
                403, "시연 보안 확인이 만료되었습니다. 새로고침 후 다시 시도하세요."
            )


async def visitor_for(db, request, *, locked=False):
    visitor = (
        await db.scalar(select(DemoSession).where(DemoSession.token_hash == digest(token(request))))
        if token(request)
        else None
    )
    if not visitor or aware(visitor.expires_at) <= utcnow():
        raise HTTPException(401, "시연 세션이 만료되었습니다. 새 시연을 시작하세요.")
    if locked:
        visitor = await lock_visitor(db, visitor.id)
        if not visitor:
            raise HTTPException(401, "초기화된 시연입니다. 새 시연을 시작하세요.")
    return visitor


async def rows(db, model, visitor):
    query = select(model).where(model.session_id == visitor.id)
    if hasattr(model, "created_at"):
        query = query.order_by(model.created_at, model.id)
    return list((await db.scalars(query)).all())


async def snapshot(db, visitor):
    versions, scans, activities, deployments = [
        await rows(db, model, visitor)
        for model in (DemoVersion, DemoScan, DemoActivity, DemoDeployment)
    ]
    duration = (
        (aware(visitor.completed_at) - aware(visitor.created_at)).total_seconds()
        if visitor.completed_at
        else None
    )
    return {
        **data(visitor),
        "project": PROJECT,
        "versions": [data(v) for v in versions],
        "scans": [data(s) for s in scans],
        "activities": [data(a) for a in activities],
        "deployment": data(deployments[0]) if deployments else None,
        "duration_seconds": round(duration, 1) if duration is not None else None,
        "help_count": sum(a.kind == "help_opened" for a in activities),
        "policy_revision": POLICY_REVISION,
        "notice": "시연 환경 · 실제 서비스에 영향을 주지 않습니다",
    }


def new_version(db, visitor, number):
    value = artifact(number)
    fingerprint = file_digest(value)
    row = DemoVersion(
        id=str(uuid4()),
        session_id=visitor.id,
        number=number,
        artifact=value,
        digest=fingerprint,
        signature=signature(fingerprint) if number == 2 else None,
    )
    db.add(row)
    return row


@router.get("/catalog")
async def catalog():
    return {
        "project": PROJECT,
        "components": artifact(1)["components"],
        "scope": "고정 예시 · 실제 저장소·취약점 DB·클라우드 미연동",
    }


@router.get("/session")
async def current(request: Request, response: Response):
    guard(request)
    response.headers["Cache-Control"] = "no-store"
    async with request.app.state.db.sessions() as db:
        try:
            visitor = await visitor_for(db, request)
        except HTTPException as exc:
            if exc.status_code != 401:
                raise
            response.delete_cookie(
                COOKIE,
                path="/",
                secure=request.url.scheme == "https",
                httponly=True,
                samesite="strict",
            )
            return {"session": None, "expired": bool(token(request))}
        return {"session": await snapshot(db, visitor), "csrf_token": csrf(token(request))}


@router.post("/session")
async def start(body: Start, request: Request, response: Response):
    guard(request, mutation=True, bootstrap=True)
    raw = str(body.request_id)
    async with request.app.state.db.sessions() as db:
        # Serialize bootstrap retries as well as creation-rate accounting.
        key = digest(
            f"demo:{request.client.host if request.client else 'unknown'}:{utcnow():%Y-%m-%d-%H}"
        )
        if db.bind.dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import insert
        else:
            from sqlalchemy.dialects.sqlite import insert
        await db.execute(
            insert(DemoRateLimit)
            .values(key=key, count=0, expires_at=utcnow() + timedelta(hours=2))
            .on_conflict_do_nothing()
        )
        await db.execute(
            update(DemoRateLimit)
            .where(DemoRateLimit.key == key)
            .values(count=DemoRateLimit.count + 1)
        )
        existing = await db.scalar(
            select(DemoSession).where(
                DemoSession.token_hash.in_([digest(token(request)), digest(raw)]),
                DemoSession.expires_at > utcnow(),
            )
        )
        if existing:
            visitor = existing
            raw = token(request) if existing.token_hash == digest(token(request)) else raw
        else:
            limit = await db.get(DemoRateLimit, key)
            if limit.count > 30:
                raise HTTPException(
                    429, "이 네트워크의 시연 시작 횟수가 많습니다. 잠시 후 다시 시도하세요."
                )
            visitor = DemoSession(
                id=str(uuid4()),
                token_hash=digest(raw),
                expires_at=utcnow() + timedelta(days=7),
                stage=2,
                active_version=1,
                revision=0,
            )
            db.add(visitor)
            await db.flush()
            version = new_version(db, visitor, 1)
            record(
                db,
                visitor,
                "project_prepared",
                "체험할 프로젝트가 준비되었습니다",
                {"version_id": version.id, "project": PROJECT["name"]},
            )
        await db.commit()
        response.set_cookie(
            COOKIE,
            raw,
            httponly=True,
            secure=request.url.scheme == "https",
            samesite="strict",
            max_age=7 * 86400,
            path="/",
        )
        response.headers["Cache-Control"] = "no-store"
        return {"session": await snapshot(db, visitor), "csrf_token": csrf(raw)}


async def own_version(db, visitor, identifier):
    version = await db.get(DemoVersion, str(identifier)) if identifier else None
    if not version or version.session_id != visitor.id:
        raise HTTPException(404, "이 시연의 배포 버전을 찾을 수 없습니다.")
    return version


async def latest_scan(db, visitor, version):
    return await db.scalar(
        select(DemoScan)
        .where(DemoScan.session_id == visitor.id, DemoScan.version_id == version.id)
        .order_by(DemoScan.created_at.desc(), DemoScan.id.desc())
        .limit(1)
    )


async def execute(db, visitor, kind, body):
    if kind == "scan":
        version = await own_version(db, visitor, body.version_id)
        if version.number != visitor.active_version:
            raise HTTPException(
                409, "이전 검사는 기록에서 확인할 수 있습니다. 현재 버전을 검사하세요."
            )
        previous = await latest_scan(db, visitor, version)
        if previous and previous.status in {"queued", "running", "completed"}:
            return {"scan_id": previous.id}
        count = await db.scalar(
            select(func.count()).select_from(DemoScan).where(DemoScan.session_id == visitor.id)
        )
        if count >= 12:
            raise HTTPException(
                429, "이 시연의 검사 한도에 도달했습니다. 결과를 내려받고 새 시연을 시작하세요."
            )
        scan = DemoScan(
            id=str(uuid4()),
            session_id=visitor.id,
            version_id=version.id,
            status="queued",
            artifact_digest=version.digest,
            policy_revision=POLICY_REVISION,
            checks=[],
            findings=[],
        )
        db.add(scan)
        record(
            db,
            visitor,
            "scan_started",
            "보안 검사를 시작했습니다",
            {"scan_id": scan.id, "version_id": version.id},
        )
        return {"scan_id": scan.id}
    if kind == "fix":
        if visitor.stage < 4:
            raise HTTPException(409, "현재 버전 배포를 눌러 차단 이유를 먼저 확인하세요.")
        version = await db.scalar(
            select(DemoVersion).where(DemoVersion.session_id == visitor.id, DemoVersion.number == 2)
        )
        if not version:
            version = new_version(db, visitor, 2)
            visitor.active_version = 2
            record(
                db,
                visitor,
                "fix_applied",
                "새 버전을 만들었습니다 · 재검사 필요",
                {
                    "version_id": version.id,
                    "changes": [
                        "order-parser 1.4.2 → 1.4.3",
                        "telemetry-helper → usage-metrics 2.0.0",
                        "허용된 시연 빌더와 교육용 서명",
                    ],
                    "verified": False,
                },
            )
        return {"version_id": version.id}
    if kind == "deploy":
        version = await own_version(db, visitor, body.version_id)
        scan = await latest_scan(db, visitor, version)
        checks, findings = evaluate(version)  # Never trust only a prior pass flag.
        reasons = [finding["title"] for finding in findings]
        if not scan or scan.status != "completed":
            reasons.append("이 버전의 검사가 끝나지 않았습니다. 다시 검사하세요.")
        elif (
            str(body.scan_id) != scan.id
            or scan.artifact_digest != version.digest
            or scan.policy_revision != POLICY_REVISION
            or not all(c["passed"] for c in scan.checks)
            or len(scan.checks) != 4
        ):
            reasons.append("대상 버전의 최신 검사 결과가 필수 조건을 충족하지 않습니다.")
        if (
            body.artifact_digest != version.digest
            or file_digest(version.artifact) != version.digest
        ):
            reasons.append("검사한 파일과 배포 요청한 파일의 고유 지문이 다릅니다.")
        if version.number != visitor.active_version:
            reasons.append("이전 버전은 기록으로 보존되어 있습니다. 현재 버전을 선택하세요.")
        if reasons:
            record(
                db,
                visitor,
                "deployment_blocked",
                "배포가 차단되었습니다",
                {
                    "version_id": version.id,
                    "reasons": reasons,
                    "policy_revision": POLICY_REVISION,
                    "next_action": "권장 수정 확인" if version.number == 1 else "다시 검사",
                },
            )
            if version.number == 1 and scan and scan.status == "completed":
                visitor.stage = max(visitor.stage, 4)
            return {"allowed": False, "reasons": reasons}
        deployment = await db.scalar(
            select(DemoDeployment).where(DemoDeployment.session_id == visitor.id)
        )
        if not deployment:
            deployment = DemoDeployment(
                id=str(uuid4()),
                session_id=visitor.id,
                version_id=version.id,
                scan_id=scan.id,
                digest=version.digest,
                asset=f"demo-orders-{visitor.id[:8]}",
            )
            db.add(deployment)
            record(
                db,
                visitor,
                "deployed",
                "검증한 버전이 시연 환경에 배포되었습니다",
                {
                    "deployment_id": deployment.id,
                    "version_id": version.id,
                    "scan_id": scan.id,
                    "asset": deployment.asset,
                    "digest": version.digest,
                    "target": "시연용 논리 자산 · 실제 컨테이너 생성 없음",
                },
            )
        visitor.stage = 6
        return {"allowed": True, "deployment_id": deployment.id}
    if kind == "replay":
        deployment = await db.scalar(
            select(DemoDeployment).where(DemoDeployment.session_id == visitor.id)
        )
        if not deployment:
            raise HTTPException(409, "검증된 버전을 먼저 시연 배포하세요.")
        previous = await db.scalar(
            select(DemoActivity).where(
                DemoActivity.session_id == visitor.id, DemoActivity.kind == "runtime_observed"
            )
        )
        if previous:
            return {"event_id": previous.id}
        rule = RuleEngine(Thresholds()).detect(REPLAY_FEATURES)
        event = record(
            db,
            visitor,
            "runtime_observed",
            "연결 요청 증가를 시연 이벤트로 관측했습니다",
            {
                "deployment_id": deployment.id,
                "asset": deployment.asset,
                "digest": deployment.digest,
                "version_id": deployment.version_id,
                "source": "시연 이벤트 재생 · 실제 eBPF 수집 아님",
                "rule_result": rule,
                "features": REPLAY_FEATURES,
                "scope": "가상 외부 주소 192.0.2.10 → 시연 주문 서비스:443",
                "interpretation": "반복 연결 요청을 기존 탐지 규칙으로 분석했습니다. 이 관측만으로 특정 부품이 공격 원인이라고 단정할 수 없습니다.",
            },
        )
        return {"event_id": event.id}
    if kind == "finish":
        observed = await db.scalar(
            select(DemoActivity).where(
                DemoActivity.session_id == visitor.id, DemoActivity.kind == "runtime_observed"
            )
        )
        if not observed:
            raise HTTPException(409, "운영 이벤트 체험 후 결과를 확인하세요.")
        if not visitor.completed_at:
            visitor.completed_at = utcnow()
            record(
                db,
                visitor,
                "completed",
                "안내 시연을 완료했습니다",
                {"scope": "시연 정책 통과 · 실제 운영 안전성 보증 아님"},
            )
        return {"completed": True}
    if kind == "help":
        record(
            db,
            visitor,
            "help_opened",
            "사용 방법과 근거를 열었습니다",
            {"step": body.step, "topic": body.topic},
        )
        return {"recorded": True}
    if kind == "feedback":
        if not visitor.completed_at:
            raise HTTPException(409, "시연 결과를 확인한 후 의견을 남길 수 있습니다.")
        previous = await db.scalar(
            select(DemoActivity).where(
                DemoActivity.session_id == visitor.id, DemoActivity.kind == "feedback"
            )
        )
        if not previous:
            record(
                db,
                visitor,
                "feedback",
                "체험 의견을 저장했습니다",
                {
                    "needed_help": body.needed_help,
                    "hardest_step": body.hardest_step,
                    "misclicks": body.misclicks,
                    "method": "방문자 자가 보고 · 연구자 관찰 결과 아님",
                },
            )
        return {"recorded": True}


@router.post("/commands/{kind}")
async def command(kind: KINDS, body: Command, request: Request, response: Response):
    guard(request, mutation=True)
    response.headers["Cache-Control"] = "no-store"
    async with request.app.state.db.sessions() as db:
        visitor = await visitor_for(db, request, locked=True)
        fingerprint = hashlib.sha256(
            json.dumps(
                {"kind": kind, **body.model_dump(mode="json", exclude={"request_id"})},
                sort_keys=True,
            ).encode()
        ).hexdigest()
        previous = await db.scalar(
            select(DemoAction).where(
                DemoAction.session_id == visitor.id, DemoAction.request_id == str(body.request_id)
            )
        )
        if previous:
            if previous.fingerprint != fingerprint:
                raise HTTPException(
                    409, "같은 요청 키를 다른 작업에 사용할 수 없습니다. 화면을 새로고침하세요."
                )
            result = previous.result
        else:
            count = await db.scalar(
                select(func.count())
                .select_from(DemoAction)
                .where(DemoAction.session_id == visitor.id)
            )
            if count >= 200:
                raise HTTPException(
                    429, "시연 작업 한도에 도달했습니다. 기록을 내려받고 처음부터 다시 체험하세요."
                )
            result = await execute(db, visitor, kind, body)
            db.add(
                DemoAction(
                    id=str(uuid4()),
                    session_id=visitor.id,
                    request_id=str(body.request_id),
                    fingerprint=fingerprint,
                    result=result,
                )
            )
        await db.commit()
        state = await snapshot(db, visitor)
    if kind == "scan":
        request.app.state.demo_jobs.start(result["scan_id"])
    return {"session": state, "result": result, "csrf_token": csrf(token(request))}


@router.get("/report")
async def report(request: Request):
    guard(request)
    async with request.app.state.db.sessions() as db:
        visitor = await visitor_for(db, request)
        state = await snapshot(db, visitor)
        return JSONResponse(
            {
                "format": "supply-chain-demo-report/1",
                "scope": "시연 전용. 고정 예시 권고, 교육용 서명, 논리 배포, 재생 이벤트. 실제 취약점 스캔·AI 분석·클라우드 배포가 아닙니다.",
                "session": state,
            },
            headers={
                "Cache-Control": "no-store",
                "Content-Disposition": f'attachment; filename="supply-chain-demo-{visitor.id[:8]}.json"',
            },
        )


@router.post("/reset")
async def reset(request: Request, response: Response):
    guard(request, mutation=True)
    async with request.app.state.db.sessions() as db:
        visitor = await db.scalar(
            select(DemoSession).where(DemoSession.token_hash == digest(token(request)))
        )
        if visitor:
            await lock_visitor(db, visitor.id)
            for model in (DemoAction, DemoDeployment, DemoActivity, DemoScan, DemoVersion):
                await db.execute(delete(model).where(model.session_id == visitor.id))
            await db.execute(delete(DemoSession).where(DemoSession.id == visitor.id))
            await db.commit()
    response.delete_cookie(
        COOKIE, path="/", secure=request.url.scheme == "https", httponly=True, samesite="strict"
    )
    response.headers["Cache-Control"] = "no-store"
    return {"session": None, "reset": True}
