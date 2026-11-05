import time
from datetime import timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from backend.core.config import Settings
from backend.db.models import Asset, DemoSession, DemoVersion, DetectionEvent, RuntimeConfig, utcnow
from backend.main import create_app


@pytest.fixture
def demo(tmp_path):
    app = create_app(
        Settings(
            _env_file=None,
            database_url=f"sqlite+aiosqlite:///{tmp_path / 'demo.db'}",
            auto_create_schema=True,
            ops_allow_insecure_local=True,
            ops_worker_enabled=False,
            metrics_enabled=False,
            model_path="missing",
            scaler_path="missing",
        )
    )
    with TestClient(app) as client:
        yield client


def start(client, key=None):
    result = client.post("/api/demo/session", json={"request_id": key or str(uuid4())})
    assert result.status_code == 200, result.text
    return result.json()


def command(client, kind, **data):
    state = client.get("/api/demo/session").json()
    return client.post(
        f"/api/demo/commands/{kind}",
        json={"request_id": str(uuid4()), **data},
        headers={"X-Demo-CSRF": state["csrf_token"]},
    )


def scan(client, version):
    result = command(client, "scan", version_id=version["id"])
    assert result.status_code == 200, result.text
    identifier = result.json()["result"]["scan_id"]
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        state = client.get("/api/demo/session").json()["session"]
        item = next(s for s in state["scans"] if s["id"] == identifier)
        if item["status"] in {"completed", "failed"}:
            return item
        time.sleep(0.02)
    raise AssertionError("Persisted scan did not finish")


def deploy(client, version, result=None, **extra):
    return command(
        client,
        "deploy",
        version_id=version["id"],
        artifact_digest=version["digest"],
        scan_id=result["id"] if result else None,
        **extra,
    )


def complete_flow(client):
    prepared = start(client)
    first = prepared["session"]["versions"][0]
    assert prepared["session"]["stage"] == 2
    assert command(client, "fix").status_code == 409
    initial = scan(client, first)
    assert len(initial["checks"]) == 4 and len(initial["findings"]) == 3
    assert initial["status"] == "completed"
    denied = deploy(client, first, initial).json()
    assert denied["result"]["allowed"] is False
    assert len(denied["result"]["reasons"]) >= 3
    assert denied["session"]["stage"] == 4
    fixed = command(client, "fix").json()["session"]
    second = next(v for v in fixed["versions"] if v["number"] == 2)
    assert len(fixed["versions"]) == 2 and len(fixed["scans"]) == 1
    assert deploy(client, second).json()["result"]["allowed"] is False
    checked = scan(client, second)
    assert checked["findings"] == [] and all(c["passed"] for c in checked["checks"])
    assert deploy(client, second, initial).json()["result"]["allowed"] is False
    mismatch = command(
        client,
        "deploy",
        version_id=second["id"],
        scan_id=checked["id"],
        artifact_digest="sha256:" + "0" * 64,
    ).json()
    assert mismatch["result"]["allowed"] is False
    deployed = deploy(client, second, checked).json()
    assert deployed["result"]["allowed"] is True
    assert deployed["session"]["deployment"]["digest"] == checked["artifact_digest"]
    assert command(client, "finish").status_code == 409
    observed = command(client, "replay").json()
    event = next(a for a in observed["session"]["activities"] if a["kind"] == "runtime_observed")
    assert event["detail"]["rule_result"] == "SYN_FLOOD"
    assert event["detail"]["deployment_id"] == deployed["result"]["deployment_id"]
    finished = command(client, "finish").json()["session"]
    assert finished["completed_at"] and finished["duration_seconds"] >= 0
    report = client.get("/api/demo/report")
    assert report.status_code == 200 and report.headers["content-disposition"].endswith('.json"')
    assert "csrf_token" not in report.text and "token_hash" not in report.text
    assert client.cookies["supply_demo"] not in report.text
    assert len(report.json()["session"]["versions"]) == 2
    return finished


def test_full_flow_and_no_operational_writes(demo):
    complete_flow(demo)

    async def counts():
        async with demo.app.state.db.sessions() as db:
            return [
                await db.scalar(select(func.count()).select_from(model))
                for model in (Asset, DetectionEvent, RuntimeConfig)
            ]

    assert demo.portal.call(counts) == [0, 0, 0]
    assert demo.get("/api/ops/incidents").status_code == 401
    assert (
        demo.post(
            "/api/ops/assets",
            json={"name": "Forbidden", "address": "192.0.2.1", "service_port": 80},
        ).status_code
        == 401
    )


def test_postgres_demo_flow(postgres_client):
    postgres_client.app.state.settings.ops_allow_insecure_local = True
    complete_flow(postgres_client)


def test_session_isolation_csrf_idempotence_and_reset(demo):
    first = start(demo)
    cookie_a = demo.cookies["supply_demo"]
    version_a = first["session"]["versions"][0]
    same = start(demo)
    assert same["session"]["id"] == first["session"]["id"]
    assert (
        demo.post(
            "/api/demo/commands/scan",
            json={"request_id": str(uuid4()), "version_id": version_a["id"]},
        ).status_code
        == 403
    )
    assert (
        demo.post(
            "/api/demo/session",
            headers={"Origin": "https://attacker.example"},
            json={"request_id": str(uuid4())},
        ).status_code
        == 403
    )
    demo.cookies.clear()
    assert demo.get("/api/demo/session").json()["session"] is None
    second = start(demo)
    assert second["session"]["id"] != first["session"]["id"]
    assert command(demo, "scan", version_id=version_a["id"]).status_code == 404
    assert demo.get("/api/demo/report").json()["session"]["id"] == second["session"]["id"]
    own = second["session"]["versions"][0]
    key = str(uuid4())
    args = {"request_id": key, "version_id": own["id"]}
    a = command(demo, "scan", **args).json()["result"]
    b = command(demo, "scan", **args).json()["result"]
    assert a == b
    assert command(demo, "help", request_id=key).status_code == 409
    result = scan(demo, own)
    assert result["id"] == a["scan_id"]
    headers = {"X-Demo-CSRF": second["csrf_token"]}
    assert demo.post("/api/demo/reset", headers=headers).status_code == 200
    assert demo.get("/api/demo/session").json()["session"] is None
    demo.cookies.set("supply_demo", cookie_a)
    assert demo.get("/api/demo/session").json()["session"]["id"] == first["session"]["id"]


def test_failed_job_can_retry_and_artifact_tampering_is_blocked(demo, monkeypatch):
    from backend.services import supply_demo

    state = start(demo)["session"]
    original = supply_demo.evaluate
    monkeypatch.setattr(
        supply_demo,
        "evaluate",
        lambda _: (_ for _ in ()).throw(RuntimeError("test worker failure")),
    )
    failed = scan(demo, state["versions"][0])
    assert failed["status"] == "failed" and failed["error"]
    monkeypatch.setattr(supply_demo, "evaluate", original)
    passed = scan(demo, state["versions"][0])
    assert passed["status"] == "completed" and passed["id"] != failed["id"]
    deploy(demo, state["versions"][0], passed)
    fixed = command(demo, "fix").json()["session"]["versions"][-1]
    checked = scan(demo, fixed)

    async def tamper():
        async with demo.app.state.db.sessions() as db:
            version = await db.get(DemoVersion, fixed["id"])
            version.artifact = {**version.artifact, "builder": "untrusted"}
            await db.commit()

    demo.portal.call(tamper)
    assert deploy(demo, fixed, checked).json()["result"]["allowed"] is False


def test_expiration_and_http_security(demo):
    result = start(demo)
    identifier = result["session"]["id"]

    async def expire():
        async with demo.app.state.db.sessions() as db:
            row = await db.get(DemoSession, identifier)
            row.expires_at = utcnow() - timedelta(seconds=1)
            await db.commit()

    demo.portal.call(expire)
    assert demo.get("/api/demo/report").status_code == 401
    assert demo.get("/api/demo/session").json()["expired"] is True
    demo.app.state.settings.ops_allow_insecure_local = False
    assert demo.post("/api/demo/session", json={"request_id": str(uuid4())}).status_code == 403
