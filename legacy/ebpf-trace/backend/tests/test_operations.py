import hashlib
import hmac
import json
import time
from datetime import timedelta
from types import SimpleNamespace
from urllib.parse import urlencode
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import select, update

from backend.core.config import Settings
from backend.core.operator_auth import provision_operator
from backend.core.schemas import FlowMessage
from backend.db.models import (
    Asset,
    Incident,
    NotificationDelivery,
    utcnow,
)
from backend.main import create_app
from backend.services.detection import process_flow
from backend.services.notifications import claim, deliver, finish, maintenance, work_once
from backend.services.rehearsal import prepare, tick

PASSWORD = "testing-only-operator-password"


@pytest.fixture
def ops_client(tmp_path):
    app = create_app(
        Settings(
            _env_file=None,
            database_url=f"sqlite+aiosqlite:///{tmp_path / 'ops.db'}",
            auto_create_schema=True,
            metrics_enabled=False,
            ops_worker_enabled=False,
            ops_allow_insecure_local=True,
            model_path="missing",
            scaler_path="missing",
            collector_token="test-collector",
            recovery_observation_seconds=10,
        )
    )
    with TestClient(app, raise_server_exceptions=False) as client:

        async def setup():
            async with app.state.db.sessions() as session:
                for name, role in [("alice", "admin"), ("bob", "approver"), ("viewer", "viewer")]:
                    await provision_operator(
                        session,
                        name,
                        name.title(),
                        role,
                        PASSWORD,
                        "U_ALICE" if name == "alice" else None,
                    )
                await session.commit()

        client.portal.call(setup)
        yield client


def auth(client, name="alice"):
    result = client.post("/api/ops/login", json={"username": name, "password": PASSWORD})
    assert result.status_code == 200, result.text
    return {
        "Cookie": "ebpf_operator=" + client.cookies.get("ebpf_operator"),
        "X-CSRF-Token": result.json()["csrf_token"],
    }


def seed(client, *, source="simulation", count=3, rollback=False, prepare_lab=True):
    async def run():
        from backend.db.models import Operator

        async with client.app.state.db.sessions() as session:
            actor = await session.scalar(select(Operator).where(Operator.username == "alice"))
            if prepare_lab:
                await prepare(session, actor)
                await tick(session, client.app.state.settings)
            for index in range(count):
                message = FlowMessage(
                    type="flow_features",
                    message_id=uuid4(),
                    timestamp=int(time.time() * 1000),
                    flow={
                        "src_ip": "192.0.2.10",
                        "dst_ip": "198.51.100.20",
                        "src_port": 5000 + index,
                        "dst_port": 443,
                        "protocol": 6,
                    },
                    features={
                        "pkt_rate": 4500,
                        "byte_rate": 270000,
                        "syn_ratio": 1,
                        "port_entropy": 0,
                        "port_cnt": 1,
                        "flow_duration": 1000,
                        "avg_pkt_size": 60,
                    },
                )
                await process_flow(client.app, session, message, source=source)
            if rollback:
                await session.rollback()
            else:
                await session.commit()

    client.portal.call(run)


def incident(client, headers, source="simulation"):
    result = client.get("/api/ops/incidents", params={"source": source}, headers=headers)
    assert result.status_code == 200, result.text
    return result.json()["items"][0]


def make_preview(client, headers, row, ttl=30):
    context = client.get(f"/api/ops/incidents/{row['id']}/response-context", headers=headers).json()
    body = {
        "request_id": str(uuid4()),
        "point_id": context["points"][0]["id"],
        "version": row["version"],
        "source_ip": "192.0.2.10",
        "ttl_seconds": ttl,
        "reason": "Verified isolated test evidence",
    }
    return client.post(
        f"/api/ops/incidents/{row['id']}/action-previews", json=body, headers=headers
    )


def test_session_csrf_rbac_and_logout(ops_client):
    c = ops_client
    assert c.get("/api/ops/incidents").status_code == 401
    admin = auth(c)
    assert (
        "HttpOnly"
        in c.post("/api/ops/login", json={"username": "alice", "password": PASSWORD}).headers[
            "set-cookie"
        ]
    )
    assert c.post("/api/ops/rehearsals", headers={"Cookie": admin["Cookie"]}).status_code == 403
    assert (
        c.post(
            "/api/ops/rehearsals", headers={**admin, "Origin": "https://untrusted.example"}
        ).status_code
        == 403
    )
    viewer = auth(c, "viewer")
    assert c.get("/api/ops/incidents", headers=viewer).status_code == 200
    assert (
        c.post(
            "/api/ops/assets",
            headers=viewer,
            json={"name": "Denied", "address": "192.0.2.3", "service_port": 80},
        ).status_code
        == 403
    )
    result = c.get("/api/ops/me", headers=admin)
    assert result.json()["csrf_token"] == admin["X-CSRF-Token"]
    assert c.post("/api/ops/logout", headers=admin).status_code == 200
    assert c.get("/api/ops/me", headers=admin).status_code == 401


def test_restricted_public_test_account(ops_client):
    c = ops_client

    async def setup():
        async with c.app.state.db.sessions() as session:
            with pytest.raises(ValueError):
                await provision_operator(session, "admin", "Test", "admin", "admin")
            with pytest.raises(ValueError):
                await provision_operator(
                    session, "other", "Test", "admin", "admin", test_account=True
                )
            await provision_operator(session, "admin", "Test", "admin", "admin", test_account=True)
            await session.commit()

    c.portal.call(setup)
    credentials = {"username": "admin", "password": "admin"}
    assert c.post("/api/ops/login", json=credentials).status_code == 401
    c.app.state.settings.ops_test_account_mode = True
    result = c.post("/api/ops/login", json=credentials)
    assert result.status_code == 200
    assert result.json()["operator"]["is_test_account"] is True
    assert c.get("/api/ops/me").status_code == 200
    c.app.state.settings.ops_test_account_mode = False
    assert c.get("/api/ops/me").status_code == 401
    for flag in ["response_live_enabled", "ops_notifications_enabled", "slack_enabled"]:
        with pytest.raises(ValueError, match="Test accounts require"):
            Settings(_env_file=None, ops_test_account_mode=True, **{flag: True})


def test_password_throttle_and_https_gate(ops_client):
    c = ops_client
    for _ in range(10):
        assert (
            c.post(
                "/api/ops/login", json={"username": "absent", "password": "incorrect"}
            ).status_code
            == 401
        )
    assert (
        c.post("/api/ops/login", json={"username": "absent", "password": "incorrect"}).status_code
        == 429
    )
    c.app.state.settings.ops_allow_insecure_local = False
    assert (
        c.post("/api/ops/login", json={"username": "alice", "password": PASSWORD}).status_code
        == 403
    )


def test_transactional_correlation_outbox_and_sources(ops_client):
    c = ops_client
    headers = auth(c)
    seed(c, rollback=True)
    assert c.get("/api/ops/incidents?source=simulation", headers=headers).json()["total"] == 0
    seed(c)
    row = incident(c, headers)
    assert row["event_count"] == 3
    detail = c.get(f"/api/ops/incidents/{row['id']}", headers=headers).json()
    assert len(detail["events"]) == 3
    assert len(detail["notifications"]) == 1
    assert detail["notifications"][0]["channel"] == "in_app"
    seed(c, source="live", count=2)
    live = incident(c, headers, "live")
    assert live["id"] != row["id"] and live["event_count"] == 2
    notifications = c.get("/api/ops/notifications?source=live", headers=headers).json()["items"]
    assert sum(n["status"] == "not_configured" for n in notifications) == 2


def test_shadow_isolation_promotion_denial_provenance_and_runtime_fallback(ops_client, message):
    from backend.db.models import ModelDeployment, ShadowPrediction
    from backend.services.model_operations import register_model
    from collector.feature_schema import CONTEXT_FEATURES

    c = ops_client
    admin = auth(c)
    manifest = {
        "id": "test-context",
        "sha256": "a" * 64,
        "schema_version": 2,
        "independent_validation": {"independent": False},
    }

    def predict(features):
        ok = features["feature_schema_version"] == 2
        return {
            "status": "ok" if ok else "incompatible_features",
            "score": 0.9 if ok else None,
            "predicted_attack": True if ok else None,
            "latency_ms": 1,
        }

    c.app.state.shadow_model = SimpleNamespace(status="ready", manifest=manifest, predict=predict)
    c.app.state.settings.shadow_sample_modulus = 1
    c.portal.call(register_model, c.app)
    path = "/api/ops/models/test-context/stage"
    assert (
        c.post(
            path, json={"stage": "shadow", "reason": "Begin isolated shadow"}, headers=admin
        ).status_code
        == 200
    )
    assert (
        c.post(
            path, json={"stage": "production", "reason": "Insufficient evidence"}, headers=admin
        ).status_code
        == 409
    )
    message["features"] = {
        **dict.fromkeys(CONTEXT_FEATURES, 0),
        "feature_schema_version": 2,
        "pkt_rate": 10,
        "byte_rate": 600,
        "avg_pkt_size": 60,
    }

    async def run(production=False, legacy=False):
        async with c.app.state.db.sessions() as session:
            if production:
                model = await session.get(ModelDeployment, "test-context")
                model.stage = "production"  # Emulate an already independently validated deployment.
            payload = {**message, "message_id": str(uuid4())}
            if legacy:
                payload["features"] = {**message["features"], "feature_schema_version": 1}
            result, event = await process_flow(c.app, session, FlowMessage(**payload))
            await session.commit()
            return result, event

    assert c.portal.call(run)[1] is None  # Positive shadow prediction cannot create an incident.
    assert c.get("/health").json()["detection_mode"] == "rules_only"
    result, event = c.portal.call(run, True)
    assert result["attack_type"] == "ANOMALY" and event["anomaly_score"] is None
    assert event["features"]["model_evidence"]["used_for_detection"]
    assert incident(c, admin, "live")["summary"]["evidence"] == "validated_model"
    assert c.get("/health").json()["detection_mode"] == "hybrid"
    assert c.portal.call(run, False, True)[1] is None
    assert c.get("/health").json()["detection_mode"] == "rules_only"
    overview = c.get("/api/ops/models", headers=admin).json()["items"][0]
    assert overview["stage"] == "shadow" and overview["statistics"]["samples"] == 3

    async def predictions():
        async with c.app.state.db.sessions() as session:
            return list(await session.scalars(select(ShadowPrediction)))

    assert len(c.portal.call(predictions)) == 3
    c.app.state.shadow_model.manifest = {**manifest, "threshold": 0.1}
    c.portal.call(register_model, c.app)
    assert c.app.state.shadow_model.status == "immutable_version_conflict"


def test_postgres_incident_outbox_rollback(postgres_client, message):
    from backend.db.models import DetectionEvent, IncidentEvent, ScenarioRun

    c = postgres_client

    async def verify():
        run_id = str(uuid4())
        async with c.app.state.db.sessions() as session:
            session.add(
                ScenarioRun(
                    id=run_id,
                    scenario_id="syn_flood",
                    status="completed",
                    thresholds={},
                    detection_mode="rules_only",
                )
            )
            await session.flush()
            _, event = await process_flow(
                c.app, session, FlowMessage(**message), source="simulation", run_id=run_id
            )
            link = await session.scalar(
                select(IncidentEvent).where(IncidentEvent.event_id == event["event_id"])
            )
            row = await session.get(Incident, link.incident_id)
            assert row.source == "simulation" and row.event_count == 1
            assert await session.scalar(
                select(NotificationDelivery).where(NotificationDelivery.incident_id == row.id)
            )
            incident_id = row.id
            await session.rollback()
        async with c.app.state.db.sessions() as session:
            assert (
                await session.scalar(
                    select(DetectionEvent).where(DetectionEvent.message_id == message["message_id"])
                )
                is None
            )
            assert await session.get(Incident, incident_id) is None

    c.portal.call(verify)
    c.app.state.settings.ops_allow_insecure_local = True
    username = "postgres_" + uuid4().hex

    async def provision():
        async with c.app.state.db.sessions() as session:
            await provision_operator(session, username, "PostgreSQL login test", "viewer", PASSWORD)
            await session.commit()

    c.portal.call(provision)
    response = c.post("/api/ops/login", json={"username": username, "password": PASSWORD})
    assert response.status_code == 200, response.text
    assert c.get("/api/ops/me").json()["operator"]["username"] == username
    assert (
        c.post(
            "/api/ops/logout", headers={"X-CSRF-Token": response.json()["csrf_token"]}
        ).status_code
        == 200
    )


def test_full_ownership_approval_apply_release_recovery_and_metrics(ops_client):
    c = ops_client
    admin, approver = auth(c), auth(c, "bob")
    seed(c)
    row = incident(c, admin)
    path = f"/api/ops/incidents/{row['id']}"
    assert make_preview(c, admin, row).status_code == 409
    row = c.post(path + "/ack", json={"version": row["version"]}, headers=admin).json()
    assert row["status"] == "acknowledged"
    assert c.post(path + "/ack", json={"version": 1}, headers=admin).status_code == 200
    assert (
        c.post(path + "/ack", json={"version": row["version"]}, headers=approver).status_code == 409
    )
    assert (
        c.post(
            path + "/transition",
            json={"version": 1, "status": "investigating", "reason": "stale request"},
            headers=admin,
        ).status_code
        == 409
    )
    row = c.post(
        path + "/transition",
        json={
            "version": row["version"],
            "status": "investigating",
            "reason": "Investigate observed source",
        },
        headers=admin,
    ).json()
    assert make_preview(c, admin, row, ttl=900).status_code == 409
    result = make_preview(c, admin, row)
    assert result.status_code == 201, result.text
    p = result.json()
    approval = {"policy_hash": p["policy_hash"], "reason": "Independent review complete"}
    assert (
        c.post(
            f"/api/ops/action-requests/{p['id']}/approve", json=approval, headers=admin
        ).status_code
        == 403
    )
    result = c.post(f"/api/ops/action-requests/{p['id']}/approve", json=approval, headers=approver)
    assert result.status_code == 200, result.text
    run = result.json()
    repeated = c.post(
        f"/api/ops/action-requests/{p['id']}/approve", json=approval, headers=approver
    )
    assert repeated.json()["id"] == run["id"]
    for _ in range(2):
        c.portal.call(maintenance, c.app)
    row = c.get(path, headers=admin).json()
    assert row["actions"][0]["status"] == "applied"
    assert (
        c.post(
            path + "/transition",
            json={
                "version": row["version"],
                "status": "resolved",
                "reason": "Cannot skip evidence",
            },
            headers=admin,
        ).status_code
        == 409
    )
    result = c.post(
        path + "/transition",
        json={
            "version": row["version"],
            "status": "contained",
            "reason": "Traffic reduced and service healthy",
        },
        headers=admin,
    )
    assert result.status_code == 200, result.text
    row = result.json()
    assert (
        c.post(
            path + "/transition",
            json={
                "version": row["version"],
                "status": "recovering",
                "reason": "Policy still active",
            },
            headers=admin,
        ).status_code
        == 409
    )
    assert (
        c.post(
            f"/api/ops/actions/{run['id']}/revoke",
            json={"reason": "Enter recovery observation"},
            headers=admin,
        ).status_code
        == 200
    )
    for _ in range(2):
        c.portal.call(maintenance, c.app)
    result = c.post(
        path + "/transition",
        json={
            "version": row["version"],
            "status": "recovering",
            "reason": "Release receipt and healthy observations",
        },
        headers=admin,
    )
    assert result.status_code == 200, result.text
    row = result.json()
    body = {
        "version": row["version"],
        "status": "resolved",
        "reason": "Stable service recovery verified",
    }
    assert c.post(path + "/transition", json=body, headers=admin).status_code == 409

    async def advance_evidence():
        async with c.app.state.db.sessions() as session:
            await session.execute(
                update(Incident)
                .where(Incident.id == row["id"])
                .values(recovering_at=utcnow() - timedelta(seconds=11))
            )
            await tick(session, c.app.state.settings)
            await tick(session, c.app.state.settings)
            await session.commit()

    c.portal.call(advance_evidence)
    result = c.post(path + "/transition", json=body, headers=admin)
    assert result.status_code == 200, result.text
    assert result.json()["status"] == "resolved"
    stats = c.get("/api/ops/metrics?source=simulation", headers=admin).json()
    assert stats["mtta"]["samples"] == stats["mttc"]["samples"] == stats["mttr"]["samples"] == 1
    assert stats["mttd"]["mean_seconds"] is None
    assert c.get("/api/ops/metrics?source=live", headers=admin).json()["incidents"] == 0
    report = c.get(path + "/report", headers=admin).json()
    assert report["recovery_verified"] and report["incident"]["source"] == "simulation"


def test_kill_switch_stale_agent_and_protected_scope(ops_client):
    c = ops_client
    admin = auth(c)
    seed(c)
    row = incident(c, admin)
    row = c.post(
        f"/api/ops/incidents/{row['id']}/ack", json={"version": row["version"]}, headers=admin
    ).json()
    assert (
        c.post(
            "/api/ops/kill-switch",
            json={"enabled": True, "reason": "Emergency exercise"},
            headers=admin,
        ).status_code
        == 200
    )
    assert make_preview(c, admin, row).status_code == 409
    c.post(
        "/api/ops/kill-switch",
        json={"enabled": False, "reason": "Exercise finished"},
        headers=admin,
    )

    async def protect():
        async with c.app.state.db.sessions() as session:
            asset = await session.get(Asset, row["asset_id"])
            asset.protected_cidrs = ["192.0.2.0/24"]
            await session.commit()

    c.portal.call(protect)
    assert "보호 대상" in make_preview(c, admin, row).json()["error"]["message"]


def test_outbox_restart_claim_retry_after_and_unknown(ops_client):
    c = ops_client
    c.app.state.settings.ops_notifications_enabled = True
    c.app.state.settings.slack_bot_token = SecretStr("secret-never-log")
    c.app.state.settings.slack_channel = "C_TEST"
    seed(c, source="live", count=1)

    async def exercise():
        row = await claim(c.app.state.db)
        assert row and row.status == "sending" and row.attempts == 1
        assert await claim(c.app.state.db) is None
        await finish(
            c.app.state.db, row, {"status": "retrying", "delay": 60, "error": "Provider rate limit"}
        )
        async with c.app.state.db.sessions() as session:
            saved = await session.get(NotificationDelivery, row.id)
            assert (
                saved.status == "retrying"
                and (
                    saved.next_attempt_at.replace(tzinfo=utcnow().tzinfo) - utcnow()
                ).total_seconds()
                > 55
            )
            saved.next_attempt_at = utcnow() - timedelta(seconds=1)
            await session.commit()
        retry = await claim(c.app.state.db)
        assert retry.attempts == 2
        async with c.app.state.db.sessions() as session:
            await session.execute(
                update(NotificationDelivery)
                .where(NotificationDelivery.id == row.id)
                .values(lease_until=utcnow() - timedelta(seconds=1))
            )
            await session.commit()
        assert await claim(c.app.state.db) is None
        async with c.app.state.db.sessions() as session:
            assert (await session.get(NotificationDelivery, row.id)).status == "unknown"

    c.portal.call(exercise)


def test_slack_429_and_credentials_not_logged(ops_client, monkeypatch, caplog):
    c = ops_client
    c.app.state.settings.ops_notifications_enabled = True
    c.app.state.settings.slack_bot_token = SecretStr("secret-never-log")
    c.app.state.settings.slack_channel = "C_TEST"
    seed(c, source="live", count=1)
    original = httpx.AsyncClient
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kw: original(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(429, headers={"Retry-After": "120"})
            ),
            **kw,
        ),
    )

    async def exercise():
        row = await claim(c.app.state.db)
        outcome = await deliver(c.app.state.settings, row)
        assert outcome["status"] == "retrying" and outcome["delay"] == 120

    c.portal.call(exercise)
    assert "secret-never-log" not in caplog.text


def test_no_external_sender_for_simulation_or_disabled(ops_client):
    c = ops_client
    seed(c)

    async def forbidden(*_):
        raise AssertionError("No external sends during training")

    c.portal.call(work_once, c.app, forbidden)


def test_slack_signature_mapping_replay_and_ack(ops_client):
    c = ops_client
    headers = auth(c)
    seed(c, source="live", count=1)
    row = incident(c, headers, "live")
    c.app.state.settings.slack_signing_secret = SecretStr("slack-test-signature")
    c.app.state.settings.slack_team_id = "T_ALLOWED"
    body = urlencode(
        {
            "payload": json.dumps(
                {
                    "team": {"id": "T_ALLOWED"},
                    "user": {"id": "U_ALICE"},
                    "actions": [{"action_id": "incident_ack", "value": row["id"]}],
                }
            )
        }
    ).encode()
    stamp = str(int(time.time()))
    signature = (
        "v0="
        + hmac.new(
            b"slack-test-signature", b"v0:" + stamp.encode() + b":" + body, hashlib.sha256
        ).hexdigest()
    )
    signed = {
        "X-Slack-Request-Timestamp": stamp,
        "X-Slack-Signature": signature,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    assert c.post("/api/integrations/slack/interactions", content=body).status_code == 401
    for _ in range(2):
        assert (
            c.post("/api/integrations/slack/interactions", content=body, headers=signed).status_code
            == 200
        )
    assert (
        c.get(f"/api/ops/incidents/{row['id']}", headers=headers).json()["status"] == "acknowledged"
    )
    assert (
        c.post(
            "/api/integrations/slack/interactions",
            content=body,
            headers={**signed, "X-Slack-Request-Timestamp": "1"},
        ).status_code
        == 401
    )


def test_agent_authentication_and_training_separation(ops_client):
    c = ops_client
    headers = auth(c)
    seed(c)
    point = c.get("/api/ops/assets", headers=headers).json()["points"][0]
    assert c.get(f"/api/ops/agents/{point['id']}/commands").status_code == 401
    assert "token_hash" not in point
    assert c.get("/api/ops/models", headers=headers).json()["automatic_response_enabled"] is False
