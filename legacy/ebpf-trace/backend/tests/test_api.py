import uuid

import pytest
from starlette.websockets import WebSocketDisconnect

AUTH = {"authorization": "Bearer test-collector-token"}


def test_health_and_validation(client):
    assert client.get("/health").json()["detection_mode"] == "rules_only"
    for path in ("/api/events?page=0", "/api/events?page_size=101", "/api/events?severity=invalid"):
        response = client.get(path)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert client.get("/api/events/9999").status_code == 404
    assert client.get("/api/metrics").json() is None
    assert client.get("/api/metrics/history").json() == {"items": []}
    assert client.get("/missing").json()["error"]["code"] == "NOT_FOUND"


def test_detect_persist_broadcast_ack_and_duplicate(client, message):
    with client.websocket_connect("/ws/dashboard") as dashboard:
        with client.websocket_connect("/ws/collector", headers=AUTH) as collector:
            assert client.get("/health").json()["collector_connected"] is True
            collector.send_json(message)
            event = dashboard.receive_json()
            assert event["type"] == "detection_event"
            assert event["severity"] == "critical"
            assert event["anomaly_score"] is None
            assert dashboard.receive_json()["type"] == "traffic"
            assert collector.receive_json() == {"type": "ack", "message_id": message["message_id"]}
            # ACK follows commit: the event is immediately available through REST.
            assert (
                client.get(f"/api/events/{event['event_id']}").json()["attack_type"] == "SYN_FLOOD"
            )
            collector.send_json(message)
            assert collector.receive_json()["type"] == "ack"
            assert client.get("/api/events").json()["total"] == 1


def test_pagination_and_filtering(client, message):
    with client.websocket_connect("/ws/collector", headers=AUTH) as ws:
        for _ in range(3):
            message["message_id"] = str(uuid.uuid4())
            ws.send_json(message)
            assert ws.receive_json()["type"] == "ack"
    data = client.get("/api/events?page=2&page_size=2&severity=critical").json()
    assert data["total"] == 3 and len(data["items"]) == 1
    assert client.get("/api/events?severity=high").json()["total"] == 0
    assert (
        client.get(
            "/api/events?start_time=2030-01-01T00:00:00Z&end_time=2020-01-01T00:00:00Z"
        ).status_code
        == 400
    )


def test_auth_validation_and_runtime_thresholds(client, message):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/collector"):
            pass
    thresholds = client.get("/api/config/thresholds").json()
    assert client.put("/api/config/thresholds", json=thresholds).status_code == 401
    thresholds["syn_pps_threshold"] = 5000
    assert (
        client.put(
            "/api/config/thresholds",
            json=thresholds,
            headers={"authorization": "Bearer test-admin-token"},
        ).status_code
        == 200
    )
    with client.websocket_connect("/ws/collector", headers=AUTH) as ws:
        ws.send_json({"type": "flow_features"})
        assert ws.receive_json()["code"] == "VALIDATION_ERROR"
        ws.send_json(message)
        assert ws.receive_json()["type"] == "ack"
    assert client.get("/api/events").json()["total"] == 0


def test_postgres_real_persistence(postgres_client, message):
    client = postgres_client
    with client.websocket_connect("/ws/collector", headers=AUTH) as ws:
        ws.send_json(message)
        assert ws.receive_json()["type"] == "ack"
    events = client.get("/api/events").json()
    assert any(event["flow"]["src_ip"] == "192.168.64.1" for event in events["items"])
