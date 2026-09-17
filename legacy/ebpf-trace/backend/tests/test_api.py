import uuid

import pytest
from starlette.websockets import WebSocketDisconnect

AUTH = {"authorization": "Bearer test-collector-token"}


def test_health_and_validation(client):
    assert client.get("/health").json()["detection_mode"] == "rules_only"
    assert client.get("/health").json()["model_status"] == "unavailable_or_unvalidated"
    for path in ("/api/events?page=0", "/api/events?page_size=101", "/api/events?severity=invalid"):
        response = client.get(path)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert client.get("/api/events/9999").status_code == 404
    assert client.get("/api/metrics").json() is None
    assert client.get("/api/metrics/history").json() == {"items": []}
    assert client.get("/missing").json()["error"]["code"] == "NOT_FOUND"


def test_capture_reports_have_provenance_and_no_invented_performance(client):
    response = client.get("/api/analysis/pcap")
    assert response.status_code == 200
    reports = response.json()["items"]
    assert {item["source"] for item in reports} == {
        "Monday-WorkingHours.pcap", "Tuesday-WorkingHours.pcap", "Wednesday-workingHours.pcap",
        "Friday-WorkingHours.pcap", "Thursday-WorkingHours.pcap"
    }
    for report in reports:
        assert report["complete"] and len(report["sha256"]) == 64
        assert report["label_status"] == "joined_conservative"
        labels = report["labels"]
        assert 0 < labels["coverage"] < 1
        assert sum(labels["distribution"].values()) == labels["counts"]["matched"]
        assert labels["timestamp_uncertainty_seconds"] == (1 if report['source'].startswith('Monday') else 60)
        assert labels['counts'].get('invalid_label_rows', 0) < labels['counts']['label_rows'] * .01
        assert report["model_validated"] is False
        assert sum(report["protocols"].values()) == report["counts"]["eligible_packets"]
        assert report["feature_schema_version"] == 2 and len(report["features"]) == 25


def test_context_contract_is_complete_and_saved_in_event_evidence(client, message):
    from collector.features import FeatureCalculator, Snapshot

    snapshot = Snapshot('192.168.64.1', '192.168.64.2', 12345, 80, 6, 1250, 75000, 1250, 0, 10**9)
    message['features'] = FeatureCalculator().compute(snapshot, 1)
    with client.websocket_connect('/ws/collector', headers=AUTH) as ws:
        incomplete = {**message, 'features': {**message['features'], 'service_pkt_rate': None}}
        ws.send_json(incomplete)
        assert ws.receive_json()['code'] == 'VALIDATION_ERROR'
        ws.send_json(message)
        assert ws.receive_json()['type'] == 'ack'
        assert client.get('/health').json()['collector_feature_schema_version'] == 2
    event = client.get('/api/events').json()['items'][0]
    assert event['features']['feature_schema_version'] == 2
    assert event['features']['service_syn_rate'] == 1250
    assert client.get('/health').json()['collector_feature_schema_version'] is None


def test_analysis_cache_is_not_mutated_and_new_evidence_is_visible(client, tmp_path, monkeypatch):
    import json

    from backend.services import analysis

    monkeypatch.setattr(analysis, 'REPORT_DIRECTORY', tmp_path)
    (tmp_path / 'evaluation').mkdir()
    path = tmp_path / 'evaluation/context-v2.json'
    path.write_text(json.dumps({'status': 'complete', 'deployment_approved': False}))
    returned = analysis.model_evaluation('context-v2')
    returned['status'] = 'mutated'
    assert client.get('/api/analysis/model').json()['context_evaluation']['status'] == 'complete'
    path.write_text(json.dumps({'status': 'updated-report', 'deployment_approved': False}))
    body = client.get('/api/analysis/model').json()
    assert body['context_evaluation']['status'] == 'updated-report'
    assert body['runtime']['mode'] == 'rules_only'


def test_stored_webhook_does_not_enable_notifications(client, message, monkeypatch):
    from pydantic import SecretStr

    def forbidden_send(*args):
        raise AssertionError("Slack must require explicit activation")

    monkeypatch.setattr("backend.websocket.collector.send_alert", forbidden_send)
    client.app.state.settings.slack_webhook_url = SecretStr("https://hooks.slack.com/test")
    with client.websocket_connect("/ws/collector", headers=AUTH) as ws:
        ws.send_json(message)
        assert ws.receive_json()["type"] == "ack"
    assert not client.app.state.alert_tasks


def test_detect_persist_broadcast_ack_and_duplicate(client, message):
    with client.websocket_connect("/ws/dashboard") as dashboard:
        with client.websocket_connect("/ws/collector", headers=AUTH) as collector:
            assert client.get("/health").json()["collector_connected"] is True
            collector.send_json(message)
            event = dashboard.receive_json()
            assert event["type"] == "detection_event"
            assert event["severity"] == "critical"
            assert event["anomaly_score"] is None
            assert event["detected_at"].endswith("+00:00")
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


def test_event_ip_search_matches_both_endpoints_and_validates(client, message):
    with client.websocket_connect('/ws/collector', headers=AUTH) as collector:
        collector.send_json(message)
        assert collector.receive_json()['type'] == 'ack'
    for address in ('192.168.64.1', '192.168.64.2'):
        assert client.get('/api/events', params={'ip': address}).json()['total'] == 1
    assert client.get('/api/events?ip=192.0.2.99').json()['total'] == 0
    assert client.get('/api/events?ip=192.168.64.1&severity=low').json()['total'] == 0
    assert client.get('/api/events?ip=invalid').status_code == 422


def test_model_evaluation_is_separate_from_runtime_and_can_be_absent(client, tmp_path, monkeypatch):
    import json

    from backend.services import analysis

    monkeypatch.setattr(analysis, 'REPORT_DIRECTORY', tmp_path)
    assert client.get('/api/analysis/pcap').status_code == 404
    body = client.get('/api/analysis/model').json()
    assert body['evaluation'] is None and body['runtime']['mode'] == 'rules_only'
    (tmp_path / 'evaluation').mkdir()
    (tmp_path / 'evaluation' / 'combined.json').write_text(json.dumps({'status': 'below_target'}))
    body = client.get('/api/analysis/model').json()
    assert body['evaluation']['status'] == 'below_target'
    assert body['runtime']['mode'] == 'rules_only'


def test_inconsistent_capture_evidence_is_not_served(client, tmp_path, monkeypatch):
    import json

    from backend.services import analysis

    monkeypatch.setattr(analysis, 'REPORT_DIRECTORY', tmp_path)
    (tmp_path / 'labels').mkdir()
    (tmp_path / 'friday.json').write_text(json.dumps({'source': 'Friday.pcap',
        'traffic_minutes': [], 'counts': {'feature_rows': 10}}))
    (tmp_path / 'labels' / 'friday.json').write_text(json.dumps({'counts': {'matched': 11}}))
    response = client.get('/api/analysis/pcap')
    assert response.status_code == 500
    assert response.json()['error']['message'] == 'An internal error occurred'
