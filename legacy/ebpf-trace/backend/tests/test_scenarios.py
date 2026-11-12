import time
import uuid

import pytest

from backend.services import scenarios

ADMIN = {'authorization': 'Bearer test-admin-token'}


def wait_complete(client, run_id):
    for _ in range(200):
        row = client.get(f'/api/scenarios/runs/{run_id}').json()
        if row['status'] != 'running':
            return row
        time.sleep(.01)
    pytest.fail('Scenario did not finish')


def exercise(client, monkeypatch):
    monkeypatch.setattr(scenarios, 'STEP_SECONDS', .005)
    client.app.state.settings.slack_enabled = True  # Simulations never invoke alert delivery.
    def forbidden(*args):
        raise AssertionError('Simulation must not send external alerts')
    monkeypatch.setattr('backend.services.notifications.deliver', forbidden)
    body = {'scenario_id': 'intrusion', 'request_id': str(uuid.uuid4())}
    assert client.post('/api/scenarios/runs', json=body).status_code == 401
    with client.websocket_connect('/ws/dashboard') as ws:
        response = client.post('/api/scenarios/runs', json=body, headers=ADMIN)
        assert response.status_code == 201
        run_id = response.json()['id']
        first = ws.receive_json()
        assert first['type'] == 'traffic' and first['source'] == 'simulation'
        result = wait_complete(client, run_id)
    assert result['status'] == 'completed'
    assert result['sample_count'] == result['matched_steps'] == 15
    assert result['event_count'] == 9
    assert not client.app.state.alert_tasks
    filters = {'scenario_run_id': run_id, 'source': 'simulation'}
    page = client.get('/api/events', params=filters).json()
    assert page['total'] == 9
    event = page['items'][0]
    assert event['expected_label'] == event['attack_type']
    assert event['scenario_run_id'] == run_id
    stats = client.get('/api/events/summary', params=filters).json()
    assert stats['total'] == sum(point['count'] for point in stats['timeline']) == 9
    assert stats['severity'] == {'critical': 3, 'high': 3, 'medium': 3}
    assert client.get('/api/events', params={**filters, 'source': 'live'}).json()['total'] == 0
    # Repeated POST with same ID returns persisted run, never doubles records.
    assert client.post('/api/scenarios/runs', json=body, headers=ADMIN).json()['id'] == run_id
    assert client.get('/api/events', params=filters).json()['total'] == 9
    assert client.post('/api/scenarios/runs', json={**body, 'scenario_id': 'port_scan'}, headers=ADMIN).status_code == 409
    review = {'is_confirmed': False, 'note': '실습 검토: 오탐 처리'}
    route = f"/api/events/{event['event_id']}/review"
    assert client.patch(route, json=review).status_code == 401
    assert client.patch(route, json=review, headers=ADMIN).json()['note'] == review['note']
    assert client.get('/api/events', params={**filters, 'review': 'false_positive'}).json()['total'] == 1
    assert client.get('/api/events/summary', params=filters).json()['is_confirmed'] == {'pending': 8, 'false_positive': 1}
    assert client.get(f"/api/events/{event['event_id']}").json()['reviewed_at']
    assert client.patch(route, json={**review, 'note': 'x' * 2001}, headers=ADMIN).status_code == 422


def test_scenario_db_graph_event_review_and_replay(client, monkeypatch):
    exercise(client, monkeypatch)


def test_postgres_scenario_transactions_and_summary(postgres_client, monkeypatch):
    exercise(postgres_client, monkeypatch)


def test_overlap_cancel_and_threshold_snapshot(client, monkeypatch):
    monkeypatch.setattr(scenarios, 'STEP_SECONDS', .05)
    body = {'scenario_id': 'syn_flood', 'request_id': str(uuid.uuid4())}
    run = client.post('/api/scenarios/runs', json=body, headers=ADMIN).json()
    another = client.post('/api/scenarios/runs', json={**body, 'request_id': str(uuid.uuid4())}, headers=ADMIN)
    assert another.status_code == 409
    thresholds = client.get('/api/config/thresholds').json()
    thresholds['syn_pps_threshold'] = 999999
    client.put('/api/config/thresholds', json=thresholds, headers=ADMIN)
    result = wait_complete(client, run['id'])
    assert result['thresholds']['syn_pps_threshold'] == 1000
    assert result['event_count'] == 3
    second = client.post('/api/scenarios/runs', json={**body, 'request_id': str(uuid.uuid4())}, headers=ADMIN).json()
    assert client.post(f"/api/scenarios/runs/{second['id']}/stop").status_code == 401
    stopped = client.post(f"/api/scenarios/runs/{second['id']}/stop", headers=ADMIN).json()
    assert stopped['status'] == 'cancelled' and stopped['sample_count'] < 9
    assert client.get('/api/events/summary?source=invalid').status_code == 422
    assert client.get('/api/events/summary?start_time=2030-01-01&end_time=2020-01-01').status_code == 400


def test_restart_marks_unfinished_run_interrupted(client):
    from backend.db.models import ScenarioRun
    async def seed():
        async with client.app.state.db.sessions() as session:
            session.add(ScenarioRun(id=str(uuid.uuid4()), scenario_id='port_scan', status='running', thresholds={}, detection_mode='rules_only'))
            await session.commit()
        await client.app.state.scenarios.recover()
    client.portal.call(seed)
    run = client.get('/api/scenarios/runs').json()['items'][0]
    assert run['status'] == 'interrupted' and run['finished_at']
