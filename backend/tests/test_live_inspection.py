import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from backend.main import create_app
from backend.services import live_inspection
from backend.services.live_inspection import (
    PacketAccumulator,
    interface_kind,
    messages_from,
    packet_tuple,
    rule_probes,
)
from collector.features import FeatureCalculator
from ml.rule_engine import RuleEngine

ADMIN = {'authorization': 'Bearer test-admin-token'}


def wait_finished(client, run_id):
    for _ in range(400):
        row = client.get(f'/api/live/inspections/{run_id}', headers=ADMIN).json()
        if row['status'] != 'running':
            return row
        time.sleep(.01)
    pytest.fail('Inspection did not finish')


def loopback(client):
    items = client.get('/api/live/interfaces', headers=ADMIN).json()['items']
    return next(item for item in items if item['kind'] == 'loopback')


def test_interfaces_are_admin_only_and_classified(client):
    assert client.get('/api/live/interfaces').status_code == 401
    body = client.get('/api/live/interfaces', headers=ADMIN).json()
    assert body['capabilities']['counters']['available'] is True
    assert {'available', 'reason'} <= set(body['capabilities']['packet'])
    assert any(item['kind'] == 'loopback' for item in body['items'])
    for item in body['items']:
        assert {'name', 'kind', 'label', 'addresses', 'is_up', 'active'} <= set(item)
    assert interface_kind('wlan0') == 'wifi' and interface_kind('en0', {'en0': 'Wi-Fi'}) == 'wifi'
    assert interface_kind('eth0') == 'ethernet' and interface_kind('docker0') == 'virtual'
    assert interface_kind('lo0') == 'loopback'


def test_counter_inspection_feeds_rules_incidents_and_dashboard(client, monkeypatch):
    monkeypatch.setattr(live_inspection, 'STEP_SECONDS', .002)
    state = {'packets': 1_000, 'bytes': 80_000}

    def counters(pernic=False):
        state['packets'] += 20_000  # ≥ baseline 1,000 × 10 → TRAFFIC_SPIKE on the real rule engine
        state['bytes'] += 1_500_000
        return {name: SimpleNamespace(packets_recv=state['packets'], bytes_recv=state['bytes'])
                for name in ('lo', 'lo0')}
    monkeypatch.setattr(live_inspection.psutil, 'net_io_counters', counters)
    name = loopback(client)['name']
    assert client.post('/api/live/inspections', json={'interface': name}).status_code == 401
    assert client.post('/api/live/inspections', json={'interface': 'nope0', 'mode': 'counters'}, headers=ADMIN).status_code == 404
    assert client.post('/api/live/inspections', json={'interface': name, 'duration_seconds': 1}, headers=ADMIN).status_code == 422
    with client.websocket_connect('/ws/dashboard') as ws:
        response = client.post('/api/live/inspections', json={'interface': name, 'mode': 'counters', 'duration_seconds': 5}, headers=ADMIN)
        assert response.status_code == 201
        run = response.json()
        assert run['status'] == 'running' and run['mode'] == 'counters'
        frames = [ws.receive_json() for _ in range(2)]
        assert any(f['type'] == 'traffic' and f['source'] == 'live' and f['capture']['interface'] == name for f in frames)
        result = wait_finished(client, run['id'])
    assert result['status'] == 'completed' and len(result['windows']) == 5
    stages = result['stages']
    assert stages['capture']['status'] == 'ok' and stages['capture']['packets'] == 100_000
    assert stages['rules']['checked'] == 5 and stages['rules']['hits']['TRAFFIC_SPIKE'] >= 1
    assert stages['model']['status'] == 'skipped' and stages['model']['reason']
    assert stages['response']['events'] >= 1 and stages['response']['incidents'] == 1
    events = client.get('/api/events', params={'source': 'live', 'attack_type': 'TRAFFIC_SPIKE'}).json()
    assert events['total'] >= 1 and events['items'][0]['flow']['src_ip'] == '0.0.0.0'
    assert result['event_ids'][-1] == events['items'][0]['event_id'] and len(result['event_ids']) == stages['response']['events']
    listing = client.get('/api/live/inspections', headers=ADMIN).json()['items']
    assert listing[0]['id'] == run['id'] and 'windows' not in listing[0]
    assert client.get(f'/api/live/inspections/{run["id"]}', headers=ADMIN).json()['stages']['rules']['thresholds']['baseline_pps'] == 1000


def test_second_inspection_conflicts_until_stopped(client, monkeypatch):
    monkeypatch.setattr(live_inspection, 'STEP_SECONDS', .05)
    name = loopback(client)['name']
    body = {'interface': name, 'mode': 'counters', 'duration_seconds': 300}
    first = client.post('/api/live/inspections', json=body, headers=ADMIN).json()
    assert client.post('/api/live/inspections', json=body, headers=ADMIN).status_code == 409
    stopped = client.post(f'/api/live/inspections/{first["id"]}/stop', headers=ADMIN).json()
    assert stopped['status'] == 'cancelled' and stopped['finished_at']
    assert client.post('/api/live/inspections', json={**body, 'duration_seconds': 5}, headers=ADMIN).status_code == 201


def test_packet_path_computes_context_features_and_detects_syn_flood():
    accumulator, now = PacketAccumulator(), time.time()
    for port in range(150):  # 150 flows × 8 SYNs: past the 1,000 SYN/s rule, inside the per-second cap
        for _ in range(8):
            accumulator.add('203.0.113.9', '198.51.100.20', 40000 + port, 443, 6, 60, True, int(now * 1e9))
    accumulator.add('198.51.100.20', '203.0.113.9', 443, 40000, 6, 1400, False, int(now * 1e9))
    messages = messages_from(accumulator.drain(), FeatureCalculator(), now)
    assert 0 < len(messages) <= live_inspection.MAX_FLOWS_PER_SECOND
    attack = messages[0]  # fullest source context ranks first, inside the per-second cap
    features = attack.features.model_dump()
    assert str(attack.flow.src_ip) == '203.0.113.9' and features['feature_schema_version'] == 2
    assert features['source_syn_rate'] >= 1000 and features['port_cnt'] == 1
    assert RuleEngine().detect(features) == 'SYN_FLOOD'
    reverse = next(m for m in messages if str(m.flow.src_ip) == '198.51.100.20')
    assert reverse.features.reverse_pkt_rate == 8 and reverse.features.bidirectional_pkt_rate == 9
    assert accumulator.drain() == []  # every flow drained exactly once

    class Layer(SimpleNamespace):
        pass

    class Packet:
        def __init__(self, layers, size):
            self.layers, self.size = layers, size

        def getlayer(self, name):
            return self.layers.get(name)

        def __len__(self):
            return self.size
    syn = Packet({'IP': Layer(src='203.0.113.9', dst='198.51.100.20'), 'TCP': Layer(sport=40001, dport=443, flags=0x02)}, 60)
    ack = Packet({'IP': Layer(src='203.0.113.9', dst='198.51.100.20'), 'TCP': Layer(sport=40001, dport=443, flags=0x12)}, 60)
    udp = Packet({'IP': Layer(src='203.0.113.9', dst='198.51.100.20'), 'UDP': Layer(sport=5000, dport=53)}, 90)
    assert packet_tuple(syn) == ('203.0.113.9', '198.51.100.20', 40001, 443, 6, 60, True)
    assert packet_tuple(ack)[6] is False and packet_tuple(udp)[4] == 17
    assert packet_tuple(Packet({}, 40)) is None


def test_defense_check_probes_every_line(client):
    assert client.post('/api/live/check').status_code == 401
    body = client.post('/api/live/check', headers=ADMIN).json()
    items = {item['id']: item for item in body['items']}
    assert [item['id'] for item in body['items']] == ['capture', 'rules', 'model', 'response']
    assert items['rules']['status'] == 'ok' and len(items['rules']['probes']) == 5
    assert {p['expected'] for p in items['rules']['probes']} == {'SYN_FLOOD', 'PORT_SCAN', 'TRAFFIC_SPIKE', 'LARGE_FLOW', 'BENIGN'}
    assert items['model']['status'] == 'skipped' and items['model']['detail']
    assert [p['route'] for p in items['response']['probes']] == ['automatic', 'approval']
    assert items['response']['status'] == 'ok' and items['response']['control'] == {'auto_response': False, 'kill_switch': False}
    assert body['summary']['fail'] == 0
    # Probes follow the stored thresholds instead of hard-coded numbers.
    client.put('/api/config/thresholds', json={'baseline_pps': 5000, 'port_cnt_threshold': 40}, headers=ADMIN)
    probes = {p['expected']: p for p in client.post('/api/live/check', headers=ADMIN).json()['items'][1]['probes']}
    assert all(p['passed'] for p in probes.values())
    thresholds = client.app.state.detector.rules.thresholds
    assert rule_probes(thresholds)[1][2]['port_cnt'] == 45


def test_history_is_read_from_the_database_across_restarts(client, monkeypatch):
    monkeypatch.setattr(live_inspection, 'STEP_SECONDS', .002)
    name = loopback(client)['name']
    body = {'interface': name, 'mode': 'counters', 'duration_seconds': 6}
    run = client.post('/api/live/inspections', json=body, headers=ADMIN).json()
    assert wait_finished(client, run['id'])['status'] == 'completed'
    # A long run left "running" by a crash is marked interrupted when the next process starts.
    monkeypatch.setattr(live_inspection, 'STEP_SECONDS', .5)
    stale = client.post('/api/live/inspections', json={**body, 'duration_seconds': 300}, headers=ADMIN).json()
    with TestClient(create_app(client.app.state.settings)) as restarted:
        items = restarted.get('/api/live/inspections', headers=ADMIN).json()['items']
        assert [item['id'] for item in items[:2]] == [stale['id'], run['id']]
        assert items[0]['status'] == 'interrupted' and items[0]['finished_at']
        detail = restarted.get(f"/api/live/inspections/{run['id']}", headers=ADMIN).json()
        assert detail['status'] == 'completed' and len(detail['windows']) == 6
        assert detail['stages']['rules']['checked'] == 6 and detail['thresholds']['baseline_pps'] == 1000
        assert [w['t'] for w in detail['windows']] == sorted(w['t'] for w in detail['windows'])
        assert restarted.get('/api/live/inspections/00000000-0000-0000-0000-000000000000', headers=ADMIN).status_code == 404
    client.post(f"/api/live/inspections/{stale['id']}/stop", headers=ADMIN)
