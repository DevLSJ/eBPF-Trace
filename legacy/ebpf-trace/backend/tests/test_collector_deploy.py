import io
import json

import pytest

from infra import update_collector


@pytest.mark.parametrize('healthy', [True, False])
def test_collector_update_preserves_state_and_rolls_back_unhealthy_release(tmp_path, monkeypatch, healthy):
    runtime, source = tmp_path / 'runtime', tmp_path / 'checkout'
    for folder in (runtime, source):
        (folder / 'collector').mkdir(parents=True)
    (runtime / 'collector/features.py').write_text('old code')
    (source / 'collector/features.py').write_text('new code')
    (runtime / '.env.collector').write_text('retained environment')
    (runtime / 'collector-outbox.db').write_bytes(b'retained pending messages')
    calls = []

    def fake_command(*args, **kwargs):
        calls.append(args)
        return str(runtime) if args[:2] == ('systemctl', 'show') else ''

    monkeypatch.setattr(update_collector, 'command', fake_command)
    monkeypatch.setattr(update_collector, 'urlopen', lambda *args, **kwargs: io.BytesIO(json.dumps({
        'collector_connected': True, 'collector_feature_schema_version': 2}).encode()))
    if healthy:
        update_collector.update(runtime, source, 'a' * 40, 'http://localhost/health')
    else:
        with pytest.raises(RuntimeError, match='deadline'):
            update_collector.update(runtime, source, 'a' * 40, 'http://localhost/health', timeout=0)
    assert (runtime / 'collector/features.py').read_text() == ('new code' if healthy else 'old code')
    assert (runtime / '.env.collector').read_text() == 'retained environment'
    assert (runtime / 'collector-outbox.db').read_bytes() == b'retained pending messages'
    assert ('sudo', '-n', 'systemctl', 'start', 'ebpf-collector.service') in calls
