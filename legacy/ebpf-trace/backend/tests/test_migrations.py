import sqlite3

from alembic import command
from alembic.config import Config


def test_additive_migration_preserves_old_events(tmp_path):
    path = tmp_path / 'migration.db'
    config = Config('alembic.ini')
    config.attributes['database_url'] = f'sqlite+aiosqlite:///{path}'
    command.upgrade(config, '423cae8d12db')
    with sqlite3.connect(path) as db:
        db.execute("""INSERT INTO detection_events
            (id,message_id,detected_at,src_ip,dst_ip,src_port,dst_port,protocol,attack_type,severity,pkt_rate,byte_rate,syn_ratio,port_entropy,flow_duration,raw_features)
            VALUES (1,'test','2026-09-17 01:00:00','192.0.2.1','192.0.2.2',1234,80,6,'SYN_FLOOD','critical',1000,60000,1,0,1000,'{}')""")
    command.upgrade(config, 'head')
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT id, source, scenario_run_id, is_confirmed FROM detection_events').fetchall() == [(1, 'live', None, None)]
        assert db.execute('SELECT COUNT(*) FROM scenario_samples').fetchone()[0] == 0
    command.downgrade(config, '423cae8d12db')
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT id FROM detection_events').fetchall() == [(1,)]
