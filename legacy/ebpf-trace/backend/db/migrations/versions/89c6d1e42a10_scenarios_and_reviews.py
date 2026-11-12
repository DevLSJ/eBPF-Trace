"""Persist simulation runs, evidence and analyst review without changing existing events."""
import sqlalchemy as sa
from alembic import op

revision = '89c6d1e42a10'
down_revision = '423cae8d12db'
branch_labels = depends_on = None


def upgrade():
    op.create_table('scenario_runs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('scenario_id', sa.String(32), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('finished_at', sa.DateTime(timezone=True)),
        sa.Column('thresholds', sa.JSON(), nullable=False),
        sa.Column('detection_mode', sa.String(16), nullable=False))
    op.create_index('ix_scenario_runs_status', 'scenario_runs', ['status'])
    with op.batch_alter_table('detection_events') as batch:
        batch.add_column(sa.Column('source', sa.String(16), nullable=False, server_default='live'))
        batch.add_column(sa.Column('scenario_run_id', sa.String(36)))
        batch.add_column(sa.Column('expected_label', sa.String(32)))
        batch.add_column(sa.Column('reviewed_at', sa.DateTime(timezone=True)))
        batch.create_foreign_key('fk_event_scenario_run', 'scenario_runs', ['scenario_run_id'], ['id'])
        batch.create_index('ix_detection_events_source', ['source'])
        batch.create_index('ix_detection_events_scenario_run_id', ['scenario_run_id'])
    op.create_table('scenario_samples',
        sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), primary_key=True),
        sa.Column('run_id', sa.String(36), sa.ForeignKey('scenario_runs.id'), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('step', sa.Integer(), nullable=False),
        sa.Column('stage', sa.String(32), nullable=False),
        sa.Column('expected_label', sa.String(32), nullable=False),
        sa.Column('detected_label', sa.String(32), nullable=False),
        sa.Column('features', sa.JSON(), nullable=False),
        sa.Column('anomaly_score', sa.Float()),
        sa.Column('event_id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), sa.ForeignKey('detection_events.id')))
    op.create_index('ix_scenario_samples_run_id', 'scenario_samples', ['run_id'])


def downgrade():
    op.drop_table('scenario_samples')
    with op.batch_alter_table('detection_events') as batch:
        batch.drop_index('ix_detection_events_source')
        batch.drop_index('ix_detection_events_scenario_run_id')
        batch.drop_constraint('fk_event_scenario_run', type_='foreignkey')
        for name in ('source', 'scenario_run_id', 'expected_label', 'reviewed_at'):
            batch.drop_column(name)
    op.drop_table('scenario_runs')
