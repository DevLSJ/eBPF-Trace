"""Local interface inspections: one row per run, one row per observed second.

Additive only. Detection events produced by an inspection stay ordinary `live` events; the run
keeps their ids so the web app can link back without a schema change to detection_events.
"""

import sqlalchemy as sa
from alembic import op

revision = "f3a1c8d2e6b4"
down_revision = "b7d3e9f1a2c4"
branch_labels = depends_on = None


def upgrade():
    op.create_table(
        "live_inspections",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("interface", sa.String(32), nullable=False),
        sa.Column("address", sa.String(45), nullable=False),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("duration_seconds", sa.Integer(), nullable=False),
        sa.Column("elapsed_seconds", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("error", sa.String(240), nullable=False, server_default=""),
        sa.Column("thresholds", sa.JSON().with_variant(sa.dialects.postgresql.JSONB(), "postgresql"), nullable=False),
        sa.Column("detection_mode", sa.String(16), nullable=False),
        sa.Column("totals", sa.JSON().with_variant(sa.dialects.postgresql.JSONB(), "postgresql"), nullable=False),
        sa.Column("event_ids", sa.JSON().with_variant(sa.dialects.postgresql.JSONB(), "postgresql"), nullable=False),
        sa.Column("incident_ids", sa.JSON().with_variant(sa.dialects.postgresql.JSONB(), "postgresql"), nullable=False),
    )
    op.create_index("ix_live_inspections_status", "live_inspections", ["status"])
    op.create_index("ix_live_inspections_started_at", "live_inspections", ["started_at"])
    op.create_table(
        "live_inspection_windows",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), primary_key=True),
        sa.Column("run_id", sa.String(36), sa.ForeignKey("live_inspections.id"), nullable=False),
        sa.Column("second", sa.Integer(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("pkt_rate", sa.Float(), nullable=False),
        sa.Column("byte_rate", sa.Float(), nullable=False),
        sa.Column("flows", sa.Integer(), nullable=False),
        sa.Column("rule_hits", sa.JSON().with_variant(sa.dialects.postgresql.JSONB(), "postgresql"), nullable=False),
        sa.Column("scored", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("min_score", sa.Float()),
        sa.Column("events", sa.JSON().with_variant(sa.dialects.postgresql.JSONB(), "postgresql"), nullable=False),
        sa.UniqueConstraint("run_id", "second"),
    )
    op.create_index("ix_live_inspection_windows_run_id", "live_inspection_windows", ["run_id"])
    op.create_index("ix_live_inspection_windows_observed_at", "live_inspection_windows", ["observed_at"])


def downgrade():
    op.drop_index("ix_live_inspection_windows_observed_at", table_name="live_inspection_windows")
    op.drop_index("ix_live_inspection_windows_run_id", table_name="live_inspection_windows")
    op.drop_table("live_inspection_windows")
    op.drop_index("ix_live_inspections_started_at", table_name="live_inspections")
    op.drop_index("ix_live_inspections_status", table_name="live_inspections")
    op.drop_table("live_inspections")
