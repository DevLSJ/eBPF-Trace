"""Isolated anonymous supply-chain demonstration, without changing operational tables."""

from alembic import op

from backend.db.models import Base

revision = "ef5720b83a19"
down_revision = "da94193c76e0"
branch_labels = None
depends_on = None

TABLES = (
    "supply_demo_sessions",
    "supply_demo_versions",
    "supply_demo_scans",
    "supply_demo_activities",
    "supply_demo_actions",
    "supply_demo_deployments",
    "supply_demo_rate_limits",
)


def upgrade():
    for name in TABLES:
        Base.metadata.tables[name].create(bind=op.get_bind())


def downgrade():
    for name in reversed(TABLES):
        op.drop_table(name)
