"""Explicitly mark restricted public test identities."""

import sqlalchemy as sa
from alembic import op

revision = "da94193c76e0"
down_revision = "c87a20b1f906"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "operators",
        sa.Column("is_test_account", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade():
    op.drop_column("operators", "is_test_account")
