"""Risk gate and the opt-in automatic response path.

Additive: existing requests and runs are labelled as operator-originated.
"""

import sqlalchemy as sa
from alembic import op

revision = "b7d3e9f1a2c4"
down_revision = "ef5720b83a19"
branch_labels = depends_on = None


def upgrade():
    with op.batch_alter_table("ops_control") as batch:
        batch.add_column(
            sa.Column("auto_response", sa.Boolean(), nullable=False, server_default=sa.false())
        )
    with op.batch_alter_table("assets") as batch:
        batch.add_column(
            sa.Column("auto_response", sa.Boolean(), nullable=False, server_default=sa.false())
        )
    with op.batch_alter_table("action_requests") as batch:
        batch.alter_column("requester_id", existing_type=sa.String(36), nullable=True)
        batch.add_column(
            sa.Column("origin", sa.String(16), nullable=False, server_default="operator")
        )
    with op.batch_alter_table("action_runs") as batch:
        batch.add_column(
            sa.Column("origin", sa.String(16), nullable=False, server_default="operator")
        )


def downgrade():
    with op.batch_alter_table("action_runs") as batch:
        batch.drop_column("origin")
    with op.batch_alter_table("action_requests") as batch:
        batch.drop_column("origin")
        batch.alter_column("requester_id", existing_type=sa.String(36), nullable=False)
    with op.batch_alter_table("assets") as batch:
        batch.drop_column("auto_response")
    with op.batch_alter_table("ops_control") as batch:
        batch.drop_column("auto_response")
