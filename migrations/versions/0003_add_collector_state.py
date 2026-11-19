"""Add durable collector watermark state.

Revision ID: 0003_add_collector_state
Revises: 0002_active_assessment_index
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0003_add_collector_state"
down_revision = "0002_active_assessment_index"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "collector_state",
        sa.Column("collector_name", sa.String(length=100), nullable=False),
        sa.Column("last_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("collector_name", name="pk_collector_state"),
    )


def downgrade() -> None:
    op.drop_table("collector_state")
