"""Replace per-status assessment uniqueness with one active row per domain.

Revision ID: 0002_active_assessment_index
Revises: 0001_create_initial_tables
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0002_active_assessment_index"
down_revision = "0001_create_initial_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Existing deployments may have one pending and one failed row for a
    # domain. Keep the most recently updated active row before adding the
    # stricter partial unique index.
    op.execute(sa.text("""
            DELETE FROM domain_assessments AS older
                USING domain_assessments AS newer
            WHERE older.domain_id = newer.domain_id
              AND older.status IN ('pending', 'failed')
              AND newer.status IN ('pending', 'failed')
              AND (
                older.updated_at < newer.updated_at
               OR (
                older.updated_at = newer.updated_at
              AND older.id < newer.id
                )
                )
            """))

    op.drop_constraint(
        "uq_domain_assessment_domain_status",
        "domain_assessments",
        type_="unique",
    )

    op.create_index(
        "uq_domain_assessment_one_active",
        "domain_assessments",
        ["domain_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('pending', 'failed')"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_domain_assessment_one_active",
        table_name="domain_assessments",
    )

    # Restoring the old constraint is only safe if no duplicate
    # (domain_id, status) pairs have been created since upgrade.
    op.create_unique_constraint(
        "uq_domain_assessment_domain_status",
        "domain_assessments",
        ["domain_id", "status"],
    )
