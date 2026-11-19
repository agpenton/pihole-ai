"""Create initial tables for pihole-ai.

Revision ID: 0001_create_initial_tables
Revises:
Create Date: 2025-01-17
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0001_create_initial_tables"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. dns_events - no dependencies
    op.create_table(
        "dns_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("client_ip", sa.String(length=45), nullable=False),
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column(
            "query_type", sa.String(length=10), nullable=False, server_default="A"
        ),
        sa.Column("response", sa.String(length=45), nullable=True),
        sa.Column(
            "response_code",
            sa.String(length=10),
            nullable=False,
            server_default="NOERROR",
        ),
        sa.Column("client_name", sa.String(length=253), nullable=True),
        sa.Column("chain", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_dns_events"),
    )
    op.create_index(
        "ix_dns_events_client_ip", "dns_events", ["client_ip"], unique=False
    )
    op.create_index("ix_dns_events_domain", "dns_events", ["domain"], unique=False)
    op.create_index(
        "ix_dns_events_domain_created",
        "dns_events",
        ["domain", "created_at"],
        unique=False,
    )
    op.create_index("ix_dns_events_event_id", "dns_events", ["event_id"], unique=True)

    # 2. domain_inventory - no dependencies
    op.create_table(
        "domain_inventory",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("normalized_domain", sa.String(length=253), nullable=False),
        sa.Column("query_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("unique_clients", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("client_ips", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_domain_inventory"),
    )
    op.create_index(
        "ix_domain_inventory_normalized_domain",
        "domain_inventory",
        ["normalized_domain"],
        unique=True,
    )

    # 3. threat_intelligence - no dependencies
    op.create_table(
        "threat_intelligence",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column("category", sa.String(length=50), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("source", sa.String(length=100), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")
        ),
        sa.PrimaryKeyConstraint("id", name="pk_threat_intelligence"),
        sa.UniqueConstraint(
            "domain",
            "category",
            "source",
            name="uq_threat_intel_domain_category_source",
        ),
    )
    op.create_index(
        "ix_threat_intelligence_domain", "threat_intelligence", ["domain"], unique=False
    )
    op.create_index(
        "ix_threat_intelligence_category",
        "threat_intelligence",
        ["category"],
        unique=False,
    )

    # 4. domain_assessments - depends on domain_inventory, dns_events
    op.create_table(
        "domain_assessments",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("domain_id", sa.Integer(), nullable=False),
        sa.Column("dns_event_id", sa.Integer(), nullable=True),
        sa.Column("suspicion_score", sa.Float(), nullable=False),
        sa.Column(
            "threat_categories", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "status", sa.String(length=20), nullable=False, server_default="pending"
        ),
        sa.Column("llm_query_id", sa.String(length=64), nullable=True),
        sa.Column("llm_response", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["dns_event_id"], ["dns_events.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["domain_id"], ["domain_inventory.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_domain_assessments"),
        sa.UniqueConstraint(
            "domain_id", "status", name="uq_domain_assessment_domain_status"
        ),
    )
    op.create_index(
        "ix_domain_assessments_domain_id",
        "domain_assessments",
        ["domain_id"],
        unique=False,
    )
    op.create_index(
        "ix_domain_assessments_dns_event_id",
        "domain_assessments",
        ["dns_event_id"],
        unique=False,
    )

    # 5. llm_usage - no dependencies
    op.create_table(
        "llm_usage",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("date", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("daily_limit", sa.Integer(), nullable=False, server_default="40"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_llm_usage"),
        sa.UniqueConstraint("date", name="uq_llm_usage_date"),
    )
    op.create_index("ix_llm_usage_date", "llm_usage", ["date"], unique=True)

    # 6. llm_cache - no dependencies
    op.create_table(
        "llm_cache",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("query_hash", sa.String(length=64), nullable=False),
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column("prompt", sa.Text(), nullable=False),
        sa.Column("response", sa.Text(), nullable=False),
        sa.Column("model", sa.String(length=100), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_llm_cache"),
    )
    op.create_index("ix_llm_cache_query_hash", "llm_cache", ["query_hash"], unique=True)
    op.create_index("ix_llm_cache_domain", "llm_cache", ["domain"], unique=False)

    # 7. block_recommendations - no dependencies
    op.create_table(
        "block_recommendations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("suspicion_score", sa.Float(), nullable=False),
        sa.Column("approved_by", sa.String(length=100), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_block_recommendations"),
        sa.UniqueConstraint("domain", name="uq_block_recommendation_domain"),
    )
    op.create_index(
        "ix_block_recommendations_domain",
        "block_recommendations",
        ["domain"],
        unique=False,
    )

    # 8. approval_audit - depends on domain_assessments
    op.create_table(
        "approval_audit",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("assessment_id", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(length=20), nullable=False),
        sa.Column("actor", sa.String(length=100), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["assessment_id"], ["domain_assessments.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_approval_audit"),
    )
    op.create_index(
        "ix_approval_audit_assessment_id",
        "approval_audit",
        ["assessment_id"],
        unique=False,
    )


def downgrade() -> None:
    # Drop in reverse dependency order
    op.drop_index("ix_approval_audit_assessment_id", table_name="approval_audit")
    op.drop_table("approval_audit")

    op.drop_index("ix_block_recommendations_domain", table_name="block_recommendations")
    op.drop_table("block_recommendations")

    op.drop_index("ix_llm_cache_domain", table_name="llm_cache")
    op.drop_index("ix_llm_cache_query_hash", table_name="llm_cache")
    op.drop_table("llm_cache")

    op.drop_index("ix_llm_usage_date", table_name="llm_usage")
    op.drop_table("llm_usage")

    op.drop_index("ix_domain_assessments_dns_event_id", table_name="domain_assessments")
    op.drop_index("ix_domain_assessments_domain_id", table_name="domain_assessments")
    op.drop_table("domain_assessments")

    op.drop_index("ix_threat_intelligence_category", table_name="threat_intelligence")
    op.drop_index("ix_threat_intelligence_domain", table_name="threat_intelligence")
    op.drop_table("threat_intelligence")

    op.drop_index(
        "ix_domain_inventory_normalized_domain", table_name="domain_inventory"
    )
    op.drop_table("domain_inventory")

    op.drop_index("ix_dns_events_event_id", table_name="dns_events")
    op.drop_index("ix_dns_events_domain_created", table_name="dns_events")
    op.drop_index("ix_dns_events_domain", table_name="dns_events")
    op.drop_index("ix_dns_events_client_ip", table_name="dns_events")
    op.drop_table("dns_events")
