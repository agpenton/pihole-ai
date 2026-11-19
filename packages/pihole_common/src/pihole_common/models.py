"""SQLAlchemy ORM models for all pihole-ai tables."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from pihole_common.database import Base


def _utcnow() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(UTC)


class DnsEvent(Base):
    """A single DNS query event from Pi-hole."""

    __tablename__ = "dns_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    client_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    domain: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    query_type: Mapped[str] = mapped_column(String(10), nullable=False, default="A")
    response: Mapped[str | None] = mapped_column(String(45), nullable=True)
    response_code: Mapped[str] = mapped_column(
        String(10), nullable=False, default="NOERROR"
    )
    client_name: Mapped[str | None] = mapped_column(String(253), nullable=True)
    chain: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )

    __table_args__ = (Index("ix_dns_events_domain_created", "domain", "created_at"),)

    assessments: Mapped[list[DomainAssessment]] = relationship(
        "DomainAssessment",
        back_populates="dns_event",
        lazy="selectin",
    )


class DomainInventory(Base):
    """Aggregated view of observed domains with query counts."""

    __tablename__ = "domain_inventory"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    normalized_domain: Mapped[str] = mapped_column(
        String(253),
        nullable=False,
        unique=True,
        index=True,
    )
    query_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )
    unique_clients: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    client_ips: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )

    assessments: Mapped[list[DomainAssessment]] = relationship(
        "DomainAssessment",
        back_populates="domain",
        lazy="selectin",
    )


class ThreatIntelligence(Base):
    """External threat intelligence feeds."""

    __tablename__ = "threat_intelligence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    __table_args__ = (
        UniqueConstraint(
            "domain",
            "category",
            "source",
            name="uq_threat_intel_domain_category_source",
        ),
    )


class DomainAssessment(Base):
    """Threat assessment for a domain, produced by the analyzer."""

    __tablename__ = "domain_assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain_id: Mapped[int] = mapped_column(
        ForeignKey("domain_inventory.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    dns_event_id: Mapped[int | None] = mapped_column(
        ForeignKey("dns_events.id", ondelete="SET NULL"),
        nullable=True,
    )
    suspicion_score: Mapped[float] = mapped_column(Float, nullable=False)
    threat_categories: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    evidence: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pending",
        server_default="pending",
    )
    llm_query_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    llm_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )

    domain: Mapped[DomainInventory] = relationship(
        "DomainInventory",
        back_populates="assessments",
    )
    dns_event: Mapped[DnsEvent] = relationship(
        "DnsEvent",
        back_populates="assessments",
    )

    __table_args__ = (
        Index(
            "uq_domain_assessment_one_active",
            "domain_id",
            unique=True,
            postgresql_where=text("status IN ('pending', 'failed')"),
        ),
    )


class LlmUsage(Base):
    """Tracks LLM API usage for quota enforcement."""

    __tablename__ = "llm_usage"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    date: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    request_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    daily_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=40)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )

    __table_args__ = (UniqueConstraint("date", name="uq_llm_usage_date"),)


class LlmCache(Base):
    """Cache for LLM responses to avoid redundant requests."""

    __tablename__ = "llm_cache"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    query_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
    )
    domain: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    prompt: Mapped[str] = mapped_column(Text, nullable=False)
    response: Mapped[str] = mapped_column(Text, nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )


class BlockRecommendation(Base):
    """Human-approved block recommendations. The LLM never blocks directly."""

    __tablename__ = "block_recommendations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    suspicion_score: Mapped[float] = mapped_column(Float, nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )

    __table_args__ = (
        UniqueConstraint("domain", name="uq_block_recommendation_domain"),
    )


class ApprovalAudit(Base):
    """Audit trail for all operator approval/rejection actions."""

    __tablename__ = "approval_audit"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("domain_assessments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    action: Mapped[str] = mapped_column(String(20), nullable=False)
    actor: Mapped[str] = mapped_column(String(100), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )
