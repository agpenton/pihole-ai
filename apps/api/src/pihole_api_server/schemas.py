"""Pydantic schemas for the pihole-ai HTTP API."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Page[T](BaseModel):
    """A page of results with stable pagination metadata."""

    items: list[T]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)
    pages: int = Field(ge=0)


class DomainAssessmentResponse(BaseModel):
    """A domain threat assessment returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    domain: str
    suspicion_score: float
    threat_categories: list[str] = Field(default_factory=list)
    evidence: dict[str, object] | None = None
    status: str
    llm_query_id: str | None = None
    created_at: datetime
    updated_at: datetime


class DomainAssessmentList(Page[DomainAssessmentResponse]):
    """Paginated domain assessment response."""


class ApprovalRequest(BaseModel):
    """Approval or rejection metadata supplied by an operator."""

    action: Literal["approve", "reject"] | None = None
    reason: str | None = Field(default=None, max_length=2000)


class BlockRecommendationResponse(BaseModel):
    """A human-approved block recommendation."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    domain: str
    reason: str
    suspicion_score: float
    approved_by: str | None
    approved_at: datetime | None
    created_at: datetime


class ApprovalList(Page[BlockRecommendationResponse]):
    """Paginated block recommendation response."""


class BlockApplicationResponse(BaseModel):
    """Result of applying an approved recommendation to Pi-hole."""

    recommendation_id: int
    assessment_id: int
    domain: str
    status: Literal["blocked"]
    already_present: bool
    audit_id: int
    detail: str


class AuditEntry(BaseModel):
    """A recorded approval or rejection action."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    assessment_id: int
    action: str
    actor: str
    reason: str | None
    created_at: datetime


class AuditList(Page[AuditEntry]):
    """Paginated audit response."""


class HealthResponse(BaseModel):
    """Service health status."""

    status: str
    version: str
    db_connected: bool


class MetricsResponse(BaseModel):
    """Metadata returned by implementations that expose metric summaries."""

    status: str = "ok"


class ErrorResponse(BaseModel):
    """Consistent application error payload."""

    detail: str
