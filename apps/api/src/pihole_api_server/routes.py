"""HTTP routes for assessments, operator approvals, and audit history."""

from __future__ import annotations

import math
from datetime import UTC, datetime
from typing import Any, cast

from fastapi import APIRouter, HTTPException, Query, Response
from pihole_common.models import (
    ApprovalAudit,
    BlockRecommendation,
    DomainAssessment,
    DomainInventory,
)
from pihole_common.security import normalize_domain
from pihole_common.telemetry import metrics_endpoint
from sqlalchemy import Select, and_, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from pihole_api_server.dependencies import (
    CurrentUser,
    DbSession,
    Pihole,
    Protected,
    RateLimited,
)
from pihole_api_server.pihole_client import BlockDomainResult, PiholeClientError
from pihole_api_server.schemas import (
    ApprovalList,
    ApprovalRequest,
    AuditEntry,
    AuditList,
    BlockApplicationResponse,
    BlockRecommendationResponse,
    DomainAssessmentList,
    DomainAssessmentResponse,
    HealthResponse,
)

API_VERSION = "0.1.0"
router = APIRouter()


def _page_count(total: int, page_size: int) -> int:
    """Return the number of pages for a result count."""
    return math.ceil(total / page_size) if total else 0


def _assessment_response(
    assessment: DomainAssessment, domain: str
) -> DomainAssessmentResponse:
    """Convert an ORM assessment and its domain name to an API response."""
    return DomainAssessmentResponse(
        id=assessment.id,
        domain=domain,
        suspicion_score=assessment.suspicion_score,
        threat_categories=assessment.threat_categories or [],
        evidence=assessment.evidence,
        status=assessment.status,
        llm_query_id=assessment.llm_query_id,
        created_at=assessment.created_at,
        updated_at=assessment.updated_at,
    )


def _recommendation_response(
    recommendation: BlockRecommendation,
) -> BlockRecommendationResponse:
    """Convert a recommendation ORM object to an API response."""
    return BlockRecommendationResponse.model_validate(recommendation)


def _assessment_query(
    status_filter: str | None,
    domain_filter: str | None,
    min_score: float | None,
    max_score: float | None,
) -> tuple[Select[tuple[DomainAssessment, str]], list[Any]]:
    """Build the assessment query and its SQLAlchemy filter expressions."""
    conditions: list[Any] = []
    if status_filter:
        conditions.append(DomainAssessment.status == status_filter)
    if domain_filter:
        conditions.append(DomainInventory.normalized_domain == domain_filter)
    if min_score is not None:
        conditions.append(DomainAssessment.suspicion_score >= min_score)
    if max_score is not None:
        conditions.append(DomainAssessment.suspicion_score <= max_score)

    query = (
        select(DomainAssessment, DomainInventory.normalized_domain)
        .join(DomainInventory, DomainAssessment.domain_id == DomainInventory.id)
        .order_by(DomainAssessment.created_at.desc(), DomainAssessment.id.desc())
    )
    return cast(Select[tuple[DomainAssessment, str]], query), conditions


@router.get("/health", response_model=HealthResponse, tags=["system"])
async def health(db: DbSession) -> HealthResponse:
    """Return service and database health."""
    try:
        await db.execute(select(1))
    except SQLAlchemyError:
        return HealthResponse(
            status="degraded", version=API_VERSION, db_connected=False
        )
    return HealthResponse(status="ok", version=API_VERSION, db_connected=True)


@router.get("/metrics", tags=["system"])
async def metrics() -> Response:
    """Expose Prometheus metrics from the shared telemetry module."""
    payload, content_type = metrics_endpoint()
    return Response(content=payload, media_type=content_type)


@router.get("/assessments", response_model=DomainAssessmentList, tags=["assessments"])
async def list_assessments(
    db: DbSession,
    _auth: Protected,
    _rate: RateLimited,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status_filter: str | None = Query(default=None, alias="status", max_length=20),
    domain: str | None = Query(default=None, max_length=253),
    min_score: float | None = Query(default=None, ge=0, le=1),
    max_score: float | None = Query(default=None, ge=0, le=1),
) -> DomainAssessmentList:
    """List assessments with pagination and optional filters."""
    normalized = None
    if domain:
        try:
            normalized = normalize_domain(domain)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    query, conditions = _assessment_query(
        status_filter, normalized, min_score, max_score
    )
    if conditions:
        query = query.where(and_(*conditions))

    count_query = select(func.count(DomainAssessment.id)).join(
        DomainInventory, DomainAssessment.domain_id == DomainInventory.id
    )
    if conditions:
        count_query = count_query.where(and_(*conditions))
    total = int((await db.scalar(count_query)) or 0)

    rows = cast(
        list[tuple[DomainAssessment, str]],
        (await db.execute(query.offset((page - 1) * page_size).limit(page_size))).all(),
    )
    items = [
        _assessment_response(assessment, domain_name)
        for assessment, domain_name in rows
    ]
    return DomainAssessmentList(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=_page_count(total, page_size),
    )


@router.get(
    "/assessments/{assessment_id}",
    response_model=DomainAssessmentResponse,
    tags=["assessments"],
)
async def get_assessment(
    assessment_id: int,
    db: DbSession,
    _auth: Protected,
    _rate: RateLimited,
) -> DomainAssessmentResponse:
    """Return one assessment by id."""
    row = (
        await db.execute(
            select(DomainAssessment, DomainInventory.normalized_domain)
            .join(DomainInventory, DomainAssessment.domain_id == DomainInventory.id)
            .where(DomainAssessment.id == assessment_id)
        )
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    assessment, domain = row
    return _assessment_response(assessment, domain)


async def _find_assessment(db: AsyncSession, assessment_id: int) -> DomainAssessment:
    """Load an assessment with its domain for a state-changing operation."""
    assessment = await db.scalar(
        select(DomainAssessment)
        .options(selectinload(DomainAssessment.domain))
        .where(DomainAssessment.id == assessment_id)
    )
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return assessment


async def _find_recommendation_assessment(
    db: AsyncSession,
    domain: str,
) -> DomainAssessment:
    """Load the latest assessment that can be applied for a recommendation."""
    assessment = await db.scalar(
        select(DomainAssessment)
        .join(DomainInventory, DomainAssessment.domain_id == DomainInventory.id)
        .where(
            DomainInventory.normalized_domain == domain,
            DomainAssessment.status.in_(("approved", "blocked", "failed")),
        )
        .order_by(DomainAssessment.updated_at.desc(), DomainAssessment.id.desc())
    )
    if assessment is None:
        raise HTTPException(
            status_code=409, detail="Approval has no applicable assessment"
        )
    return assessment


async def _approval_request(
    request: ApprovalRequest | None, expected_action: str
) -> ApprovalRequest:
    """Validate the optional action body against the route being called."""
    value = request or ApprovalRequest()
    if value.action is not None and value.action != expected_action:
        raise HTTPException(
            status_code=400, detail=f"Request action must be '{expected_action}'"
        )
    return value


@router.post(
    "/assessments/{assessment_id}/approve",
    response_model=BlockRecommendationResponse,
    tags=["approvals"],
)
async def approve_assessment(
    assessment_id: int,
    db: DbSession,
    current_user: CurrentUser,
    _rate: RateLimited,
    request: ApprovalRequest | None = None,
) -> BlockRecommendationResponse:
    """Approve an assessment and create its block recommendation."""
    approval = await _approval_request(request, "approve")
    assessment = await _find_assessment(db, assessment_id)
    if assessment.status not in {"pending", "approved"}:
        raise HTTPException(
            status_code=409, detail="Only pending assessments can be approved"
        )
    assert assessment.domain is not None

    recommendation = await db.scalar(
        select(BlockRecommendation).where(
            BlockRecommendation.domain == assessment.domain.normalized_domain
        )
    )
    now = datetime.now(UTC)
    if recommendation is None:
        recommendation = BlockRecommendation(
            domain=assessment.domain.normalized_domain,
            reason=approval.reason or "Approved by operator",
            suspicion_score=assessment.suspicion_score,
            approved_by=current_user,
            approved_at=now,
        )
        db.add(recommendation)
    else:
        recommendation.reason = approval.reason or recommendation.reason
        recommendation.suspicion_score = assessment.suspicion_score
        recommendation.approved_by = current_user
        recommendation.approved_at = now

    assessment.status = "approved"
    db.add(
        ApprovalAudit(
            assessment_id=assessment.id,
            action="approve",
            actor=current_user,
            reason=approval.reason,
        )
    )
    await db.commit()
    await db.refresh(recommendation)
    return _recommendation_response(recommendation)


@router.post(
    "/assessments/{assessment_id}/reject", response_model=AuditEntry, tags=["approvals"]
)
async def reject_assessment(
    assessment_id: int,
    db: DbSession,
    current_user: CurrentUser,
    _rate: RateLimited,
    request: ApprovalRequest | None = None,
) -> AuditEntry:
    """Reject an assessment and record the operator decision."""
    rejection = await _approval_request(request, "reject")
    assessment = await _find_assessment(db, assessment_id)
    if assessment.status not in {"pending", "rejected"}:
        raise HTTPException(
            status_code=409, detail="Only pending assessments can be rejected"
        )

    assessment.status = "rejected"
    audit = ApprovalAudit(
        assessment_id=assessment.id,
        action="reject",
        actor=current_user,
        reason=rejection.reason,
    )
    db.add(audit)
    await db.commit()
    await db.refresh(audit)
    return AuditEntry.model_validate(audit)


@router.get("/approvals", response_model=ApprovalList, tags=["approvals"])
async def list_approvals(
    db: DbSession,
    _auth: Protected,
    _rate: RateLimited,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> ApprovalList:
    """List human-approved block recommendations."""
    total = int((await db.scalar(select(func.count(BlockRecommendation.id)))) or 0)
    query = select(BlockRecommendation).order_by(
        BlockRecommendation.created_at.desc(), BlockRecommendation.id.desc()
    )
    rows = (
        (await db.execute(query.offset((page - 1) * page_size).limit(page_size)))
        .scalars()
        .all()
    )
    items = [_recommendation_response(recommendation) for recommendation in rows]
    return ApprovalList(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=_page_count(total, page_size),
    )


@router.get(
    "/approvals/{domain}",
    response_model=BlockRecommendationResponse,
    tags=["approvals"],
)
async def get_approval(
    domain: str, db: DbSession, _auth: Protected, _rate: RateLimited
) -> BlockRecommendationResponse:
    """Return the recommendation for a domain."""
    try:
        normalized = normalize_domain(domain)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    recommendation = await db.scalar(
        select(BlockRecommendation).where(BlockRecommendation.domain == normalized)
    )
    if recommendation is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    return _recommendation_response(recommendation)


@router.post(
    "/approvals/{domain}/apply",
    response_model=BlockApplicationResponse,
    tags=["approvals"],
)
async def apply_approval(
    domain: str,
    db: DbSession,
    current_user: CurrentUser,
    client: Pihole,
    _rate: RateLimited,
) -> BlockApplicationResponse:
    """Apply an approved recommendation to Pi-hole's exact deny list."""
    try:
        normalized = normalize_domain(domain)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    recommendation = await db.scalar(
        select(BlockRecommendation).where(BlockRecommendation.domain == normalized)
    )
    if recommendation is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    assessment = await _find_recommendation_assessment(db, normalized)

    if assessment.status not in {"approved", "blocked", "failed"}:
        raise HTTPException(
            status_code=409, detail="Only approved recommendations can be applied"
        )

    if assessment.status == "blocked":
        result = BlockDomainResult(already_present=True)
        detail = "Domain was already applied; no Pi-hole mutation was attempted"
    else:
        try:
            result = await client.add_block_domain(
                normalized, comment=recommendation.reason
            )
        except PiholeClientError as exc:
            assessment.status = "failed"
            audit = ApprovalAudit(
                assessment_id=assessment.id,
                action="apply_failed",
                actor=current_user,
                reason=str(exc),
            )
            db.add(audit)
            await db.commit()
            await db.refresh(audit)
            raise HTTPException(
                status_code=502, detail="Failed to apply block to Pi-hole"
            ) from exc

        assessment.status = "blocked"
        detail = (
            "Domain was already present in Pi-hole"
            if result.already_present
            else "Domain was added to Pi-hole"
        )

    audit = ApprovalAudit(
        assessment_id=assessment.id,
        action="apply",
        actor=current_user,
        reason=detail,
    )
    db.add(audit)
    await db.commit()
    await db.refresh(audit)
    return BlockApplicationResponse(
        recommendation_id=recommendation.id,
        assessment_id=assessment.id,
        domain=normalized,
        status="blocked",
        already_present=result.already_present,
        audit_id=audit.id,
        detail=detail,
    )


@router.post("/approvals/{domain}/remove", tags=["approvals"])
async def remove_approval(
    domain: str,
    db: DbSession,
    _auth: Protected,
    _rate: RateLimited,
) -> dict[str, object]:
    """Remove a block recommendation for a domain."""
    try:
        normalized = normalize_domain(domain)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    recommendation = await db.scalar(
        select(BlockRecommendation).where(BlockRecommendation.domain == normalized)
    )
    if recommendation is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    await db.delete(recommendation)
    await db.commit()
    return {"removed": True, "domain": normalized}


@router.get("/audit", response_model=AuditList, tags=["audit"])
async def list_audit(
    db: DbSession,
    _auth: Protected,
    _rate: RateLimited,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    assessment_id: int | None = Query(default=None, ge=1),
    action: str | None = Query(default=None, max_length=20),
) -> AuditList:
    """List approval audit entries."""
    conditions: list[Any] = []
    if assessment_id is not None:
        conditions.append(ApprovalAudit.assessment_id == assessment_id)
    if action:
        conditions.append(ApprovalAudit.action == action)
    count_query = select(func.count(ApprovalAudit.id))
    query = select(ApprovalAudit).order_by(
        ApprovalAudit.created_at.desc(), ApprovalAudit.id.desc()
    )
    if conditions:
        criterion = and_(*conditions)
        count_query = count_query.where(criterion)
        query = query.where(criterion)
    total = int((await db.scalar(count_query)) or 0)
    rows = (
        (await db.execute(query.offset((page - 1) * page_size).limit(page_size)))
        .scalars()
        .all()
    )
    items = [AuditEntry.model_validate(entry) for entry in rows]
    return AuditList(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=_page_count(total, page_size),
    )


@router.get("/audit/{audit_id}", response_model=AuditEntry, tags=["audit"])
async def get_audit(
    audit_id: int, db: DbSession, _auth: Protected, _rate: RateLimited
) -> AuditEntry:
    """Return one audit entry by id."""
    entry = await db.get(ApprovalAudit, audit_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Audit entry not found")
    return AuditEntry.model_validate(entry)
