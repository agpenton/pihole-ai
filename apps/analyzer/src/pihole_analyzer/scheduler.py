"""Domain scheduler with separate retry timing for failed LLM assessments."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pihole_common.config import get_settings
from pihole_common.database import async_session_factory
from pihole_common.models import DomainAssessment, DomainInventory
from sqlalchemy import and_, exists, or_, select


class DomainScheduler:
    """Select domains that need a first assessment or a retry."""

    def __init__(
            self,
            lookback_hours: int = 24,
            retry_interval_minutes: int | None = None,
    ) -> None:
        self.lookback = timedelta(hours=lookback_hours)
        configured_retry = get_settings().analyzer.llm_retry_interval_minutes
        self.retry_interval = timedelta(
            minutes=retry_interval_minutes or configured_retry
        )

    async def get_pending_domains(
            self,
            limit: int = 100,
    ) -> list[DomainInventory]:
        """Return domains without a recent assessment or due for retry."""
        now = datetime.now(UTC)
        assessment_cutoff = now - self.lookback
        retry_cutoff = now - self.retry_interval

        recent_or_waiting = exists(
            select(1).where(
                DomainAssessment.domain_id == DomainInventory.id,
                or_(
                    and_(
                        DomainAssessment.status != "failed",
                        DomainAssessment.created_at >= assessment_cutoff,
                        ),
                    and_(
                        DomainAssessment.status == "failed",
                        DomainAssessment.updated_at >= retry_cutoff,
                        ),
                ),
                )
        )

        statement = (
            select(DomainInventory)
            .where(~recent_or_waiting)
            .order_by(
                DomainInventory.query_count.desc(),
                DomainInventory.last_seen.desc(),
            )
            .limit(limit)
        )

        async with async_session_factory() as session:
            result = await session.execute(statement)
            return list(result.scalars().all())