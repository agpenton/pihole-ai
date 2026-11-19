"""PostgreSQL-backed daily LLM quota enforcement."""

from __future__ import annotations

import logging
from datetime import UTC, date, datetime, timedelta

from pihole_common.models import LlmUsage
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

logger = logging.getLogger(__name__)


class QuotaManager:
    """Enforce a configurable daily LLM request quota."""

    def __init__(
            self,
            session_factory: async_sessionmaker[AsyncSession],
            daily_limit: int = 40,
    ) -> None:
        self.session_factory = session_factory
        self.daily_limit = daily_limit

    async def _get_or_create_today(
            self,
            session: AsyncSession,
    ) -> LlmUsage:
        """Get today's row, creating it when necessary."""
        today = date.today()
        start = datetime.combine(today, datetime.min.time(), tzinfo=UTC)
        end = datetime.combine(
            today + timedelta(days=1),
            datetime.min.time(),
            tzinfo=UTC,
            )

        result = await session.execute(
            select(LlmUsage)
            .where(LlmUsage.date >= start, LlmUsage.date < end)
            .with_for_update()
        )
        record = result.scalar_one_or_none()

        if record is None:
            record = LlmUsage(
                date=start,
                request_count=0,
                daily_limit=self.daily_limit,
            )
            session.add(record)
            await session.flush()

        # Apply the configured quota to today's record as well.
        record.daily_limit = self.daily_limit
        return record

    async def can_make_request(self) -> bool:
        """Return whether another request is allowed."""
        async with self.session_factory() as session:
            record = await self._get_or_create_today(session)
            allowed = record.request_count < record.daily_limit
            await session.commit()
            return allowed

    async def record_request(self) -> None:
        """Record one successful upstream request."""
        async with self.session_factory() as session:
            record = await self._get_or_create_today(session)
            record.request_count += 1
            await session.commit()

            logger.info(
                "llm_quota_recorded",
                extra={
                    "request_count": record.request_count,
                    "daily_limit": record.daily_limit,
                    "remaining": max(
                        0,
                        record.daily_limit - record.request_count,
                        ),
                },
            )