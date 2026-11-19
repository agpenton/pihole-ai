"""PostgreSQL-backed LLM response cache."""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime, timedelta

from pihole_common.models import LlmCache
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

logger = logging.getLogger(__name__)


def _compute_hash(domain: str, prompt: str, model: str) -> str:
    """Create a stable cache key."""
    value = f"{domain}|{prompt}|{model}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class ResponseCache:
    """PostgreSQL-backed response cache with TTL."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self.session_factory = session_factory

    async def get(self, query_hash: str) -> str | None:
        """Return a non-expired cached response."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(LlmCache).where(
                    LlmCache.query_hash == query_hash,
                    LlmCache.expires_at > datetime.now(UTC),
                )
            )
            row = result.scalar_one_or_none()
            return row.response if row else None

    async def set(
        self,
        domain: str,
        prompt: str,
        response: str,
        model: str,
        ttl_hours: int = 24,
    ) -> None:
        """Insert or refresh a cache record."""
        query_hash = _compute_hash(domain, prompt, model)
        now = datetime.now(UTC)

        statement = pg_insert(LlmCache).values(
            query_hash=query_hash,
            domain=domain,
            prompt=prompt,
            response=response,
            model=model,
            created_at=now,
            expires_at=now + timedelta(hours=ttl_hours),
        )
        statement = statement.on_conflict_do_update(
            index_elements=[LlmCache.query_hash],
            set_={
                "response": response,
                "prompt": prompt,
                "model": model,
                "created_at": now,
                "expires_at": now + timedelta(hours=ttl_hours),
            },
        )

        async with self.session_factory() as session:
            await session.execute(statement)
            await session.commit()
