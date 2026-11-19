"""Threat intelligence checker — matches domains against the threat_intelligence table."""

from __future__ import annotations

from typing import Any

from pihole_common.database import async_session_factory
from pihole_common.models import ThreatIntelligence
from sqlalchemy import select


class ThreatChecker:
    """Query the local threat_intelligence table for domain matches."""

    async def check_domain(self, domain: str) -> list[dict[str, Any]]:
        """Check a domain against threat intelligence records.

        Args:
            domain: A normalized domain name.

        Returns:
            List of threat matches with keys: category, confidence, source.
        """
        async with async_session_factory() as session:
            stmt = (
                select(ThreatIntelligence)
                .where(
                    ThreatIntelligence.domain == domain,
                    ThreatIntelligence.is_active == True,  # noqa: E712
                )
                .order_by(ThreatIntelligence.confidence.desc())
            )
            result = await session.execute(stmt)
            rows = result.all()

        return [
            {
                "category": row.category,
                "confidence": row.confidence,
                "source": row.source,
            }
            for row in rows
        ]
