"""Tests for structured threat-intelligence feed population."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import httpx
import pytest
from pihole_common.models import ThreatIntelligence
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from pihole_analyzer.threat_feeds import (
    ThreatFeedAdapter,
    ThreatFeedConfig,
    ThreatFeedError,
    ThreatFeedRefresher,
    load_feed_configs,
    normalize_feed_entry,
    upsert_threat_indicators,
)


class FakeResult:
    """Small async SQLAlchemy result substitute for unit tests."""

    def __init__(
        self, rows: list[ThreatIntelligence] | None = None, rowcount: int = 0
    ) -> None:
        self._rows = rows or []
        self.rowcount = rowcount

    def scalars(self) -> FakeResult:
        return self

    def all(self) -> list[ThreatIntelligence]:
        return self._rows


class FakeSession:
    """Capture database operations without requiring PostgreSQL."""

    def __init__(
        self, existing: list[ThreatIntelligence] | None = None, deactivated: int = 0
    ) -> None:
        self.existing = existing or []
        self.deactivated = deactivated
        self.added: list[ThreatIntelligence] = []
        self.committed = False
        self.executed: list[Any] = []

    async def execute(self, statement: Any) -> FakeResult:
        self.executed.append(statement)
        if len(self.executed) == 2:
            return FakeResult(rowcount=self.deactivated)
        return FakeResult(rows=self.existing)

    def add(self, value: ThreatIntelligence) -> None:
        self.added.append(value)

    async def commit(self) -> None:
        self.committed = True


class SessionContext:
    """Async context manager returned by a fake session factory."""

    def __init__(self, session: FakeSession) -> None:
        self.session = session

    async def __aenter__(self) -> FakeSession:
        return self.session

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        return None


class SessionFactory:
    """Callable fake matching the async session factory contract."""

    def __init__(self, session: FakeSession) -> None:
        self.session = session

    def __call__(self) -> SessionContext:
        return SessionContext(self.session)


def make_transport(payload: Any, status_code: int = 200) -> httpx.MockTransport:
    """Create a deterministic mocked HTTP feed endpoint."""

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json=payload, request=request)

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_adapter_fetches_and_normalizes_structured_feed() -> None:
    """A JSON envelope is normalized and duplicate indicators keep max confidence."""
    config = ThreatFeedConfig(
        name="test-feed", url="https://feeds.example.test/list.json", category="malware"
    )
    transport = make_transport(
        {
            "entries": [
                {"domain": "Bad.Example.", "confidence": 0.4},
                {"indicator": "bad.example", "confidence": 0.9},
            ]
        }
    )

    async with httpx.AsyncClient(transport=transport) as client:
        indicators = await ThreatFeedAdapter(config, client=client).fetch()

    assert indicators == [
        indicators[0].__class__("bad.example", "malware", 0.9, "test-feed")
    ]


@pytest.mark.asyncio
async def test_adapter_rejects_redirects() -> None:
    """Feed requests do not follow redirects to an unconfigured host."""
    config = ThreatFeedConfig(
        name="test-feed", url="https://feeds.example.test/list.json"
    )
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            302,
            headers={"Location": "https://unexpected.example.test/feed"},
            request=request,
        )
    )

    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(ThreatFeedError, match="redirects"):
            await ThreatFeedAdapter(config, client=client).fetch()


def test_normalize_feed_entry_rejects_invalid_domain() -> None:
    """Malformed entries cannot enter the threat-intelligence table."""
    config = ThreatFeedConfig(
        name="test-feed", url="https://feeds.example.test/list.json"
    )

    with pytest.raises(ThreatFeedError, match="Invalid feed domain"):
        normalize_feed_entry({"domain": "https://bad.example/path"}, config)


def test_load_feed_configs_from_analyzer_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Feed population remains disabled unless the analyzer feed setting is set."""
    monkeypatch.setenv(
        "ANALYZER_THREAT_FEEDS",
        '[{"name":"urlhaus","url":"https://feeds.example.test/feed.json","ttl_seconds":3600}]',
    )

    configs = load_feed_configs()

    assert len(configs) == 1
    assert configs[0].name == "urlhaus"
    assert configs[0].ttl_seconds == 3600


@pytest.mark.asyncio
async def test_upsert_reactivates_and_expires_records() -> None:
    """Successful refreshes update records and deactivate entries past their TTL."""
    existing = ThreatIntelligence(
        domain="bad.example",
        category="malware",
        confidence=0.1,
        source="test-feed",
        first_seen=datetime(2025, 1, 1, tzinfo=UTC),
        last_seen=datetime(2025, 1, 1, tzinfo=UTC),
        is_active=False,
    )
    session = FakeSession(existing=[existing], deactivated=2)
    now = datetime(2025, 1, 2, tzinfo=UTC)

    activated, deactivated = await upsert_threat_indicators(
        cast(AsyncSession, session),
        [
            normalize_feed_entry(
                {"domain": "bad.example", "confidence": 0.9},
                ThreatFeedConfig(
                    name="test-feed",
                    url="https://feeds.example.test/list.json",
                    category="malware",
                ),
            )
        ],
        source="test-feed",
        ttl_seconds=3600,
        now=now,
    )

    assert activated == 1
    assert deactivated == 2
    assert existing.confidence == 0.9
    assert existing.last_seen == now
    assert existing.is_active is True
    assert session.committed is True


@pytest.mark.asyncio
async def test_refresh_isolates_http_failure_without_touching_database() -> None:
    """A failed feed request is reported and cannot deactivate stale records."""
    config = ThreatFeedConfig(name="broken", url="https://feeds.example.test/list.json")
    session = FakeSession()
    transport = make_transport({"error": "unavailable"}, status_code=503)

    async with httpx.AsyncClient(transport=transport) as client:
        results = await ThreatFeedRefresher(
            [config],
            session_factory=cast(
                async_sessionmaker[AsyncSession], SessionFactory(session)
            ),
            client=client,
        ).refresh()

    assert results[0].source == "broken"
    assert results[0].error is not None
    assert session.committed is False
    assert session.added == []
