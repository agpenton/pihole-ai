"""Focused tests for daily LLM quota enforcement."""

from __future__ import annotations

import asyncio
from importlib import import_module
from typing import Any, Self, cast

LlmUsage = cast(Any, import_module("pihole_common.models").LlmUsage)
QuotaManager = cast(Any, import_module("pihole_llm_gateway.quota").QuotaManager)


class ScalarResult:
    """Minimal result object implementing the quota read seam."""

    def __init__(self, record: Any) -> None:
        self.record = record

    def scalar_one_or_none(self) -> Any:
        """Return the configured usage record."""
        return self.record


class QuotaSession:
    """Async session fake that records quota mutations."""

    def __init__(self, record: Any = None) -> None:
        self.record = record
        self.added: list[Any] = []
        self.flush_count = 0
        self.commit_count = 0

    async def __aenter__(self) -> Self:
        """Enter the fake session context."""
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        """Exit the fake session context."""

    async def execute(self, _statement: Any) -> ScalarResult:
        """Return the configured usage row."""
        return ScalarResult(self.record)

    def add(self, record: Any) -> None:
        """Record a newly created usage row."""
        self.added.append(record)
        self.record = record

    async def flush(self) -> None:
        """Record the flush needed for a newly created row."""
        self.flush_count += 1

    async def commit(self) -> None:
        """Record the transaction commit."""
        self.commit_count += 1


class SessionFactory:
    """Callable async-session factory for quota tests."""

    def __init__(self, session: QuotaSession) -> None:
        self.session = session

    def __call__(self) -> QuotaSession:
        """Return the configured async context manager."""
        return self.session


def test_can_make_request_creates_today_record_when_missing() -> None:
    """A missing daily row is initialized and allows the first request."""
    session = QuotaSession()
    manager = QuotaManager(cast(Any, SessionFactory(session)))

    allowed = asyncio.run(manager.can_make_request())

    assert allowed is True
    assert len(session.added) == 1
    assert session.record.request_count == 0
    assert session.record.daily_limit == 40
    assert session.flush_count == 1
    assert session.commit_count == 1


def test_can_make_request_returns_false_at_daily_limit() -> None:
    """A quota at its limit blocks another request."""
    record = LlmUsage(request_count=40, daily_limit=40)
    session = QuotaSession(record)
    manager = QuotaManager(cast(Any, SessionFactory(session)))

    assert asyncio.run(manager.can_make_request()) is False
    assert session.added == []
    assert session.commit_count == 1


def test_can_make_request_allows_requests_below_daily_limit() -> None:
    """A quota below its limit remains available."""
    record = LlmUsage(request_count=39, daily_limit=40)
    session = QuotaSession(record)
    manager = QuotaManager(cast(Any, SessionFactory(session)))

    assert asyncio.run(manager.can_make_request()) is True


def test_record_request_increments_and_commits_usage() -> None:
    """Recording a successful request increments today's count exactly once."""
    record = LlmUsage(request_count=7, daily_limit=40)
    session = QuotaSession(record)
    manager = QuotaManager(cast(Any, SessionFactory(session)))

    asyncio.run(manager.record_request())

    assert record.request_count == 8
    assert session.commit_count == 1
    assert session.added == []


def test_record_request_initializes_missing_record_before_incrementing() -> None:
    """Recording the first request creates a zero-count row before incrementing it."""
    session = QuotaSession()
    manager = QuotaManager(cast(Any, SessionFactory(session)))

    asyncio.run(manager.record_request())

    assert len(session.added) == 1
    assert session.record.request_count == 1
    assert session.record.daily_limit == 40
    assert session.flush_count == 1
    assert session.commit_count == 1
