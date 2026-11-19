"""Focused tests for the PostgreSQL-backed response cache."""

from __future__ import annotations

import asyncio
from importlib import import_module
from typing import Any, Self, cast

from pihole_common.models import LlmCache

ResponseCache = cast(Any, import_module("pihole_llm_gateway.cache").ResponseCache)


class ScalarResult:
    """Minimal result object implementing the cache's read seam."""

    def __init__(self, row: Any) -> None:
        self.row = row

    def scalar_one_or_none(self) -> Any:
        """Return the configured cache entry."""
        return self.row


class CacheSession:
    """Async session fake that records writes and returns one configured row."""

    def __init__(self, row: Any = None) -> None:
        self.row = row
        self.added: list[Any] = []
        self.committed = False

    async def __aenter__(self) -> Self:
        """Enter the fake session context."""
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        """Exit the fake session context."""

    async def execute(self, _statement: Any) -> ScalarResult:
        """Return the configured cache row."""
        return ScalarResult(self.row)

    def add(self, entry: Any) -> None:
        """Record an inserted cache entry."""
        self.added.append(entry)

    async def commit(self) -> None:
        """Record that the transaction was committed."""
        self.committed = True


class SessionFactory:
    """Callable async-session factory for cache tests."""

    def __init__(self, session: CacheSession) -> None:
        self.session = session

    def __call__(self) -> CacheSession:
        """Return the configured async context manager."""
        return self.session


def test_get_returns_cached_response() -> None:
    """A non-expired database row is returned unchanged."""
    row = type(
        "CacheRow",
        (),
        {
            "response": '{"is_malicious": false}',
        },
    )()
    session = CacheSession(row)

    result = asyncio.run(ResponseCache(cast(Any, SessionFactory(session))).get("hash"))

    assert result == '{"is_malicious": false}'


def test_get_returns_none_on_cache_miss() -> None:
    """A missing database row is treated as a cache miss."""
    session = CacheSession()

    result = asyncio.run(
        ResponseCache(cast(Any, SessionFactory(session))).get("missing")
    )

    assert result is None


def test_set_persists_entry_with_deterministic_key_and_ttl() -> None:
    """Setting a response writes all fields and computes a stable cache key."""
    session = CacheSession()
    cache = ResponseCache(cast(Any, SessionFactory(session)))

    asyncio.run(
        cache.set("example.com", "prompt", "response", "test-model", ttl_hours=2)
    )

    assert len(session.added) == 1
    entry = session.added[0]
    assert isinstance(entry, LlmCache)
    assert entry.query_hash == "c0790d98bb0770b2bd8aa17acfb460ef"
    assert entry.domain == "example.com"
    assert entry.prompt == "prompt"
    assert entry.response == "response"
    assert entry.model == "test-model"
    assert entry.expires_at is not None
    assert session.committed is True


def test_set_changes_key_when_model_changes() -> None:
    """Responses from different models do not share cache entries."""
    session = CacheSession()
    cache = ResponseCache(cast(Any, SessionFactory(session)))

    asyncio.run(cache.set("example.com", "prompt", "response", "model-a"))
    asyncio.run(cache.set("example.com", "prompt", "response", "model-b"))

    assert len(session.added) == 2
    assert session.added[0].query_hash != session.added[1].query_hash
