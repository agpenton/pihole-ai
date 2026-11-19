# pyright: reportMissingImports=false

"""Threat-intelligence feed adapters and database refresh operations.

Feeds are deliberately kept outside the deterministic scoring path.  A refresh
only activates records from a successful, validated feed response; a failed
request never expires existing intelligence.
"""

from __future__ import annotations

import json
import math
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

import httpx
from pihole_common.database import async_session_factory
from pihole_common.models import ThreatIntelligence
from pihole_common.security import normalize_domain
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

_SOURCE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$")
_CATEGORY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,49}$")
_DEFAULT_TIMEOUT = 10.0
_DEFAULT_TTL = 24 * 60 * 60
_DEFAULT_MAX_ENTRIES = 100_000
_DEFAULT_MAX_BYTES = 10 * 1024 * 1024


class ThreatFeedError(ValueError):
    """Raised when a feed configuration or response is unsafe or malformed."""


@dataclass(frozen=True, slots=True)
class ThreatFeedConfig:
    """Configuration for one structured JSON threat feed."""

    name: str
    url: str
    category: str = "unknown"
    confidence: float = 0.5
    ttl_seconds: int = _DEFAULT_TTL
    timeout_seconds: float = _DEFAULT_TIMEOUT
    max_entries: int = _DEFAULT_MAX_ENTRIES
    max_bytes: int = _DEFAULT_MAX_BYTES

    def __post_init__(self) -> None:
        """Validate feed configuration before any network request is made."""
        if not _SOURCE_PATTERN.fullmatch(self.name):
            raise ThreatFeedError("Feed name must contain only safe identifier characters")
        _validate_url(self.url)
        _validate_category(self.category)
        _validate_confidence(self.confidence)
        if self.ttl_seconds <= 0:
            raise ThreatFeedError("Feed ttl_seconds must be positive")
        if not 0 < self.timeout_seconds <= 300:
            raise ThreatFeedError("Feed timeout_seconds must be between 0 and 300")
        if self.max_entries <= 0:
            raise ThreatFeedError("Feed max_entries must be positive")
        if self.max_bytes <= 0:
            raise ThreatFeedError("Feed max_bytes must be positive")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ThreatFeedConfig:
        """Build a validated config from a JSON object."""
        try:
            name = str(value["name"]).strip()
            url = str(value["url"]).strip()
        except (KeyError, TypeError) as exc:
            raise ThreatFeedError("Each threat feed requires a name and URL") from exc

        try:
            ttl_seconds = int(value.get("ttl_seconds", _DEFAULT_TTL))
            timeout_seconds = float(value.get("timeout_seconds", _DEFAULT_TIMEOUT))
            max_entries = int(value.get("max_entries", _DEFAULT_MAX_ENTRIES))
            max_bytes = int(value.get("max_bytes", _DEFAULT_MAX_BYTES))
        except (TypeError, ValueError) as exc:
            raise ThreatFeedError("Feed numeric settings must be valid numbers") from exc

        return cls(
            name=name,
            url=url,
            category=str(value.get("category", "unknown")).strip().lower(),
            confidence=value.get("confidence", 0.5),
            ttl_seconds=ttl_seconds,
            timeout_seconds=timeout_seconds,
            max_entries=max_entries,
            max_bytes=max_bytes,
        )


@dataclass(frozen=True, slots=True)
class ThreatIndicator:
    """A normalized indicator ready to be persisted."""

    domain: str
    category: str
    confidence: float
    source: str


def _validate_url(url: str) -> None:
    """Allow only HTTP(S) URLs without embedded credentials or fragments."""
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ThreatFeedError("Feed URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.fragment:
        raise ThreatFeedError("Feed URL must not contain credentials or fragments")


def _validate_category(category: str) -> str:
    """Validate and return a normalized feed category."""
    normalized = category.strip().lower()
    if not _CATEGORY_PATTERN.fullmatch(normalized):
        raise ThreatFeedError("Feed category contains unsupported characters")
    return normalized


def _validate_confidence(confidence: Any) -> float:
    """Validate confidence as a finite number in the inclusive 0..1 range."""
    if isinstance(confidence, bool):
        raise ThreatFeedError("Feed confidence must be a number")
    try:
        normalized = float(confidence)
    except (TypeError, ValueError) as exc:
        raise ThreatFeedError("Feed confidence must be a number") from exc
    if not math.isfinite(normalized) or not 0 <= normalized <= 1:
        raise ThreatFeedError("Feed confidence must be between 0 and 1")
    return normalized


def _payload_entries(payload: Any) -> list[Any]:
    """Extract entries from common structured JSON feed envelopes."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("entries", "indicators", "data", "domains"):
            entries = payload.get(key)
            if isinstance(entries, list):
                return entries
    raise ThreatFeedError("Feed response must be a JSON list or a supported structured envelope")


def normalize_feed_entry(entry: Any, config: ThreatFeedConfig) -> ThreatIndicator:
    """Normalize one structured feed entry, rejecting non-domain indicators."""
    if isinstance(entry, str):
        raw_domain: Any = entry
        category: Any = config.category
        confidence: Any = config.confidence
    elif isinstance(entry, Mapping):
        raw_domain = entry.get("domain", entry.get("indicator", entry.get("value")))
        category = entry.get("category", config.category)
        confidence = entry.get("confidence", config.confidence)
    else:
        raise ThreatFeedError("Feed entries must be strings or objects")

    if not isinstance(raw_domain, str):
        raise ThreatFeedError("Feed entry is missing a domain")
    try:
        domain = normalize_domain(raw_domain)
    except ValueError as exc:
        raise ThreatFeedError(f"Invalid feed domain: {raw_domain!r}") from exc

    normalized_category = _validate_category(str(category))
    normalized_confidence = _validate_confidence(confidence)
    return ThreatIndicator(domain, normalized_category, normalized_confidence, config.name)


class ThreatFeedAdapter:
    """Fetch and normalize one bounded URL-based structured feed."""

    def __init__(self, config: ThreatFeedConfig, client: httpx.AsyncClient | None = None) -> None:
        self.config = config
        self._client = client

    async def fetch(self) -> list[ThreatIndicator]:
        """Fetch a JSON feed and return normalized indicators.

        Redirects are intentionally disabled so a configured feed cannot be
        silently redirected to an unexpected host.  The response size and
        entry count are bounded before normalization.
        """
        if self._client is not None:
            response = await self._client.get(self.config.url, headers={"Accept": "application/json"})
            return self._parse_response(response)

        async with httpx.AsyncClient(
            timeout=self.config.timeout_seconds,
            follow_redirects=False,
            headers={"Accept": "application/json"},
        ) as client:
            response = await client.get(self.config.url)
            return self._parse_response(response)

    def _parse_response(self, response: httpx.Response) -> list[ThreatIndicator]:
        """Validate the HTTP response and normalize its JSON payload."""
        if response.is_redirect:
            raise ThreatFeedError("Feed redirects are not allowed")
        response.raise_for_status()
        if len(response.content) > self.config.max_bytes:
            raise ThreatFeedError("Feed response exceeds configured max_bytes")
        try:
            payload = response.json()
        except ValueError as exc:
            raise ThreatFeedError("Feed response is not valid JSON") from exc

        entries = _payload_entries(payload)
        if len(entries) > self.config.max_entries:
            raise ThreatFeedError("Feed response exceeds configured max_entries")

        indicators: dict[tuple[str, str, str], ThreatIndicator] = {}
        for entry in entries:
            indicator = normalize_feed_entry(entry, self.config)
            key = (indicator.domain, indicator.category, indicator.source)
            current = indicators.get(key)
            if current is None or indicator.confidence > current.confidence:
                indicators[key] = indicator
        return list(indicators.values())


@dataclass(frozen=True, slots=True)
class FeedRefreshResult:
    """Outcome for one configured feed."""

    source: str
    fetched: int = 0
    activated: int = 0
    deactivated: int = 0
    error: str | None = None


async def upsert_threat_indicators(
    session: AsyncSession,
    indicators: Sequence[ThreatIndicator],
    *,
    source: str,
    ttl_seconds: int,
    now: datetime | None = None,
) -> tuple[int, int]:
    """Upsert a successful feed and deactivate records past its TTL.

    Expiration is based on ``last_seen`` because the existing schema does not
    need a new column or migration.  Deactivation runs only after a successful
    fetch, so transient feed outages preserve the last known intelligence.
    """
    refreshed_at = now or datetime.now(UTC)
    keys = {(item.domain, item.category, source) for item in indicators}
    existing: dict[tuple[str, str, str], ThreatIntelligence] = {}

    if keys:
        stmt = select(ThreatIntelligence).where(
            ThreatIntelligence.source == source,
            ThreatIntelligence.domain.in_([key[0] for key in keys]),
            ThreatIntelligence.category.in_([key[1] for key in keys]),
        )
        result = await session.execute(stmt)
        existing = {(row.domain, row.category, row.source): row for row in result.scalars().all()}

    activated = 0
    for indicator in indicators:
        key = (indicator.domain, indicator.category, source)
        row = existing.get(key)
        if row is None:
            session.add(
                ThreatIntelligence(
                    domain=indicator.domain,
                    category=indicator.category,
                    confidence=indicator.confidence,
                    source=source,
                    first_seen=refreshed_at,
                    last_seen=refreshed_at,
                    is_active=True,
                )
            )
            activated += 1
            continue

        row.confidence = indicator.confidence
        row.last_seen = refreshed_at
        if not row.is_active:
            activated += 1
        row.is_active = True

    cutoff = refreshed_at - timedelta(seconds=ttl_seconds)
    deactivation = await session.execute(
        update(ThreatIntelligence)
        .where(
            ThreatIntelligence.source == source,
            ThreatIntelligence.last_seen < cutoff,
            ThreatIntelligence.is_active.is_(True),
        )
        .values(is_active=False)
    )
    await session.commit()
    rowcount = getattr(deactivation, "rowcount", 0)
    return activated, rowcount if isinstance(rowcount, int) else 0


class ThreatFeedRefresher:
    """Refresh configured feeds, isolating failures between sources."""

    def __init__(
        self,
        feeds: Sequence[ThreatFeedConfig],
        *,
        session_factory: async_sessionmaker[AsyncSession] = async_session_factory,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.feeds = tuple(feeds)
        self._session_factory = session_factory
        self._client = client

    async def refresh(self, now: datetime | None = None) -> list[FeedRefreshResult]:
        """Fetch all feeds and persist successful results.

        The method is safe to call from a scheduler: each feed is independent,
        failures are returned as data, and no exception from one feed prevents
        the remaining feeds from refreshing.
        """
        results: list[FeedRefreshResult] = []
        for config in self.feeds:
            try:
                indicators = await ThreatFeedAdapter(config, client=self._client).fetch()
                async with self._session_factory() as session:
                    activated, deactivated = await upsert_threat_indicators(
                        session,
                        indicators,
                        source=config.name,
                        ttl_seconds=config.ttl_seconds,
                        now=now,
                    )
                results.append(
                    FeedRefreshResult(
                        source=config.name,
                        fetched=len(indicators),
                        activated=activated,
                        deactivated=deactivated,
                    )
                )
            except Exception as exc:  # noqa: BLE001 - isolate scheduled feed failures
                results.append(FeedRefreshResult(source=config.name, error=str(exc)))
        return results


def load_feed_configs(raw: str | None = None) -> tuple[ThreatFeedConfig, ...]:
    """Load feed definitions from ``ANALYZER_THREAT_FEEDS`` JSON.

    The value must be a JSON array of objects.  An unset or blank value means
    threat-feed population is disabled, preserving current deterministic-only
    behavior by default.
    """
    value = os.getenv("ANALYZER_THREAT_FEEDS") if raw is None else raw
    if not value or not value.strip():
        return ()
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ThreatFeedError("ANALYZER_THREAT_FEEDS must contain valid JSON") from exc
    if not isinstance(payload, list):
        raise ThreatFeedError("ANALYZER_THREAT_FEEDS must be a JSON array")
    try:
        return tuple(ThreatFeedConfig.from_mapping(item) for item in payload)
    except (TypeError, ValueError) as exc:
        if isinstance(exc, ThreatFeedError):
            raise
        raise ThreatFeedError("ANALYZER_THREAT_FEEDS contains an invalid feed") from exc


async def refresh_threat_intelligence(
    feeds: Sequence[ThreatFeedConfig] | None = None,
    *,
    session_factory: async_sessionmaker[AsyncSession] = async_session_factory,
    client: httpx.AsyncClient | None = None,
    now: datetime | None = None,
) -> list[FeedRefreshResult]:
    """Callable scheduled-refresh entry point for threat intelligence feeds."""
    configured_feeds = tuple(load_feed_configs() if feeds is None else feeds)
    return await ThreatFeedRefresher(
        configured_feeds,
        session_factory=session_factory,
        client=client,
    ).refresh(now=now)


__all__ = [
    "FeedRefreshResult",
    "ThreatFeedAdapter",
    "ThreatFeedConfig",
    "ThreatFeedError",
    "ThreatFeedRefresher",
    "ThreatIndicator",
    "load_feed_configs",
    "normalize_feed_entry",
    "refresh_threat_intelligence",
    "upsert_threat_indicators",
]
