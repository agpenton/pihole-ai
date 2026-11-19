"""Focused behavior tests for the Pi-hole DNS collector."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, ClassVar, Self, cast

import httpx
import pytest
from click.testing import CliRunner
from pihole_common.security import compute_evidence_hash

from pihole_collector import __main__ as collector_module


class FakeResponse:
    """Minimal HTTP response used by the client tests."""

    def __init__(self, payload: Any, error: Exception | None = None) -> None:
        self.payload = payload
        self.error = error

    def raise_for_status(self) -> None:
        """Raise the configured HTTP error, if any."""
        if self.error:
            raise self.error

    def json(self) -> Any:
        """Return the configured response payload."""
        return self.payload


class FakeHttpClient:
    """Async context-manager replacement for httpx.AsyncClient."""

    responses: ClassVar[list[FakeResponse]] = []
    calls: ClassVar[list[dict[str, Any]]] = []

    def __init__(self, timeout: float) -> None:
        self.timeout = timeout

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append({"timeout": self.timeout, "url": url, **kwargs})
        return self.responses.pop(0)


@pytest.fixture
def fake_http_client(monkeypatch: pytest.MonkeyPatch) -> type[FakeHttpClient]:
    """Replace HTTPX and reset request state for each client test."""
    FakeHttpClient.responses = []
    FakeHttpClient.calls = []
    monkeypatch.setattr(collector_module.httpx, "AsyncClient", FakeHttpClient)
    return FakeHttpClient


class FakeScalarResult:
    """Scalar result stand-in for SQLAlchemy's result wrapper."""

    def __init__(self, values: set[str]) -> None:
        self.values = values

    def all(self) -> list[str]:
        """Return inserted event IDs."""
        return list(self.values)


class FakeResult:
    """Minimal SQLAlchemy result covering scalar and row lookups."""

    def __init__(self, scalar_values: set[str], scalar_one_value: Any) -> None:
        self.scalar_values = scalar_values
        self.scalar_one_value = scalar_one_value

    def scalars(self) -> FakeScalarResult:
        """Return configured scalar event IDs."""
        return FakeScalarResult(self.scalar_values)

    def scalar_one(self) -> Any:
        """Return the configured domain inventory row."""
        return self.scalar_one_value


class FakeSession:
    """Async-session stand-in used by ingestion tests."""

    def __init__(self, inserted_ids: set[str], client_ips: list[str] | None = None) -> None:
        self.inserted_ids = inserted_ids
        self.inventory = SimpleNamespace(
            client_ips=client_ips or [],
            unique_clients=len(client_ips or []),
            query_count=0,
            first_seen=None,
            last_seen=None,
        )
        self.added: list[Any] = []
        self.commits = 0
        self.rollbacks = 0
        self.statements: list[Any] = []
        self.execute_count = 0

    async def execute(self, statement: Any) -> FakeResult:
        """Return inserted IDs for the event insert and inventory for later reads."""
        self.statements.append(statement)
        self.execute_count += 1
        table_name = getattr(getattr(statement, "table", None), "name", None)
        if table_name == "domain_inventory":
            values = {column.name: getattr(value, "value", value) for column, value in statement._values.items()}
            self.inventory.query_count += int(values["query_count"])
            self.inventory.first_seen = (
                values["first_seen"]
                if self.inventory.first_seen is None
                else min(self.inventory.first_seen, values["first_seen"])
            )
            self.inventory.last_seen = (
                values["last_seen"]
                if self.inventory.last_seen is None
                else max(self.inventory.last_seen, values["last_seen"])
            )
        inserted_ids = self.inserted_ids if self.execute_count == 1 else set()
        return FakeResult(inserted_ids, self.inventory)

    def add_all(self, events: list[Any]) -> None:
        """Record events scheduled for insertion."""
        self.added.extend(events)

    async def commit(self) -> None:
        """Record a successful commit."""
        self.commits += 1

    async def rollback(self) -> None:
        """Record a rollback after a failed transaction."""
        self.rollbacks += 1


class FakeMetric:
    """Small metric double that records labels and increments."""

    def __init__(self) -> None:
        self.labels_seen: list[dict[str, str]] = []
        self.increments: list[int] = []

    def labels(self, **labels: str) -> FakeMetric:
        """Record metric labels and return this metric child."""
        self.labels_seen.append(labels)
        return self

    def inc(self, amount: int = 1) -> None:
        """Record a metric increment."""
        self.increments.append(amount)


class SessionContext:
    """Async context manager for the collector's session factory."""

    def __init__(self, session: FakeSession) -> None:
        self.session = session
        self.entered = False
        self.exited = False

    async def __aenter__(self) -> FakeSession:
        self.entered = True
        return self.session

    async def __aexit__(self, *_args: object) -> None:
        self.exited = True


class FakeCollectorClient:
    """Pi-hole client double for collector polling tests."""

    def __init__(self, entries: list[dict[str, Any]] | None = None, error: Exception | None = None) -> None:
        self.entries = entries or []
        self.error = error
        self.from_times: list[datetime | None] = []

    async def get_query_log(self, from_time: datetime | None = None, limit: int = 10000) -> list[dict[str, Any]]:
        """Return entries and record incremental-poll arguments."""
        del limit
        self.from_times.append(from_time)
        if self.error:
            raise self.error
        return self.entries


class FakeSettings:
    """Settings subset required to construct a DnsCollector."""

    pihole = SimpleNamespace(url="http://pi.hole/admin/api.php", api_token="token", timeout=3.0, poll_interval=0.01)


def test_pihole_client_builds_urls_with_and_without_auth() -> None:
    """URL construction strips endpoint slashes and appends auth correctly."""
    client = collector_module.PiholeClient("http://pi.hole/", api_token="secret")

    assert client._build_url("/stats_v5.php") == "http://pi.hole/stats_v5.php?auth=secret"
    assert client._build_url("querylog.php?all=true") == "http://pi.hole/querylog.php?all=true&auth=secret"
    assert collector_module.PiholeClient("http://pi.hole/", api_token=None)._build_url("stats_v5.php") == (
        "http://pi.hole/stats_v5.php"
    )


@pytest.mark.asyncio
async def test_pihole_client_fetches_stats_and_forward_destinations(
    fake_http_client: type[FakeHttpClient],
) -> None:
    """Stats and forwarding endpoints return decoded JSON and use configured timeout."""
    fake_http_client.responses = [FakeResponse({"domains_being_blocked": 12}), FakeResponse([{"name": "Cloudflare"}])]
    client = collector_module.PiholeClient("http://pi.hole/api", api_token="secret", timeout=4.5)

    stats = await client.get_stats_v5()
    destinations = await client.get_forward_destinations()

    assert stats == {"domains_being_blocked": 12}
    assert destinations == [{"name": "Cloudflare"}]
    assert fake_http_client.calls == [
        {"timeout": 4.5, "url": "http://pi.hole/api/stats_v5.php?auth=secret"},
        {"timeout": 4.5, "url": "http://pi.hole/api/forward_destinations.php?auth=secret"},
    ]


@pytest.mark.asyncio
async def test_pihole_client_query_log_unwraps_data_and_sends_from_parameter(
    fake_http_client: type[FakeHttpClient],
) -> None:
    """Query-log responses support Pi-hole's wrapped payload and incremental timestamp."""
    fake_http_client.responses = [FakeResponse({"status": True, "data": [{"domain": "example.com"}]})]
    client = collector_module.PiholeClient("http://pi.hole/api")
    from_time = datetime.fromtimestamp(1_700_000_000, tz=UTC)

    entries = await client.get_query_log(from_time=from_time, limit=1)

    assert entries == [{"domain": "example.com"}]
    assert fake_http_client.calls == [
        {
            "timeout": 10.0,
            "url": "http://pi.hole/api/querylog.php",
            "params": {"all": "true", "from": "1700000000"},
        }
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [[{"domain": "example.com"}], {"status": True}, "unexpected"])
async def test_pihole_client_query_log_handles_supported_and_empty_payloads(
    fake_http_client: type[FakeHttpClient], payload: Any
) -> None:
    """List payloads are returned and malformed response shapes become an empty list."""
    fake_http_client.responses = [FakeResponse(payload)]

    entries = await collector_module.PiholeClient("http://pi.hole").get_query_log()

    assert entries == (payload if isinstance(payload, list) else [])


@pytest.mark.asyncio
async def test_pihole_client_propagates_http_errors(fake_http_client: type[FakeHttpClient]) -> None:
    """HTTP failures remain visible to callers for the collector to handle."""
    error = httpx.HTTPStatusError(
        "bad response",
        request=httpx.Request("GET", "http://pi.hole/stats_v5.php"),
        response=httpx.Response(503),
    )
    fake_http_client.responses = [FakeResponse({}, error)]

    with pytest.raises(httpx.HTTPStatusError):
        await collector_module.PiholeClient("http://pi.hole").get_stats_v5()


@pytest.mark.parametrize(
    ("entry", "expected_domain", "expected_client", "expected_type"),
    [
        (
            {
                "timestamp": 1_700_000_000,
                "domain": " Example.COM. ",
                "client": "192.0.2.10",
                "type": "AAAA",
                "response": "2001:db8::1",
                "reply": "NODATA",
                "forward": "router",
                "chain": ["Example.COM."],
            },
            "example.com",
            "192.0.2.10",
            "AAAA",
        ),
        (
            {
                "timestamp": 1_700_000_001,
                "query": "legacy.example.org",
                "ip": "192.0.2.11",
            },
            "legacy.example.org",
            "192.0.2.11",
            "A",
        ),
    ],
)
def test_normalize_query_log_entry_maps_v6_and_legacy_fields(
    entry: dict[str, Any], expected_domain: str, expected_client: str, expected_type: str
) -> None:
    """Normalization accepts v6 names and the legacy query/ip aliases."""
    normalized = collector_module.normalize_query_log_entry(entry)

    assert normalized is not None
    assert normalized["domain"] == expected_domain
    assert normalized["client_ip"] == expected_client
    assert normalized["query_type"] == expected_type
    assert normalized["response"] == entry.get("response", "")
    assert normalized["response_code"] == entry.get("reply", "NOERROR")
    assert normalized["created_at"].tzinfo is UTC
    assert normalized["event_id"] == compute_evidence_hash(
        expected_domain, expected_client, str(entry["timestamp"]), expected_type
    )


def test_normalize_query_log_entry_preserves_optional_fields_and_defaults() -> None:
    """Optional Pi-hole fields are retained while response defaults are applied."""
    normalized = collector_module.normalize_query_log_entry(
        {"timestamp": 1_700_000_002, "domain": "example.net", "client": "192.0.2.12"}
    )

    assert normalized is not None
    assert normalized["response"] == ""
    assert normalized["response_code"] == "NOERROR"
    assert normalized["client_name"] is None
    assert normalized["chain"] is None


@pytest.mark.parametrize(
    "entry",
    [
        {},
        {"timestamp": 0, "domain": "example.com"},
        {"timestamp": 1_700_000_000},
        {"timestamp": 1_700_000_000, "domain": "not a domain"},
        {"timestamp": "not-a-timestamp", "domain": "example.com"},
    ],
)
def test_normalize_query_log_entry_rejects_invalid_entries(entry: dict[str, Any]) -> None:
    """Entries without usable timestamps or domains are skipped safely."""
    assert collector_module.normalize_query_log_entry(entry) is None


@pytest.mark.asyncio
async def test_ingest_events_inserts_new_events_and_counts_duplicates(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ingestion persists only new events and updates their domain inventory."""
    duplicate_metric = FakeMetric()
    event_metric = FakeMetric()
    monkeypatch.setattr(collector_module, "dns_events_duplicates_total", duplicate_metric)
    monkeypatch.setattr(collector_module, "dns_events_total", event_metric)
    session = FakeSession({"new-event"})
    events: list[dict[str, Any]] = [
        {
            "event_id": "already-seen",
            "client_ip": "192.0.2.20",
            "domain": "old.example",
            "query_type": "A",
            "response": "192.0.2.1",
            "response_code": "NOERROR",
            "client_name": None,
            "chain": None,
            "created_at": datetime(2025, 1, 1, tzinfo=UTC),
        },
        {
            "event_id": "new-event",
            "client_ip": "192.0.2.21",
            "domain": "new.example",
            "query_type": "AAAA",
            "response": "2001:db8::1",
            "response_code": "NODATA",
            "client_name": "client",
            "chain": ["new.example"],
            "created_at": datetime(2025, 1, 1, tzinfo=UTC),
        },
    ]

    inserted, duplicates = await collector_module.ingest_events(cast(Any, session), events)

    assert (inserted, duplicates) == (1, 1)
    assert session.added == []
    assert session.execute_count == 3
    assert session.inventory.client_ips == ["192.0.2.21"]
    assert session.inventory.unique_clients == 1
    assert session.inventory.query_count == 1
    assert session.inventory.first_seen == datetime(2025, 1, 1, tzinfo=UTC)
    assert session.inventory.last_seen == datetime(2025, 1, 1, tzinfo=UTC)
    assert session.commits == 1
    assert duplicate_metric.increments == [1]
    assert event_metric.labels_seen == [{"query_type": "AAAA", "response_code": "NODATA"}]
    assert event_metric.increments == [1]


@pytest.mark.asyncio
async def test_ingest_events_does_not_commit_when_all_events_are_duplicates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An all-duplicate batch avoids an unnecessary database commit."""
    duplicate_metric = FakeMetric()
    event_metric = FakeMetric()
    monkeypatch.setattr(collector_module, "dns_events_duplicates_total", duplicate_metric)
    monkeypatch.setattr(collector_module, "dns_events_total", event_metric)
    session = FakeSession(set())
    events = [
        {
            "event_id": "event-1",
            "client_ip": "192.0.2.1",
            "domain": "one.example",
            "created_at": datetime(2025, 1, 1, tzinfo=UTC),
        },
        {
            "event_id": "event-2",
            "client_ip": "192.0.2.2",
            "domain": "two.example",
            "created_at": datetime(2025, 1, 1, tzinfo=UTC),
        },
    ]

    assert await collector_module.ingest_events(cast(Any, session), events) == (0, 2)
    assert session.added == []
    assert session.commits == 0
    assert duplicate_metric.increments == [2]
    assert event_metric.increments == []


@pytest.mark.asyncio
async def test_ingest_events_handles_empty_batches(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty batches are no-ops with zero metric increments."""
    duplicate_metric = FakeMetric()
    event_metric = FakeMetric()
    monkeypatch.setattr(collector_module, "dns_events_duplicates_total", duplicate_metric)
    monkeypatch.setattr(collector_module, "dns_events_total", event_metric)
    session = FakeSession(set())

    assert await collector_module.ingest_events(cast(Any, session), []) == (0, 0)
    assert session.statements == []
    assert session.commits == 0
    assert duplicate_metric.increments == []
    assert event_metric.increments == []


@pytest.mark.asyncio
async def test_dns_collector_poll_and_ingest_normalizes_entries_and_tracks_latest_timestamp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Polling passes normalized events to ingestion and advances the watermark."""
    entries = [
        {"timestamp": 1_700_000_005, "domain": "FIRST.Example", "client": "192.0.2.30"},
        {"timestamp": 1_700_000_010, "query": "second.example", "ip": "192.0.2.31"},
        {"timestamp": 1_700_000_011},
    ]
    client = FakeCollectorClient(entries)
    collector = cast(Any, object.__new__(collector_module.DnsCollector))
    collector.client = client
    collector._last_timestamp = 1_700_000_000
    collector.settings = FakeSettings()
    ingested: list[dict[str, Any]] = []

    async def fake_ingest(_session: Any, events: list[dict[str, Any]]) -> tuple[int, int]:
        ingested.extend(events)
        return 2, 0

    session = FakeSession(set())
    context = SessionContext(session)
    monkeypatch.setattr(collector_module, "async_session_factory", lambda: context)
    monkeypatch.setattr(collector_module, "ingest_events", fake_ingest)

    result = await collector.poll_and_ingest()

    assert result == (2, 0)
    assert client.from_times == [datetime.fromtimestamp(1_700_000_000, tz=UTC)]
    assert collector._last_timestamp == 1_700_000_010
    assert [event["domain"] for event in ingested] == ["first.example", "second.example"]
    assert context.entered is True
    assert context.exited is True


@pytest.mark.asyncio
async def test_dns_collector_poll_skips_database_for_empty_or_failed_polls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty results and HTTP failures return zero counts without opening a session."""
    collector = cast(Any, object.__new__(collector_module.DnsCollector))
    collector._last_timestamp = 0
    collector.settings = FakeSettings()
    context_created = False

    def session_factory() -> SessionContext:
        nonlocal context_created
        context_created = True
        return SessionContext(FakeSession(set()))

    monkeypatch.setattr(collector_module, "async_session_factory", session_factory)

    collector.client = FakeCollectorClient(cast(list[dict[str, Any]], [{"timestamp": 0, "domain": "example.com"}]))
    assert await collector.poll_and_ingest() == (0, 0)
    assert context_created is False

    collector.client = FakeCollectorClient(error=httpx.ConnectError("unavailable"))
    assert await collector.poll_and_ingest() == (0, 0)
    assert context_created is False


def test_dns_collector_run_polls_until_stopped(monkeypatch: pytest.MonkeyPatch) -> None:
    """The run loop performs a poll and honors the running flag after sleep."""
    collector = cast(Any, object.__new__(collector_module.DnsCollector))
    collector._running = False
    collector.settings = FakeSettings()
    poll_count = 0

    async def fake_poll() -> tuple[int, int]:
        nonlocal poll_count
        poll_count += 1
        return 0, 0

    async def stop_after_sleep(_interval: float) -> None:
        collector._running = False

    monkeypatch.setattr(collector, "poll_and_ingest", fake_poll)
    monkeypatch.setattr(asyncio, "sleep", stop_after_sleep)

    async def exercise() -> None:
        await collector.run()

    asyncio.run(exercise())

    assert collector._running is False
    assert poll_count == 1


def test_dns_collector_stop_clears_running_flag() -> None:
    """Stopping a collector is idempotent and clears its loop flag."""
    collector = cast(Any, object.__new__(collector_module.DnsCollector))
    collector._running = True
    collector.settings = FakeSettings()

    async def exercise() -> None:
        await collector.stop()
        await collector.stop()

    asyncio.run(exercise())

    assert collector._running is False


def test_dns_collector_constructor_uses_pihole_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Construction wires the configured Pi-hole endpoint into the client."""
    monkeypatch.setattr(collector_module, "get_settings", lambda: FakeSettings())

    collector = collector_module.DnsCollector()

    assert collector.client.base_url == "http://pi.hole/admin/api.php"
    assert collector.client.api_token == "token"
    assert collector.client.timeout == 3.0
    assert collector._last_timestamp == 0
    assert collector._running is False


def test_cli_once_initializes_collects_and_closes(monkeypatch: pytest.MonkeyPatch) -> None:
    """The one-shot CLI path initializes the database and performs one poll."""
    calls: list[str] = []

    class FakeCliCollector:
        async def poll_and_ingest(self) -> tuple[int, int]:
            calls.append("poll")
            return 1, 0

    def fake_settings() -> Any:
        settings = FakeSettings()
        cast(Any, settings).telemetry = SimpleNamespace(service_name="collector", metrics_enabled=False)
        return settings

    async def fake_init_db() -> None:
        calls.append("init")

    async def fake_close_db() -> None:
        calls.append("close")

    monkeypatch.setattr(collector_module, "get_settings", fake_settings)
    monkeypatch.setattr(collector_module, "init_db", fake_init_db)
    monkeypatch.setattr(collector_module, "close_db", fake_close_db)
    monkeypatch.setattr(collector_module, "DnsCollector", FakeCliCollector)

    result = CliRunner().invoke(collector_module.main, ["--once"])

    assert result.exit_code == 0, result.output
    assert calls == ["init", "poll", "close"]
