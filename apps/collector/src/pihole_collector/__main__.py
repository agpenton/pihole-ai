"""DNS Collector — polls the Pi-hole v6 REST API and persists DNS events."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import math
import signal
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import click
import httpx
import structlog
from pihole_common.config import get_settings
from pihole_common.database import async_session_factory, close_db, init_db
from pihole_common.models import CollectorState, DnsEvent, DomainInventory
from pihole_common.security import compute_evidence_hash, normalize_domain
from pihole_common.telemetry import (
    dns_events_duplicates_total,
    dns_events_total,
    set_app_info,
    start_metrics_server,
)
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger()
JsonDict = dict[str, Any]

COLLECTOR_NAME = "pihole-dns-collector"
EVENT_INSERT_BATCH_SIZE = 3000
WATERMARK_OVERLAP = timedelta(seconds=1)
LOCAL_DOMAIN_SUFFIXES = ("fritz.box", "home.arpa", "local", "_dns.resolver.arpa", "dns.resolver.arpa")
LOCAL_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
    )
)

QUERY_TYPE_NAMES = {
    1: "A", 2: "AAAA", 3: "ANY", 4: "SRV", 5: "SOA", 6: "PTR", 7: "TXT",
    8: "NAPTR", 9: "MX", 10: "DS", 11: "RRSIG", 12: "DNSKEY", 13: "NS",
    14: "OTHER", 15: "SVCB", 16: "HTTPS",
}


@dataclass(frozen=True)
class IngestResult:
    """Database ingestion counts and inserted events, used for post-commit metrics."""

    inserted: int
    duplicates: int
    inserted_events: list[JsonDict]


class PiholeClient:
    """Minimal authenticated client for the Pi-hole v6 REST API."""

    def __init__(self, base_url: str, password: str | None = None, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.password = password
        self.timeout = timeout

    async def _authenticate(self, client: httpx.AsyncClient) -> str | None:
        """Create a v6 API session and return its SID."""
        if not self.password:
            return None
        response = await client.post(f"{self.base_url}/auth", json={"password": self.password})
        response.raise_for_status()
        session = response.json().get("session", {})
        if not session.get("valid") or not session.get("sid"):
            raise httpx.HTTPError("Pi-hole v6 authentication returned no valid SID")
        return str(session["sid"])

    async def _logout(self, client: httpx.AsyncClient, sid: str | None) -> None:
        """Invalidate an API session when one was created."""
        if not sid:
            return
        try:
            response = await client.delete(f"{self.base_url}/auth", headers={"X-FTL-SID": sid})
            if response.status_code not in (200, 204):
                logger.warning("pihole_logout_failed", status=response.status_code)
        except httpx.HTTPError:
            logger.warning("pihole_logout_failed", exc_info=True)

    async def get_query_log(self, from_time: datetime | None = None, limit: int = 10000) -> list[JsonDict]:
        """Fetch query records from Pi-hole v6 GET /api/queries."""
        now = datetime.now(UTC)
        start = from_time or (now - timedelta(hours=24))
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            sid = await self._authenticate(client)
            headers = {"X-FTL-SID": sid} if sid else {}
            try:
                response = await client.get(
                    f"{self.base_url}/queries",
                    params={"from": int(start.timestamp()), "until": int(now.timestamp()), "length": limit},
                    headers=headers,
                )
                response.raise_for_status()
                payload = response.json()
            finally:
                await self._logout(client, sid)
        if isinstance(payload, list):
            return cast(list[JsonDict], payload)
        if isinstance(payload, dict):
            records = payload.get("queries", payload.get("data", []))
            if isinstance(records, list):
                return cast(list[JsonDict], records)
        raise ValueError("Unexpected response from Pi-hole v6 /api/queries")

    async def get_summary(self) -> JsonDict:
        """Fetch Pi-hole v6 summary statistics."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            sid = await self._authenticate(client)
            headers = {"X-FTL-SID": sid} if sid else {}
            try:
                response = await client.get(f"{self.base_url}/stats/summary", headers=headers)
                response.raise_for_status()
                return cast(JsonDict, response.json())
            finally:
                await self._logout(client, sid)


def _client_ip(value: Any) -> str:
    """Normalize Pi-hole's client field, which may be a string or object."""
    if isinstance(value, dict):
        return str(value.get("ip") or value.get("name") or "unknown")
    return str(value or "unknown")


def _query_type(value: Any) -> str:
    """Normalize query type names and numeric IDs."""
    if isinstance(value, int):
        return QUERY_TYPE_NAMES.get(value, f"TYPE{value}")
    return str(value or "A").upper()


def _entry_timestamp(entry: JsonDict) -> float | None:
    """Return a valid positive Unix timestamp from a raw Pi-hole record."""
    value = entry.get("timestamp", entry.get("time"))
    if value is None or isinstance(value, bool):
        return None
    try:
        timestamp = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(timestamp) or timestamp <= 0:
        return None
    return timestamp


def _is_local_ip(value: str) -> bool:
    """Return whether an IP literal belongs to a local/private address range."""
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    if address.is_loopback or address.is_link_local or address.is_private or address.is_unspecified:
        return True
    return any(address in network for network in LOCAL_NETWORKS if address.version == network.version)


def _is_private_reverse_dns(domain: str) -> bool:
    """Recognize RFC1918 IPv4 reverse zones, including DNS-SD prefixes."""
    suffix = ".in-addr.arpa"
    if not domain.endswith(suffix):
        return False
    labels = domain[: -len(suffix)].split(".")
    if len(labels) < 4:
        return False
    octets = labels[-4:]
    if not all(label.isdigit() and 0 <= int(label) <= 255 for label in octets):
        return False
    address = ".".join(reversed(octets))
    return _is_local_ip(address)


def is_local_domain(value: str) -> bool:
    """Identify local hostnames, private IPs, and local reverse-DNS queries."""
    domain = value.strip().rstrip(".").lower()
    if not domain:
        return True
    if _is_local_ip(domain) or _is_private_reverse_dns(domain):
        return True
    if domain == "localhost" or "." not in domain:
        return True
    return any(domain == suffix or domain.endswith(f".{suffix}") for suffix in LOCAL_DOMAIN_SUFFIXES)


def normalize_query_log_entry(entry: JsonDict) -> JsonDict | None:
    """Convert a Pi-hole v6 query record into the internal event schema."""
    try:
        raw_timestamp = entry.get("timestamp", entry.get("time", 0))
        timestamp = _entry_timestamp(entry)
        if timestamp is None:
            return None
        domain_value = entry.get("domain") or entry.get("query")
        if not domain_value:
            return None
        domain = normalize_domain(str(domain_value))
        client = _client_ip(entry.get("client") or entry.get("ip"))
        query_type = _query_type(entry.get("type"))
        status = entry.get("status", entry.get("reply", "UNKNOWN"))
        response = entry.get("response") or entry.get("forward")
        client_name = entry.get("client", {}).get("name") if isinstance(entry.get("client"), dict) else None
        chain = entry.get("chain")
        # Keep the raw timestamp representation in the event hash for backwards
        # compatibility with IDs already stored by the current collector.
        event_id = compute_evidence_hash(domain, client, str(raw_timestamp), query_type)
        return {
            "event_id": event_id,
            "client_ip": client,
            "domain": domain,
            "query_type": query_type,
            "response": str(response) if response is not None else None,
            "response_code": str(status)[:10],
            "client_name": client_name,
            "chain": chain,
            "created_at": datetime.fromtimestamp(timestamp, tz=UTC),
        }
    except (ValueError, KeyError, TypeError, OverflowError) as exc:
        logger.warning("query_record_normalization_failed", error=str(exc))
        return None


async def ingest_events(session: AsyncSession, events: list[JsonDict]) -> IngestResult:
    """Insert DNS events in bounded batches and update inventory in the same transaction.

    The caller owns the transaction. This function intentionally does not commit
    or roll back, allowing the collector watermark to be committed atomically
    with DNS events and domain inventory.
    """
    if not events:
        return IngestResult(inserted=0, duplicates=0, inserted_events=[])

    unique_by_id: dict[str, JsonDict] = {}
    for event in events:
        unique_by_id.setdefault(event["event_id"], event)
    unique_events = list(unique_by_id.values())

    inserted_ids: set[str] = set()
    for offset in range(0, len(unique_events), EVENT_INSERT_BATCH_SIZE):
        batch = unique_events[offset : offset + EVENT_INSERT_BATCH_SIZE]
        statement = pg_insert(DnsEvent).values(batch)
        statement = statement.on_conflict_do_nothing(index_elements=[DnsEvent.event_id]).returning(DnsEvent.event_id)
        result = await session.execute(statement)
        inserted_ids.update(result.scalars().all())

    inserted_events = [event for event in unique_events if event["event_id"] in inserted_ids]
    inserted = len(inserted_events)
    duplicates = len(events) - inserted

    events_by_domain: dict[str, list[JsonDict]] = {}
    for event in inserted_events:
        events_by_domain.setdefault(event["domain"], []).append(event)

    for domain_name, domain_events in events_by_domain.items():
        clients = list(dict.fromkeys(event["client_ip"] for event in domain_events))
        inventory_insert = pg_insert(DomainInventory).values(
            normalized_domain=domain_name,
            query_count=len(domain_events),
            first_seen=min(event["created_at"] for event in domain_events),
            last_seen=max(event["created_at"] for event in domain_events),
            unique_clients=len(clients),
            client_ips=clients,
        )
        inventory_upsert = inventory_insert.on_conflict_do_update(
            index_elements=[DomainInventory.normalized_domain],
            set_={
                "query_count": DomainInventory.query_count + inventory_insert.excluded.query_count,
                "first_seen": func.least(DomainInventory.first_seen, inventory_insert.excluded.first_seen),
                "last_seen": func.greatest(DomainInventory.last_seen, inventory_insert.excluded.last_seen),
                "updated_at": datetime.now(UTC),
            },
        )
        await session.execute(inventory_upsert)
        inventory = (
            await session.execute(
                select(DomainInventory).where(DomainInventory.normalized_domain == domain_name).with_for_update()
            )
        ).scalar_one()
        existing_clients = [str(client_ip) for client_ip in (inventory.client_ips or [])]
        merged_clients = list(dict.fromkeys([*existing_clients, *clients]))
        inventory.client_ips = merged_clients
        inventory.unique_clients = len(merged_clients)
        inventory.updated_at = datetime.now(UTC)

    return IngestResult(inserted=inserted, duplicates=duplicates, inserted_events=inserted_events)


class DnsCollector:
    """Poll Pi-hole and ingest new DNS events with a PostgreSQL-persisted watermark."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.client = PiholeClient(
            base_url=self.settings.pihole.api_base_url,
            password=self.settings.pihole.effective_password,
            timeout=self.settings.pihole.timeout,
        )
        self._running = False

    async def _load_watermark(self) -> datetime | None:
        """Read the persisted timestamp for this collector."""
        async with async_session_factory() as session:
            return await session.scalar(
                select(CollectorState.last_timestamp).where(CollectorState.collector_name == COLLECTOR_NAME)
            )

    async def poll_and_ingest(self) -> tuple[int, int]:
        """Fetch one query-log page and atomically persist events plus its watermark."""
        persisted_watermark = await self._load_watermark()
        if persisted_watermark is not None:
            # Keep a one-second overlap to avoid losing records at integer-second boundaries.
            from_time = persisted_watermark - WATERMARK_OVERLAP
        else:
            from_time = datetime.now(UTC) - timedelta(hours=self.settings.pihole.initial_lookback_hours)

        try:
            entries = await self.client.get_query_log(from_time=from_time, limit=self.settings.pihole.query_limit)
        except (httpx.HTTPError, ValueError) as exc:
            logger.error("pihole_query_fetch_failed", error=str(exc))
            return 0, 0

        normalized: list[JsonDict] = []
        latest_raw_timestamp = persisted_watermark.timestamp() if persisted_watermark else 0.0
        saw_raw_timestamp = False
        filtered_local = 0
        for entry in entries:
            timestamp = _entry_timestamp(entry)
            if timestamp is not None:
                saw_raw_timestamp = True
                latest_raw_timestamp = max(latest_raw_timestamp, timestamp)
            raw_domain = entry.get("domain") or entry.get("query")
            if raw_domain and is_local_domain(str(raw_domain)):
                filtered_local += 1
                continue
            event = normalize_query_log_entry(entry)
            if event is not None:
                normalized.append(event)

        # Do not advance to wall-clock time: only advance to a timestamp actually
        # observed in Pi-hole's response. This also advances over filtered local
        # records so they are not fetched forever.
        if not saw_raw_timestamp or latest_raw_timestamp <= 0:
            logger.info("poll_complete", fetched=len(entries), normalized=0, inserted=0, duplicates=0,
                        filtered_local=filtered_local, watermark_updated=False)
            return 0, 0

        latest_watermark = datetime.fromtimestamp(latest_raw_timestamp, tz=UTC)
        async with async_session_factory() as session:
            async with session.begin():
                result = await ingest_events(session, normalized)
                state_insert = pg_insert(CollectorState).values(
                    collector_name=COLLECTOR_NAME,
                    last_timestamp=latest_watermark,
                    updated_at=datetime.now(UTC),
                )
                state_upsert = state_insert.on_conflict_do_update(
                    index_elements=[CollectorState.collector_name],
                    set_={
                        "last_timestamp": func.greatest(
                            CollectorState.last_timestamp,
                            state_insert.excluded.last_timestamp,
                        ),
                        "updated_at": datetime.now(UTC),
                    },
                )
                await session.execute(state_upsert)

        # Metrics are emitted only after the transaction has committed.
        dns_events_duplicates_total.inc(result.duplicates)
        for event in result.inserted_events:
            dns_events_total.labels(
                query_type=event["query_type"],
                response_code=event["response_code"],
            ).inc()

        logger.info(
            "poll_complete",
            fetched=len(entries),
            normalized=len(normalized),
            inserted=result.inserted,
            duplicates=result.duplicates,
            filtered_local=filtered_local,
            watermark=latest_watermark.isoformat(),
        )
        return result.inserted, result.duplicates

    async def run(self) -> None:
        """Run the collector polling loop."""
        self._running = True
        logger.info("collector_started", interval=self.settings.pihole.poll_interval,
                    api_url=self.settings.pihole.api_base_url)
        while self._running:
            try:
                await self.poll_and_ingest()
            except Exception:
                logger.exception("collector_cycle_failed")
            await asyncio.sleep(self.settings.pihole.poll_interval)

    async def stop(self) -> None:
        """Stop the collector loop."""
        self._running = False
        logger.info("collector_stopped")


@click.command()
@click.option("--once", is_flag=True, help="Run one poll and exit")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
def main(once: bool = False, verbose: bool = False) -> None:
    """Start the Pi-hole DNS collector."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    settings = get_settings()
    set_app_info("pihole-dns-collector")
    if settings.telemetry.metrics_enabled:
        start_metrics_server()

    async def run_collector() -> None:
        await init_db()  # Connectivity check only; migrations run in a separate Job.
        collector = DnsCollector()
        try:
            if once:
                await collector.poll_and_ingest()
                return
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, lambda: asyncio.create_task(collector.stop()))
            await collector.run()
        finally:
            await close_db()

    asyncio.run(run_collector())


if __name__ == "__main__":
    main()
