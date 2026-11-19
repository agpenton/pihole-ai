"""DNS Collector — polls Pi-hole v6 REST API and stores DNS events."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import signal
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import click
import httpx
import structlog
from pihole_common.config import get_settings
from pihole_common.database import async_session_factory, close_db, init_db
from pihole_common.models import DnsEvent, DomainInventory
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

# Keep each multi-row INSERT below asyncpg's 32,767 bind-parameter limit.
# The current DnsEvent insert binds 9 values per row; 3,000 rows = 27,000.
EVENT_INSERT_BATCH_SIZE = 3000

# Local DNS namespaces that should never enter AI analysis.
LOCAL_DOMAIN_SUFFIXES = (
    "fritz.box",
    "home.arpa",
    "local",
)

# Private and local IPv4 networks.
LOCAL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
)

QUERY_TYPE_NAMES = {
    1: "A",
    2: "AAAA",
    3: "ANY",
    4: "SRV",
    5: "SOA",
    6: "PTR",
    7: "TXT",
    8: "NAPTR",
    9: "MX",
    10: "DS",
    11: "RRSIG",
    12: "DNSKEY",
    13: "NS",
    14: "OTHER",
    15: "SVCB",
    16: "HTTPS",
}


class PiholeClient:
    """Minimal authenticated client for the Pi-hole v6 REST API."""

    def __init__(
        self,
        base_url: str,
        password: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.password = password
        self.timeout = timeout

    async def _authenticate(self, client: httpx.AsyncClient) -> str | None:
        """Create a v6 API session and return its SID."""
        if not self.password:
            return None

        response = await client.post(
            f"{self.base_url}/auth",
            json={"password": self.password},
        )
        response.raise_for_status()

        payload = response.json()
        session = payload.get("session", {})
        if not session.get("valid") or not session.get("sid"):
            raise httpx.HTTPError("Pi-hole v6 authentication returned no valid SID")

        return str(session["sid"])

    async def _logout(self, client: httpx.AsyncClient, sid: str | None) -> None:
        """Invalidate the API session where one was created."""
        if not sid:
            return

        try:
            response = await client.delete(
                f"{self.base_url}/auth",
                headers={"X-FTL-SID": sid},
            )
            if response.status_code not in (200, 204):
                logger.warning("pihole_logout_failed", status=response.status_code)
        except httpx.HTTPError:
            logger.warning("pihole_logout_failed", exc_info=True)

    async def get_query_log(
        self,
        from_time: datetime | None = None,
        limit: int = 10000,
    ) -> list[JsonDict]:
        """Fetch query records from Pi-hole v6 GET /api/queries."""
        now = datetime.now(UTC)
        start = from_time or (now - timedelta(hours=24))

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            sid = await self._authenticate(client)
            headers = {"X-FTL-SID": sid} if sid else {}

            try:
                response = await client.get(
                    f"{self.base_url}/queries",
                    params={
                        "from": int(start.timestamp()),
                        "until": int(now.timestamp()),
                        "length": limit,
                    },
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
        """Fetch summary statistics from Pi-hole v6."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            sid = await self._authenticate(client)
            headers = {"X-FTL-SID": sid} if sid else {}

            try:
                response = await client.get(
                    f"{self.base_url}/stats/summary",
                    headers=headers,
                )
                response.raise_for_status()
                return cast(JsonDict, response.json())
            finally:
                await self._logout(client, sid)


def _client_ip(value: Any) -> str:
    """Normalize Pi-hole client field, which may be a string or object."""
    if isinstance(value, dict):
        return str(value.get("ip") or value.get("name") or "unknown")
    return str(value or "unknown")


def _query_type(value: Any) -> str:
    """Normalize query type names and numeric IDs."""
    if isinstance(value, int):
        return QUERY_TYPE_NAMES.get(value, f"TYPE{value}")
    return str(value or "A").upper()


def _is_local_ip(value: str) -> bool:
    """Return True when an IPv4 address belongs to a local network."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False

    return any(address in network for network in LOCAL_NETWORKS)


def _is_private_reverse_dns(domain: str) -> bool:
    """
    Detect private IPv4 reverse-DNS queries.

    Handles ordinary PTR names:
        0.178.168.192.in-addr.arpa

    Also handles DNS-SD names:
        lb._dns-sd._udp.0.178.168.192.in-addr.arpa
    """
    labels = domain.split(".")

    if len(labels) < 6:
        return False

    if labels[-2:] != ["in-addr", "arpa"]:
        return False

    reverse_labels = labels[:-2]

    # DNS-SD labels may precede the four IPv4 octets.
    for index in range(len(reverse_labels) - 3):
        candidate = reverse_labels[index : index + 4]

        if not all(label.isdecimal() for label in candidate):
            continue

        try:
            octets = [int(label) for label in candidate]

            if any(octet < 0 or octet > 255 for octet in octets):
                continue

            address = ipaddress.ip_address(
                ".".join(str(octet) for octet in reversed(octets))
            )
        except ValueError:
            continue

        if any(address in network for network in LOCAL_NETWORKS):
            return True

    return False


def is_local_domain(value: str) -> bool:
    """
    Identify local domains and private reverse-DNS queries.

    These records are excluded from Pi-hole AI ingestion.
    """
    domain = value.strip().rstrip(".").lower()

    if not domain:
        return True

    # Ignore local namespaces and their subdomains.
    if any(
        domain == suffix or domain.endswith(f".{suffix}")
        for suffix in LOCAL_DOMAIN_SUFFIXES
    ):
        return True

    # Ignore the special DNS resolver discovery namespace.
    if domain == "_dns.resolver.arpa" or domain.endswith("._dns.resolver.arpa"):
        return True

    # Ignore private IPv4 addresses queried directly.
    if _is_local_ip(domain):
        return True

    # Ignore private IPv4 reverse-DNS queries.
    if _is_private_reverse_dns(domain):
        return True

    # Ignore single-label local hostnames.
    if "." not in domain:
        return True

    return False


def normalize_query_log_entry(entry: JsonDict) -> JsonDict | None:
    """Convert a Pi-hole v6 query record into the internal event schema."""
    try:
        timestamp = entry.get("timestamp", entry.get("time", 0))
        if not timestamp:
            return None

        domain_value = entry.get("domain") or entry.get("query")
        if not domain_value:
            return None

        raw_domain = str(domain_value).strip().rstrip(".")

        # Filter local infrastructure before domain normalization.
        if is_local_domain(raw_domain):
            return None

        domain = normalize_domain(raw_domain)
        client = _client_ip(entry.get("client") or entry.get("ip"))
        query_type = _query_type(entry.get("type"))

        # v6 uses status/reply fields rather than the old v5 reply shape.
        status = entry.get("status", entry.get("reply", "UNKNOWN"))
        response = entry.get("response") or entry.get("forward")

        client_name = None
        if isinstance(entry.get("client"), dict):
            client_name = entry["client"].get("name")

        chain = entry.get("chain")
        event_id = compute_evidence_hash(
            domain,
            client,
            str(timestamp),
            query_type,
        )

        return {
            "event_id": event_id,
            "client_ip": client,
            "domain": domain,
            "query_type": query_type,
            "response": str(response) if response is not None else None,
            "response_code": str(status)[:10],
            "client_name": client_name,
            "chain": chain,
            "created_at": datetime.fromtimestamp(float(timestamp), tz=UTC),
        }
    except (ValueError, KeyError, TypeError, OverflowError) as exc:
        logger.warning("query_record_normalization_failed", error=str(exc))
        return None


async def ingest_events(
    session: AsyncSession,
    events: list[JsonDict],
) -> tuple[int, int]:
    """Persist events and update domain inventory idempotently."""
    if not events:
        return 0, 0

    unique_events_by_id: dict[str, JsonDict] = {}
    for event in events:
        unique_events_by_id.setdefault(event["event_id"], event)

    unique_events = list(unique_events_by_id.values())

    try:
        # Insert in chunks to stay below asyncpg's bind-parameter limit.
        inserted_ids: set[str] = set()

        for offset in range(0, len(unique_events), EVENT_INSERT_BATCH_SIZE):
            batch = unique_events[offset : offset + EVENT_INSERT_BATCH_SIZE]

            event_insert = pg_insert(DnsEvent).values(batch)
            event_insert = event_insert.on_conflict_do_nothing(
                index_elements=[DnsEvent.event_id]
            ).returning(DnsEvent.event_id)

            result = await session.execute(event_insert)
            inserted_ids.update(result.scalars().all())

        new_events = [
            event for event in unique_events if event["event_id"] in inserted_ids
        ]

        inserted = len(new_events)
        duplicates = len(events) - inserted

        events_by_domain: dict[str, list[JsonDict]] = {}
        for event in new_events:
            events_by_domain.setdefault(event["domain"], []).append(event)

        for domain_name, domain_events in events_by_domain.items():
            clients = list(dict.fromkeys(event["client_ip"] for event in domain_events))
            first_seen = min(event["created_at"] for event in domain_events)
            last_seen = max(event["created_at"] for event in domain_events)

            inventory_insert = pg_insert(DomainInventory).values(
                normalized_domain=domain_name,
                query_count=len(domain_events),
                first_seen=first_seen,
                last_seen=last_seen,
                unique_clients=len(clients),
                client_ips=clients,
            )

            inventory_upsert = inventory_insert.on_conflict_do_update(
                index_elements=[DomainInventory.normalized_domain],
                set_={
                    "query_count": (
                        DomainInventory.query_count
                        + inventory_insert.excluded.query_count
                    ),
                    "first_seen": func.least(
                        DomainInventory.first_seen,
                        inventory_insert.excluded.first_seen,
                    ),
                    "last_seen": func.greatest(
                        DomainInventory.last_seen,
                        inventory_insert.excluded.last_seen,
                    ),
                    "updated_at": datetime.now(UTC),
                },
            )
            await session.execute(inventory_upsert)

            inventory = (
                await session.execute(
                    select(DomainInventory)
                    .where(DomainInventory.normalized_domain == domain_name)
                    .with_for_update()
                )
            ).scalar_one()

            existing_clients = [
                str(client_ip) for client_ip in (inventory.client_ips or [])
            ]
            merged_clients = list(dict.fromkeys([*existing_clients, *clients]))
            inventory.client_ips = merged_clients
            inventory.unique_clients = len(merged_clients)
            inventory.updated_at = datetime.now(UTC)

        if new_events:
            await session.commit()

    except Exception:
        await session.rollback()
        raise

    dns_events_duplicates_total.inc(duplicates)

    for event in new_events:
        dns_events_total.labels(
            query_type=event["query_type"],
            response_code=event["response_code"],
        ).inc()

    return inserted, duplicates


class DnsCollector:
    """Poll Pi-hole and ingest new DNS events."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.client = PiholeClient(
            base_url=self.settings.pihole.api_base_url,
            password=self.settings.pihole.effective_password,
            timeout=self.settings.pihole.timeout,
        )
        self._last_timestamp = 0.0
        self._running = False

    async def poll_and_ingest(self) -> tuple[int, int]:
        """Fetch and persist one query-log batch."""
        last_timestamp = (
            datetime.fromtimestamp(self._last_timestamp, tz=UTC)
            if self._last_timestamp
            else datetime.now(UTC)
            - timedelta(hours=self.settings.pihole.initial_lookback_hours)
        )

        try:
            entries = await self.client.get_query_log(
                from_time=last_timestamp,
                limit=self.settings.pihole.query_limit,
            )
        except (httpx.HTTPError, ValueError) as exc:
            logger.error("pihole_query_fetch_failed", error=str(exc))
            return 0, 0

        normalized: list[JsonDict] = []
        latest_timestamp = self._last_timestamp

        for entry in entries:
            event = normalize_query_log_entry(entry)
            if event is None:
                continue

            normalized.append(event)
            latest_timestamp = max(
                latest_timestamp,
                event["created_at"].timestamp(),
            )

        if not normalized:
            return 0, 0

        async with async_session_factory() as session:
            inserted, duplicates = await ingest_events(session, normalized)

        self._last_timestamp = latest_timestamp

        logger.info(
            "poll_complete",
            fetched=len(entries),
            normalized=len(normalized),
            inserted=inserted,
            duplicates=duplicates,
        )
        return inserted, duplicates

    async def run(self) -> None:
        """Run the polling loop."""
        self._running = True
        logger.info(
            "collector_started",
            interval=self.settings.pihole.poll_interval,
            api_url=self.settings.pihole.api_base_url,
        )

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
        await init_db()
        collector = DnsCollector()

        try:
            if once:
                await collector.poll_and_ingest()
                return

            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(
                    sig,
                    lambda: asyncio.create_task(collector.stop()),
                )

            await collector.run()
        finally:
            await close_db()

    asyncio.run(run_collector())


if __name__ == "__main__":
    main()
