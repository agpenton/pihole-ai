"""Security analyzer entry point."""

from __future__ import annotations

import asyncio
import json
import logging
import signal
from typing import Any

import click
import structlog
from pihole_common.config import get_settings
from pihole_common.database import async_session_factory, close_db, init_db
from pihole_common.models import DomainAssessment, DomainInventory
from pihole_common.telemetry import (
    analyzer_assessments_total,
    analyzer_suspicious_domains_total,
    set_app_info,
    start_metrics_server,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pihole_analyzer.checkers import ThreatChecker
from pihole_analyzer.enrichment import EnrichmentService
from pihole_analyzer.scheduler import DomainScheduler
from pihole_analyzer.threat_feeds import (
    ThreatFeedRefresher,
    load_feed_configs,
    refresh_threat_intelligence,
)
from pihole_llm_gateway.service import LlmGateway

logger = structlog.get_logger()


async def save_assessment(
        session: AsyncSession,
        domain: DomainInventory,
        enrichment: dict[str, Any],
        *,
        status: str = "pending",
        llm_response: dict[str, Any] | None = None,
) -> DomainAssessment:
    """Create or update the active assessment for a domain.

    The partial unique index added by migration 0002 permits only one
    pending/failed assessment per domain. Reusing the active row avoids
    repeated inserts and preserves a stable assessment ID across retries.
    """
    if status not in {"pending", "failed"}:
        raise ValueError(f"Unsupported analyzer assessment status: {status}")

    result = await session.execute(
        select(DomainAssessment)
        .where(
            DomainAssessment.domain_id == domain.id,
            DomainAssessment.status.in_(("pending", "failed")),
            )
        .order_by(DomainAssessment.updated_at.desc(), DomainAssessment.id.desc())
        .with_for_update()
    )
    assessment = result.scalars().first()

    evidence = dict(enrichment.get("evidence") or {})
    if llm_response is not None:
        evidence["llm_assessment"] = llm_response

    if assessment is None:
        assessment = DomainAssessment(
            domain_id=domain.id,
            suspicion_score=float(enrichment["suspicion_score"]),
            threat_categories=list(enrichment.get("threat_categories") or []),
            evidence=evidence,
            status=status,
            llm_response=(
                json.dumps(llm_response, ensure_ascii=False)
                if llm_response is not None
                else None
            ),
        )
        session.add(assessment)
    else:
        assessment.suspicion_score = float(enrichment["suspicion_score"])
        assessment.threat_categories = list(
            enrichment.get("threat_categories") or []
        )
        assessment.evidence = evidence
        assessment.status = status
        assessment.llm_response = (
            json.dumps(llm_response, ensure_ascii=False)
            if llm_response is not None
            else None
        )

    await session.commit()
    await session.refresh(assessment)
    return assessment


class Analyzer:
    """Run deterministic threat checks and optional LLM enrichment."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.scheduler = DomainScheduler()
        self.checker = ThreatChecker()
        self.enricher = EnrichmentService()
        self.llm_gateway = LlmGateway()
        self.feed_refresher = ThreatFeedRefresher(load_feed_configs())
        self._running = False

    async def analyze_domain(
            self,
            session: AsyncSession,
            domain: DomainInventory,
    ) -> bool:
        """Analyze one domain and persist either pending or failed status."""
        domain_name = domain.normalized_domain

        try:
            threat_matches = await self.checker.check_domain(domain_name)
            enrichment = self.enricher.enrich_assessment(
                domain_name,
                threat_matches,
            )

            llm_result: dict[str, Any] | None = None
            status = "pending"

            if enrichment.get("needs_llm"):
                context = {
                    "suspicion_score": enrichment["suspicion_score"],
                    "threat_categories": enrichment.get("threat_categories", []),
                    "evidence": enrichment.get("evidence", {}),
                    "query_count": domain.query_count,
                    "unique_clients": domain.unique_clients,
                    "first_seen": domain.first_seen.isoformat(),
                    "last_seen": domain.last_seen.isoformat(),
                }

                try:
                    raw_result = await self.llm_gateway.assess(
                        domain_name,
                        context,
                    )
                    llm_result = dict(raw_result)

                    # The LLM can increase the risk score, but cannot lower
                    # deterministic evidence or change the approval workflow.
                    if llm_result.get("is_malicious") is True:
                        confidence = float(llm_result["confidence"])
                        enrichment["suspicion_score"] = max(
                            float(enrichment["suspicion_score"]),
                            confidence,
                        )
                        categories = list(
                            enrichment.get("threat_categories") or []
                        )
                        if "llm:malicious" not in categories:
                            categories.append("llm:malicious")
                        enrichment["threat_categories"] = categories
                    else:
                        categories = list(
                            enrichment.get("threat_categories") or []
                        )
                        if "llm:not_malicious" not in categories:
                            categories.append("llm:not_malicious")
                        enrichment["threat_categories"] = categories

                except Exception as exc:
                    # Keep the failure visible and retryable. Never convert
                    # an LLM outage into a successful assessment.
                    status = "failed"
                    evidence = dict(enrichment.get("evidence") or {})
                    evidence["llm_error"] = {
                        "type": type(exc).__name__,
                        "message": str(exc)[:1000],
                    }
                    enrichment["evidence"] = evidence

                    logger.warning(
                        "llm_assessment_failed",
                        domain=domain_name,
                        error_type=type(exc).__name__,
                        error=str(exc),
                    )

            assessment = await save_assessment(
                session,
                domain,
                enrichment,
                status=status,
                llm_response=llm_result,
            )

            analyzer_assessments_total.labels(status=assessment.status).inc()

            if (
                    float(enrichment["suspicion_score"])
                    >= self.settings.analyzer.min_suspicion_score
            ):
                analyzer_suspicious_domains_total.inc()

            logger.info(
                "assessment_saved",
                domain=domain_name,
                assessment_id=assessment.id,
                score=enrichment["suspicion_score"],
                needs_llm=enrichment.get("needs_llm", False),
                llm_status=(
                    "completed"
                    if llm_result is not None
                    else "failed" if status == "failed"
                    else "not_required"
                ),
                assessment_status=assessment.status,
            )
            return True

        except Exception:
            await session.rollback()
            logger.exception(
                "domain_analysis_failed",
                domain=domain_name,
            )
            return False

    async def run_cycle(self) -> int:
        """Refresh feeds and process eligible domains."""
        feed_results = await self.feed_refresher.refresh()

        for result in feed_results:
            if result.error:
                logger.warning(
                    "threat_feed_refresh_failed",
                    source=result.source,
                    error=result.error,
                )
            else:
                logger.info(
                    "threat_feed_refreshed",
                    source=result.source,
                    fetched=result.fetched,
                    activated=result.activated,
                    deactivated=result.deactivated,
                )

        pending = await self.scheduler.get_pending_domains(limit=100)
        if not pending:
            logger.info("no_pending_domains")
            return 0

        processed = 0
        async with async_session_factory() as session:
            for domain in pending:
                if await self.analyze_domain(session, domain):
                    processed += 1

        logger.info("cycle_complete", processed=processed)
        return processed

    async def run(self) -> None:
        """Run the periodic analyzer loop."""
        self._running = True
        logger.info("analyzer_started")

        while self._running:
            try:
                await self.run_cycle()
            except Exception:
                logger.exception("analysis_cycle_failed")

            await asyncio.sleep(300)

    async def stop(self) -> None:
        """Stop the analyzer loop."""
        self._running = False
        logger.info("analyzer_stopped")


@click.command()
@click.option("--once", is_flag=True, help="Run one cycle and exit")
@click.option(
    "--refresh-feeds",
    is_flag=True,
    help="Refresh threat feeds and exit",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
def main(
        once: bool = False,
        refresh_feeds: bool = False,
        verbose: bool = False,
) -> None:
    """Run the Pi-hole AI security analyzer."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    settings = get_settings()
    set_app_info("pihole-security-analyzer")

    if settings.telemetry.metrics_enabled:
        start_metrics_server()

    async def run_analyzer() -> None:
        await init_db()
        try:
            analyzer = Analyzer()

            if refresh_feeds:
                results = await refresh_threat_intelligence()
                for result in results:
                    if result.error:
                        logger.warning(
                            "threat_feed_refresh_failed",
                            source=result.source,
                            error=result.error,
                        )
                    else:
                        logger.info(
                            "threat_feed_refreshed",
                            source=result.source,
                            fetched=result.fetched,
                            activated=result.activated,
                            deactivated=result.deactivated,
                        )
            elif once:
                await analyzer.run_cycle()
            else:
                loop = asyncio.get_running_loop()
                for sig in (signal.SIGINT, signal.SIGTERM):
                    loop.add_signal_handler(
                        sig,
                        lambda: asyncio.create_task(analyzer.stop()),
                    )
                await analyzer.run()
        finally:
            await close_db()

    asyncio.run(run_analyzer())


if __name__ == "__main__":
    main()