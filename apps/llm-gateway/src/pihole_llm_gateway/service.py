"""Reusable LLM assessment service."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx
from pihole_common.config import get_settings
from pihole_common.database import async_session_factory
from pihole_common.telemetry import (
    circuit_breaker_state,
    llm_cache_hits_total,
    llm_cache_misses_total,
    llm_quota_remaining,
    llm_request_duration_seconds,
    llm_requests_total,
    measure_duration,
)

from pihole_llm_gateway.cache import ResponseCache, _compute_hash
from pihole_llm_gateway.circuit_breaker import CircuitBreaker, CircuitBreakerOpen
from pihole_llm_gateway.client import OpenRouterClient
from pihole_llm_gateway.quota import QuotaManager
from pihole_llm_gateway.validator import ResponseValidator

logger = logging.getLogger(__name__)


class LlmGateway:
    """Assess domains using OpenRouter with cache, quota and circuit breaker."""

    def __init__(self) -> None:
        self.settings = get_settings()

        self.client = OpenRouterClient(
            api_key=self.settings.llm.api_key,
            model=self.settings.llm.model,
            base_url=self.settings.llm.base_url,
            timeout=self.settings.llm.timeout,
            max_output_tokens=self.settings.llm.max_output_tokens,
        )
        self.quota = QuotaManager(
            async_session_factory,
            daily_limit=self.settings.llm.daily_quota,
        )
        self.cache = ResponseCache(async_session_factory)
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=self.settings.llm.circuit_breaker_threshold,
            recovery_timeout=self.settings.llm.circuit_breaker_timeout,
        )
        self.validator = ResponseValidator()
        self._semaphore = asyncio.Semaphore(
            max(1, self.settings.llm.max_concurrent_requests)
        )

    async def assess(
        self,
        domain: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, object]:
        """Return a validated assessment for a domain."""
        context = context or {}

        if not self.settings.llm.api_key:
            raise RuntimeError("LLM_API_KEY is not configured")

        prompt = self.client._build_prompt(domain, context)
        query_hash = _compute_hash(domain, prompt, self.client.model)

        cached = await self.cache.get(query_hash)
        if cached is not None:
            llm_cache_hits_total.inc()
            return self.validator.validate(cached)

        llm_cache_misses_total.inc()

        async with self._semaphore:
            if not await self.quota.can_make_request():
                raise RuntimeError("Daily LLM quota exhausted")

            attempts = max(1, self.settings.llm.max_retries + 1)
            last_error: Exception | None = None

            for attempt in range(attempts):
                try:
                    with measure_duration(
                        llm_request_duration_seconds,
                        status="success",
                    ):
                        raw_response = await self.circuit_breaker.call(
                            self.client.query,
                            domain,
                            context,
                        )

                    validated = self.validator.validate(raw_response)

                    await self.cache.set(
                        domain,
                        prompt,
                        raw_response,
                        self.client.model,
                        ttl_hours=self.settings.llm.cache_ttl_hours,
                    )
                    await self.quota.record_request()

                    llm_requests_total.labels(
                        status="success",
                        model=self.client.model,
                    ).inc()
                    circuit_breaker_state.labels(service="llm-gateway").set(
                        self.circuit_breaker.state
                    )
                    llm_quota_remaining.set(max(0, self.settings.llm.daily_quota - 1))

                    logger.info(
                        "llm_assessment_complete",
                        extra={
                            "domain": domain,
                            "is_malicious": validated["is_malicious"],
                            "confidence": validated["confidence"],
                        },
                    )
                    return validated

                except CircuitBreakerOpen:
                    llm_requests_total.labels(
                        status="circuit_open",
                        model=self.client.model,
                    ).inc()
                    raise

                except (httpx.HTTPError, ValueError, TypeError) as exc:
                    last_error = exc
                    logger.warning(
                        "llm_assessment_attempt_failed",
                        extra={
                            "domain": domain,
                            "attempt": attempt + 1,
                            "attempts": attempts,
                            "error": str(exc),
                        },
                    )
                    if attempt + 1 < attempts:
                        await asyncio.sleep(
                            self.settings.llm.retry_backoff * (2**attempt)
                        )

            llm_requests_total.labels(
                status="error",
                model=self.client.model,
            ).inc()
            raise RuntimeError(
                f"LLM assessment failed after {attempts} attempts"
            ) from last_error
