"""Prometheus metrics and structured logging for pihole-ai applications."""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from contextlib import contextmanager
from functools import wraps
from typing import Any, ParamSpec, TypeVar

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    Info,
    generate_latest,
    start_http_server,
)
from structlog import get_logger

from pihole_common.config import get_settings

logger = get_logger()

_P = ParamSpec("_P")
_R = TypeVar("_R")

# ---------------------------------------------------------------------------
# Application info
# ---------------------------------------------------------------------------

_app_info = Info(
    "app",
    "Application metadata",
    namespace="",
)


def set_app_info(service_name: str, version: str = "0.1.0") -> None:
    """Set application info metrics."""
    _app_info.info({"name": service_name, "version": version})


# ---------------------------------------------------------------------------
# DNS Event counters
# ---------------------------------------------------------------------------

dns_events_total = Counter(
    "pihole_dns_events_total",
    "Total DNS events ingested",
    ["query_type", "response_code"],
)

dns_events_duplicates_total = Counter(
    "pihole_dns_events_duplicates_total",
    "Total duplicate DNS events discarded",
)

# ---------------------------------------------------------------------------
# Analyzer metrics
# ---------------------------------------------------------------------------

analyzer_assessments_total = Counter(
    "pihole_analyzer_assessments_total",
    "Total assessments produced",
    ["status"],
)

analyzer_suspicious_domains_total = Counter(
    "pihole_analyzer_suspicious_domains_total",
    "Total suspicious domains flagged",
)

# ---------------------------------------------------------------------------
# LLM Gateway metrics
# ---------------------------------------------------------------------------

llm_requests_total = Counter(
    "pihole_llm_requests_total",
    "Total LLM API requests",
    ["status", "model"],
)

llm_request_duration_seconds = Histogram(
    "pihole_llm_request_duration_seconds",
    "LLM API request duration",
    ["status"],
    buckets=[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0],
)

llm_cache_hits_total = Counter(
    "pihole_llm_cache_hits_total",
    "Total LLM cache hits",
)

llm_cache_misses_total = Counter(
    "pihole_llm_cache_misses_total",
    "Total LLM cache misses",
)

llm_quota_remaining = Gauge(
    "pihole_llm_quota_remaining",
    "Remaining LLM requests in daily quota",
)

circuit_breaker_state = Gauge(
    "pihole_llm_circuit_breaker_state",
    "Circuit breaker state (0=closed, 1=open, 2=half-open)",
    ["service"],
)

# ---------------------------------------------------------------------------
# API Server metrics
# ---------------------------------------------------------------------------

api_requests_total = Counter(
    "pihole_api_requests_total",
    "Total API requests",
    ["endpoint", "method", "status_code"],
)

api_request_duration_seconds = Histogram(
    "pihole_api_request_duration_seconds",
    "API request duration",
    ["endpoint", "method"],
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

# ---------------------------------------------------------------------------
# Database metrics
# ---------------------------------------------------------------------------

db_connections_in_use = Gauge(
    "pihole_db_connections_in_use",
    "Number of database connections currently in use",
)

db_query_duration_seconds = Histogram(
    "pihole_db_query_duration_seconds",
    "Database query duration",
    ["operation"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def start_metrics_server(port: int | None = None) -> None:
    """Start the Prometheus metrics HTTP server.

    Args:
        port: Port to serve metrics on. Defaults to settings value.
    """
    settings = get_settings()
    if not port:
        port = settings.telemetry.metrics_port
    start_http_server(port)
    logger.info("metrics_server_started", port=port)


@contextmanager
def measure_duration(metric: Histogram, **labels: Any) -> Any:
    """Context manager to record a histogram duration.

    Args:
        metric: The histogram to record against.
        **labels: Label values to apply.

    Yields:
        A timer object.
    """
    start = time.monotonic()
    try:
        yield
    finally:
        elapsed = time.monotonic() - start
        metric.labels(**labels).observe(elapsed)


def metrics_endpoint() -> tuple[bytes, str]:
    """Return the Prometheus metrics payload.

    Returns:
        Tuple of (metrics bytes, content type).
    """
    return generate_latest(), CONTENT_TYPE_LATEST


def with_metrics(
    endpoint: str, method: str = "GET"
) -> Callable[[Callable[_P, Awaitable[_R]]], Callable[_P, Awaitable[_R]]]:
    """Decorator to wrap a FastAPI endpoint with metrics recording.

    Args:
        endpoint: The endpoint path for labeling.
        method: The HTTP method.

    Returns:
        Decorated function.
    """

    def decorator(func: Callable[_P, Awaitable[_R]]) -> Callable[_P, Awaitable[_R]]:
        @wraps(func)
        async def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _R:
            with measure_duration(api_request_duration_seconds, endpoint=endpoint, method=method):
                try:
                    result = await func(*args, **kwargs)
                    api_requests_total.labels(endpoint=endpoint, method=method, status_code=200).inc()
                    return result
                except Exception:
                    api_requests_total.labels(endpoint=endpoint, method=method, status_code=500).inc()
                    raise

        return wrapper

    return decorator
