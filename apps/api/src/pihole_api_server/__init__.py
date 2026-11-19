"""FastAPI application for pihole-ai assessments and approvals."""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pihole_common.database import (
    async_session_factory,
    close_db,
    init_db,
)
from pihole_common.telemetry import (
    api_request_duration_seconds,
    api_requests_total,
    measure_duration,
    set_app_info,
)
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from pihole_api_server.routes import API_VERSION, router

__version__ = API_VERSION
logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Initialize and dispose of the shared database engine."""
    await init_db()
    try:
        yield
    finally:
        await close_db()


def _cors_origins() -> list[str]:
    """Read configured CORS origins."""
    value = os.getenv("CORS_ORIGINS", "")
    origins = [origin.strip() for origin in value.split(",") if origin.strip()]
    return origins or ["*"]


def create_app() -> FastAPI:
    """Create the API application."""
    app = FastAPI(
        title="pihole-ai API",
        version=API_VERSION,
        description=("Threat assessments, operator approvals, and audit history."),
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def request_middleware(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Attach request IDs and record request metrics."""
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        endpoint = request.url.path
        method = request.method

        with measure_duration(
            api_request_duration_seconds,
            endpoint=endpoint,
            method=method,
        ):
            try:
                response = await call_next(request)
            except Exception:
                api_requests_total.labels(
                    endpoint=endpoint,
                    method=method,
                    status_code="500",
                ).inc()
                logger.exception(
                    "api_request_failed",
                    request_id=request_id,
                    method=method,
                    endpoint=endpoint,
                )
                raise

        api_requests_total.labels(
            endpoint=endpoint,
            method=method,
            status_code=str(response.status_code),
        ).inc()
        response.headers["X-Request-ID"] = request_id
        return response

    @app.get("/livez", tags=["system"])
    async def liveness() -> dict[str, str]:
        """Process-only liveness check; deliberately does not touch DB."""
        return {"status": "ok"}

    @app.get("/readyz", tags=["system"])
    async def readiness() -> Response:
        """Readiness check that verifies PostgreSQL connectivity."""
        try:
            async with async_session_factory() as session:
                await session.execute(select(1))
        except SQLAlchemyError:
            return Response(
                content='{"status":"degraded","db_connected":false}',
                status_code=503,
                media_type="application/json",
            )

        return Response(
            content='{"status":"ok","db_connected":true}',
            status_code=200,
            media_type="application/json",
        )

    set_app_info("pihole-ai-api", API_VERSION)
    app.include_router(router)
    return app


__all__ = ["__version__", "create_app"]
