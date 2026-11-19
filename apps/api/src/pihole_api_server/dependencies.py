"""FastAPI dependencies shared by API routes."""

from __future__ import annotations

import hmac
import os
from collections import defaultdict, deque
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from pihole_common.config import Settings
from pihole_common.config import get_settings as load_settings
from pihole_common.database import get_db_session as shared_db_session
from sqlalchemy.ext.asyncio import AsyncSession

from pihole_api_server.pihole_client import PiholeClient


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield a shared async database session."""
    async for session in shared_db_session():
        yield session


def get_settings() -> Settings:
    """Return the cached application settings."""
    return load_settings()


def get_pihole_client(settings: Annotated[Settings, Depends(get_settings)]) -> PiholeClient:
    """Build the Pi-hole client used by block-application routes."""
    return PiholeClient(
        base_url=settings.pihole.url,
        api_token=settings.pihole.api_token,
        timeout=settings.pihole.timeout,
    )


def _configured_api_key() -> str | None:
    """Read the optional API key without requiring a shared-config change."""
    return os.getenv("PIHOLE_API_KEY") or os.getenv("API_KEY")


async def require_api_key(
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> None:
    """Validate the API key when one is configured.

    Local development remains backwards-compatible when neither supported
    environment variable is set. Deployments that set a key must provide the
    matching ``X-API-Key`` header.
    """
    expected = _configured_api_key()
    if expected is None:
        return
    if x_api_key is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key required")
    if not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid API key")


async def get_current_user(
    x_user: Annotated[str | None, Header(alias="X-User")] = None,
    _: Annotated[None, Depends(require_api_key)] = None,
) -> str:
    """Return the operator identity used for audit records.

    JWT validation is intentionally not enabled until JWT settings are added to
    the shared configuration package. A trusted ``X-User`` value is useful for
    local and internal deployments; production deployments should place this
    service behind an authenticated gateway.
    """
    return x_user.strip() if x_user and x_user.strip() else "api"


class SlidingWindowRateLimiter:
    """Small in-process sliding-window limiter for one API process."""

    def __init__(self, limit: int = 120, window: timedelta = timedelta(minutes=1)) -> None:
        self.limit = limit
        self.window = window
        self._requests: dict[str, deque[datetime]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        """Record a request and return whether it is within the configured limit."""
        now = datetime.now(UTC)
        requests = self._requests[key]
        cutoff = now - self.window
        while requests and requests[0] <= cutoff:
            requests.popleft()
        if len(requests) >= self.limit:
            return False
        requests.append(now)
        return True


_rate_limiter = SlidingWindowRateLimiter()


async def rate_limit(
    x_forwarded_for: Annotated[str | None, Header()] = None,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> None:
    """Apply a modest per-client in-process request limit."""
    client_key = x_forwarded_for or x_api_key or "anonymous"
    if not _rate_limiter.allow(client_key):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")


DbSession = Annotated[AsyncSession, Depends(get_db_session)]
CurrentUser = Annotated[str, Depends(get_current_user)]
Protected = Annotated[None, Depends(require_api_key)]
RateLimited = Annotated[None, Depends(rate_limit)]
Pihole = Annotated[PiholeClient, Depends(get_pihole_client)]
