"""Async SQLAlchemy engine and session factory.

Database schema lifecycle is owned by Alembic migrations. Application startup
only verifies connectivity; it must never create or mutate tables implicitly.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from pihole_common.config import get_settings


class Base(DeclarativeBase):
    """Base class for all ORM models."""


_settings = get_settings()
_engine = create_async_engine(
    _settings.database.url,
    pool_size=_settings.database.pool_size,
    max_overflow=_settings.database.max_overflow,
    pool_timeout=_settings.database.pool_timeout,
    pool_recycle=_settings.database.pool_recycle,
    echo=_settings.database.echo,
)

async_session_factory = async_sessionmaker(
    _engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async database session for application dependencies."""
    async with async_session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Verify database connectivity; schema changes are exclusively Alembic-managed.

    Kept under the existing function name to avoid breaking application startup
    imports. This function deliberately does not call ``Base.metadata.create_all``.
    """
    async with _engine.connect() as connection:
        await connection.execute(text("SELECT 1"))


async def close_db() -> None:
    """Dispose of the async engine during application shutdown."""
    await _engine.dispose()
