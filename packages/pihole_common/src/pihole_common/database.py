"""Async SQLAlchemy database engine and session factory."""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from pihole_common.config import get_settings


class Base(DeclarativeBase):
    """Base class for all ORM models."""


_engine = create_async_engine(
    get_settings().database.url,
    pool_size=get_settings().database.pool_size,
    max_overflow=get_settings().database.max_overflow,
    pool_timeout=get_settings().database.pool_timeout,
    pool_recycle=get_settings().database.pool_recycle,
    echo=get_settings().database.echo,
)

async_session_factory = async_sessionmaker(
    _engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for FastAPI: yield an async database session."""
    async with async_session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Create all tables. Use during application startup."""
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Dispose of the engine. Use during application shutdown."""
    await _engine.dispose()
