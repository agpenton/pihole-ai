"""Alembic environment for pihole-ai PostgreSQL migrations."""

from __future__ import annotations

from alembic import context
from sqlalchemy import engine_from_config, pool

# Import the model module so every table is registered on Base.metadata.
from pihole_common import models  # noqa: F401
from pihole_common.config import get_settings
from pihole_common.database import Base

target_metadata = Base.metadata


def get_url() -> str:
    """Return the synchronous psycopg URL assembled from DB_* settings."""
    return get_settings().database.sync_url


def run_migrations_offline() -> None:
    """Run migrations without creating a DBAPI connection."""
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations using a short-lived synchronous connection."""
    connectable = engine_from_config(
        {"sqlalchemy.url": get_url()},
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    try:
        with connectable.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                compare_type=True,
            )
            with context.begin_transaction():
                context.run_migrations()
    finally:
        connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
