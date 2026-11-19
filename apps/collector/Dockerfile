FROM python:3.12-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock ./
COPY packages/ packages/
COPY apps/ apps/
RUN uv sync --frozen

FROM python:3.12-slim AS runtime
WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/packages /app/packages
COPY --from=builder /app/apps /app/apps
# Alembic files must be in the runtime image for the migration Job.
COPY alembic.ini /app/alembic.ini
COPY migrations/ /app/migrations/
RUN groupadd --gid 10001 appuser && useradd --uid 10001 --gid 10001 --create-home appuser
USER 10001:10001
ENV PATH="/app/.venv/bin:$PATH"
ENTRYPOINT ["python", "-m", "pihole_collector"]
