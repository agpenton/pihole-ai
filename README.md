# pihole-ai

AI-powered DNS security analysis for Pi-hole.

## Architecture

```
Pi-hole ──► DNS Collector ──► PostgreSQL
                            │
                            ▼
                      Security Analyzer ──► LLM Gateway (OpenRouter)
                            │
                            ▼
                       API Server ──► Human Approval
```

## Applications

- **DNS Collector** — Polls Pi-hole v6 API, normalizes/deduplicates DNS events, stores in PostgreSQL
- **Security Analyzer** — Deterministic threat assessment, enrichment, selects suspicious domains for LLM
- **LLM Gateway** — OpenRouter free inference, 40-request daily budget, caching, circuit breaker
- **API Server** — FastAPI endpoints for assessments, approvals, audit history

## Getting Started

### Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager
- PostgreSQL 17+

### Installation

```bash
# Install uv if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies
uv sync

# Set up the database
alembic upgrade head
```

### Run Individual Applications

```bash
# DNS Collector
uv run -m pihole_collector

# Security Analyzer
uv run -m pihole_analyzer

# LLM Gateway
uv run -m pihole_llm_gateway

# API Server
uv run -m pihole_api_server
```

## Development

```bash
# Run linter
uv run ruff check .

# Run type checker
uv run mypy .

# Run tests
uv run pytest
```

## Docker

```bash
# Build all images
docker buildx bake --push

# Build a single image
docker buildx bake --push collector
```
