"""Run the pihole-ai API server with Uvicorn."""

from __future__ import annotations

import os

import uvicorn

from pihole_api_server import create_app


def main() -> None:
    """Start the API server."""
    host = os.getenv("API_HOST", "0.0.0.0")
    port = int(os.getenv("API_PORT", "8000"))
    log_level = os.getenv("API_LOG_LEVEL", "info").lower()
    uvicorn.run(create_app(), host=host, port=port, log_level=log_level)


if __name__ == "__main__":
    main()
