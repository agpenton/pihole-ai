"""Command-line entry point for the standalone LLM assessment utility."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import click
from pihole_common.config import get_settings
from pihole_common.database import close_db, init_db
from pihole_common.telemetry import set_app_info, start_metrics_server

from pihole_llm_gateway.service import LlmGateway


@click.command()
@click.option("--domain", "-d", required=True, help="Domain to assess")
@click.option("--context-json", "-c", default=None, help="Optional JSON context")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
def main(
    domain: str,
    context_json: str | None,
    verbose: bool = False,
) -> None:
    """Run one LLM assessment."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    settings = get_settings()
    set_app_info("pihole-llm-gateway")

    if settings.telemetry.metrics_enabled:
        start_metrics_server()

    context: dict[str, Any] = {}
    if context_json:
        try:
            parsed = json.loads(context_json)
        except json.JSONDecodeError as exc:
            raise click.BadParameter("context-json must be valid JSON") from exc

        if not isinstance(parsed, dict):
            raise click.BadParameter("context-json must contain a JSON object")
        context = parsed

    async def run() -> None:
        await init_db()
        try:
            result = await LlmGateway().assess(domain, context)
            click.echo(json.dumps(result, indent=2))
        finally:
            await close_db()

    asyncio.run(run())


if __name__ == "__main__":
    main()
