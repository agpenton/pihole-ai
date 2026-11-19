"""Focused tests for OpenRouter client success and failure paths."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from importlib import import_module
from typing import Any, Self, cast
from unittest.mock import patch

import httpx  # type: ignore[import-not-found]
import pytest  # type: ignore[import-not-found]

client_module = import_module("pihole_llm_gateway.client")
OpenRouterClient = cast(Any, client_module.OpenRouterClient)


class FakeResponse:
    """Small response fake covering the methods used by the client."""

    def __init__(self, payload: dict[str, Any], error: Exception | None = None) -> None:
        self.payload = payload
        self.error = error

    def raise_for_status(self) -> None:
        """Raise the configured transport/API error, if any."""
        if self.error is not None:
            raise self.error

    def json(self) -> dict[str, Any]:
        """Return the configured JSON payload."""
        return self.payload


class FakeAsyncClient:
    """AsyncClient replacement that records request details."""

    response: FakeResponse
    instances: list[FakeAsyncClient]

    def __init__(self, *, timeout: float) -> None:
        self.timeout = timeout
        self.requests: list[dict[str, Any]] = []
        FakeAsyncClient.instances.append(self)

    async def __aenter__(self) -> Self:
        """Enter the fake HTTP client context."""
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        """Exit the fake HTTP client context."""

    async def post(self, url: str, *, json: dict[str, Any], headers: dict[str, str]) -> FakeResponse:
        """Record a request and return the configured response."""
        self.requests.append({"url": url, "json": json, "headers": headers})
        return self.response


def run_query(
    query: Callable[[str, dict[str, Any]], Coroutine[Any, Any, str]],
    domain: str = "example.com",
) -> str:
    """Run a query from a synchronous test while preserving async behavior."""
    return asyncio.run(query(domain, {"tld": ".com", "score": 0.3}))


def test_query_posts_expected_request_and_returns_assistant_content() -> None:
    """A successful response uses the configured endpoint, auth, model, and prompt."""
    FakeAsyncClient.instances = []
    FakeAsyncClient.response = FakeResponse({"choices": [{"message": {"content": '{"is_malicious": false}'}}]})
    client = OpenRouterClient(
        "secret",
        model="test-model",
        base_url="https://router.test/api/v1/",
        timeout=7.5,
    )

    with patch.object(client_module.httpx, "AsyncClient", FakeAsyncClient):
        result = run_query(client.query)

    assert result == '{"is_malicious": false}'
    request = FakeAsyncClient.instances[0].requests[0]
    assert request["url"] == "https://router.test/api/v1/chat/completions"
    assert request["headers"] == {
        "Authorization": "Bearer secret",
        "Content-Type": "application/json",
    }
    assert request["json"]["model"] == "test-model"
    assert request["json"]["messages"][0]["role"] == "user"
    assert "Domain: example.com" in request["json"]["messages"][0]["content"]
    assert "tld=.com" in request["json"]["messages"][0]["content"]
    assert FakeAsyncClient.instances[0].timeout == 7.5


def test_query_propagates_http_errors() -> None:
    """HTTP status failures are not hidden from callers."""
    request = httpx.Request("POST", "https://router.test/chat/completions")
    response = httpx.Response(503, request=request)
    FakeAsyncClient.instances = []
    FakeAsyncClient.response = FakeResponse(
        {}, httpx.HTTPStatusError("service unavailable", request=request, response=response)
    )
    client = OpenRouterClient("secret")

    with (
        patch.object(client_module.httpx, "AsyncClient", FakeAsyncClient),
        pytest.raises(httpx.HTTPStatusError, match="service unavailable"),
    ):
        run_query(client.query)


def test_query_rejects_empty_choices() -> None:
    """A response without choices is treated as an invalid upstream response."""
    FakeAsyncClient.instances = []
    FakeAsyncClient.response = FakeResponse({"choices": []})
    client = OpenRouterClient("secret")

    with (
        patch.object(client_module.httpx, "AsyncClient", FakeAsyncClient),
        pytest.raises(ValueError, match="Empty response from OpenRouter"),
    ):
        run_query(client.query)


def test_query_rejects_missing_message_content() -> None:
    """A choice without assistant content is rejected rather than returning an empty string."""
    FakeAsyncClient.instances = []
    FakeAsyncClient.response = FakeResponse({"choices": [{"message": {}}]})
    client = OpenRouterClient("secret")

    with (
        patch.object(client_module.httpx, "AsyncClient", FakeAsyncClient),
        pytest.raises(ValueError, match="No content in OpenRouter response"),
    ):
        run_query(client.query)


def test_query_rejects_choice_without_message() -> None:
    """Malformed choices fail with the same actionable missing-content error."""
    FakeAsyncClient.instances = []
    FakeAsyncClient.response = FakeResponse({"choices": [{}]})
    client = OpenRouterClient("secret")

    with (
        patch.object(client_module.httpx, "AsyncClient", FakeAsyncClient),
        pytest.raises(ValueError, match="No content in OpenRouter response"),
    ):
        run_query(client.query)
