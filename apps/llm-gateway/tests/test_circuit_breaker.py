"""Focused tests for circuit-breaker transitions and failure handling."""

from __future__ import annotations

import asyncio
import time

from pihole_llm_gateway.circuit_breaker import CircuitBreaker, CircuitBreakerOpen


def test_successful_async_call_returns_result_and_keeps_circuit_closed() -> None:
    """A successful call returns its value and clears prior failure state."""
    breaker = CircuitBreaker(failure_threshold=2)

    async def succeed(value: str) -> str:
        return value

    assert asyncio.run(breaker.call(succeed, "ok")) == "ok"
    assert breaker.state == 0


def test_threshold_failures_open_circuit_and_block_following_calls() -> None:
    """The threshold failure opens the circuit and prevents the next call."""
    breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=30)
    calls = 0

    async def fail() -> None:
        nonlocal calls
        calls += 1
        raise RuntimeError("upstream unavailable")

    for _ in range(2):
        try:
            asyncio.run(breaker.call(fail))
        except RuntimeError:
            pass

    assert breaker.state == 1
    assert calls == 2

    try:
        asyncio.run(breaker.call(fail))
    except CircuitBreakerOpen as exc:
        assert exc.recovery_timeout == 30
    else:
        raise AssertionError("an open circuit must reject calls")

    assert calls == 2


def test_recovery_timeout_transitions_to_half_open_and_success_closes_circuit() -> None:
    """After recovery, one successful probe closes the circuit and clears failures."""
    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=1)

    async def fail() -> None:
        raise RuntimeError("failure")

    try:
        asyncio.run(breaker.call(fail))
    except RuntimeError:
        pass

    breaker._opened_at = time.monotonic() - breaker.recovery_timeout
    assert breaker.state == 2

    async def recover() -> str:
        return "recovered"

    assert asyncio.run(breaker.call(recover)) == "recovered"
    assert breaker.state == 0


def test_half_open_probe_failure_reopens_circuit() -> None:
    """A failed recovery probe keeps the circuit open."""
    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=1)

    async def fail() -> None:
        raise RuntimeError("failure")

    try:
        asyncio.run(breaker.call(fail))
    except RuntimeError:
        pass

    breaker._opened_at = time.monotonic() - breaker.recovery_timeout
    assert breaker.state == 2

    try:
        asyncio.run(breaker.call(fail))
    except RuntimeError:
        pass
    else:
        raise AssertionError("the recovery probe should propagate the upstream failure")

    assert breaker.state == 1


def test_synchronous_callable_is_supported() -> None:
    """The wrapper supports non-coroutine callables as well as async functions."""
    breaker = CircuitBreaker()

    assert asyncio.run(breaker.call(lambda value: value + 1, 4)) == 5
    assert breaker.state == 0
