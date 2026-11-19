"""Circuit breaker pattern for LLM API calls."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class CircuitBreakerOpen(Exception):
    """Raised when the circuit breaker is open and calls are blocked."""

    def __init__(self, recovery_timeout: int) -> None:
        super().__init__(
            f"Circuit breaker open. Retry after {recovery_timeout} seconds."
        )
        self.recovery_timeout = recovery_timeout


class CircuitBreaker:
    """Stateless circuit breaker that tracks recent failures.

    Opens after `failure_threshold` failures within the lookback window.
    Blocks all calls while open until `recovery_timeout` seconds have elapsed.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        window_seconds: int = 60,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.window_seconds = window_seconds

        self._failures: list[float] = []
        self._state: int = 0  # 0=closed, 1=open, 2=half-open
        self._opened_at: float = 0.0

    @property
    def state(self) -> int:
        """Current circuit state: 0=closed, 1=open, 2=half-open."""
        if (
            self._state == 1
            and time.monotonic() - self._opened_at >= self.recovery_timeout
        ):
            self._state = 2  # Transition to half-open
            logger.info("circuit_breaker_half_open")
        return self._state

    def _cleanup_failures(self) -> None:
        """Remove failures outside the lookback window."""
        cutoff = time.monotonic() - self.window_seconds
        self._failures = [t for t in self._failures if t > cutoff]

    async def call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Execute a function through the circuit breaker.

        Args:
            func: Async callable to execute.
            *args: Positional arguments for the callable.
            **kwargs: Keyword arguments for the callable.

        Returns:
            The result of the function call.

        Raises:
            CircuitBreakerOpen: If the circuit is open.
        """
        # Check circuit state
        current_state = self.state
        if current_state == 1:
            raise CircuitBreakerOpen(self.recovery_timeout)

        # In half-open state, allow one request through
        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)

            # Success: reset failures, close circuit
            self._failures = []
            self._state = 0
            logger.info("circuit_breaker_closed")
            return result

        except Exception:
            # Failure: record and possibly open circuit
            self._failures.append(time.monotonic())
            self._cleanup_failures()

            if len(self._failures) >= self.failure_threshold:
                self._state = 1
                self._opened_at = time.monotonic()
                logger.warning(
                    "circuit_breaker_opened",
                    extra={
                        "failures": len(self._failures),
                        "threshold": self.failure_threshold,
                    },
                )

            raise
