"""
Wrap a tool client with retries, backoff, and optional fallbacks.

The core rule: transport failures are worth retrying, domain errors are not.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol


class TransportError(Exception):
    pass


class ToolTimeout(TransportError):
    pass


class ToolServerError(TransportError):
    pass


class ToolMalformedResponse(TransportError):
    pass


class DomainToolError(Exception):
    pass


class ToolUnavailable(Exception):

    def __init__(self, tool: str, last_error: Exception) -> None:
        super().__init__(f"tool {tool!r} unavailable after retries: {last_error}")
        self.tool = tool
        self.last_error = last_error


class ToolClient(Protocol):
    def call(self, tool: str, **kwargs) -> dict: ...


@dataclass
class CallMetrics:
    total_calls: int = 0
    total_attempts: int = 0
    retries: int = 0
    transport_failures: int = 0
    degradations: int = 0
    fallbacks_used: int = 0
    per_tool_retries: dict[str, int] = field(default_factory=dict)

    def record_retry(self, tool: str) -> None:
        self.retries += 1
        self.per_tool_retries[tool] = self.per_tool_retries.get(tool, 0) + 1


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 4
    base_delay: float = 0.05
    max_delay: float = 2.0
    jitter_frac: float = 0.25

    def delay_for(self, attempt: int, rng: random.Random) -> float:
        # Exponential backoff capped at max_delay, plus jitter so a fleet of
        # agents retrying at once does not sync up into a thundering herd.
        raw = min(self.max_delay, self.base_delay * (2 ** (attempt - 1)))
        return raw + rng.uniform(0.0, raw * self.jitter_frac)


class ResilientToolClient:

    def __init__(
        self,
        inner: ToolClient,
        *,
        policy: RetryPolicy | None = None,
        metrics: CallMetrics | None = None,
        sleep: Callable[[float], None] | None = None,
        rng: random.Random | None = None,
        fallbacks: Optional[dict[str, Callable[[dict], dict]]] = None,
        enabled: bool = True,
    ) -> None:
        self.inner = inner
        self.policy = policy or RetryPolicy()
        self.metrics = metrics or CallMetrics()
        self._sleep = sleep or (lambda _s: None)
        self._rng = rng or random.Random()
        self.fallbacks = fallbacks or {}
        self.enabled = enabled

    def call(self, tool: str, **kwargs) -> dict:
        self.metrics.total_calls += 1

        if not self.enabled:
            self.metrics.total_attempts += 1
            try:
                return self.inner.call(tool, **kwargs)
            except TransportError as exc:
                self.metrics.transport_failures += 1
                raise ToolUnavailable(tool, exc) from exc

        last_error: Exception | None = None
        for attempt in range(1, self.policy.max_attempts + 1):
            self.metrics.total_attempts += 1
            try:
                return self.inner.call(tool, **kwargs)
            except DomainToolError:
                # A domain error is a real answer from the tool, not a glitch.
                # Retrying would just get the same rejection, so let it propagate.
                raise
            except TransportError as exc:
                last_error = exc
                self.metrics.transport_failures += 1
                if attempt < self.policy.max_attempts:
                    self.metrics.record_retry(tool)
                    self._sleep(self.policy.delay_for(attempt, self._rng))
                    continue

        # Out of retries. A registered fallback lets the agent keep going in a
        # degraded state rather than failing the whole task.
        fallback = self.fallbacks.get(tool)
        if fallback is not None:
            self.metrics.fallbacks_used += 1
            self.metrics.degradations += 1
            return fallback(kwargs)

        self.metrics.degradations += 1
        raise ToolUnavailable(tool, last_error or RuntimeError("unknown"))
