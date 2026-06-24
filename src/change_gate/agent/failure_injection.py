"""
Test-only wrapper that randomly injects transport failures into tool calls.

Used by the eval harness to measure how well the resilience layer copes.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Callable

from .resilience import (
    ToolClient,
    ToolMalformedResponse,
    ToolServerError,
    ToolTimeout,
)

FAILURE_MODES = ("timeout", "server_error", "malformed", "partial", "latency_spike")


@dataclass
class InjectionStats:
    injected: int = 0
    by_mode: dict[str, int] = field(default_factory=dict)

    def record(self, mode: str) -> None:
        self.injected += 1
        self.by_mode[mode] = self.by_mode.get(mode, 0) + 1


class FailureInjector:

    def __init__(
        self,
        inner: ToolClient,
        *,
        rate: float = 0.0,
        rng: random.Random | None = None,
        modes: tuple[str, ...] = FAILURE_MODES,
        sleep: Callable[[float], None] | None = None,
        stats: InjectionStats | None = None,
    ) -> None:
        self.inner = inner
        self.rate = max(0.0, min(1.0, rate))
        self._rng = rng or random.Random()
        self._modes = modes
        self._sleep = sleep or (lambda _s: None)
        self.stats = stats or InjectionStats()

    def call(self, tool: str, **kwargs) -> dict:
        if self.rate > 0.0 and self._rng.random() < self.rate:
            mode = self._rng.choice(self._modes)
            self.stats.record(mode)
            return self._inject(mode, tool, kwargs)
        return self.inner.call(tool, **kwargs)

    def _inject(self, mode: str, tool: str, kwargs: dict) -> dict:
        if mode == "timeout":
            raise ToolTimeout(f"injected timeout calling {tool}")
        if mode == "server_error":
            raise ToolServerError(f"injected HTTP 503 from {tool}")
        if mode == "malformed":
            raise ToolMalformedResponse(f"injected malformed payload from {tool}")
        if mode == "partial":
            raise ToolMalformedResponse(f"injected partial payload from {tool}")
        # A latency spike is not an error. We burn the configured delay and then
        # let the real call through, which is why it can still succeed.
        if mode == "latency_spike":
            self._sleep(0.0)
            return self.inner.call(tool, **kwargs)
        raise AssertionError(f"unknown failure mode {mode!r}")
