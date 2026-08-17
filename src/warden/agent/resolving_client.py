"""
Agent-side closed-world check: a tool call that does not resolve is never sent.

Each rejection is counted as a hallucinated call and returned to the agent as a
domain error with the reason, so the resilience layer does not retry it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..tool_registry import RejectedCall, resolve_call
from .resilience import DomainToolError, ToolClient


@dataclass
class HallucinationStats:
    rejected: int = 0
    by_kind: dict[str, int] = field(default_factory=dict)
    calls: list[dict] = field(default_factory=list)

    def record(self, exc: RejectedCall) -> None:
        self.rejected += 1
        self.by_kind[exc.kind] = self.by_kind.get(exc.kind, 0) + 1
        self.calls.append({"tool": exc.tool, "kind": exc.kind, "detail": exc.detail})


class ResolvingToolClient:

    def __init__(self, inner: ToolClient, *, stats: HallucinationStats | None = None) -> None:
        self.inner = inner
        self.stats = stats or HallucinationStats()

    def call(self, tool: str, **kwargs) -> dict:
        try:
            resolve_call(tool, kwargs)
        except RejectedCall as exc:
            self.stats.record(exc)
            raise DomainToolError(f"not sent: {exc}") from exc
        return self.inner.call(tool, **kwargs)
