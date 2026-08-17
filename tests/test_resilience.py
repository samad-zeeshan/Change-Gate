
from __future__ import annotations

import random

import pytest

from warden.agent.resilience import (
    CallMetrics,
    DomainToolError,
    ResilientToolClient,
    RetryPolicy,
    ToolServerError,
    ToolTimeout,
    ToolUnavailable,
)


class _FlakyClient:

    def __init__(self, fail_n: int, exc=ToolTimeout):
        self.fail_n = fail_n
        self.calls = 0
        self.exc = exc

    def call(self, tool: str, **kwargs) -> dict:
        self.calls += 1
        if self.calls <= self.fail_n:
            raise self.exc(f"flaky {self.calls}")
        return {"ok": True, "tool": tool}


def test_retry_recovers_transient_failure():
    inner = _FlakyClient(fail_n=2)
    metrics = CallMetrics()
    client = ResilientToolClient(inner, policy=RetryPolicy(max_attempts=4), metrics=metrics)
    result = client.call("get_change_request", request_id="cr-001")
    assert result["ok"] is True
    assert inner.calls == 3
    assert metrics.retries == 2


def test_retries_exhausted_raises_tool_unavailable():
    inner = _FlakyClient(fail_n=99)
    client = ResilientToolClient(inner, policy=RetryPolicy(max_attempts=3))
    with pytest.raises(ToolUnavailable):
        client.call("assess_change_risk", request_id="x")


def test_domain_errors_are_not_retried():
    class _DomainFail:
        def __init__(self):
            self.calls = 0

        def call(self, tool, **kw):
            self.calls += 1
            raise DomainToolError("not found")

    inner = _DomainFail()
    client = ResilientToolClient(inner, policy=RetryPolicy(max_attempts=5))
    with pytest.raises(DomainToolError):
        client.call("get_change_request", request_id="nope")
    assert inner.calls == 1


def test_fallback_used_when_registered():
    inner = _FlakyClient(fail_n=99)
    metrics = CallMetrics()
    client = ResilientToolClient(
        inner,
        policy=RetryPolicy(max_attempts=2),
        metrics=metrics,
        fallbacks={"get_recent_changes": lambda kw: {"changes": [], "fallback": True}},
    )
    out = client.call("get_recent_changes")
    assert out["fallback"] is True
    assert metrics.fallbacks_used == 1
    assert metrics.degradations == 1


def test_backoff_is_monotonic_nondecreasing():
    policy = RetryPolicy(base_delay=0.1, max_delay=10, jitter_frac=0.0)
    rng = random.Random(0)
    delays = [policy.delay_for(a, rng) for a in range(1, 5)]
    assert delays == sorted(delays)
    assert delays[0] < delays[-1]


def test_baseline_disabled_fails_after_single_attempt():
    inner = _FlakyClient(fail_n=1, exc=ToolServerError)
    metrics = CallMetrics()
    client = ResilientToolClient(inner, metrics=metrics, enabled=False)
    with pytest.raises(ToolUnavailable):
        client.call("get_dependency_graph")
    assert inner.calls == 1
    assert metrics.retries == 0
