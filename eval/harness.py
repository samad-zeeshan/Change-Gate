"""
Run the agent over seed scenarios under injected failures and score the outcomes.

The key metric is safety: degrading to a human route is fine, auto-approving wrong is not.
"""

from __future__ import annotations

import random
import sys
from dataclasses import dataclass, field
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from warden.agent.failure_injection import FailureInjector, InjectionStats  # noqa: E402
from warden.agent.graph import run_task  # noqa: E402
from warden.agent.llm import DeterministicExplainer  # noqa: E402
from warden.agent.resilience import (  # noqa: E402
    CallMetrics,
    ResilientToolClient,
    RetryPolicy,
)
from warden.agent.state import AgentDeps  # noqa: E402
from warden.agent.tool_client import InProcessToolClient  # noqa: E402
from warden.audit import AuditLog  # noqa: E402
from warden.clock import FixedClock  # noqa: E402
from warden.data import seed  # noqa: E402
from warden.db.repository import InMemoryRepository  # noqa: E402
from warden.security import (  # noqa: E402
    SCOPE_APPROVE,
    SCOPE_APPROVE_PROD,
    SCOPE_READ,
    AuthPrincipal,
)
from warden.tools import ToolService  # noqa: E402

PER_ATTEMPT_MS = 8.0
SPIKE_SECONDS = 0.25


class _LatencyAccumulator:
    def __init__(self) -> None:
        self.seconds = 0.0

    def add(self, seconds: float) -> None:
        self.seconds += max(0.0, seconds)


@dataclass
class TaskOutcome:
    scenario: str
    nominal: str
    terminal: str | None
    outcome: str
    success: bool
    attempts: int
    retries: int
    degradations: int
    injected: int
    latency_ms: float
    degraded_flag: bool


@dataclass
class ConditionResult:
    resilience: bool
    failure_rate: float
    n: int
    successes: int
    outcomes: dict[str, int] = field(default_factory=dict)
    mean_retries: float = 0.0
    mean_attempts: float = 0.0
    total_degradations: int = 0
    unsafe: int = 0
    p50_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0

    @property
    def success_rate(self) -> float:
        return self.successes / self.n if self.n else 0.0


def _principal_for(tenant_id: str) -> AuthPrincipal:
    return AuthPrincipal(
        subject=f"agent-{tenant_id}",
        tenant_id=tenant_id,
        role="lead",
        scopes=frozenset({SCOPE_READ, SCOPE_APPROVE, SCOPE_APPROVE_PROD}),
    )


def classify(nominal: str, terminal: str | None) -> tuple[str, bool]:
    # "nominal" is what the agent should decide with full context. Routing when we
    # should not have is a safe degrade and still counts as success. Auto-approving
    # when we should not is the one outcome we call unsafe.
    if terminal is None:
        return "failed", False
    if terminal == nominal:
        return "correct", True
    if terminal == "route" and nominal != "route":
        return "safe_degrade", True
    if terminal == "auto_approve" and nominal != "auto_approve":
        return "unsafe", False
    return "wrong", False


def run_one_task(
    scenario: seed.Scenario,
    *,
    failure_rate: float,
    resilience: bool,
    rng_seed: int,
) -> TaskOutcome:
    tenant_id = scenario.request.tenant_id
    repo = InMemoryRepository(tenant_id, audit_log=AuditLog())
    service = ToolService(repo, FixedClock(seed.EVAL_NOW), principal=_principal_for(tenant_id))

    latency = _LatencyAccumulator()
    inner = InProcessToolClient(service)
    injector = FailureInjector(
        inner,
        rate=failure_rate,
        rng=random.Random(rng_seed),
        sleep=lambda _s: latency.add(SPIKE_SECONDS),
        stats=InjectionStats(),
    )
    metrics = CallMetrics()
    client = ResilientToolClient(
        injector,
        policy=RetryPolicy(),
        metrics=metrics,
        sleep=latency.add,
        rng=random.Random(rng_seed + 9973),
        enabled=resilience,
    )
    deps = AgentDeps(
        client=client,
        explainer=DeterministicExplainer(),
        degrade_on_failure=resilience,
        trace_id=f"eval-{scenario.name}-{rng_seed}",
    )

    final = run_task(scenario.request.id, seed.EVAL_NOW.isoformat(), deps)
    terminal = final.get("terminal_decision")
    outcome, success = classify(scenario.expected.value, terminal)

    latency_ms = metrics.total_attempts * PER_ATTEMPT_MS + latency.seconds * 1000.0
    return TaskOutcome(
        scenario=scenario.name,
        nominal=scenario.expected.value,
        terminal=terminal,
        outcome=outcome,
        success=success,
        attempts=metrics.total_attempts,
        retries=metrics.retries,
        degradations=metrics.degradations,
        injected=injector.stats.injected,
        latency_ms=round(latency_ms, 3),
        degraded_flag=bool(final.get("degraded")),
    )


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    # Linear interpolation between the two ranks the percentile falls between, so
    # small samples do not snap to a single observed value.
    ordered = sorted(values)
    k = (len(ordered) - 1) * pct
    lo = int(k)
    hi = min(lo + 1, len(ordered) - 1)
    return round(ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo), 3)


def run_condition(
    *,
    resilience: bool,
    failure_rate: float,
    n: int,
    base_seed: int,
) -> tuple[ConditionResult, list[TaskOutcome]]:
    scenarios = seed.SCENARIOS
    outcomes: list[TaskOutcome] = []
    for i in range(n):
        scenario = scenarios[i % len(scenarios)]
        rng_seed = base_seed + i * 131
        outcomes.append(
            run_one_task(
                scenario,
                failure_rate=failure_rate,
                resilience=resilience,
                rng_seed=rng_seed,
            )
        )

    result = ConditionResult(resilience=resilience, failure_rate=failure_rate, n=n,
                             successes=sum(1 for o in outcomes if o.success))
    for o in outcomes:
        result.outcomes[o.outcome] = result.outcomes.get(o.outcome, 0) + 1
    result.mean_retries = round(sum(o.retries for o in outcomes) / n, 3) if n else 0.0
    result.mean_attempts = round(sum(o.attempts for o in outcomes) / n, 3) if n else 0.0
    result.total_degradations = sum(o.degradations for o in outcomes)
    result.unsafe = result.outcomes.get("unsafe", 0)
    lat = [o.latency_ms for o in outcomes]
    result.p50_latency_ms = _percentile(lat, 0.50)
    result.p95_latency_ms = _percentile(lat, 0.95)
    return result, outcomes
