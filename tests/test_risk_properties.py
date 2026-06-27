
from __future__ import annotations

import dataclasses
from datetime import datetime, timezone

import pytest

from change_gate.data import seed
from change_gate.domain.models import (
    ChangeKind,
    ChangeRequest,
    DependencyGraph,
    Environment,
    Requester,
    RiskBand,
    Role,
    Service,
)
from change_gate.domain.risk import assess_risk, band_for

NOW = seed.EVAL_NOW
POLICY = seed.ACME_CONTEXT.policy


def _req(**kw) -> ChangeRequest:
    base = dict(
        id="p", tenant_id="acme", requester=Requester("u", Role.LEAD),
        service_id="x", key="k", kind=ChangeKind.CONFIG,
        environment=Environment.STAGING, current_value=100, proposed_value=110,
        window_start=datetime(2026, 7, 5, tzinfo=timezone.utc),
        window_end=datetime(2026, 7, 5, 1, tzinfo=timezone.utc),
    )
    base.update(kw)
    return ChangeRequest(**base)


def _ctx_with_graph(graph: DependencyGraph):
    return dataclasses.replace(
        seed.ACME_CONTEXT, graph=graph, freeze_windows=[],
        change_history=[], incident_history=[],
    )


_INSIDE_FREEZE = dict(
    environment=Environment.PROD,
    window_start=datetime(2026, 6, 26, tzinfo=timezone.utc),
    window_end=datetime(2026, 6, 26, 1, tzinfo=timezone.utc),
)


@pytest.mark.parametrize(
    "extra",
    [
        dict(service_id="notifications", kind=ChangeKind.FLAG,
             current_value=False, proposed_value=False),
        dict(service_id="db-core", kind=ChangeKind.CONFIG, current_value=20, proposed_value=400),
    ],
    ids=["min_other_factors", "max_other_factors"],
)
def test_freeze_collision_dominates_regardless_of_other_factors(extra):
    req = _req(**{**_INSIDE_FREEZE, **extra})
    a = assess_risk(req, seed.ACME_CONTEXT, NOW)
    assert a.hard_deny is True
    assert a.band is RiskBand.HIGH
    assert a.factor("freeze_collision").is_hard_deny is True


def test_blast_radius_monotonic_when_adding_dependents():
    svc = lambda sid, t: Service(sid, sid.upper(), t)  # noqa: E731
    g0 = DependencyGraph(services={"x": svc("x", 0.1)}, depends_on={"x": frozenset()})
    g1 = DependencyGraph(
        services={"x": svc("x", 0.1), "y": svc("y", 0.2)},
        depends_on={"x": frozenset(), "y": frozenset({"x"})},
    )
    g2 = DependencyGraph(
        services={"x": svc("x", 0.1), "y": svc("y", 0.2), "z": svc("z", 0.3)},
        depends_on={"x": frozenset(), "y": frozenset({"x"}), "z": frozenset({"y"})},
    )
    req = _req(service_id="x")
    s0 = assess_risk(req, _ctx_with_graph(g0), NOW).score
    s1 = assess_risk(req, _ctx_with_graph(g1), NOW).score
    s2 = assess_risk(req, _ctx_with_graph(g2), NOW).score
    assert s0 <= s1 <= s2
    assert s2 > s0


def test_blast_radius_monotonic_over_real_topology():
    def score_for(service_id: str) -> float:
        return assess_risk(_req(service_id=service_id), seed.ACME_CONTEXT, NOW).score

    assert score_for("notifications") <= score_for("search") <= score_for("db-core")


def test_magnitude_monotonic_in_percent_delta():
    base = dict(service_id="notifications", current_value=100)
    scores = [
        assess_risk(_req(**base, proposed_value=v), _ctx_with_graph(
            DependencyGraph(services={"notifications": Service("notifications", "N", 0.05)},
                            depends_on={"notifications": frozenset()})
        ), NOW).score
        for v in (101, 110, 150, 300)
    ]
    assert scores == sorted(scores)
    assert scores[-1] >= scores[0]


def test_flag_flip_not_less_than_no_op():
    g = DependencyGraph(services={"notifications": Service("notifications", "N", 0.05)},
                        depends_on={"notifications": frozenset()})
    ctx = _ctx_with_graph(g)
    no_op = _req(service_id="notifications", kind=ChangeKind.FLAG,
                 current_value=True, proposed_value=True)
    flip = _req(service_id="notifications", kind=ChangeKind.FLAG,
                current_value=False, proposed_value=True)
    assert assess_risk(flip, ctx, NOW).score >= assess_risk(no_op, ctx, NOW).score


def test_band_boundaries_from_policy_thresholds():
    low = POLICY.band_low_max
    med = POLICY.band_medium_max
    assert band_for(0.0, POLICY) is RiskBand.LOW
    assert band_for(low - 0.01, POLICY) is RiskBand.LOW
    assert band_for(low, POLICY) is RiskBand.MEDIUM
    assert band_for(med - 0.01, POLICY) is RiskBand.MEDIUM
    assert band_for(med, POLICY) is RiskBand.HIGH
    assert band_for(100.0, POLICY) is RiskBand.HIGH
