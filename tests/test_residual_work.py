"""Residual-work analysis over synthetic DGF-style projects, after arXiv 2609.29345."""

from __future__ import annotations

import pytest

from eval.dgf.generate import generate_project, project_params
from eval.residual_work import (
    Costs,
    human_work,
    run_gate_on_project,
    summarise_projects,
    threshold_holds,
)


def test_projects_are_reproducible_from_their_seed():
    params = project_params(300, seed=2609)
    assert len(params) == 300
    a = generate_project(params[7])
    b = generate_project(params[7])
    assert [r.request.id for r in a.requests] == [r.request.id for r in b.requests]
    assert [r.risky for r in a.requests] == [r.risky for r in b.requests]


def test_the_real_engine_decides_every_request():
    project = generate_project(project_params(3, seed=1)[0])
    decisions = run_gate_on_project(project)
    assert len(decisions) == len(project.requests)
    assert set(decisions) <= {"auto_approve", "route", "deny"}


def test_work_follows_the_cost_model_on_a_hand_sized_case():
    costs = Costs(review=10, exception_rate=0.5, exception=20, verification=2,
                  correction=100, maintenance=30)
    decisions = ["auto_approve", "auto_approve", "route", "deny"]
    risky = [False, True, True, False]
    manual, gate, parts = human_work(decisions, risky, costs)
    assert manual == 40
    # route 10, auto 2*2 verification, one risky auto 100, one safe deny re-reviewed 10,
    # exceptions 0.5 * 3 gate-handled * 20 = 30, maintenance 30
    assert gate == pytest.approx(10 + 4 + 100 + 10 + 30 + 30)
    assert parts["correction"] == 100 and parts["maintenance"] == 30


def test_threshold_matches_the_totals():
    costs = Costs(review=10, exception_rate=0.1, exception=20, verification=1,
                  correction=50, maintenance=0)
    decisions = ["auto_approve"] * 8 + ["route"] * 2
    risky = [False] * 10
    manual, gate, _ = human_work(decisions, risky, costs)
    assert threshold_holds(decisions, risky, costs) == (gate < manual)


def test_summary_names_when_the_gate_adds_work():
    rows = [
        {"reduces_work": False, "exception_rate": 0.28, "calibration_noise": 1.2,
         "requests": 30, "relative_change": 0.4, "automation_share": 0.5},
        {"reduces_work": True, "exception_rate": 0.02, "calibration_noise": 0.1,
         "requests": 300, "relative_change": -0.5, "automation_share": 0.6},
    ]
    s = summarise_projects(rows)
    assert s["projects"] == 2 and s["gate_reduces_work"] == 1
    assert "by_exception_rate" in s and "by_calibration" in s and "by_volume" in s


def test_a_change_that_breaks_policy_is_never_labelled_safe():
    # A freeze collision or a requester without authority must not ship, whatever
    # its outage risk. Denying it is not rework.
    from warden.data import seed as fixture
    from warden.domain.decision import validate_request
    from warden.domain.risk import assess_risk

    for p in project_params(20, seed=2609):
        project = generate_project(p)
        for lr in project.requests:
            risk = assess_risk(lr.request, project.ctx, fixture.EVAL_NOW)
            valid = validate_request(lr.request, project.ctx).ok
            if risk.hard_deny or not valid:
                assert lr.risky, lr.request.id
