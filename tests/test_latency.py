"""Latency per decision: percentile maths, the harness, and the local explainer's fallback."""

from __future__ import annotations

from eval.latency import measure, percentiles
from warden.agent.llm import DeterministicExplainer, LocalExplainer


def test_percentiles_use_nearest_rank():
    xs = list(range(1, 101))
    assert percentiles(xs) == {"p50": 50, "p95": 95, "p99": 99}
    assert percentiles([7.0]) == {"p50": 7.0, "p95": 7.0, "p99": 7.0}


def test_in_process_decisions_are_timed_and_correct():
    out = measure("inprocess", DeterministicExplainer(), n=10)
    assert out["n"] == 10 and out["wrong_decisions"] == 0
    assert 0 < out["ms"]["p50"] <= out["ms"]["p95"] <= out["ms"]["p99"]


def test_the_local_explainer_falls_back_when_the_model_is_down():
    explainer = LocalExplainer(base_url="http://127.0.0.1:9/v1", timeout=0.5)
    breakdown = {"score": 14.0, "band": "low", "factors": [], "hard_deny": False}
    request = {"environment": "dev", "key": "k", "service_id": "s",
               "requester": {"id": "u", "role": "developer"}}
    decision = {"decision": "auto_approve", "reasons": []}
    text = explainer.explain_risk(breakdown, request, decision)
    assert text == DeterministicExplainer().explain_risk(breakdown, request, decision)
