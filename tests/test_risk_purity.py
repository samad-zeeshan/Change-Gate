
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

from change_gate.data import seed
from change_gate.domain import decision as decision_mod
from change_gate.domain import risk

NOW = seed.EVAL_NOW


def test_assessment_carries_exactly_the_canonical_weighted_factors():
    s = seed.SCENARIOS_BY_NAME["high_blast_prod_config"]
    a = risk.assess_risk(s.request, seed.ACME_CONTEXT, NOW)
    names = {f.name for f in a.factors}
    assert set(risk.WEIGHTED_FACTORS) <= names
    assert "freeze_collision" in names


@pytest.mark.parametrize("scenario", seed.SCENARIOS, ids=lambda s: s.name)
def test_scoring_is_reproducible(scenario):
    ctx = seed.TENANTS[scenario.request.tenant_id]
    a = risk.assess_risk(scenario.request, ctx, NOW)
    b = risk.assess_risk(scenario.request, ctx, NOW)
    assert a == b
    assert a.inputs_fingerprint == b.inputs_fingerprint
    fingerprints = {risk.assess_risk(scenario.request, ctx, NOW).score for _ in range(25)}
    assert len(fingerprints) == 1


def test_fingerprint_changes_when_inputs_change():
    s = seed.SCENARIOS_BY_NAME["high_blast_prod_config"]
    ctx = seed.ACME_CONTEXT
    base = risk.assess_risk(s.request, ctx, NOW)
    moved = risk.assess_risk(
        s.request.__class__(**{**s.request.__dict__, "proposed_value": 21}), ctx, NOW
    )
    assert base.inputs_fingerprint != moved.inputs_fingerprint


_FORBIDDEN_IN_SCORING = {"anthropic", "openai", "langchain", "langgraph", "httpx"}


def _module_file(mod) -> Path:
    return Path(mod.__file__)


@pytest.mark.parametrize("module", [risk, decision_mod])
def test_scoring_modules_import_no_llm_or_network(module):
    tree = ast.parse(_module_file(module).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    leaked = imported & _FORBIDDEN_IN_SCORING
    assert not leaked, f"{module.__name__} imports forbidden modules in scoring path: {leaked}"


def test_no_llm_call_during_scoring(monkeypatch):
    tripped = {"count": 0}

    class _Tripwire:
        def __getattr__(self, _name):
            tripped["count"] += 1
            raise AssertionError("LLM client touched during deterministic scoring")

    monkeypatch.setitem(sys.modules, "anthropic", _Tripwire())

    for scenario in seed.SCENARIOS:
        ctx = seed.TENANTS[scenario.request.tenant_id]
        risk.assess_risk(scenario.request, ctx, NOW)

    assert tripped["count"] == 0
