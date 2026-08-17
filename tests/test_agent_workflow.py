
from __future__ import annotations

import pytest

from warden.agent.graph import run_task
from warden.agent.llm import DeterministicExplainer
from warden.agent.resilience import CallMetrics, ResilientToolClient
from warden.agent.state import AgentDeps
from warden.agent.tool_client import InProcessToolClient
from warden.data import seed


def _deps(service) -> AgentDeps:
    client = ResilientToolClient(InProcessToolClient(service), metrics=CallMetrics())
    return AgentDeps(client=client, explainer=DeterministicExplainer(), trace_id="t-agent")


@pytest.mark.parametrize("scenario", seed.SCENARIOS, ids=lambda s: s.name)
def test_agent_reaches_expected_terminal_decision(acme_service, scenario):
    final = run_task(scenario.request.id, seed.EVAL_NOW.isoformat(), _deps(acme_service))
    assert final.get("failed") is not True
    assert final["terminal_decision"] == scenario.expected.value, scenario.note


def test_agent_emits_explanation_and_routing_message(acme_service):
    s = seed.SCENARIOS_BY_NAME["high_blast_prod_config"]
    final = run_task(s.request.id, seed.EVAL_NOW.isoformat(), _deps(acme_service))
    assert final["explanation"]
    assert final["routing_message"]
    assert str(final["risk"]["score"]) in final["explanation"]


def test_agent_workflow_visits_all_steps(acme_service):
    s = seed.SCENARIOS_BY_NAME["low_risk_dev_flag"]
    final = run_task(s.request.id, seed.EVAL_NOW.isoformat(), _deps(acme_service))
    assert final["request"] is not None
    assert final["validation"]["ok"] is True
    assert final["risk"]["band"] == "low"
    assert final["decision"]["decision"] == "auto_approve"
