
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from change_gate.policy import (
    ActionPolicy,
    ProposedAction,
    load_action_policy,
    load_policy_document,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def policy() -> ActionPolicy:
    return load_action_policy()


def _proposal(**kw) -> ProposedAction:
    # A human approver recording a dev deny on a fresh request: allowed by the
    # last rule. Each test changes one fact to land on one rule.
    base = dict(
        tool="record_decision", action="deny", persona="human", subject="alice",
        caller_tenant="acme", request_tenant="acme", environment="dev", state="new",
        freeze_active=False, request_valid=True, requester_id="u-dev",
    )
    base.update(kw)
    return ProposedAction(**base)


def test_baseline_proposal_is_allowed_by_the_explicit_allow_rule(policy):
    verdict = policy.check(_proposal())
    assert verdict.allowed is True
    assert verdict.rule_id == "allow-known-actions"


@pytest.mark.parametrize(
    "change, rule",
    [
        (dict(request_tenant="globex"), "tenant-mismatch"),
        (dict(persona="unknown"), "unknown-persona"),
        (dict(persona="robot"), "unknown-persona"),
        (dict(tool="approve_change", action="approve", persona="agent", state="routed"),
         "agent-cannot-approve"),
        (dict(action="auto_approve", persona="agent", environment="prod"),
         "agent-no-prod-apply"),
        (dict(action="auto_approve", request_valid=False), "invalid-request-blocks-apply"),
        (dict(tool="approve_change", action="approve", state="routed", request_valid=False),
         "invalid-request-blocks-apply"),
        (dict(action="auto_approve", freeze_active=True), "freeze-blocks-apply"),
        (dict(tool="approve_change", action="approve", state="routed", freeze_active=True),
         "freeze-blocks-apply"),
        (dict(tool="approve_change", action="approve", state="routed", subject="u-dev"),
         "no-self-approval"),
        (dict(state="routed"), "record-needs-new"),
        (dict(state="auto_approved", action="auto_approve"), "record-needs-new"),
        (dict(tool="route_change", action="route", state="routed"), "route-needs-new"),
        (dict(tool="approve_change", action="approve", state="new"),
         "human-decision-needs-routed"),
        (dict(tool="deny_change", action="deny", state="denied"),
         "human-decision-needs-routed"),
    ],
)
def test_each_deny_rule(policy, change, rule):
    verdict = policy.check(_proposal(**change))
    assert verdict.allowed is False
    assert verdict.rule_id == rule
    assert verdict.reason


@pytest.mark.parametrize(
    "change",
    [
        dict(action="auto_approve"),
        dict(action="route"),
        dict(action="auto_approve", persona="agent", environment="dev"),
        dict(action="route", persona="agent", environment="prod"),
        dict(tool="route_change", action="route", persona="agent"),
        dict(tool="approve_change", action="approve", state="routed", environment="prod"),
        dict(tool="deny_change", action="deny", state="routed"),
    ],
)
def test_allowed_actions(policy, change):
    assert policy.check(_proposal(**change)).allowed is True


def test_unknown_action_falls_through_to_default_deny(policy):
    verdict = policy.check(_proposal(action="delete_audit_log"))
    assert verdict.allowed is False
    assert verdict.rule_id == "default"


def test_first_matching_rule_wins(policy):
    # Wrong tenant and agent prod apply both match. The tenant rule is first.
    verdict = policy.check(_proposal(request_tenant="globex", persona="agent",
                                     action="auto_approve", environment="prod"))
    assert verdict.rule_id == "tenant-mismatch"


def test_verdict_carries_the_policy_version(policy):
    assert policy.check(_proposal()).policy_version == load_policy_document()["version"]


def test_policy_rules_cannot_come_from_a_prompt_only_from_the_file(policy):
    # The check takes structured facts. There is no free-text field a request
    # description or tool result could land in.
    fields = {f.name for f in dataclasses.fields(ProposedAction)}
    assert not fields & {"description", "prompt", "note", "explanation", "instructions"}


def _doc() -> dict:
    return load_policy_document()


def test_loader_rejects_an_unknown_condition_field():
    doc = _doc()
    doc["rules"][0]["when"] = {"tenant_macth": False}
    with pytest.raises(ValueError):
        ActionPolicy.from_document(doc)


def test_loader_rejects_a_bad_effect():
    doc = _doc()
    doc["rules"][0]["effect"] = "maybe"
    with pytest.raises(ValueError):
        ActionPolicy.from_document(doc)


def test_loader_rejects_a_bad_default():
    doc = _doc()
    doc["default"] = "allow-ish"
    with pytest.raises(ValueError):
        ActionPolicy.from_document(doc)


def test_loader_rejects_duplicate_rule_ids():
    doc = _doc()
    doc["rules"].append(dict(doc["rules"][0]))
    with pytest.raises(ValueError):
        ActionPolicy.from_document(doc)


def test_policy_file_with_rules_matches_the_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((ROOT / "policy" / "policy.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(_doc(), schema)
    bad = _doc()
    bad["rules"][0]["when"] = {"not_a_field": 1}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bad, schema)
