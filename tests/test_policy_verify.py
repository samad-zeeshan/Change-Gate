"""SMT check of policy updates: a new version may not allow what the previous one denied unless listed."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

pytest.importorskip("z3")

from policy.verify import (  # noqa: E402
    load_history,
    new_allows,
    previous_version,
    verify,
)
from warden.policy import load_policy_document  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def current():
    return load_policy_document()


def _without_rule(doc: dict, rule_id: str) -> dict:
    out = copy.deepcopy(doc)
    out["rules"] = [r for r in out["rules"] if r["id"] != rule_id]
    out["version"] = doc["version"] + "-widened"
    return out


def test_a_policy_compared_with_itself_adds_nothing(current):
    assert new_allows(current, current) == []


def test_dropping_the_prod_rule_is_caught_with_a_counterexample(current):
    widened = _without_rule(current, "agent-no-prod-apply")
    found = new_allows(current, widened)
    assert {"persona": "agent", "tool": "record_decision", "environment": "prod",
            "state": "new"} in found
    report = verify(current, widened, approved=[])
    assert report["result"] == "fail"


def test_listing_the_new_allow_in_the_change_file_passes(current):
    widened = _without_rule(current, "agent-no-prod-apply")
    approved = [{"persona": "agent", "tool": "record_decision", "environment": "prod",
                 "state": "*"}]
    assert verify(current, widened, approved=approved)["result"] == "pass"


def test_a_narrowing_change_needs_no_listing(current):
    narrowed = copy.deepcopy(current)
    narrowed["rules"].insert(0, {"id": "no-prod-at-all", "effect": "deny",
                                 "when": {"environment": "prod"}, "reason": "test"})
    assert new_allows(current, narrowed) == []


def test_widening_a_human_role_is_caught(current):
    widened = copy.deepcopy(current)
    widened["personas"]["human"]["base_roles"].append("recorder")
    found = new_allows(current, widened)
    assert any(f["persona"] == "human" and f["tool"] == "record_decision" for f in found)


def test_delivering_router_to_the_agent_is_caught(current):
    widened = copy.deepcopy(current)
    widened["role_delivery"]["agent"]["learnable"].append("router")
    found = new_allows(current, widened)
    assert any(f["persona"] == "agent" and f["tool"] == "route_change" for f in found)


def test_the_output_hash_is_stable(current):
    widened = _without_rule(current, "agent-no-prod-apply")
    a = verify(current, widened, approved=[])
    b = verify(current, widened, approved=[])
    assert a["output_hash"] == b["output_hash"] and len(a["output_hash"]) == 64


def test_history_holds_every_version_and_the_current_one_is_last(current):
    history = load_history()
    assert history[-1]["version"] == current["version"]
    assert history[-1] == current
    assert previous_version(history)["version"] != current["version"]


def test_the_committed_verification_matches_a_fresh_run(current):
    committed = json.loads((ROOT / "policy" / "verification.json").read_text(encoding="utf-8"))
    changes = json.loads((ROOT / "policy" / "changes.json").read_text(encoding="utf-8"))
    fresh = verify(previous_version(load_history()), current,
                   approved=changes["approved_new_allows"])
    assert fresh["result"] == "pass"
    assert committed == fresh
