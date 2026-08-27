"""The audit chain records which policy version, and which verifier run, governed each write."""

from __future__ import annotations

import json
from pathlib import Path

from warden.policy import load_policy_document, policy_sha256

ROOT = Path(__file__).resolve().parents[1]


def _events(audit_log):
    return [e for e in audit_log.for_tenant("acme") if e.action == "policy_version"]


def test_first_write_records_the_policy_version_once(bound_service, audit_log):
    service = bound_service("cr-002")
    service.record_decision("cr-002")
    bound_service("cr-005").record_decision("cr-005")
    (event,) = _events(audit_log)
    doc = load_policy_document()
    verification = json.loads((ROOT / "policy" / "verification.json").read_text("utf-8"))
    assert event.after["policy_version"] == doc["version"]
    assert event.after["policy_sha256"] == policy_sha256(doc)
    assert event.after["verifier_output_hash"] == verification["output_hash"]
    assert event.after["verifier_result"] == "pass"
    assert audit_log.for_tenant("acme")[0].action == "policy_version"
    assert audit_log.verify_chain("acme")


def test_a_denied_write_is_still_under_a_recorded_version(bound_service, audit_log):
    service = bound_service("cr-002")
    service.record_decision("cr-002")
    try:
        service.record_decision("cr-002")
    except Exception:  # noqa: BLE001 - the second record is refused by policy
        pass
    actions = [e.action for e in audit_log.for_tenant("acme")]
    assert actions[0] == "policy_version" and actions.count("policy_version") == 1
    assert "policy_denied" in actions


def test_a_policy_without_a_matching_verification_is_marked_unverified(acme_repo, clock,
                                                                       elevated_principal,
                                                                       audit_log):
    import dataclasses

    from warden.policy import ActionPolicy
    from warden.tools import ToolService

    loose = ActionPolicy(version="local-edit", rules=[], default="allow")
    bound = dataclasses.replace(elevated_principal, request_id="cr-001")
    ToolService(acme_repo, clock, principal=bound, policy=loose).record_decision("cr-001")
    (event,) = _events(audit_log)
    assert event.after["verifier_result"] == "unverified"
