"""Evidence-backed audit entries: every row says which credential, role, clause and inputs decided it."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from warden.agent.tool_client import InProcessToolClient
from warden.audit import compute_evidence_hash
from warden.sessions import RoleSessions

from conftest import walk_to_decide

ROOT = Path(__file__).resolve().parents[1]


def _run(bound_service, rid="cr-002"):
    client = InProcessToolClient(bound_service(rid), sessions=RoleSessions())
    walk_to_decide(client)
    return client, client.call("record_decision", trace_id="t-ev")


def test_every_entry_carries_evidence_and_its_hash(bound_service, audit_log):
    _run(bound_service)
    rows = audit_log.for_tenant("acme")
    assert rows
    for row in rows:
        assert row.evidence, row.action
        assert row.evidence_hash == compute_evidence_hash(row.evidence)
        assert row.evidence["verifier"]["version"]


def test_a_decision_names_credential_role_clause_and_risk_inputs(bound_service, audit_log):
    _, out = _run(bound_service)
    (row,) = [r for r in audit_log.for_tenant("acme") if r.action == "record_decision"]
    ev = row.evidence
    assert ev["credential"]["request_id"] == "cr-002"
    assert ev["credential"]["jti"] == "t-cr-002"
    assert ev["persona"] == "agent"
    assert ev["roles"] == ["recorder"]
    assert ev["policy"]["rule_id"] == "allow-known-actions"
    assert ev["policy"]["version"] == json.loads(
        (ROOT / "policy" / "warden.policy.json").read_text("utf-8"))["version"]
    assert ev["risk"]["inputs_fingerprint"] == out["risk"]["inputs_fingerprint"]
    assert ev["risk"]["score"] == out["risk"]["score"]
    verification = json.loads((ROOT / "policy" / "verification.json").read_text("utf-8"))
    assert ev["verifier"]["output_hash"] == verification["output_hash"]


def test_a_refusal_names_the_rule_that_refused(bound_service, audit_log):
    client, _ = _run(bound_service)
    try:
        client.call("record_decision")
    except Exception:  # noqa: BLE001
        pass
    denied = [r for r in audit_log.for_tenant("acme") if r.action == "policy_denied"]
    assert denied[-1].evidence["policy"]["rule_id"] == "record-needs-new"


def test_editing_evidence_breaks_the_chain(bound_service, audit_log):
    _run(bound_service)
    assert audit_log.verify_chain("acme")
    i = next(k for k, e in enumerate(audit_log._entries) if e.action == "record_decision")
    forged = {**audit_log._entries[i].evidence, "persona": "human"}
    audit_log._entries[i] = dataclasses.replace(audit_log._entries[i], evidence=forged)
    assert audit_log.verify_chain("acme") is False


def test_a_rehashed_evidence_edit_still_breaks_the_chain(bound_service, audit_log):
    # Recomputing the evidence hash is not enough: the entry hash covers it too.
    _run(bound_service)
    i = next(k for k, e in enumerate(audit_log._entries) if e.action == "record_decision")
    forged = {**audit_log._entries[i].evidence, "roles": ["approver"]}
    audit_log._entries[i] = dataclasses.replace(
        audit_log._entries[i], evidence=forged, evidence_hash=compute_evidence_hash(forged))
    assert audit_log.verify_chain("acme") is False


def test_old_style_rows_without_evidence_still_verify(audit_log, acme_repo):
    from warden.data import seed

    acme_repo.append_audit(subject="x", action="note", environment="", decision="n",
                           risk_band="", risk_score=0.0, before=None, after=None, reason="r",
                           risk_breakdown={}, request_id="", trace_id="",
                           timestamp=seed.EVAL_NOW)
    assert audit_log.verify_chain("acme")
