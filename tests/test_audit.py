
from __future__ import annotations

import dataclasses

import pytest

from change_gate.audit import AuditLog
from change_gate.clock import FixedClock
from change_gate.data import seed
from change_gate.db.repository import InMemoryRepository
from change_gate.security import SCOPE_APPROVE, SCOPE_READ, AuthPrincipal, AuthorizationError
from change_gate.tools import ToolService


def _service(scopes, audit_log):
    repo = InMemoryRepository("acme", audit_log=audit_log)
    principal = AuthPrincipal(subject="agent-acme", tenant_id="acme", role="lead", scopes=scopes)
    return ToolService(repo, FixedClock(seed.EVAL_NOW), principal=principal)


def test_exactly_one_audit_row_per_governed_write():
    log = AuditLog()
    svc = _service(frozenset({SCOPE_READ, SCOPE_APPROVE, "change:approve:prod"}), log)
    for s in seed.SCENARIOS:
        svc.record_decision(s.request.id, now=seed.EVAL_NOW.isoformat())
    rows = log.for_tenant("acme")
    assert len(rows) == len(seed.SCENARIOS)
    assert [r.seq for r in rows] == list(range(1, len(seed.SCENARIOS) + 1))


def test_hash_chain_verifies_then_breaks_on_tamper():
    log = AuditLog()
    svc = _service(frozenset({SCOPE_READ, SCOPE_APPROVE, "change:approve:prod"}), log)
    for s in seed.SCENARIOS:
        svc.record_decision(s.request.id, now=seed.EVAL_NOW.isoformat())
    assert log.verify_chain("acme") is True

    tampered = dataclasses.replace(log._entries[1], decision="auto_approve")
    log._entries[1] = tampered
    assert log.verify_chain("acme") is False


def test_unauthorized_prod_approval_blocked_and_logged():
    log = AuditLog()
    svc_noscope = _service(frozenset({SCOPE_READ}), log)
    s = seed.SCENARIOS_BY_NAME["high_blast_prod_config"]
    with pytest.raises(AuthorizationError):
        svc_noscope.record_decision(s.request.id, now=seed.EVAL_NOW.isoformat())
    blocked = [r for r in log.for_tenant("acme") if r.action == "record_decision_denied"]
    assert len(blocked) == 1
    assert "authorization denied" in blocked[0].reason


def test_prod_auto_approve_requires_elevated_scope():
    from change_gate.domain.models import Decision, Environment
    from change_gate.security import authorize_write

    base = AuthPrincipal("a", "acme", "lead", frozenset({SCOPE_READ, SCOPE_APPROVE}))
    with pytest.raises(AuthorizationError):
        authorize_write(base, decision=Decision.AUTO_APPROVE,
                        environment=Environment.PROD, tenant_id="acme")
    elevated = AuthPrincipal("a", "acme", "lead",
                             frozenset({SCOPE_READ, SCOPE_APPROVE, "change:approve:prod"}))
    authorize_write(elevated, decision=Decision.AUTO_APPROVE,
                    environment=Environment.PROD, tenant_id="acme")
