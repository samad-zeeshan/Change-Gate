
from __future__ import annotations

import dataclasses

import pytest

from warden.audit import AuditLog
from warden.clock import FixedClock
from warden.data import seed
from warden.db.repository import InMemoryRepository
from warden.domain.models import Environment, RiskBand
from warden.policy import PolicyDenied
from warden.security import (
    PERSONA_HUMAN,
    PERSONA_UNKNOWN,
    SCOPE_APPROVE,
    SCOPE_APPROVE_PROD,
    SCOPE_READ,
    AuthPrincipal,
)
from warden.tools import ToolService

ALL = frozenset({SCOPE_READ, SCOPE_APPROVE, SCOPE_APPROVE_PROD})


def _human(subject: str = "alice") -> AuthPrincipal:
    return AuthPrincipal(subject, "acme", "lead", ALL, persona=PERSONA_HUMAN,
                         gate_roles=frozenset({"approver", "recorder"}))


@pytest.fixture
def repo(audit_log) -> InMemoryRepository:
    return InMemoryRepository("acme", audit_log=audit_log)


@pytest.fixture
def agent(repo, clock, elevated_principal) -> ToolService:
    return ToolService(repo, clock, principal=elevated_principal)


@pytest.fixture
def human(repo, clock) -> ToolService:
    return ToolService(repo, clock, principal=_human())


def _config(repo, key, env):
    return repo.get_config_state(key, env).value


def _last(audit_log):
    return audit_log.for_tenant("acme")[-1]


def test_request_state_follows_the_audit_chain(agent):
    assert agent.request_state("cr-002") == "new"
    agent.record_decision("cr-002")
    assert agent.request_state("cr-002") == "routed"
    agent.record_decision("cr-001")
    assert agent.request_state("cr-001") == "auto_approved"
    agent.record_decision("cr-003")
    assert agent.request_state("cr-003") == "denied"


def test_recording_a_request_twice_is_denied_and_audited(agent, audit_log):
    agent.record_decision("cr-002")
    with pytest.raises(PolicyDenied) as exc:
        agent.record_decision("cr-002")
    assert exc.value.rule_id == "record-needs-new"
    last = _last(audit_log)
    assert last.action == "policy_denied"
    assert last.decision == "blocked"
    assert "record-needs-new" in last.reason
    assert audit_log.verify_chain("acme")


@pytest.fixture
def lenient_band(monkeypatch):
    # A tenant whose policy lets the engine auto-approve up to the high band, so
    # a prod request reaches auto_approve and the persona rule is what decides.
    ctx = seed.TENANTS["acme"]
    lenient = dataclasses.replace(
        ctx, policy=dataclasses.replace(ctx.policy, auto_approve_max_band=RiskBand.HIGH)
    )
    monkeypatch.setitem(seed.TENANTS, "acme", lenient)


def test_agent_prod_auto_approve_is_downgraded_to_route(lenient_band, agent, repo,
                                                        audit_log):
    result = agent.record_decision("cr-002")
    assert result["decision"] == "route"
    assert result["applied_config_change"] is False
    assert _config(repo, "db_pool_size", Environment.PROD) == 20
    assert any("agent-no-prod-apply" in r for r in result["reasons"])
    actions = [e.action for e in audit_log.for_tenant("acme")]
    assert actions == ["policy_version", "policy_denied", "record_decision"]
    assert agent.request_state("cr-002") == "routed"
    assert audit_log.verify_chain("acme")


def test_human_prod_auto_approve_is_allowed_in_the_same_setup(lenient_band, human, repo):
    result = human.record_decision("cr-002")
    assert result["decision"] == "auto_approve"
    assert _config(repo, "db_pool_size", Environment.PROD) == 40


def test_agent_cannot_approve_a_routed_change(agent, repo, audit_log):
    agent.record_decision("cr-002")
    with pytest.raises(PolicyDenied) as exc:
        agent.approve_change("cr-002", reason="looks fine")
    assert exc.value.rule_id == "agent-cannot-approve"
    assert _config(repo, "db_pool_size", Environment.PROD) == 20
    assert _last(audit_log).action == "policy_denied"


def test_human_approver_approves_a_routed_change(agent, human, repo, audit_log):
    agent.record_decision("cr-005")
    assert agent.request_state("cr-005") == "routed"
    result = human.approve_change("cr-005", reason="checked with payments on-call")
    assert result["decision"] == "approve"
    assert result["applied_config_change"] is True
    assert _config(repo, "fraud_threshold", Environment.STAGING) == 110.0
    last = _last(audit_log)
    assert (last.action, last.subject, last.before, last.after) == (
        "approve_change", "alice", 100.0, 110.0)
    assert human.request_state("cr-005") == "approved"
    assert audit_log.verify_chain("acme")


def test_requester_cannot_approve_their_own_change(agent, repo, clock):
    agent.record_decision("cr-005")
    requester = ToolService(repo, clock, principal=_human(subject="u-lead"))
    with pytest.raises(PolicyDenied) as exc:
        requester.approve_change("cr-005")
    assert exc.value.rule_id == "no-self-approval"
    assert _config(repo, "fraud_threshold", Environment.STAGING) == 100.0


def test_approve_is_blocked_inside_a_freeze_window(agent, human, repo):
    agent.route_change("cr-003", reason="needs a person")
    with pytest.raises(PolicyDenied) as exc:
        human.approve_change("cr-003")
    assert exc.value.rule_id == "freeze-blocks-apply"
    assert _config(repo, "checkout_v2", Environment.PROD) is False


def test_approve_is_blocked_for_an_invalid_request(agent, human, repo):
    # cr-004 is a developer asking for a prod change. Routing it skips scoring,
    # so the apply rule is what stops a later approval.
    agent.route_change("cr-004")
    with pytest.raises(PolicyDenied) as exc:
        human.approve_change("cr-004")
    assert exc.value.rule_id == "invalid-request-blocks-apply"


def test_approve_needs_a_routed_request(human):
    with pytest.raises(PolicyDenied) as exc:
        human.approve_change("cr-005")
    assert exc.value.rule_id == "human-decision-needs-routed"


def test_route_twice_is_denied(agent):
    out = agent.route_change("cr-002", reason="escalate")
    assert out["decision"] == "route"
    with pytest.raises(PolicyDenied) as exc:
        agent.route_change("cr-002")
    assert exc.value.rule_id == "route-needs-new"


def test_human_denies_a_routed_change(agent, human, repo):
    agent.record_decision("cr-002")
    out = human.deny_change("cr-002", reason="pool size needs a load test first")
    assert out["decision"] == "deny"
    assert out["applied_config_change"] is False
    assert human.request_state("cr-002") == "denied"
    with pytest.raises(PolicyDenied):
        human.approve_change("cr-002")


def test_unknown_persona_cannot_write(repo, clock, audit_log):
    stranger = AuthPrincipal("x", "acme", "lead", ALL, persona=PERSONA_UNKNOWN)
    svc = ToolService(repo, clock, principal=stranger)
    with pytest.raises(PolicyDenied) as exc:
        svc.record_decision("cr-001")
    assert exc.value.rule_id == "unknown-persona"
    assert _config(repo, "beta_banner", Environment.DEV) is False
    assert _last(audit_log).action == "policy_denied"


def test_service_without_a_principal_cannot_write(repo, clock):
    svc = ToolService(repo, clock)
    with pytest.raises(PolicyDenied):
        svc.record_decision("cr-001")


def test_every_denial_is_one_audit_entry_and_the_chain_verifies(agent, human, repo, clock):
    log = repo.audit_log
    attempts = [
        lambda: agent.approve_change("cr-002"),
        lambda: human.approve_change("cr-001"),
        lambda: agent.deny_change("cr-002"),
    ]
    agent.record_decision("cr-001")
    before = len(log.for_tenant("acme"))
    for attempt in attempts:
        with pytest.raises(PolicyDenied):
            attempt()
    denied = log.for_tenant("acme")[before:]
    assert [e.action for e in denied] == ["policy_denied"] * len(attempts)
    assert log.verify_chain("acme")


def test_policy_denials_name_the_policy_version(agent, audit_log):
    from warden.policy import load_policy_document

    with pytest.raises(PolicyDenied):
        agent.approve_change("cr-002")
    assert load_policy_document()["version"] in _last(audit_log).reason


def test_policy_check_happens_before_any_side_effect(agent, repo, monkeypatch):
    applied = []
    monkeypatch.setattr(repo, "apply_config_change",
                        lambda *a, **k: applied.append(a) or None)
    agent.record_decision("cr-005")
    with pytest.raises(PolicyDenied):
        agent.approve_change("cr-005")
    assert applied == []


def test_a_fresh_audit_log_means_a_fresh_state():
    log = AuditLog()
    repo = InMemoryRepository("acme", audit_log=log)
    svc = ToolService(repo, FixedClock(seed.EVAL_NOW), principal=_human())
    assert svc.request_state("cr-001") == "new"
