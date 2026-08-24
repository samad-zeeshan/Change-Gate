"""Progressive role delivery: the agent starts with a role catalog and learns only what the task needs."""

from __future__ import annotations

import dataclasses

import pytest

from warden.agent.resilience import DomainToolError
from warden.agent.tool_client import InProcessToolClient
from warden.config import Settings
from warden.data import seed
from warden.security import PERSONA_HUMAN, AuthPrincipal
from warden.server import app as server_app
from warden.sessions import RoleSessions
from warden.tool_registry import REGISTRY, RejectedCall, resolve_call
from warden.tools import ToolService


@pytest.fixture
def agent_client(bound_service):
    return InProcessToolClient(bound_service("cr-002"), sessions=RoleSessions())


def test_catalog_tools_are_registered_and_learn_role_needs_a_role():
    assert {"list_roles", "learn_role"} <= set(REGISTRY)
    with pytest.raises(RejectedCall) as exc:
        resolve_call("learn_role", {})
    assert exc.value.kind == "missing_argument"


def test_a_fresh_credential_holds_only_the_catalog(agent_client, audit_log):
    catalog = agent_client.call("list_roles")
    assert set(catalog["learnable"]) == {"reader", "recorder"}
    assert catalog["learned"] == []
    with pytest.raises(DomainToolError) as exc:
        agent_client.call("get_change_request")
    assert "holds no role" in str(exc.value)
    assert audit_log.for_tenant("acme")[-1].action == "tool_denied"


def test_learning_reader_delivers_the_reads_and_is_audited(agent_client, audit_log):
    out = agent_client.call("learn_role", role="reader")
    assert out["granted"] == "reader"
    assert "get_change_request" in out["tools"]
    assert agent_client.call("get_change_request")["id"] == "cr-002"
    learned = [e for e in audit_log.for_tenant("acme") if e.action == "role_learned"]
    assert len(learned) == 1 and "reader" in learned[0].reason


@pytest.mark.parametrize("role", ["approver", "router"])
def test_roles_outside_the_delivery_list_are_refused(agent_client, audit_log, role):
    with pytest.raises(DomainToolError):
        agent_client.call("learn_role", role=role)
    assert audit_log.for_tenant("acme")[-1].action == "role_denied"


def test_recorder_waits_until_the_risk_was_assessed(agent_client):
    agent_client.call("learn_role", role="reader")
    with pytest.raises(DomainToolError) as exc:
        agent_client.call("learn_role", role="recorder")
    assert "assess_change_risk" in str(exc.value)
    agent_client.call("assess_change_risk")
    agent_client.call("learn_role", role="recorder")
    assert agent_client.call("record_decision")["decision"] == "route"


def test_a_new_credential_starts_from_nothing(bound_service):
    sessions = RoleSessions()
    first = InProcessToolClient(bound_service("cr-002"), sessions=sessions)
    first.call("learn_role", role="reader")
    other = InProcessToolClient(bound_service("cr-005"), sessions=sessions)
    with pytest.raises(DomainToolError):
        other.call("get_change_request")


def test_humans_are_not_subject_to_delivery(bound_service, audit_log):
    agent = InProcessToolClient(bound_service("cr-005"), sessions=RoleSessions())
    for step in (("learn_role", {"role": "reader"}), ("assess_change_risk", {}),
                 ("learn_role", {"role": "recorder"}), ("record_decision", {})):
        agent.call(step[0], **step[1])
    human = AuthPrincipal("alice", "acme", "lead", frozenset({"change:read", "change:approve"}),
                          persona=PERSONA_HUMAN, gate_roles=frozenset({"approver"}),
                          request_id="cr-005", token_id="human-1")
    client = InProcessToolClient(bound_service("cr-005", human), sessions=RoleSessions())
    assert client.call("approve_change", reason="checked")["decision"] == "approve"


async def test_the_server_lists_tools_only_after_they_are_learned(acme_repo, elevated_principal):
    bound = dataclasses.replace(elevated_principal, request_id="cr-002", token_id="srv-1")
    server = server_app.build_server(
        Settings(issuer="https://idp.example/realms/warden", jwks_uri="https://idp.example/c",
                 resource_url="https://mcp.warden.example/mcp",
                 now_override=seed.EVAL_NOW.isoformat()),
        repo_factory=lambda t: acme_repo, principal_provider=lambda: bound)
    before = {t.name for t in await server.list_tools()}
    assert before == {"list_roles", "learn_role"}
    await server.call_tool("learn_role", {"role": "reader"})
    after = {t.name for t in await server.list_tools()}
    assert "get_change_request" in after and "record_decision" not in after


def test_delivery_can_be_switched_off_for_the_v1_shape(bound_service):
    client = InProcessToolClient(bound_service("cr-002"), sessions=RoleSessions(),
                                 role_delivery=False)
    assert client.call("get_change_request")["id"] == "cr-002"


def test_service_has_no_catalog_methods():
    # Delivery lives in the boundary. The tool service never grants anything.
    assert not hasattr(ToolService, "learn_role")
