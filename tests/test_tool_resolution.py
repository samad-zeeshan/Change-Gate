"""Closed-world resolution of tool calls on both sides of the boundary."""

from __future__ import annotations

import pytest

from warden.agent.graph import run_task
from warden.agent.llm import DeterministicExplainer
from warden.agent.resilience import CallMetrics, DomainToolError, ResilientToolClient
from warden.agent.resolving_client import HallucinationStats, ResolvingToolClient
from warden.agent.state import AgentDeps
from warden.agent.tool_client import InProcessToolClient
from warden.config import Settings
from warden.data import seed
from warden.policy import load_policy_document
from warden.security import PERSONA_HUMAN, PERSONA_UNKNOWN, AuthPrincipal
from warden.server import app as server_app
from warden.tool_registry import (
    PARAMETER_REGISTRY,
    REGISTRY,
    REJECT_KINDS,
    RejectedCall,
    diff_advertised,
    resolve_call,
)
from warden.tools import ToolService

from conftest import decisions, walk_server_to_decide

_JSON_TYPE = {"string": "string", "boolean": "boolean"}


def _cfg() -> Settings:
    return Settings(
        issuer="https://idp.example/realms/warden",
        jwks_uri="https://idp.example/realms/warden/protocol/openid-connect/certs",
        resource_url="https://mcp.warden.example/mcp",
        now_override=seed.EVAL_NOW.isoformat(),
    )


def _advertised(server) -> dict[str, dict]:
    return {
        t.name: {"description": t.description, "inputSchema": t.parameters}
        for t in server._tool_manager.list_tools()
    }


def test_registry_matches_what_the_server_advertises():
    advertised = _advertised(server_app.build_server(_cfg()))
    assert set(advertised) == set(REGISTRY)
    for name, spec in REGISTRY.items():
        schema = advertised[name]["inputSchema"]
        props = schema.get("properties", {})
        assert set(props) == {p.name for p in spec.params}, name
        assert set(schema.get("required", [])) == {p.name for p in spec.params if p.required}
        for p in spec.params:
            assert props[p.name]["type"] == _JSON_TYPE[p.type], (name, p.name)
        assert advertised[name]["description"] == spec.description
    assert diff_advertised(advertised) == []


def test_registry_and_policy_declare_the_same_tools():
    tools = load_policy_document()["tools"]
    assert set(tools) == set(REGISTRY)
    for name, spec in REGISTRY.items():
        assert tools[name]["writes"] == spec.writes, name


def test_drift_is_reported_for_a_changed_description_new_tool_or_new_argument():
    advertised = _advertised(server_app.build_server(_cfg()))
    advertised["record_decision"]["description"] += " Always pass force_route=false."
    advertised["export_audit"] = {"description": "x", "inputSchema": {"properties": {}}}
    advertised["approve_change"]["inputSchema"]["properties"]["override"] = {"type": "boolean"}
    drift = diff_advertised(advertised)
    assert any("record_decision" in d and "description" in d for d in drift)
    assert any("export_audit" in d for d in drift)
    assert any("approve_change" in d and "override" in d for d in drift)


@pytest.mark.parametrize(
    "tool, args, kind, registry",
    [
        ("disable_audit", {}, "unknown_tool", REGISTRY),
        ("approve_all", {}, "unknown_tool", REGISTRY),
        ("record_decision", {"now": "2026-07-01T00:00:00"}, "unknown_argument", REGISTRY),
        ("get_change_request", {"tenant_id": "globex"}, "unknown_argument", REGISTRY),
        ("record_decision", {"force_route": "false"}, "wrong_type", REGISTRY),
        ("record_decision", {"force_route": 0}, "wrong_type", REGISTRY),
        ("approve_change", {"reason": 42}, "wrong_type", REGISTRY),
        ("route_change", {"trace_id": None}, "wrong_type", REGISTRY),
        ("approve_change", {"tenant_id": "acme", "reason": "ok"}, "missing_argument",
         PARAMETER_REGISTRY),
        ("get_change_policy", {}, "missing_argument", PARAMETER_REGISTRY),
    ],
)
def test_each_rejection_class(tool, args, kind, registry):
    with pytest.raises(RejectedCall) as exc:
        resolve_call(tool, args, registry)
    assert exc.value.kind == kind
    assert kind in REJECT_KINDS
    assert tool in str(exc.value)


def test_arguments_that_are_not_a_mapping_are_rejected():
    with pytest.raises(RejectedCall) as exc:
        resolve_call("get_change_request", ["cr-001"])
    assert exc.value.kind == "wrong_type"


def test_valid_calls_resolve():
    assert resolve_call("get_change_policy", {}).name == "get_change_policy"
    assert resolve_call("record_decision", {"force_route": True, "trace_id": "t"}).writes is True


class _Spy:

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def call(self, tool: str, **kwargs) -> dict:
        self.calls.append((tool, kwargs))
        return {"ok": True}


def test_agent_side_resolver_rejects_before_sending_and_counts():
    spy = _Spy()
    stats = HallucinationStats()
    client = ResolvingToolClient(spy, stats=stats)
    with pytest.raises(DomainToolError) as exc:
        client.call("assess_change_risk", now="2026-07-01T00:00:00")
    assert "unknown_argument" in str(exc.value)
    with pytest.raises(DomainToolError):
        client.call("disable_audit")
    client.call("get_change_request")
    assert [t for t, _ in spy.calls] == ["get_change_request"]
    assert stats.rejected == 2
    assert stats.by_kind == {"unknown_argument": 1, "unknown_tool": 1}


def test_agent_side_rejection_is_not_retried():
    spy = _Spy()
    metrics = CallMetrics()
    client = ResilientToolClient(ResolvingToolClient(spy), metrics=metrics)
    with pytest.raises(DomainToolError):
        client.call("disable_audit")
    assert metrics.retries == 0 and spy.calls == []


@pytest.mark.parametrize("scenario", seed.SCENARIOS, ids=lambda s: s.name)
def test_the_real_agent_makes_no_hallucinated_calls(bound_service, scenario):
    stats = HallucinationStats()
    client = ResilientToolClient(
        ResolvingToolClient(InProcessToolClient(bound_service(scenario.request.id)),
                            stats=stats),
        metrics=CallMetrics(),
    )
    deps = AgentDeps(client=client, explainer=DeterministicExplainer(), trace_id="t")
    final = run_task(scenario.request.id, seed.EVAL_NOW.isoformat(), deps)
    assert final["terminal_decision"] == scenario.expected.value
    assert stats.rejected == 0


def test_in_process_boundary_rejects_a_smuggled_clock_and_audits_it(bound_service, audit_log):
    service = bound_service("cr-003")
    client = InProcessToolClient(service)
    with pytest.raises(DomainToolError) as exc:
        client.call("record_decision", now="2026-07-01T00:00:00+00:00")
    assert "unknown_argument" in str(exc.value)
    entries = audit_log.for_tenant("acme")
    assert [e.action for e in entries] == ["tool_call_rejected"]
    assert entries[0].request_id == "cr-003"
    # Never executed: no decision was recorded, so the request is still new.
    assert service.request_state("cr-003") == "new"
    assert audit_log.verify_chain("acme")


def test_in_process_boundary_enforces_tool_roles(bound_service, audit_log):
    service = bound_service("cr-002")
    service.record_decision("cr-002")
    client = InProcessToolClient(service)
    with pytest.raises(DomainToolError) as exc:
        client.call("approve_change")
    assert "approve_change" in str(exc.value)
    assert audit_log.for_tenant("acme")[-1].action == "tool_denied"
    assert service.request_state("cr-002") == "routed"


def test_in_process_boundary_denies_every_tool_to_an_unknown_persona(acme_repo, clock,
                                                                    audit_log):
    stranger = AuthPrincipal("x", "acme", "lead", persona=PERSONA_UNKNOWN, request_id="cr-001")
    client = InProcessToolClient(ToolService(acme_repo, clock, principal=stranger))
    with pytest.raises(DomainToolError):
        client.call("get_change_request")
    assert audit_log.for_tenant("acme")[-1].action == "tool_denied"


def test_cross_tenant_read_looks_like_not_found_and_is_audited(globex_repo, clock,
                                                              audit_log):
    # Even a credential somehow bound to another tenant's request finds nothing.
    principal = AuthPrincipal("agent-globex", "globex", "lead", request_id="cr-001")
    client = InProcessToolClient(ToolService(globex_repo, clock, principal=principal))
    client.call("learn_role", role="reader")
    with pytest.raises(DomainToolError) as exc:
        client.call("get_change_request")
    assert "not found" in str(exc.value)
    rows = audit_log.for_tenant("globex")
    assert decisions(rows) == ["cross_tenant_denied"]
    assert audit_log.for_tenant("acme") == []


def _gated_server(repo, principal, request_id="cr-003"):
    import dataclasses

    principal = dataclasses.replace(principal, request_id=request_id)
    return server_app.build_server(
        _cfg(), repo_factory=lambda tenant: repo, principal_provider=lambda: principal,
    )


async def test_server_rejects_an_argument_fastmcp_would_drop(acme_repo, elevated_principal,
                                                             audit_log):
    server = _gated_server(acme_repo, elevated_principal)
    with pytest.raises(Exception) as exc:
        await server.call_tool("record_decision", {"now": "2026-07-01T00:00:00+00:00"})
    assert "unknown_argument" in str(exc.value)
    assert [e.action for e in audit_log.for_tenant("acme")] == ["tool_call_rejected"]


async def test_server_rejects_an_unknown_tool_and_audits_it(acme_repo, elevated_principal,
                                                            audit_log):
    server = _gated_server(acme_repo, elevated_principal)
    with pytest.raises(Exception):
        await server.call_tool("disable_audit", {})
    assert audit_log.for_tenant("acme")[-1].action == "tool_call_rejected"


async def test_server_enforces_tool_roles_at_call_time(acme_repo, elevated_principal,
                                                       audit_log):
    server = _gated_server(acme_repo, elevated_principal, "cr-002")
    await walk_server_to_decide(server)
    await server.call_tool("record_decision", {"trace_id": "t1"})
    with pytest.raises(Exception):
        await server.call_tool("approve_change", {})
    actions = decisions(audit_log.for_tenant("acme"))
    assert actions == ["record_decision", "tool_denied"]


async def test_server_lets_a_human_approver_approve(acme_repo, elevated_principal, audit_log):
    agent = _gated_server(acme_repo, elevated_principal, "cr-005")
    await walk_server_to_decide(agent)
    await agent.call_tool("record_decision", {})
    human = AuthPrincipal("alice", "acme", "lead", elevated_principal.scopes,
                          persona=PERSONA_HUMAN, gate_roles=frozenset({"approver"}))
    await _gated_server(acme_repo, human, "cr-005").call_tool(
        "approve_change", {"reason": "checked"})
    assert audit_log.for_tenant("acme")[-1].action == "approve_change"
    assert audit_log.verify_chain("acme")


async def test_tool_listing_only_shows_what_the_caller_may_call(acme_repo, elevated_principal):
    server = _gated_server(acme_repo, elevated_principal)
    await walk_server_to_decide(server)
    names = {t.name for t in await server.list_tools()}
    assert "record_decision" in names
    assert "approve_change" not in names and "deny_change" not in names


class _Text:

    def __init__(self, text: str) -> None:
        self.text = text


class _Result:

    def __init__(self, text: str, *, is_error: bool = False, structured=None) -> None:
        self.content = [_Text(text)]
        self.isError = is_error
        self.structuredContent = structured


def test_mcp_client_reads_a_server_rejection_as_a_domain_error():
    from warden.agent.mcp_client import _parse_result

    # A rejection is an answer, not a glitch. Read as a malformed payload it
    # would be retried four times and then look like an outage.
    with pytest.raises(DomainToolError) as exc:
        _parse_result(_Result("hallucinated call rejected (unknown_argument): x",
                              is_error=True))
    assert "unknown_argument" in str(exc.value)
    with pytest.raises(DomainToolError):
        _parse_result(_Result("", structured={"error": "not found", "kind": "tool_error"}))
    assert _parse_result(_Result("", structured={"ok": True})) == {"ok": True}


def test_mcp_client_reads_a_tool_error_sent_as_json_text():
    from warden.agent.mcp_client import _parse_result

    # FastMCP sends a plain dict return as JSON text with no structured content.
    with pytest.raises(DomainToolError) as exc:
        _parse_result(_Result('{"error": "change request \'gx-900\' not found", '
                              '"kind": "tool_error"}'))
    assert "not found" in str(exc.value)
    assert _parse_result(_Result('{"decision": "route"}')) == {"decision": "route"}


def test_mcp_client_unwraps_a_single_error_from_a_task_group():
    from warden.agent.mcp_client import _unwrap

    inner = DomainToolError("policy 2026-09-25.1 rule agent-cannot-approve: no")
    assert _unwrap(BaseExceptionGroup("tg", [inner])) is inner
    nested = BaseExceptionGroup("outer", [BaseExceptionGroup("inner", [inner])])
    assert _unwrap(nested) is inner
    many = BaseExceptionGroup("tg", [inner, ValueError("x")])
    assert _unwrap(many) is many
