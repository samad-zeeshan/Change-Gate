
from __future__ import annotations

import pytest

from change_gate.agent.graph import run_task
from change_gate.agent.llm import DeterministicExplainer
from change_gate.agent.resilience import CallMetrics, DomainToolError, ResilientToolClient
from change_gate.agent.resolving_client import HallucinationStats, ResolvingToolClient
from change_gate.agent.state import AgentDeps
from change_gate.agent.tool_client import InProcessToolClient
from change_gate.config import Settings
from change_gate.data import seed
from change_gate.policy import load_policy_document
from change_gate.security import PERSONA_HUMAN, PERSONA_UNKNOWN, AuthPrincipal
from change_gate.server import app as server_app
from change_gate.tool_registry import (
    REGISTRY,
    REJECT_KINDS,
    RejectedCall,
    diff_advertised,
    resolve_call,
)
from change_gate.tools import ToolService

_JSON_TYPE = {"string": "string", "boolean": "boolean"}


def _cfg() -> Settings:
    return Settings(
        issuer="https://idp.example/realms/change-gate",
        jwks_uri="https://idp.example/realms/change-gate/protocol/openid-connect/certs",
        resource_url="https://mcp.change-gate.example/mcp",
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
    "tool, args, kind",
    [
        ("disable_audit", {}, "unknown_tool"),
        ("approve_all", {"request_id": "cr-002"}, "unknown_tool"),
        ("record_decision", {"request_id": "cr-003", "now": "2026-07-01T00:00:00"},
         "unknown_argument"),
        ("get_change_request", {"request_id": "cr-001", "tenant_id": "globex"},
         "unknown_argument"),
        ("record_decision", {"request_id": "cr-001", "force_route": "false"}, "wrong_type"),
        ("record_decision", {"request_id": "cr-001", "force_route": 0}, "wrong_type"),
        ("get_change_request", {"request_id": 42}, "wrong_type"),
        ("route_change", {"request_id": None}, "wrong_type"),
        ("approve_change", {"reason": "ok"}, "missing_argument"),
        ("get_config_state", {"key": "db_pool_size"}, "missing_argument"),
    ],
)
def test_each_rejection_class(tool, args, kind):
    with pytest.raises(RejectedCall) as exc:
        resolve_call(tool, args)
    assert exc.value.kind == kind
    assert kind in REJECT_KINDS
    assert tool in str(exc.value)


def test_arguments_that_are_not_a_mapping_are_rejected():
    with pytest.raises(RejectedCall) as exc:
        resolve_call("get_change_request", ["cr-001"])
    assert exc.value.kind == "wrong_type"


def test_valid_calls_resolve():
    assert resolve_call("get_change_policy", {}).name == "get_change_policy"
    assert resolve_call("record_decision", {"request_id": "cr-001", "force_route": True,
                                            "trace_id": "t"}).writes is True


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
        client.call("assess_change_risk", request_id="cr-003", now="2026-07-01T00:00:00")
    assert "unknown_argument" in str(exc.value)
    with pytest.raises(DomainToolError):
        client.call("disable_audit")
    client.call("get_change_request", request_id="cr-001")
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
def test_the_real_agent_makes_no_hallucinated_calls(acme_service, scenario):
    stats = HallucinationStats()
    client = ResilientToolClient(
        ResolvingToolClient(InProcessToolClient(acme_service), stats=stats),
        metrics=CallMetrics(),
    )
    deps = AgentDeps(client=client, explainer=DeterministicExplainer(), trace_id="t")
    final = run_task(scenario.request.id, seed.EVAL_NOW.isoformat(), deps)
    assert final["terminal_decision"] == scenario.expected.value
    assert stats.rejected == 0


def test_in_process_boundary_rejects_a_smuggled_clock_and_audits_it(acme_service, audit_log):
    client = InProcessToolClient(acme_service)
    with pytest.raises(DomainToolError) as exc:
        client.call("record_decision", request_id="cr-003", now="2026-07-01T00:00:00+00:00")
    assert "unknown_argument" in str(exc.value)
    entries = audit_log.for_tenant("acme")
    assert [e.action for e in entries] == ["tool_call_rejected"]
    assert entries[0].request_id == "cr-003"
    # Never executed: no decision was recorded, so the request is still new.
    assert acme_service.request_state("cr-003") == "new"
    assert audit_log.verify_chain("acme")


def test_in_process_boundary_enforces_tool_roles(acme_service, audit_log):
    acme_service.record_decision("cr-002")
    client = InProcessToolClient(acme_service)
    with pytest.raises(DomainToolError) as exc:
        client.call("approve_change", request_id="cr-002")
    assert "approve_change" in str(exc.value)
    assert audit_log.for_tenant("acme")[-1].action == "tool_denied"
    assert acme_service.request_state("cr-002") == "routed"


def test_in_process_boundary_denies_every_tool_to_an_unknown_persona(acme_repo, clock,
                                                                    audit_log):
    stranger = AuthPrincipal("x", "acme", "lead", persona=PERSONA_UNKNOWN)
    client = InProcessToolClient(ToolService(acme_repo, clock, principal=stranger))
    with pytest.raises(DomainToolError):
        client.call("get_change_request", request_id="cr-001")
    assert audit_log.for_tenant("acme")[-1].action == "tool_denied"


def test_cross_tenant_read_looks_like_not_found_and_is_audited(globex_repo, clock,
                                                              audit_log):
    principal = AuthPrincipal("agent-globex", "globex", "lead")
    client = InProcessToolClient(ToolService(globex_repo, clock, principal=principal))
    with pytest.raises(DomainToolError) as exc:
        client.call("get_change_request", request_id="cr-001")
    assert "not found" in str(exc.value)
    rows = audit_log.for_tenant("globex")
    assert [r.action for r in rows] == ["cross_tenant_denied"]
    assert audit_log.for_tenant("acme") == []


def _gated_server(repo, principal):
    return server_app.build_server(
        _cfg(), repo_factory=lambda tenant: repo, principal_provider=lambda: principal,
    )


async def test_server_rejects_an_argument_fastmcp_would_drop(acme_repo, elevated_principal,
                                                             audit_log):
    server = _gated_server(acme_repo, elevated_principal)
    with pytest.raises(Exception) as exc:
        await server.call_tool("record_decision",
                               {"request_id": "cr-003", "now": "2026-07-01T00:00:00+00:00"})
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
    server = _gated_server(acme_repo, elevated_principal)
    await server.call_tool("record_decision", {"request_id": "cr-002", "trace_id": "t1"})
    with pytest.raises(Exception):
        await server.call_tool("approve_change", {"request_id": "cr-002"})
    actions = [e.action for e in audit_log.for_tenant("acme")]
    assert actions == ["record_decision", "tool_denied"]


async def test_server_lets_a_human_approver_approve(acme_repo, elevated_principal, audit_log):
    await _gated_server(acme_repo, elevated_principal).call_tool(
        "record_decision", {"request_id": "cr-005"})
    human = AuthPrincipal("alice", "acme", "lead", elevated_principal.scopes,
                          persona=PERSONA_HUMAN, gate_roles=frozenset({"approver"}))
    await _gated_server(acme_repo, human).call_tool(
        "approve_change", {"request_id": "cr-005", "reason": "checked"})
    assert audit_log.for_tenant("acme")[-1].action == "approve_change"
    assert audit_log.verify_chain("acme")


async def test_tool_listing_only_shows_what_the_caller_may_call(acme_repo, elevated_principal):
    names = {t.name for t in await _gated_server(acme_repo, elevated_principal).list_tools()}
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
    from change_gate.agent.mcp_client import _parse_result

    # A rejection is an answer, not a glitch. Read as a malformed payload it
    # would be retried four times and then look like an outage.
    with pytest.raises(DomainToolError) as exc:
        _parse_result(_Result("hallucinated call rejected (unknown_argument): x",
                              is_error=True))
    assert "unknown_argument" in str(exc.value)
    with pytest.raises(DomainToolError):
        _parse_result(_Result("", structured={"error": "not found", "kind": "tool_error"}))
    assert _parse_result(_Result("", structured={"ok": True})) == {"ok": True}
