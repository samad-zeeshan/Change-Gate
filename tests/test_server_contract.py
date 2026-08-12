
from __future__ import annotations

import pytest

from change_gate.agent.graph import run_task
from change_gate.agent.llm import DeterministicExplainer
from change_gate.agent.resilience import CallMetrics, ResilientToolClient
from change_gate.agent.state import AgentDeps
from change_gate.agent.tool_client import InProcessToolClient
from change_gate.config import Settings
from change_gate.data import seed
from change_gate.server import app as server_app


def _server():
    cfg = Settings(
        issuer="https://idp.example/realms/change-gate",
        jwks_uri="https://idp.example/realms/change-gate/protocol/openid-connect/certs",
        resource_url="https://mcp.change-gate.example/mcp",
        now_override=seed.EVAL_NOW.isoformat(),
    )
    return server_app.build_server(cfg)


def _declared_params(server) -> dict[str, set[str]]:
    return {
        t.name: set(t.parameters.get("properties", {}))
        for t in server._tool_manager.list_tools()
    }


class _Recorder:

    def __init__(self, inner) -> None:
        self.inner = inner
        self.calls: list[tuple[str, dict]] = []

    def call(self, tool: str, **kwargs) -> dict:
        self.calls.append((tool, dict(kwargs)))
        return self.inner.call(tool, **kwargs)


@pytest.mark.parametrize("scenario", seed.SCENARIOS, ids=lambda s: s.name)
def test_agent_only_sends_arguments_the_server_declares(acme_service, scenario):
    # FastMCP drops arguments a tool does not declare without saying so. Anything
    # the agent sends that is not in the server signature works offline and is
    # silently lost over MCP, so the two must match exactly.
    recorder = _Recorder(InProcessToolClient(acme_service))
    deps = AgentDeps(
        client=ResilientToolClient(recorder, metrics=CallMetrics()),
        explainer=DeterministicExplainer(),
        trace_id="t-contract",
    )
    run_task(scenario.request.id, seed.EVAL_NOW.isoformat(), deps)

    declared = _declared_params(_server())
    assert recorder.calls
    for tool, kwargs in recorder.calls:
        assert tool in declared, f"agent calls {tool!r}, which the server does not expose"
        extra = set(kwargs) - declared[tool]
        assert not extra, f"{tool} would silently drop {sorted(extra)} over MCP"


async def test_record_decision_over_mcp_keeps_trace_id(monkeypatch, acme_repo,
                                                       elevated_principal, audit_log):
    monkeypatch.setattr(server_app, "connect", lambda dsn, tenant: acme_repo)
    monkeypatch.setattr(server_app, "_principal_from_context", lambda: elevated_principal)
    server = _server()

    await server.call_tool("record_decision", {"request_id": "cr-002", "trace_id": "t-mcp-1"})

    entry = audit_log.for_tenant("acme")[-1]
    assert entry.request_id == "cr-002"
    assert entry.trace_id == "t-mcp-1"


async def test_server_audits_a_write_refused_for_a_missing_scope(acme_repo, audit_log):
    from change_gate.security import SCOPE_READ, AuthPrincipal

    read_only = AuthPrincipal("svc-read", "acme", "lead", frozenset({SCOPE_READ}))
    server = server_app.build_server(
        Settings(issuer="https://idp.example/realms/change-gate",
                 jwks_uri="https://idp.example/certs",
                 resource_url="https://mcp.change-gate.example/mcp",
                 now_override=seed.EVAL_NOW.isoformat()),
        repo_factory=lambda tenant: acme_repo, principal_provider=lambda: read_only,
    )
    with pytest.raises(Exception):
        await server.call_tool("record_decision", {"request_id": "cr-002"})
    rows = audit_log.for_tenant("acme")
    assert [r.action for r in rows] == ["scope_denied"]
    assert rows[0].request_id == "cr-002"
    assert "change:approve" in rows[0].reason
