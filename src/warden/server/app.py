
from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Optional

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from pydantic import AnyHttpUrl

from .. import telemetry
from ..clock import FixedClock, SystemClock, ensure_utc
from ..boundary import ToolBoundary
from ..config import Settings, settings
from ..db.postgres_repository import connect
from ..db.repository import Repository
from ..personas import load_persona_map
from ..security import (
    PERSONA_UNKNOWN,
    SCOPE_APPROVE,
    SCOPE_READ,
    AuthPrincipal,
    AuthorizationError,
)
from ..tool_registry import REGISTRY
from ..tools import ToolError, ToolService
from .auth import JWKSResolver, ResourceServerConfig, TokenValidator


class JWTVerifier(TokenVerifier):

    def __init__(self, validator: TokenValidator) -> None:
        self._validator = validator

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        try:
            principal = self._validator.validate(token)
        except Exception:  # noqa: BLE001 - any validation failure => unauthenticated
            return None
        return AccessToken(
            token=token,
            client_id=principal.subject,
            scopes=sorted(principal.scopes),
            subject=principal.subject,
            resource=self._validator.config.audience,
            claims={
                "tenant_id": principal.tenant_id,
                "role": principal.role,
                "persona": principal.persona,
                "gate_roles": sorted(principal.gate_roles),
            },
        )


def _principal_from_context() -> AuthPrincipal:
    at = get_access_token()
    if at is None:  # pragma: no cover - SDK enforces auth before tools run
        raise AuthorizationError("no authenticated principal in context")
    claims = at.claims or {}
    return AuthPrincipal(
        subject=at.subject or at.client_id,
        tenant_id=str(claims.get("tenant_id", "")),
        role=str(claims.get("role", "")),
        scopes=frozenset(at.scopes),
        # A missing persona means the token never went through the persona map,
        # so it gets no persona and no roles rather than a default one.
        persona=str(claims.get("persona") or PERSONA_UNKNOWN),
        gate_roles=frozenset(claims.get("gate_roles") or ()),
    )


class GatedFastMCP(FastMCP):
    """FastMCP with the boundary checks run on the raw arguments first.

    FastMCP validates arguments against each tool's signature but drops any it
    does not recognise. The gate sees the call before that happens.
    """

    def __init__(self, *args, gate: Callable[[str, dict], None],
                 visible: Callable[[str], bool], **kwargs) -> None:
        self._gate = gate
        self._visible = visible
        super().__init__(*args, **kwargs)

    async def call_tool(self, name: str, arguments: dict[str, Any]):
        self._gate(name, arguments)
        return await super().call_tool(name, arguments)

    async def list_tools(self):
        # Listing is filtered for the caller, but that is only visibility. A
        # scripted client can call a hidden tool by name, which is why the gate
        # above checks roles again on every call.
        tools = await super().list_tools()
        return [t for t in tools if self._visible(t.name)]


def build_server(
    cfg: Settings | None = None,
    *,
    repo_factory: Callable[[str], Repository] | None = None,
    principal_provider: Callable[[], AuthPrincipal] | None = None,
    validator: TokenValidator | None = None,
) -> FastMCP:
    # The keyword arguments exist so the red-team runner and the tests can run
    # this exact server without Postgres or Keycloak. Production passes none.
    cfg = cfg or settings()
    telemetry.setup_telemetry(cfg.service_name)
    persona_map = load_persona_map()

    validator = validator or TokenValidator(
        ResourceServerConfig(
            issuer=cfg.issuer,
            audience=cfg.resource_url,
            leeway_seconds=cfg.leeway_seconds,
        ),
        JWKSResolver(jwks_uri=cfg.jwks_uri),
        persona_map=persona_map,
    )

    clock = (
        FixedClock(ensure_utc(datetime.fromisoformat(cfg.now_override)))
        if cfg.now_override
        else SystemClock()
    )

    def _principal() -> AuthPrincipal:
        return principal_provider() if principal_provider else _principal_from_context()

    def _repo(tenant_id: str) -> Repository:
        return repo_factory(tenant_id) if repo_factory else connect(cfg.pg_dsn, tenant_id)

    def _service() -> ToolService:
        principal = _principal()
        return ToolService(_repo(principal.tenant_id), clock, principal=principal)

    def _gate(name: str, arguments: dict) -> None:
        ToolBoundary(_service(), persona_map).admit(name, arguments)

    def _visible(name: str) -> bool:
        try:
            return persona_map.may_call(_principal(), name)
        except AuthorizationError:
            return False

    mcp = GatedFastMCP(
        name="warden",
        instructions="Multi-tenant config-change / feature-flag approval gate.",
        host=cfg.host,
        port=cfg.port,
        token_verifier=JWTVerifier(validator),
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(cfg.issuer),
            resource_server_url=AnyHttpUrl(cfg.resource_url),
            required_scopes=[SCOPE_READ],
        ),
        gate=_gate,
        visible=_visible,
    )

    def _now() -> str:
        return clock.now().isoformat()

    def tool(name: str):
        # Descriptions come from the pinned registry, so what the server
        # advertises is exactly what the agent side checks against.
        return mcp.tool(name=name, description=REGISTRY[name].description)


    @tool("get_change_request")
    def get_change_request(request_id: str) -> dict:
        with telemetry.span("tool.get_change_request", tool="get_change_request"):
            return _wrap(lambda s: s.get_change_request(request_id))

    @tool("get_change_policy")
    def get_change_policy() -> dict:
        return _wrap(lambda s: s.get_change_policy())

    @tool("get_config_state")
    def get_config_state(key: str, environment: str) -> dict:
        return _wrap(lambda s: s.get_config_state(key, environment))

    @tool("get_dependency_graph")
    def get_dependency_graph() -> dict:
        return _wrap(lambda s: s.get_dependency_graph())

    @tool("get_freeze_windows")
    def get_freeze_windows() -> dict:
        return _wrap(lambda s: s.get_freeze_windows())

    @tool("get_recent_changes")
    def get_recent_changes() -> dict:
        return _wrap(lambda s: s.get_recent_changes())

    @tool("validate_change_request")
    def validate_change_request(request_id: str) -> dict:
        return _wrap(lambda s: s.validate_change_request(request_id))

    @tool("assess_change_risk")
    def assess_change_risk(request_id: str) -> dict:
        with telemetry.span("tool.assess_change_risk", tool="assess_change_risk"):
            return _wrap(lambda s: s.assess_change_risk(request_id, now=_now()))


    @tool("record_decision")
    def record_decision(
        request_id: str, explanation: str = "", force_route: bool = False, trace_id: str = ""
    ) -> dict:
        with telemetry.span("tool.record_decision", tool="record_decision"):
            return _wrap(
                lambda s: s.record_decision(
                    request_id, now=_now(), trace_id=trace_id, explanation=explanation,
                    force_route=force_route,
                ),
                require=(SCOPE_APPROVE,), request_id=request_id,
            )

    @tool("route_change")
    def route_change(request_id: str, reason: str = "", trace_id: str = "") -> dict:
        return _wrap(
            lambda s: s.route_change(request_id, reason=reason, trace_id=trace_id),
            require=(SCOPE_APPROVE,), request_id=request_id,
        )

    @tool("approve_change")
    def approve_change(request_id: str, reason: str = "", trace_id: str = "") -> dict:
        return _wrap(
            lambda s: s.approve_change(request_id, reason=reason, trace_id=trace_id),
            require=(SCOPE_APPROVE,), request_id=request_id,
        )

    @tool("deny_change")
    def deny_change(request_id: str, reason: str = "", trace_id: str = "") -> dict:
        return _wrap(
            lambda s: s.deny_change(request_id, reason=reason, trace_id=trace_id),
            require=(SCOPE_APPROVE,), request_id=request_id,
        )

    def _wrap(run, require: tuple[str, ...] = (), request_id: str = "") -> dict:
        principal = _principal()
        service = ToolService(_repo(principal.tenant_id), clock, principal=principal)
        for scope in require:
            if not principal.has_scope(scope):
                # Refused before ToolService runs, so it is audited here. Without
                # this, a write refused for scope would leave no trace.
                msg = f"missing required scope: {scope}"
                ToolBoundary(service, persona_map).audit_refusal(
                    "scope_denied", {"request_id": request_id}, msg)
                raise AuthorizationError(msg)
        try:
            return run(service)
        except ToolError as exc:
            return {"error": str(exc), "kind": "tool_error"}

    return mcp


def main() -> None:
    cfg = settings()
    server = build_server(cfg)
    server.run(transport="streamable-http")


if __name__ == "__main__":
    main()
