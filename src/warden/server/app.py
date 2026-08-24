"""The MCP server: token checks, the tool boundary, and the task credential exchange.

Tools are built from the pinned registry, so the server advertises exactly what
the agent side checks.
"""

from __future__ import annotations

import inspect
from datetime import datetime
from typing import Any, Callable, Optional

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from pydantic import AnyHttpUrl

from .. import telemetry
from ..boundary import ToolBoundary
from ..clock import FixedClock, SystemClock, ensure_utc
from ..config import Settings, settings
from ..credentials import CredentialRefused, TaskCredentialIssuer, exchange_for_task
from ..db.postgres_repository import connect
from ..db.repository import Repository
from ..personas import load_persona_map
from ..sessions import RoleSessions
from ..security import (
    BINDING_REQUEST,
    PERSONA_UNKNOWN,
    SCOPE_APPROVE,
    SCOPE_READ,
    AuthPrincipal,
    AuthorizationError,
)
from ..tool_registry import ToolSpec, registry_for
from ..tools import ToolError, ToolService
from .auth import AuthError, JWKSResolver, ResourceServerConfig, TokenValidator, validate_bearer

_PY_TYPE = {"string": str, "boolean": bool}
_DEFAULT = {"string": "", "boolean": False}
_TRACED = {"get_change_request", "assess_change_risk", "record_decision"}


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
                "request_id": principal.request_id,
                "tenants": sorted(principal.tenants),
                "token_id": principal.token_id,
                "raw": principal.claims,
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
        request_id=str(claims.get("request_id") or ""),
        tenants=frozenset(claims.get("tenants") or ()),
        token_id=str(claims.get("token_id") or ""),
        claims=dict(claims.get("raw") or {}),
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
    task_issuer: TaskCredentialIssuer | None = None,
    binding: str = BINDING_REQUEST,
    sessions_provider: Callable[[], RoleSessions] | None = None,
    role_delivery: bool = True,
) -> FastMCP:
    # The keyword arguments exist so the red-team runner and the tests can run
    # this exact server without Postgres or Keycloak. Production passes none.
    cfg = cfg or settings()
    telemetry.setup_telemetry(cfg.service_name)
    persona_map = load_persona_map()
    registry = registry_for(binding)

    task_issuer = task_issuer or (validator.task_issuer if validator else None) or \
        TaskCredentialIssuer(audience=cfg.resource_url, key=cfg.task_key())
    validator = validator or TokenValidator(
        ResourceServerConfig(
            issuer=cfg.issuer,
            audience=cfg.resource_url,
            leeway_seconds=cfg.leeway_seconds,
        ),
        JWKSResolver(jwks_uri=cfg.jwks_uri),
        persona_map=persona_map,
        task_issuer=task_issuer,
    )

    clock = (
        FixedClock(ensure_utc(datetime.fromisoformat(cfg.now_override)))
        if cfg.now_override
        else SystemClock()
    )

    # Learned roles have to outlive one MCP session, because the agent opens a new
    # session per call. They live here, keyed by the task credential's id.
    shared_sessions = RoleSessions()

    def _sessions() -> RoleSessions:
        return sessions_provider() if sessions_provider else shared_sessions

    def _principal() -> AuthPrincipal:
        return principal_provider() if principal_provider else _principal_from_context()

    def _repo(tenant_id: str) -> Repository:
        return repo_factory(tenant_id) if repo_factory else connect(cfg.pg_dsn, tenant_id)

    def _boundary() -> ToolBoundary:
        principal = _principal()

        def for_tenant(tenant: str) -> ToolService:
            import dataclasses

            scoped = dataclasses.replace(principal, tenant_id=tenant)
            return ToolService(_repo(tenant), clock, principal=scoped)

        service = ToolService(_repo(principal.tenant_id), clock, principal=principal)
        return ToolBoundary(service, persona_map, binding=binding, tenant_service=for_tenant,
                            sessions=_sessions(), role_delivery=role_delivery)

    def _gate(name: str, arguments: dict) -> None:
        _boundary().admit(name, arguments)

    def _visible(name: str) -> bool:
        try:
            principal = _principal()
            learned = _sessions().learned(principal) if role_delivery else None
            return persona_map.may_call(principal, name, learned)
        except AuthorizationError:
            return False

    mcp = GatedFastMCP(
        name="warden",
        instructions="Warden: an approval gate for config changes and feature-flag flips.",
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

    def _run(spec: ToolSpec, args: dict) -> dict:
        boundary = _boundary()
        service = boundary.service
        if spec.writes and not service.principal.has_scope(SCOPE_APPROVE):
            # Refused before ToolService runs, so it is audited here. Without
            # this, a write refused for scope would leave no trace.
            msg = f"missing required scope: {SCOPE_APPROVE}"
            boundary.audit_refusal("scope_denied", args, msg)
            raise AuthorizationError(msg)
        # The server owns the clock. The agent never sends a time, and a time it
        # tried to send was already rejected by the gate as an unknown argument.
        if spec.name in ("assess_change_risk", "record_decision"):
            args = {**args, "now": clock.now().isoformat()}
        try:
            with telemetry.span(f"tool.{spec.name}", tool=spec.name) if spec.name in _TRACED \
                    else _nullspan():
                return boundary.dispatch(spec, args)
        except ToolError as exc:
            return {"error": str(exc), "kind": "tool_error"}

    for spec in registry.values():
        mcp.add_tool(_tool_fn(spec, _run), name=spec.name, description=spec.description)

    @mcp.custom_route("/credentials/task", methods=["POST"])
    async def task_credential(request):
        from starlette.responses import JSONResponse

        try:
            principal = validate_bearer(validator, request.headers.get("authorization"))
            body = await request.json()
            request_id = str(body.get("request_id", ""))
            token = exchange_for_task(task_issuer, principal, request_id,
                                      _repo(principal.tenant_id))
        except AuthError as exc:
            return JSONResponse({"error": exc.error_code, "detail": exc.description},
                                status_code=exc.status)
        except CredentialRefused as exc:
            return JSONResponse({"error": "refused", "detail": str(exc)}, status_code=403)
        return JSONResponse({"access_token": token, "token_type": "Bearer",
                             "expires_in": task_issuer.lifetime_seconds,
                             "request_id": request_id})

    mcp.task_issuer = task_issuer
    return mcp


class _nullspan:

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _tool_fn(spec: ToolSpec, run: Callable[[ToolSpec, dict], dict]):
    # FastMCP reads the input schema from the function signature, so the
    # signature is built from the registry entry instead of written by hand.
    params = [
        inspect.Parameter(p.name, inspect.Parameter.KEYWORD_ONLY,
                          default=inspect.Parameter.empty if p.required else _DEFAULT[p.type],
                          annotation=_PY_TYPE[p.type])
        for p in spec.params
    ]

    def fn(**kwargs) -> dict:
        return run(spec, kwargs)

    fn.__signature__ = inspect.Signature(params, return_annotation=dict)
    fn.__annotations__ = {p.name: _PY_TYPE[p.type] for p in spec.params} | {"return": dict}
    fn.__name__ = spec.name
    return fn


def main() -> None:
    cfg = settings()
    server = build_server(cfg)
    server.run(transport="streamable-http")


if __name__ == "__main__":
    main()
