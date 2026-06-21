
from __future__ import annotations

from datetime import datetime
from typing import Optional

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from pydantic import AnyHttpUrl

from .. import telemetry
from ..clock import FixedClock, SystemClock, ensure_utc
from ..config import Settings, settings
from ..db.postgres_repository import connect
from ..security import (
    SCOPE_APPROVE,
    SCOPE_READ,
    AuthPrincipal,
    AuthorizationError,
)
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
            claims={"tenant_id": principal.tenant_id, "role": principal.role},
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
    )


def build_server(cfg: Settings | None = None) -> FastMCP:
    cfg = cfg or settings()
    telemetry.setup_telemetry(cfg.service_name)

    validator = TokenValidator(
        ResourceServerConfig(
            issuer=cfg.issuer,
            audience=cfg.resource_url,
            leeway_seconds=cfg.leeway_seconds,
        ),
        JWKSResolver(jwks_uri=cfg.jwks_uri),
    )

    mcp = FastMCP(
        name="change-gate",
        instructions="Multi-tenant config-change / feature-flag approval gate.",
        host=cfg.host,
        port=cfg.port,
        token_verifier=JWTVerifier(validator),
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(cfg.issuer),
            resource_server_url=AnyHttpUrl(cfg.resource_url),
            required_scopes=[SCOPE_READ],
        ),
    )

    clock = (
        FixedClock(ensure_utc(datetime.fromisoformat(cfg.now_override)))
        if cfg.now_override
        else SystemClock()
    )

    def _now() -> str:
        return clock.now().isoformat()


    @mcp.tool()
    def get_change_request(request_id: str) -> dict:
        with telemetry.span("tool.get_change_request", tool="get_change_request"):
            return _wrap(lambda s: s.get_change_request(request_id))

    @mcp.tool()
    def get_change_policy() -> dict:
        return _wrap(lambda s: s.get_change_policy())

    @mcp.tool()
    def get_config_state(key: str, environment: str) -> dict:
        return _wrap(lambda s: s.get_config_state(key, environment))

    @mcp.tool()
    def get_dependency_graph() -> dict:
        return _wrap(lambda s: s.get_dependency_graph())

    @mcp.tool()
    def get_freeze_windows() -> dict:
        return _wrap(lambda s: s.get_freeze_windows())

    @mcp.tool()
    def get_recent_changes() -> dict:
        return _wrap(lambda s: s.get_recent_changes())

    @mcp.tool()
    def validate_change_request(request_id: str) -> dict:
        return _wrap(lambda s: s.validate_change_request(request_id))

    @mcp.tool()
    def assess_change_risk(request_id: str) -> dict:
        with telemetry.span("tool.assess_change_risk", tool="assess_change_risk"):
            return _wrap(lambda s: s.assess_change_risk(request_id, now=_now()))


    @mcp.tool()
    def record_decision(request_id: str, explanation: str = "", force_route: bool = False) -> dict:
        with telemetry.span("tool.record_decision", tool="record_decision"):
            return _wrap(
                lambda s: s.record_decision(
                    request_id, now=_now(), explanation=explanation, force_route=force_route
                ),
                require=(SCOPE_APPROVE,),
            )

    def _wrap(run, require: tuple[str, ...] = ()) -> dict:
        principal = _principal_from_context()
        for scope in require:
            if not principal.has_scope(scope):
                raise AuthorizationError(f"missing required scope: {scope}")
        repo = connect(cfg.pg_dsn, principal.tenant_id)
        service = ToolService(repo, clock, principal=principal)
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
