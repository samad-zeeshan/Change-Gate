"""
Scope based authorization for decision writes.

Prod auto-approvals need a separate scope so a normal approver cannot ship to prod.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .domain.models import Decision, Environment

SCOPE_READ = "change:read"
SCOPE_APPROVE = "change:approve"
SCOPE_APPROVE_PROD = "change:approve:prod"
ALL_SCOPES = (SCOPE_READ, SCOPE_APPROVE, SCOPE_APPROVE_PROD)

PERSONA_AGENT = "agent"
PERSONA_HUMAN = "human"
PERSONA_UNKNOWN = "unknown"

BINDING_REQUEST = "request"
BINDING_PARAMETER = "parameter"


class AuthorizationError(PermissionError):

    def __init__(self, message: str, *, required_scope: str | None = None) -> None:
        super().__init__(message)
        self.required_scope = required_scope


@dataclass(frozen=True)
class AuthPrincipal:
    subject: str
    tenant_id: str
    role: str
    scopes: frozenset[str] = field(default_factory=frozenset)
    # Principals built in-process (the CLI, the eval, tests) stand for the agent's
    # service account unless told otherwise. A principal built from a token always
    # sets persona from the token's signed claims, so this default never reaches
    # a network caller.
    persona: str = PERSONA_AGENT
    gate_roles: frozenset[str] = field(default_factory=frozenset)
    # Set only from a task credential. An empty value means the token names a
    # tenant but no change request, and the boundary refuses every tool call.
    request_id: str = ""
    # Tenants the credential may name as an argument. Used only by the parameter
    # arm of the tenant ablation, which is the pattern request binding replaces.
    tenants: frozenset[str] = field(default_factory=frozenset)
    token_id: str = ""
    claims: dict = field(default_factory=dict, compare=False, hash=False)

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes

    def entitled_tenants(self) -> frozenset[str]:
        return self.tenants or frozenset({self.tenant_id})


def required_scope_for(decision: Decision, environment: Environment) -> str | None:
    # Only an actual auto-approve write to prod needs the elevated scope. Routing
    # or denying a prod change is just the base approve scope.
    if decision is Decision.AUTO_APPROVE and environment is Environment.PROD:
        return SCOPE_APPROVE_PROD
    return SCOPE_APPROVE


def authorize_write(
    principal: AuthPrincipal,
    *,
    decision: Decision,
    environment: Environment,
    tenant_id: str,
) -> None:
    # Tenant match comes first. A valid token for tenant A must never write to
    # tenant B, even with every scope. This mirrors the RLS check in the database.
    if principal.tenant_id != tenant_id:
        raise AuthorizationError(
            f"principal tenant {principal.tenant_id!r} may not write for tenant "
            f"{tenant_id!r}"
        )

    needed = required_scope_for(decision, environment)
    if not principal.has_scope(SCOPE_APPROVE):
        raise AuthorizationError(
            "insufficient scope: change:approve required for any decision write",
            required_scope=SCOPE_APPROVE,
        )
    if needed == SCOPE_APPROVE_PROD and not principal.has_scope(SCOPE_APPROVE_PROD):
        raise AuthorizationError(
            "insufficient scope: prod approval requires change:approve:prod",
            required_scope=SCOPE_APPROVE_PROD,
        )
