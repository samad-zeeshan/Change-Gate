"""Issue short-lived task credentials bound to one tenant and one change request.

The dispatcher trades the caller's IdP token for one of these before any tool runs.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from .db.repository import CrossTenantAccess
from .security import PERSONA_AGENT, PERSONA_HUMAN, AuthPrincipal

TASK_ISSUER = "urn:warden:task-credentials"
TOKEN_USE = "task"


class CredentialRefused(PermissionError):
    pass


@dataclass
class TaskCredentialIssuer:
    audience: str
    issuer: str = TASK_ISSUER
    # Five minutes covers one agent run with retries. Keycloak's own access
    # tokens in the realm export also last 300 seconds.
    lifetime_seconds: int = 300
    kid: str = "warden-task-1"
    key: Optional[rsa.RSAPrivateKey] = None
    _public_pem: bytes = field(init=False, repr=False, default=b"")

    def __post_init__(self) -> None:
        if self.key is None:
            self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        from cryptography.hazmat.primitives import serialization

        self._public_pem = self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    @property
    def public_pem(self) -> bytes:
        return self._public_pem

    def issue(self, principal: AuthPrincipal, request_id: str) -> str:
        now = int(time.time())
        base = principal.claims or {}
        claims = {
            "iss": self.issuer, "aud": self.audience, "sub": principal.subject,
            "azp": base.get("azp", ""), "tenant_id": principal.tenant_id,
            "request_id": request_id, "role": principal.role,
            "scope": " ".join(sorted(principal.scopes)),
            "iat": now, "exp": now + self.lifetime_seconds, "jti": uuid.uuid4().hex,
            "token_use": TOKEN_USE,
        }
        # Realm roles ride along unchanged so the persona map resolves them the
        # same way it did for the IdP token. Nothing is widened here.
        if "gate_roles" in base:
            claims["gate_roles"] = base["gate_roles"]
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": self.kid})


def exchange_for_task(issuer: TaskCredentialIssuer, principal: AuthPrincipal,
                      request_id: str, repo) -> str:
    if principal.request_id or (principal.claims or {}).get("token_use") == TOKEN_USE:
        # A task credential that could mint another would let a steered agent
        # re-scope itself to any request in the tenant.
        raise CredentialRefused("a task credential cannot be exchanged")
    if principal.persona not in (PERSONA_AGENT, PERSONA_HUMAN):
        raise CredentialRefused(f"persona {principal.persona!r} gets no task credential")
    try:
        req = repo.get_change_request(request_id)
    except CrossTenantAccess:
        req = None
    if req is None or req.tenant_id != principal.tenant_id:
        raise CredentialRefused(f"change request {request_id!r} not found")
    return issuer.issue(principal, request_id)
