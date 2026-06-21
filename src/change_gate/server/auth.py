"""
Resource-server side of OAuth: validate a bearer JWT and build an AuthPrincipal.

Signature, issuer, and audience are all checked before any claim is trusted.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from typing import Optional

import jwt
from jwt import InvalidAudienceError, InvalidIssuerError, PyJWKClient
from jwt.algorithms import RSAAlgorithm

from ..security import AuthPrincipal


class AuthError(Exception):

    status = 401
    error_code = "invalid_token"

    def __init__(self, description: str) -> None:
        super().__init__(description)
        self.description = description


class MissingToken(AuthError):
    error_code = "invalid_request"


class InvalidToken(AuthError):
    error_code = "invalid_token"


class InsufficientScope(AuthError):
    status = 403
    error_code = "insufficient_scope"


class JWKSResolver:

    def __init__(
        self,
        *,
        static_jwks: Optional[dict] = None,
        jwks_uri: Optional[str] = None,
    ) -> None:
        if not static_jwks and not jwks_uri:
            raise ValueError("JWKSResolver needs either static_jwks or jwks_uri")
        self._static = static_jwks
        self._client = PyJWKClient(jwks_uri) if jwks_uri else None
        self._lock = threading.Lock()

    def key_for(self, token: str):
        # Reading the header is safe before verifying. We only use the kid to pick
        # which key to verify against, and the signature check still has to pass.
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if self._static is not None:
            for jwk in self._static.get("keys", []):
                if jwk.get("kid") == kid or kid is None:
                    return RSAAlgorithm.from_jwk(json.dumps(jwk))
            raise InvalidToken(f"no signing key for kid {kid!r}")
        with self._lock:  # pragma: no cover - exercised only against live Keycloak
            return self._client.get_signing_key_from_jwt(token).key


@dataclass
class ResourceServerConfig:
    issuer: str
    audience: str
    leeway_seconds: int = 30
    algorithms: tuple[str, ...] = ("RS256",)
    tenant_claim: str = "tenant_id"
    role_claim: str = "role"


class TokenValidator:
    def __init__(self, config: ResourceServerConfig, resolver: JWKSResolver) -> None:
        self.config = config
        self.resolver = resolver

    def validate(self, token: str) -> AuthPrincipal:
        try:
            key = self.resolver.key_for(token)
        except AuthError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise InvalidToken(f"could not resolve signing key: {exc}") from exc

        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=list(self.config.algorithms),
                audience=self.config.audience,
                issuer=self.config.issuer,
                leeway=self.config.leeway_seconds,
                # require forces these claims to be present. Without it a token
                # that simply omits exp or aud would sail through validation.
                options={"require": ["exp", "iat", "aud", "iss"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise InvalidToken("token expired") from exc
        except jwt.ImmatureSignatureError as exc:
            raise InvalidToken("token not yet valid (nbf)") from exc
        except InvalidAudienceError as exc:
            raise InvalidToken("wrong audience: token not issued for this resource") from exc
        except InvalidIssuerError as exc:
            raise InvalidToken("untrusted issuer") from exc
        except jwt.InvalidSignatureError as exc:
            raise InvalidToken("bad signature") from exc
        except jwt.PyJWTError as exc:
            raise InvalidToken(f"invalid token: {exc}") from exc

        return self._principal_from_claims(claims)

    def _principal_from_claims(self, claims: dict) -> AuthPrincipal:
        scopes = frozenset(str(claims.get("scope", "")).split())
        tenant_id = claims.get(self.config.tenant_claim)
        if not tenant_id:
            raise InvalidToken("token missing tenant_id claim")
        role = claims.get(self.config.role_claim, "")
        return AuthPrincipal(
            subject=claims.get("sub", ""),
            tenant_id=str(tenant_id),
            role=str(role),
            scopes=scopes,
        )


def validate_bearer(validator: TokenValidator, authorization_header: Optional[str]) -> AuthPrincipal:
    if not authorization_header:
        raise MissingToken("missing Authorization header")
    # Split once so a token containing spaces stays intact, then require the
    # exact "Bearer <token>" shape.
    parts = authorization_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise MissingToken("Authorization header must be 'Bearer <token>'")
    return validator.validate(parts[1].strip())


def require_scopes(principal: AuthPrincipal, *needed: str) -> None:
    for scope in needed:
        if not principal.has_scope(scope):
            raise InsufficientScope(f"missing required scope: {scope}")


def www_authenticate_header(resource_metadata_url: str, error: Optional[AuthError] = None) -> str:
    parts = [f'Bearer resource_metadata="{resource_metadata_url}"']
    if error is not None:
        parts.append(f'error="{error.error_code}"')
        parts.append(f'error_description="{error.description}"')
    return ", ".join(parts)
