"""
OAuth helpers: PKCE generation and the token flows against a Keycloak issuer.

resource is passed through so tokens are audience-bound to this server (RFC 8707).
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from urllib.parse import urlencode


def _b64url(raw: bytes) -> str:
    # OAuth wants base64url with no padding. The stray = signs are not URL safe
    # and the spec drops them.
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class PKCE:
    verifier: str
    challenge: str
    method: str = "S256"


def generate_pkce() -> PKCE:
    # The verifier is the secret we keep, the challenge is its SHA-256 sent up
    # front. Only the holder of the verifier can later redeem the code, which
    # stops an intercepted auth code from being exchanged by anyone else.
    verifier = _b64url(secrets.token_bytes(32))
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return PKCE(verifier=verifier, challenge=_b64url(digest), method="S256")


def build_authorization_url(
    authorize_endpoint: str,
    *,
    client_id: str,
    redirect_uri: str,
    scopes: list[str],
    resource: str,
    pkce: PKCE,
    state: str,
) -> str:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "resource": resource,
        "code_challenge": pkce.challenge,
        "code_challenge_method": pkce.method,
        "state": state,
    }
    return f"{authorize_endpoint}?{urlencode(params)}"


def exchange_code_for_token(
    token_endpoint: str,
    *,
    client_id: str,
    code: str,
    redirect_uri: str,
    resource: str,
    pkce: PKCE,
    timeout: float = 10.0,
) -> dict:  # pragma: no cover - needs a live IdP
    import httpx

    data = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": redirect_uri,
        "resource": resource,
        "code_verifier": pkce.verifier,
    }
    resp = httpx.post(token_endpoint, data=data, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def fetch_token_client_credentials(
    token_endpoint: str,
    *,
    client_id: str,
    client_secret: str,
    scopes: list[str],
    resource: str,
    timeout: float = 10.0,
) -> str:  # pragma: no cover - needs a live IdP
    import httpx

    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": " ".join(scopes),
        "resource": resource,
    }
    resp = httpx.post(token_endpoint, data=data, timeout=timeout)
    resp.raise_for_status()
    return resp.json()["access_token"]


def token_endpoint_from_issuer(issuer: str) -> str:
    return f"{issuer.rstrip('/')}/protocol/openid-connect/token"


def authorize_endpoint_from_issuer(issuer: str) -> str:
    return f"{issuer.rstrip('/')}/protocol/openid-connect/auth"
