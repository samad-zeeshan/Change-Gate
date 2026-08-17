
from __future__ import annotations

import json
import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from warden.security import (
    SCOPE_APPROVE_PROD,
)
from warden.server.auth import (
    InsufficientScope,
    InvalidToken,
    JWKSResolver,
    MissingToken,
    ResourceServerConfig,
    TokenValidator,
    require_scopes,
    validate_bearer,
    www_authenticate_header,
)
from warden.server.metadata import protected_resource_metadata, well_known_path

ISSUER = "https://idp.example/realms/warden"
AUDIENCE = "https://mcp.warden.example/mcp"
KID = "test-key-1"


@pytest.fixture(scope="module")
def keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def jwks(keypair):
    jwk = json.loads(RSAAlgorithm(RSAAlgorithm.SHA256).to_jwk(keypair.public_key()))
    jwk["kid"] = KID
    jwk["alg"] = "RS256"
    jwk["use"] = "sig"
    return {"keys": [jwk]}


@pytest.fixture
def validator(jwks):
    cfg = ResourceServerConfig(issuer=ISSUER, audience=AUDIENCE, leeway_seconds=30)
    return TokenValidator(cfg, JWKSResolver(static_jwks=jwks))


def _mint(keypair, *, aud=AUDIENCE, iss=ISSUER, scope="change:read change:approve",
          tenant="acme", role="lead", exp_delta=300, nbf_delta=-10):
    now = int(time.time())
    claims = {
        "iss": iss,
        "aud": aud,
        "sub": "user-123",
        "iat": now,
        "nbf": now + nbf_delta,
        "exp": now + exp_delta,
        "scope": scope,
        "tenant_id": tenant,
        "role": role,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(claims, keypair, algorithm="RS256", headers={"kid": KID})


def test_valid_token_yields_principal(validator, keypair):
    token = _mint(keypair, scope="change:read change:approve change:approve:prod")
    principal = validate_bearer(validator, f"Bearer {token}")
    assert principal.tenant_id == "acme"
    assert principal.role == "lead"
    assert principal.has_scope(SCOPE_APPROVE_PROD)


def test_missing_token_is_401_with_prm_pointer(validator):
    with pytest.raises(MissingToken):
        validate_bearer(validator, None)
    prm_url = f"{AUDIENCE}{well_known_path()}"
    header = www_authenticate_header(prm_url)
    assert "Bearer" in header and well_known_path() in header


def test_wrong_audience_rejected(validator, keypair):
    token = _mint(keypair, aud="https://some-other-rs.example")
    with pytest.raises(InvalidToken) as exc:
        validate_bearer(validator, f"Bearer {token}")
    assert "audience" in str(exc.value)


def test_expired_token_rejected(validator, keypair):
    token = _mint(keypair, exp_delta=-60)
    with pytest.raises(InvalidToken) as exc:
        validate_bearer(validator, f"Bearer {token}")
    assert "expired" in str(exc.value)


def test_not_yet_valid_token_rejected(validator, keypair):
    token = _mint(keypair, nbf_delta=600)
    with pytest.raises(InvalidToken):
        validate_bearer(validator, f"Bearer {token}")


def test_untrusted_issuer_rejected(validator, keypair):
    token = _mint(keypair, iss="https://evil.example/realms/x")
    with pytest.raises(InvalidToken) as exc:
        validate_bearer(validator, f"Bearer {token}")
    assert "issuer" in str(exc.value)


def test_tampered_signature_rejected(validator, keypair):
    token = _mint(keypair)
    tampered = token[:-3] + ("aaa" if not token.endswith("aaa") else "bbb")
    with pytest.raises(InvalidToken):
        validate_bearer(validator, f"Bearer {tampered}")


def test_base_scope_cannot_do_prod_approval(validator, keypair):
    token = _mint(keypair, scope="change:read change:approve")
    principal = validate_bearer(validator, f"Bearer {token}")
    with pytest.raises(InsufficientScope):
        require_scopes(principal, SCOPE_APPROVE_PROD)


def test_prm_document_lists_authorization_server():
    doc = protected_resource_metadata(AUDIENCE, ISSUER)
    assert doc["resource"] == AUDIENCE
    assert ISSUER in doc["authorization_servers"]
    assert SCOPE_APPROVE_PROD in doc["scopes_supported"]
