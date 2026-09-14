"""PKCE generation and the authorization URL the console builds."""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlparse

from warden.agent.oauth import build_authorization_url, generate_pkce


def test_pkce_challenge_is_s256_of_verifier():
    pkce = generate_pkce()
    assert pkce.method == "S256"
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(pkce.verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    assert pkce.challenge == expected
    assert "=" not in pkce.verifier and "=" not in pkce.challenge


def test_pkce_values_are_unique_per_call():
    assert generate_pkce().verifier != generate_pkce().verifier


def test_authorization_url_includes_pkce_and_resource():
    pkce = generate_pkce()
    url = build_authorization_url(
        "https://idp.example/auth",
        client_id="agent",
        redirect_uri="http://localhost:9999/cb",
        scopes=["change:read", "change:approve"],
        resource="https://mcp.example/mcp",
        pkce=pkce,
        state="xyz",
    )
    q = parse_qs(urlparse(url).query)
    assert q["code_challenge_method"] == ["S256"]
    assert q["code_challenge"] == [pkce.challenge]
    assert q["resource"] == ["https://mcp.example/mcp"]
    assert q["response_type"] == ["code"]
    assert q["state"] == ["xyz"]
