"""Persona mapping from signed claims, tool roles, and the realm export that issues them."""

from __future__ import annotations

import json
import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from warden.personas import PersonaMap, load_persona_map
from warden.policy import default_policy_path, load_policy_document
from warden.security import (
    PERSONA_AGENT,
    PERSONA_HUMAN,
    PERSONA_UNKNOWN,
    AuthPrincipal,
)
from warden.server.auth import JWKSResolver, ResourceServerConfig, TokenValidator

ROOT = Path(__file__).resolve().parents[1]
ISSUER = "https://idp.example/realms/warden"
AUDIENCE = "https://mcp.warden.example/mcp"

READS = (
    "get_change_request", "get_change_policy", "get_config_state", "get_dependency_graph",
    "get_freeze_windows", "get_recent_changes", "validate_change_request",
    "assess_change_risk",
)


@pytest.fixture(scope="module")
def pmap() -> PersonaMap:
    return load_persona_map()


def _human(*gate_roles: str) -> AuthPrincipal:
    return AuthPrincipal("alice", "acme", "lead", persona=PERSONA_HUMAN,
                         gate_roles=frozenset(gate_roles))


def _agent() -> AuthPrincipal:
    return AuthPrincipal("svc-agent", "acme", "lead", persona=PERSONA_AGENT)


def test_agent_client_maps_to_agent_persona(pmap):
    persona, roles = pmap.resolve({"azp": "warden-agent"})
    assert persona == PERSONA_AGENT
    assert roles == frozenset()


def test_console_client_maps_to_human_persona(pmap):
    persona, _ = pmap.resolve({"azp": "warden-console"})
    assert persona == PERSONA_HUMAN


def test_approver_realm_role_maps_to_gate_roles(pmap):
    _, roles = pmap.resolve({"azp": "warden-console", "gate_roles": ["change-approver"]})
    assert roles == frozenset({"approver", "recorder"})


def test_role_claim_accepts_space_separated_string(pmap):
    _, roles = pmap.resolve({"azp": "warden-console",
                             "gate_roles": "change-requester change-approver"})
    assert "approver" in roles


def test_unmapped_realm_roles_grant_nothing(pmap):
    _, roles = pmap.resolve({"azp": "warden-console", "gate_roles": ["admin", "root"]})
    assert roles == frozenset()


def test_agent_cannot_pick_up_roles_from_a_claim(pmap):
    # The agent's roles are fixed by the policy file. A role claim on a
    # service-account token is ignored, whatever it says.
    persona, roles = pmap.resolve({"azp": "warden-agent",
                                   "gate_roles": ["change-approver"]})
    assert persona == PERSONA_AGENT
    assert roles == frozenset()
    principal = AuthPrincipal("svc", "acme", "lead", persona=persona, gate_roles=roles)
    assert "approver" not in pmap.roles_for(principal)


@pytest.mark.parametrize("claims", [{}, {"azp": ""}, {"azp": "some-other-client"}])
def test_unlisted_or_missing_client_is_unknown_with_no_roles(pmap, claims):
    persona, roles = pmap.resolve(claims)
    assert persona == PERSONA_UNKNOWN
    principal = AuthPrincipal("x", "acme", "lead", persona=persona, gate_roles=roles)
    assert pmap.roles_for(principal) == frozenset()
    assert not any(pmap.may_call(principal, t) for t in pmap.tool_roles)


def test_role_sets_per_persona(pmap):
    assert pmap.roles_for(_agent()) == frozenset({"reader", "recorder", "router"})
    assert pmap.roles_for(_human()) == frozenset({"reader", "router"})
    assert pmap.roles_for(_human("approver", "recorder")) == frozenset(
        {"reader", "router", "approver", "recorder"}
    )


def test_human_gate_roles_are_limited_to_what_the_map_can_grant(pmap):
    # gate_roles on a principal only ever come from resolve(), but roles_for does
    # not trust them blindly either.
    assert "superuser" not in pmap.roles_for(_human("superuser"))


@pytest.mark.parametrize("tool", READS)
def test_every_persona_with_roles_can_read(pmap, tool):
    assert pmap.may_call(_agent(), tool)
    assert pmap.may_call(_human(), tool)


def test_agent_tool_permissions(pmap):
    agent = _agent()
    assert pmap.may_call(agent, "record_decision")
    assert pmap.may_call(agent, "route_change")
    assert not pmap.may_call(agent, "approve_change")
    assert not pmap.may_call(agent, "deny_change")


def test_human_without_approver_role_cannot_decide(pmap):
    requester = _human()
    assert pmap.may_call(requester, "route_change")
    assert not pmap.may_call(requester, "record_decision")
    assert not pmap.may_call(requester, "approve_change")
    assert not pmap.may_call(requester, "deny_change")


def test_human_approver_can_decide(pmap):
    approver = _human("approver", "recorder")
    for tool in ("record_decision", "approve_change", "deny_change", "route_change"):
        assert pmap.may_call(approver, tool)


def test_unknown_tool_is_never_callable(pmap):
    assert not pmap.may_call(_human("approver", "recorder"), "disable_audit")


def test_a_client_listed_for_both_personas_is_a_config_error():
    doc = load_policy_document()
    doc["personas"]["human"]["clients"].append(doc["personas"]["agent"]["clients"][0])
    with pytest.raises(ValueError):
        PersonaMap.from_policy(doc)


def test_policy_file_matches_its_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((ROOT / "policy" / "policy.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(load_policy_document(), schema)
    assert default_policy_path() == ROOT / "policy" / "warden.policy.json"


@pytest.fixture(scope="module")
def signer():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm(RSAAlgorithm.SHA256).to_jwk(key.public_key()))
    jwk["kid"] = "k1"
    return key, {"keys": [jwk]}


def _token(key, **extra) -> str:
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "sub-1", "iat": now, "exp": now + 300,
              "scope": "change:read", "tenant_id": "acme", "role": "lead", **extra}
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "k1"})


def test_token_validator_sets_persona_from_azp(signer, pmap):
    key, jwks = signer
    validator = TokenValidator(ResourceServerConfig(issuer=ISSUER, audience=AUDIENCE),
                               JWKSResolver(static_jwks=jwks), persona_map=pmap)
    agent = validator.validate(_token(key, azp="warden-agent"))
    human = validator.validate(_token(key, azp="warden-console",
                                      gate_roles=["change-approver"]))
    assert agent.persona == PERSONA_AGENT
    assert human.persona == PERSONA_HUMAN
    assert human.gate_roles == frozenset({"approver", "recorder"})


def test_token_validator_without_persona_map_never_grants_a_persona(signer):
    key, jwks = signer
    validator = TokenValidator(ResourceServerConfig(issuer=ISSUER, audience=AUDIENCE),
                               JWKSResolver(static_jwks=jwks))
    principal = validator.validate(_token(key, azp="warden-agent"))
    assert principal.persona == PERSONA_UNKNOWN


def _realm() -> dict:
    return json.loads((ROOT / "keycloak" / "realm-export.json").read_text(encoding="utf-8"))


def test_realm_agent_clients_only_use_client_credentials(pmap):
    clients = {c["clientId"]: c for c in _realm()["clients"]}
    for cid in pmap.agent_clients:
        assert clients[cid]["serviceAccountsEnabled"] is True
        # A person must not be able to log in through the agent's client and come
        # out holding the agent persona.
        assert clients[cid]["standardFlowEnabled"] is False
        assert clients[cid]["directAccessGrantsEnabled"] is False


def test_realm_console_client_is_public_with_pkce(pmap):
    clients = {c["clientId"]: c for c in _realm()["clients"]}
    for cid in pmap.human_clients:
        c = clients[cid]
        assert c["publicClient"] is True
        assert c["standardFlowEnabled"] is True
        assert c["serviceAccountsEnabled"] is False
        assert c["attributes"]["pkce.code.challenge.method"] == "S256"


def test_realm_role_names_match_the_persona_map(pmap):
    realm_roles = {r["name"] for r in _realm()["roles"]["realm"]}
    assert set(pmap.human_role_map) <= realm_roles


async def test_server_verifier_carries_persona_into_the_tool_principal(signer, pmap,
                                                                        monkeypatch):
    from warden.server import app as server_app

    key, jwks = signer
    validator = TokenValidator(ResourceServerConfig(issuer=ISSUER, audience=AUDIENCE),
                               JWKSResolver(static_jwks=jwks), persona_map=pmap)
    verifier = server_app.JWTVerifier(validator)
    access = await verifier.verify_token(
        _token(key, azp="warden-console", gate_roles=["change-approver"])
    )
    monkeypatch.setattr(server_app, "get_access_token", lambda: access)

    principal = server_app._principal_from_context()
    assert principal.persona == PERSONA_HUMAN
    assert principal.gate_roles == frozenset({"approver", "recorder"})


def test_access_token_without_persona_claim_is_unknown(monkeypatch):
    from mcp.server.auth.provider import AccessToken

    from warden.server import app as server_app

    access = AccessToken(token="t", client_id="c", scopes=["change:read"],
                         claims={"tenant_id": "acme", "role": "lead"})
    monkeypatch.setattr(server_app, "get_access_token", lambda: access)
    assert server_app._principal_from_context().persona == PERSONA_UNKNOWN


def test_realm_puts_a_subject_in_every_client_token():
    # Keycloak 26 only adds sub through the "basic" scope, which this realm does not
    # import. Each client carries the subject mapper itself instead.
    for client in _realm()["clients"]:
        mappers = [m["protocolMapper"] for m in client.get("protocolMappers", [])]
        assert "oidc-sub-mapper" in mappers, client["clientId"]
