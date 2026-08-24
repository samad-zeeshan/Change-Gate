"""Request-bound credentials: tenant and request come from the token, never an argument."""

from __future__ import annotations

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from warden.agent.resilience import DomainToolError
from warden.agent.tool_client import InProcessToolClient
from warden.boundary import ToolBoundary, ToolDenied
from warden.config import Settings
from warden.credentials import CredentialRefused, TaskCredentialIssuer, exchange_for_task
from warden.data import seed
from warden.db.repository import InMemoryRepository
from warden.personas import load_persona_map
from warden.security import (
    PERSONA_AGENT,
    PERSONA_HUMAN,
    SCOPE_APPROVE,
    SCOPE_APPROVE_PROD,
    SCOPE_READ,
    AuthPrincipal,
)
from warden.server import app as server_app
from warden.server.auth import InvalidToken, JWKSResolver, ResourceServerConfig, TokenValidator
from warden.tool_registry import REGISTRY, RESOURCE_ARGS, RejectedCall, registry_for, resolve_call
from warden.tools import ToolService

from conftest import walk_server_to_decide, walk_to_decide

ISSUER = "https://idp.example/realms/warden"
AUDIENCE = "https://mcp.warden.example/mcp"
SCOPES = frozenset({SCOPE_READ, SCOPE_APPROVE, SCOPE_APPROVE_PROD})


@pytest.fixture(scope="module")
def idp_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def issuer():
    return TaskCredentialIssuer(audience=AUDIENCE)


@pytest.fixture
def validator(idp_key, issuer):
    jwk = json.loads(RSAAlgorithm(RSAAlgorithm.SHA256).to_jwk(idp_key.public_key()))
    jwk["kid"] = "idp"
    return TokenValidator(ResourceServerConfig(issuer=ISSUER, audience=AUDIENCE),
                          JWKSResolver(static_jwks={"keys": [jwk]}),
                          persona_map=load_persona_map(), task_issuer=issuer)


def _idp_token(key, **extra) -> str:
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "service-account-warden-agent",
              "azp": "warden-agent", "iat": now, "exp": now + 300,
              "scope": " ".join(sorted(SCOPES)), "tenant_id": "acme", "role": "lead",
              "jti": "base-1", **extra}
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "idp"})


def _bound(rid: str, persona: str = PERSONA_AGENT, **kw) -> AuthPrincipal:
    return AuthPrincipal("service-account-warden-agent", "acme", "lead", SCOPES,
                         persona=persona, request_id=rid, token_id=f"t-{rid}", **kw)


# -------------------------------------------------------------------- tool schemas


def test_no_tool_schema_can_name_a_tenant_or_a_request():
    for spec in REGISTRY.values():
        names = {p.name for p in spec.params}
        assert not names & set(RESOURCE_ARGS), spec.name


def test_the_parameter_arm_puts_the_ids_back_for_the_ablation():
    params = registry_for("parameter")
    for name, spec in params.items():
        names = {p.name for p in spec.params}
        assert "tenant_id" in names, name
        assert ("request_id" in names) == REGISTRY[name].request_scoped, name


def test_a_request_id_argument_is_an_unknown_argument():
    with pytest.raises(RejectedCall) as exc:
        resolve_call("get_change_request", {"request_id": "gx-900"})
    assert exc.value.kind == "unknown_argument"


# ------------------------------------------------------------------ task credentials


def test_task_credential_carries_tenant_and_request_and_is_short_lived(validator, idp_key,
                                                                       issuer):
    base = validator.validate(_idp_token(idp_key))
    assert base.request_id == ""
    token = issuer.issue(base, "cr-002")
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["tenant_id"] == "acme" and claims["request_id"] == "cr-002"
    assert claims["exp"] - claims["iat"] <= 300
    bound = validator.validate(token)
    assert bound.request_id == "cr-002"
    assert bound.persona == PERSONA_AGENT
    assert bound.token_id == claims["jti"]


def test_a_request_claim_from_the_idp_is_ignored(validator, idp_key):
    # Only the task issuer can bind a request. The IdP knows nothing about change
    # requests, so a request_id in its token is not a binding.
    principal = validator.validate(_idp_token(idp_key, request_id="cr-003"))
    assert principal.request_id == ""


def test_an_expired_task_credential_is_refused(validator, idp_key):
    short = TaskCredentialIssuer(audience=AUDIENCE, lifetime_seconds=-120)
    v = TokenValidator(validator.config, validator.resolver,
                       persona_map=validator.persona_map, task_issuer=short)
    token = short.issue(v.validate(_idp_token(idp_key)), "cr-002")
    with pytest.raises(InvalidToken):
        v.validate(token)


def test_a_task_credential_signed_by_another_key_is_refused(validator, idp_key):
    rogue = TaskCredentialIssuer(audience=AUDIENCE)
    token = rogue.issue(validator.validate(_idp_token(idp_key)), "gx-900")
    with pytest.raises(InvalidToken):
        validator.validate(token)


def test_exchange_binds_a_request_in_the_callers_tenant(validator, idp_key, issuer):
    base = validator.validate(_idp_token(idp_key))
    repo = InMemoryRepository("acme")
    token = exchange_for_task(issuer, base, "cr-001", repo)
    assert validator.validate(token).request_id == "cr-001"


def test_exchange_refuses_another_tenants_request(validator, idp_key, issuer):
    import dataclasses

    foreign = dataclasses.replace(seed.SCENARIOS[0].request, id="gx-1", tenant_id="globex")
    repo = InMemoryRepository("acme", requests=[foreign])
    with pytest.raises(CredentialRefused):
        exchange_for_task(issuer, validator.validate(_idp_token(idp_key)), "gx-1", repo)


def test_a_task_credential_cannot_mint_another(validator, idp_key, issuer):
    task = validator.validate(issuer.issue(validator.validate(_idp_token(idp_key)), "cr-001"))
    with pytest.raises(CredentialRefused):
        exchange_for_task(issuer, task, "cr-002", InMemoryRepository("acme"))


def test_exchange_refuses_an_unknown_persona(validator, idp_key, issuer):
    stranger = validator.validate(_idp_token(idp_key, azp="someone-else"))
    with pytest.raises(CredentialRefused):
        exchange_for_task(issuer, stranger, "cr-001", InMemoryRepository("acme"))


# ------------------------------------------------------------------------ boundary


def test_an_unbound_credential_can_call_nothing_and_is_audited(acme_repo, clock, audit_log):
    unbound = AuthPrincipal("agent", "acme", "lead", SCOPES)
    client = InProcessToolClient(ToolService(acme_repo, clock, principal=unbound))
    with pytest.raises(DomainToolError) as exc:
        client.call("get_change_policy")
    assert "not bound" in str(exc.value)
    assert audit_log.for_tenant("acme")[-1].action == "unbound_credential"


def test_a_bound_credential_reads_and_decides_its_own_request(acme_repo, clock, audit_log):
    client = InProcessToolClient(ToolService(acme_repo, clock, principal=_bound("cr-002")))
    walk_to_decide(client)
    assert client.call("get_change_request")["id"] == "cr-002"
    assert client.call("get_config_state")["key"] == "db_pool_size"
    out = client.call("record_decision", trace_id="t")
    assert out["request_id"] == "cr-002" and out["decision"] == "route"


def test_no_signature_can_reach_another_request(acme_repo, clock, audit_log):
    client = InProcessToolClient(ToolService(acme_repo, clock, principal=_bound("cr-002")))
    walk_to_decide(client)
    with pytest.raises(DomainToolError) as exc:
        client.call("record_decision", request_id="cr-001")
    assert "unknown_argument" in str(exc.value)
    assert audit_log.for_tenant("acme")[-1].action == "tool_call_rejected"


def test_the_service_refuses_a_request_the_credential_is_not_bound_to(acme_repo, clock,
                                                                      audit_log):
    service = ToolService(acme_repo, clock, principal=_bound("cr-002"))
    with pytest.raises(Exception) as exc:
        service.record_decision("cr-001")
    assert "bound" in str(exc.value)
    assert service.request_state("cr-001") == "new"
    assert audit_log.for_tenant("acme")[-1].action == "binding_denied"


def test_parameter_arm_serves_any_entitled_tenant(audit_log, clock):
    # The Stochastic Deputy pattern: the tenant argument is validated against the
    # entitlement, and the entitlement includes a tenant this task never needed.
    import dataclasses

    foreign = dataclasses.replace(seed.SCENARIOS[0].request, id="gx-1", tenant_id="globex")
    repos = {t: InMemoryRepository(t, audit_log=audit_log, requests=[foreign])
             for t in ("acme", "globex")}
    shared = AuthPrincipal("agent", "acme", "lead", SCOPES,
                           tenants=frozenset({"acme", "globex"}))

    def service_for(tenant):
        return ToolService(repos[tenant], clock, principal=dataclasses.replace(
            shared, tenant_id=tenant))

    # The parameter arm is the v1 shape, which had no role delivery.
    boundary = ToolBoundary(service_for("acme"), load_persona_map(), binding="parameter",
                            tenant_service=service_for, role_delivery=False)
    out = boundary.call("get_change_request", {"tenant_id": "globex", "request_id": "gx-1"})
    assert out["tenant_id"] == "globex"

    single = ToolBoundary(ToolService(repos["acme"], clock, principal=dataclasses.replace(
        shared, tenants=frozenset({"acme"}))), load_persona_map(), binding="parameter",
        tenant_service=service_for, role_delivery=False)
    with pytest.raises(ToolDenied):
        single.call("get_change_request", {"tenant_id": "globex", "request_id": "gx-1"})


# -------------------------------------------------------------------------- server


def _cfg() -> Settings:
    return Settings(issuer=ISSUER, jwks_uri="https://idp.example/certs",
                    resource_url=AUDIENCE, now_override=seed.EVAL_NOW.isoformat())


def test_the_server_advertises_no_resource_ids():
    server = server_app.build_server(_cfg())
    for tool in server._tool_manager.list_tools():
        assert not set(tool.parameters.get("properties", {})) & set(RESOURCE_ARGS), tool.name


async def test_the_server_derives_the_request_from_the_credential(acme_repo, audit_log):
    server = server_app.build_server(_cfg(), repo_factory=lambda t: acme_repo,
                                     principal_provider=lambda: _bound("cr-005"))
    await walk_server_to_decide(server)
    await server.call_tool("record_decision", {"trace_id": "t-srv"})
    entry = audit_log.for_tenant("acme")[-1]
    assert entry.request_id == "cr-005" and entry.action == "record_decision"


async def test_a_human_needs_a_bound_credential_too(acme_repo, audit_log):
    human = AuthPrincipal("alice", "acme", "lead", SCOPES, persona=PERSONA_HUMAN,
                          gate_roles=frozenset({"approver"}))
    server = server_app.build_server(_cfg(), repo_factory=lambda t: acme_repo,
                                     principal_provider=lambda: human)
    with pytest.raises(Exception):
        await server.call_tool("approve_change", {"reason": "ok"})
    assert audit_log.for_tenant("acme")[-1].action == "unbound_credential"
