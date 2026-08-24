
from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from warden.audit import AuditLog  # noqa: E402
from warden.clock import FixedClock  # noqa: E402
from warden.data import seed  # noqa: E402
from warden.db.repository import InMemoryRepository  # noqa: E402
from warden.security import (  # noqa: E402
    SCOPE_APPROVE,
    SCOPE_APPROVE_PROD,
    SCOPE_READ,
    AuthPrincipal,
)
from warden.tools import ToolService  # noqa: E402


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(seed.EVAL_NOW)


@pytest.fixture
def audit_log() -> AuditLog:
    return AuditLog()


@pytest.fixture
def acme_repo(audit_log) -> InMemoryRepository:
    return InMemoryRepository("acme", audit_log=audit_log)


@pytest.fixture
def globex_repo(audit_log) -> InMemoryRepository:
    return InMemoryRepository("globex", audit_log=audit_log)


@pytest.fixture
def elevated_principal() -> AuthPrincipal:
    return AuthPrincipal(
        subject="agent-acme",
        tenant_id="acme",
        role="lead",
        scopes=frozenset({SCOPE_READ, SCOPE_APPROVE, SCOPE_APPROVE_PROD}),
    )


@pytest.fixture
def acme_service(acme_repo, clock, elevated_principal) -> ToolService:
    return ToolService(acme_repo, clock, principal=elevated_principal)


@pytest.fixture
def bound_service(acme_repo, clock, elevated_principal):
    # The dispatcher's job in tests: a service whose credential names one request.
    import dataclasses

    def make(request_id: str, principal: AuthPrincipal | None = None) -> ToolService:
        base = principal or elevated_principal
        bound = dataclasses.replace(base, request_id=request_id, token_id=f"t-{request_id}")
        return ToolService(acme_repo, clock, principal=bound)

    return make


def walk_to_decide(client) -> None:
    """The agent's delivery protocol up to the write: reader, assess, recorder."""
    client.call("learn_role", role="reader")
    client.call("assess_change_risk")
    client.call("learn_role", role="recorder")


async def walk_server_to_decide(server) -> None:
    await server.call_tool("learn_role", {"role": "reader"})
    await server.call_tool("assess_change_risk", {})
    await server.call_tool("learn_role", {"role": "recorder"})


def decisions(entries) -> list[str]:
    # Role grants are audited too. Most tests care about everything else.
    return [e.action for e in entries if e.action != "role_learned"]
