
from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from change_gate.audit import AuditLog  # noqa: E402
from change_gate.clock import FixedClock  # noqa: E402
from change_gate.data import seed  # noqa: E402
from change_gate.db.repository import InMemoryRepository  # noqa: E402
from change_gate.security import (  # noqa: E402
    SCOPE_APPROVE,
    SCOPE_APPROVE_PROD,
    SCOPE_READ,
    AuthPrincipal,
)
from change_gate.tools import ToolService  # noqa: E402


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
