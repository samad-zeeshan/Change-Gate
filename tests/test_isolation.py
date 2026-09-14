"""Tenant isolation in memory and, when a DSN is set, under Postgres row-level security."""

from __future__ import annotations

import os

import pytest

from warden.db.repository import CrossTenantAccess, InMemoryRepository


def test_inmemory_cross_tenant_read_denied():
    globex = InMemoryRepository("globex")
    with pytest.raises(CrossTenantAccess):
        globex.get_change_request("cr-001")


def test_inmemory_cross_tenant_audit_write_denied():
    acme = InMemoryRepository("acme")
    with pytest.raises(CrossTenantAccess):
        acme.append_audit(tenant_id="globex", subject="x", action="a", environment="prod",
                          decision="deny", risk_band="high", risk_score=99.0,
                          before=None, after=None, reason="r", risk_breakdown={},
                          request_id="cr", trace_id="", timestamp=__import__("datetime").datetime.now())


def test_inmemory_sandboxes_are_independent():
    a = InMemoryRepository("acme")
    b = InMemoryRepository("acme")
    from warden.domain.models import Environment

    a.apply_config_change("beta_banner", Environment.DEV, False, True)
    assert b.get_config_state("beta_banner", Environment.DEV).value is False


def test_inmemory_extra_requests_keep_tenant_isolation():
    import dataclasses

    from warden.data import seed

    foreign = dataclasses.replace(seed.SCENARIOS[0].request, id="gx-1", tenant_id="globex")
    acme = InMemoryRepository("acme", requests=[foreign])
    globex = InMemoryRepository("globex", requests=[foreign])
    assert globex.get_change_request("gx-1") is foreign
    with pytest.raises(CrossTenantAccess):
        acme.get_change_request("gx-1")
    assert acme.get_change_request("cr-001") is not None
    assert InMemoryRepository("acme").get_change_request("gx-1") is None


APP_DSN = os.getenv("WARDEN_PG_DSN")
ADMIN_DSN = os.getenv("WARDEN_PG_ADMIN_DSN")
pg = pytest.mark.skipif(not APP_DSN, reason="WARDEN_PG_DSN not set")


@pg
@pytest.mark.postgres
def test_rls_scopes_reads_to_the_bound_tenant():
    from warden.db.postgres_repository import connect

    acme = connect(APP_DSN, "acme")
    globex = connect(APP_DSN, "globex")

    acme_services = set(acme.get_tenant_context().graph.services)
    globex_services = set(globex.get_tenant_context().graph.services)

    assert "db-core" in acme_services and "db-core" not in globex_services
    assert "edge" in globex_services and "edge" not in acme_services
    assert acme_services.isdisjoint(globex_services)


@pg
@pytest.mark.postgres
def test_rls_blocks_cross_tenant_write():
    import psycopg

    conn = psycopg.connect(APP_DSN)
    with conn.cursor() as cur:
        cur.execute("SELECT set_config('app.current_tenant', 'acme', false)")
    conn.commit()
    with pytest.raises(psycopg.errors.Error):
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO services(tenant_id, id, name, traffic_fraction) "
                "VALUES ('globex', 'sneaky', 'sneaky', 0.1)"
            )
        conn.commit()
    conn.rollback()


@pytest.mark.skipif(not ADMIN_DSN, reason="WARDEN_PG_ADMIN_DSN not set")
@pytest.mark.postgres
def test_control_isolation_fails_without_rls_then_restore():
    import psycopg

    admin = psycopg.connect(ADMIN_DSN)
    try:
        with admin.cursor() as cur:
            cur.execute("ALTER TABLE services DISABLE ROW LEVEL SECURITY")
        admin.commit()

        from warden.db.postgres_repository import connect

        acme = connect(APP_DSN, "acme")
        leaked = set(acme.get_tenant_context().graph.services)
        assert "edge" in leaked, "expected a leak with RLS disabled — control has teeth"
    finally:
        with admin.cursor() as cur:
            cur.execute("ALTER TABLE services ENABLE ROW LEVEL SECURITY")
            cur.execute("ALTER TABLE services FORCE ROW LEVEL SECURITY")
        admin.commit()
        admin.close()


@pg
@pytest.mark.postgres
def test_rls_rescopes_when_tenant_changes_on_one_connection():
    import psycopg

    conn = psycopg.connect(APP_DSN)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('app.current_tenant', 'acme', false)")
            cur.execute("SELECT id FROM services")
            acme_view = {r[0] for r in cur.fetchall()}
            cur.execute("SELECT set_config('app.current_tenant', 'globex', false)")
            cur.execute("SELECT id FROM services")
            globex_view = {r[0] for r in cur.fetchall()}
        conn.commit()
    finally:
        conn.close()

    assert "db-core" in acme_view and "edge" not in acme_view
    assert "edge" in globex_view and "db-core" not in globex_view
    assert acme_view.isdisjoint(globex_view)


@pg
@pytest.mark.postgres
def test_unset_tenant_context_denies_returns_zero_rows_not_error():
    import psycopg

    conn = psycopg.connect(APP_DSN)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM services")
            count = cur.fetchone()[0]
        conn.commit()
    finally:
        conn.close()

    assert count == 0


@pg
@pytest.mark.postgres
def test_postgres_chain_with_evidence_verifies_as_read_back():
    import dataclasses

    from warden.audit import verify_entries
    from warden.clock import FixedClock
    from warden.data import seed
    from warden.db.postgres_repository import connect
    from warden.security import SCOPE_APPROVE, SCOPE_READ, AuthPrincipal
    from warden.tools import ToolService

    repo = connect(APP_DSN, "acme")
    agent = AuthPrincipal("svc", "acme", "lead", frozenset({SCOPE_READ, SCOPE_APPROVE}),
                          token_id="pg-evidence")
    for rid in ("cr-002", "cr-005"):
        svc = ToolService(repo, FixedClock(seed.EVAL_NOW),
                          principal=dataclasses.replace(agent, request_id=rid))
        if svc.request_state(rid) == "new":
            svc.record_decision(rid)
    entries = repo.audit_log_entries()
    assert entries and all(e.evidence for e in entries if e.action != "policy_version")
    assert verify_entries(entries, "acme")
