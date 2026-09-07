"""Red-team over live Keycloak and Postgres. Skipped unless the CI job's services are up."""

from __future__ import annotations

import os

import pytest

from eval.live import login_form_action
from eval.redteam import load_cases, run_corpus

LIVE = pytest.mark.skipif(not (os.getenv("WARDEN_LIVE_ISSUER") and os.getenv("WARDEN_PG_ADMIN_DSN")),
                          reason="live Keycloak and Postgres not configured")


def test_login_form_action_reads_keycloak_markup():
    page = ('<form id="kc-form-login" onsubmit="login.disabled = true; return true;" '
            'action="http://localhost:8080/realms/warden/login-actions/authenticate?'
            'session_code=abc&amp;execution=x" method="post">')
    assert login_form_action(page).endswith("session_code=abc&execution=x")


@LIVE
@pytest.mark.keycloak
@pytest.mark.postgres
def test_live_cases_are_contained_and_audited():
    ids = {"uaa-rp-01", "wtr-rp-01", "pes-hu-03", "uaa-at-01", "fwb-mn-01"}
    run = run_corpus("live", [c for c in load_cases() if c["id"] in ids])
    s = run["summary"]["overall"]
    assert s["cases"] == len(ids)
    assert s["attack_successes"] == 0
    assert s["unsafe_auto_approvals"] == 0 and s["cross_tenant_reads"] == 0
    assert s["audit_gaps"] == 0
    assert s["audit_chain_verified"] == s["cases"]
    human = next(c for c in run["cases"] if c["id"] == "pes-hu-03")
    assert human["steered_calls"][0]["rule"] == "no-self-approval"
