
from __future__ import annotations

import pytest

from warden.data import seed
from warden.domain.models import Decision


@pytest.mark.parametrize("scenario", seed.SCENARIOS, ids=lambda s: s.name)
def test_scenario_reaches_expected_decision(acme_service, scenario):
    result = acme_service.record_decision(
        scenario.request.id, now=seed.EVAL_NOW.isoformat(), trace_id="t-test"
    )
    assert result["decision"] == scenario.expected.value, scenario.note


def test_auto_approve_applies_simulated_config_change(acme_service):
    s = seed.SCENARIOS_BY_NAME["low_risk_dev_flag"]
    result = acme_service.record_decision(s.request.id, now=seed.EVAL_NOW.isoformat())
    assert result["decision"] == Decision.AUTO_APPROVE.value
    assert result["applied_config_change"] is True
    assert result["before"] is False and result["after"] is True


def test_deny_does_not_apply_a_change(acme_service):
    s = seed.SCENARIOS_BY_NAME["freeze_window_collision"]
    result = acme_service.record_decision(s.request.id, now=seed.EVAL_NOW.isoformat())
    assert result["decision"] == Decision.DENY.value
    assert result["applied_config_change"] is False
    assert any("freeze" in r for r in result["reasons"])


def test_route_includes_full_risk_breakdown(acme_service):
    s = seed.SCENARIOS_BY_NAME["high_blast_prod_config"]
    result = acme_service.record_decision(s.request.id, now=seed.EVAL_NOW.isoformat())
    assert result["decision"] == Decision.ROUTE.value
    factors = {f["name"] for f in result["risk"]["factors"]}
    assert {"blast_radius", "environment_criticality", "magnitude", "recency",
            "freeze_collision"} <= factors


def test_every_governed_write_emits_exactly_one_audit_row(acme_service, audit_log):
    for s in seed.SCENARIOS:
        acme_service.record_decision(s.request.id, now=seed.EVAL_NOW.isoformat())
    assert len(audit_log.for_tenant("acme")) == len(seed.SCENARIOS)
    assert audit_log.verify_chain("acme") is True
