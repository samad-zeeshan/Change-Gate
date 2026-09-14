"""Each risk factor on its own: blast radius, environment, magnitude, recency."""

from __future__ import annotations

from datetime import datetime, timezone

from warden.data import seed
from warden.domain import risk
from warden.domain.models import (
    ChangeKind,
    ChangeRequest,
    Environment,
    Requester,
    Role,
)

NOW = seed.EVAL_NOW
CTX = seed.ACME_CONTEXT


def _req(**kw) -> ChangeRequest:
    base = dict(
        id="t", tenant_id="acme", requester=Requester("u", Role.LEAD),
        service_id="db-core", key="db_pool_size", kind=ChangeKind.CONFIG,
        environment=Environment.PROD, current_value=20, proposed_value=40,
        window_start=datetime(2026, 7, 5, tzinfo=timezone.utc),
        window_end=datetime(2026, 7, 5, 1, tzinfo=timezone.utc),
    )
    base.update(kw)
    return ChangeRequest(**base)


def test_blast_radius_counts_all_transitive_dependents():
    f = risk.blast_radius(_req(service_id="db-core"), CTX)
    assert f.raw["downstream_count"] == 6
    assert set(f.raw["affected_services"]) == {
        "auth", "catalog", "search", "gateway", "payments", "notifications"
    }
    assert f.normalized == 1.0


def test_blast_radius_is_zero_for_a_leaf_with_no_dependents():
    f = risk.blast_radius(_req(service_id="notifications"), CTX)
    assert f.raw["downstream_count"] == 0
    assert f.normalized == 0.0


def test_blast_radius_single_dependent():
    f = risk.blast_radius(_req(service_id="search"), CTX)
    assert set(f.raw["affected_services"]) == {"catalog", "gateway"}


def test_environment_criticality_uses_policy_weights():
    assert risk.environment_criticality(_req(environment=Environment.DEV), CTX).normalized == 0.20
    assert risk.environment_criticality(_req(environment=Environment.STAGING), CTX).normalized == 0.60
    assert risk.environment_criticality(_req(environment=Environment.PROD), CTX).normalized == 1.00


def test_freeze_collision_detected_inside_window_is_hard_deny():
    req = _req(
        environment=Environment.PROD,
        window_start=datetime(2026, 6, 26, tzinfo=timezone.utc),
        window_end=datetime(2026, 6, 26, 1, tzinfo=timezone.utc),
    )
    f = risk.freeze_collision(req, CTX, NOW)
    assert f.is_hard_deny is True
    assert "mid-year-prod-freeze" in f.raw["colliding_windows"]


def test_freeze_collision_absent_after_clock_advances_past_window():
    req = _req(
        environment=Environment.PROD,
        window_start=datetime(2026, 6, 26, tzinfo=timezone.utc),
        window_end=datetime(2026, 6, 26, 1, tzinfo=timezone.utc),
    )
    later = datetime(2026, 7, 1, tzinfo=timezone.utc)
    f = risk.freeze_collision(req, CTX, later)
    assert f.is_hard_deny is False


def test_freeze_collision_does_not_apply_to_unfrozen_environment():
    req = _req(
        environment=Environment.DEV,
        window_start=datetime(2026, 6, 26, tzinfo=timezone.utc),
        window_end=datetime(2026, 6, 26, 1, tzinfo=timezone.utc),
    )
    assert risk.freeze_collision(req, CTX, NOW).is_hard_deny is False


def test_magnitude_numeric_percent_delta():
    f = risk.magnitude(_req(current_value=20, proposed_value=40), CTX)
    assert f.raw["percent_delta"] == 1.0
    assert f.normalized == 1.0


def test_magnitude_small_numeric_delta_is_partial():
    f = risk.magnitude(_req(current_value=100, proposed_value=110), CTX)
    assert abs(f.raw["percent_delta"] - 0.1) < 1e-9
    assert abs(f.normalized - 0.2) < 1e-9


def test_magnitude_flag_flip_in_prod_is_full():
    f = risk.magnitude(
        _req(kind=ChangeKind.FLAG, environment=Environment.PROD,
             current_value=False, proposed_value=True),
        CTX,
    )
    assert f.raw["flipped"] is True
    assert f.normalized == 1.0


def test_magnitude_flag_no_op_is_zero():
    f = risk.magnitude(
        _req(kind=ChangeKind.FLAG, current_value=True, proposed_value=True),
        CTX,
    )
    assert f.normalized == 0.0


def test_recency_recent_incident_raises_score():
    f = risk.recency(_req(service_id="payments", key="fraud_threshold"), CTX, NOW)
    assert f.raw["recent_incident_count"] == 1
    assert f.normalized == 0.9


def test_recency_old_incident_outside_lookback_is_ignored():
    f = risk.recency(_req(service_id="search", key="search_timeout_ms"), CTX, NOW)
    assert f.raw["recent_incident_count"] == 0
    assert f.normalized == 0.0


def test_recency_depends_on_injected_clock():
    req = _req(service_id="payments", key="fraud_threshold")
    inside = risk.recency(req, CTX, datetime(2026, 6, 21, tzinfo=timezone.utc))
    outside = risk.recency(req, CTX, datetime(2027, 6, 21, tzinfo=timezone.utc))
    assert inside.normalized == 0.9
    assert outside.normalized == 0.0
