"""Two fixture tenants and five change requests that exercise every decision path."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from ..domain.models import (
    ChangeKind,
    ChangePolicy,
    ChangeRecord,
    ChangeRequest,
    ConfigValue,
    Decision,
    DependencyGraph,
    Environment,
    FreezeWindow,
    IncidentRecord,
    Requester,
    Role,
    Service,
    TenantContext,
)

EVAL_NOW = datetime(2026, 6, 25, 12, 0, 0, tzinfo=timezone.utc)


def _dt(y, m, d, h=0) -> datetime:
    return datetime(y, m, d, h, 0, 0, tzinfo=timezone.utc)


_ACME = "acme"

_ACME_SERVICES = {
    "gateway": Service("gateway", "API Gateway", traffic_fraction=0.90),
    "auth": Service("auth", "Auth Service", traffic_fraction=0.50),
    "catalog": Service("catalog", "Catalog Service", traffic_fraction=0.60),
    "search": Service("search", "Search Service", traffic_fraction=0.30),
    "db-core": Service("db-core", "Core Database", traffic_fraction=0.20),
    "payments": Service("payments", "Payments Service", traffic_fraction=0.40),
    "ledger": Service("ledger", "Ledger Service", traffic_fraction=0.10),
    "notifications": Service("notifications", "Notifications", traffic_fraction=0.05),
}

_ACME_DEPENDS_ON = {
    "gateway": frozenset({"auth", "catalog"}),
    "auth": frozenset({"db-core"}),
    "catalog": frozenset({"db-core", "search"}),
    "search": frozenset({"db-core"}),
    "db-core": frozenset(),
    "payments": frozenset({"auth", "ledger"}),
    "ledger": frozenset(),
    "notifications": frozenset({"auth"}),
}

_ACME_GRAPH = DependencyGraph(services=_ACME_SERVICES, depends_on=_ACME_DEPENDS_ON)

_ACME_CONFIG = {
    ("beta_banner", Environment.DEV): ConfigValue("beta_banner", Environment.DEV, ChangeKind.FLAG, False),
    ("checkout_v2", Environment.PROD): ConfigValue("checkout_v2", Environment.PROD, ChangeKind.FLAG, False),
    ("db_pool_size", Environment.PROD): ConfigValue("db_pool_size", Environment.PROD, ChangeKind.CONFIG, 20),
    ("fraud_threshold", Environment.STAGING): ConfigValue("fraud_threshold", Environment.STAGING, ChangeKind.CONFIG, 100.0),
    ("search_timeout_ms", Environment.DEV): ConfigValue("search_timeout_ms", Environment.DEV, ChangeKind.CONFIG, 200),
}

_ACME_FREEZE = [
    FreezeWindow(
        id="acme-freeze-1",
        name="mid-year-prod-freeze",
        start=_dt(2026, 6, 20),
        end=_dt(2026, 6, 30),
        environments=frozenset({Environment.PROD}),
        reason="Mid-year revenue period: prod changes frozen.",
    )
]

_ACME_INCIDENTS = [
    IncidentRecord(service_id="payments", at=_dt(2026, 6, 20), severity="sev1", resolved=True),
    IncidentRecord(service_id="search", at=_dt(2026, 1, 5), severity="sev2", resolved=True),
]

_ACME_CHANGES = [
    ChangeRecord("db-core", "db_pool_size", Environment.PROD, _dt(2026, 3, 1), Decision.AUTO_APPROVE),
]

_ACME_POLICY = ChangePolicy(
    tenant_id=_ACME,
    env_criticality={
        Environment.DEV: 0.20,
        Environment.STAGING: 0.60,
        Environment.PROD: 1.00,
    },
    env_authority={
        Environment.DEV: frozenset({Role.DEVELOPER, Role.LEAD, Role.ONCALL}),
        Environment.STAGING: frozenset({Role.LEAD, Role.ONCALL}),
        Environment.PROD: frozenset({Role.LEAD, Role.ONCALL}),
    },
    factor_weights={
        "blast_radius": 0.35,
        "environment_criticality": 0.30,
        "magnitude": 0.20,
        "recency": 0.15,
    },
    band_low_max=30.0,
    band_medium_max=65.0,
    recency_lookback_days=14,
    magnitude_full_delta=0.5,
    blast_radius_saturation=5,
)

ACME_CONTEXT = TenantContext(
    tenant_id=_ACME,
    policy=_ACME_POLICY,
    graph=_ACME_GRAPH,
    freeze_windows=_ACME_FREEZE,
    config=_ACME_CONFIG,
    change_history=_ACME_CHANGES,
    incident_history=_ACME_INCIDENTS,
)


_GLOBEX = "globex"

_GLOBEX_SERVICES = {
    "edge": Service("edge", "Edge Proxy", traffic_fraction=0.80),
    "billing": Service("billing", "Billing", traffic_fraction=0.50),
}
_GLOBEX_GRAPH = DependencyGraph(
    services=_GLOBEX_SERVICES,
    depends_on={"edge": frozenset({"billing"}), "billing": frozenset()},
)
_GLOBEX_CONFIG = {
    ("dark_mode", Environment.PROD): ConfigValue("dark_mode", Environment.PROD, ChangeKind.FLAG, False),
}
_GLOBEX_POLICY = ChangePolicy(
    tenant_id=_GLOBEX,
    env_criticality={Environment.DEV: 0.2, Environment.STAGING: 0.5, Environment.PROD: 1.0},
    env_authority={
        Environment.DEV: frozenset({Role.DEVELOPER, Role.LEAD}),
        Environment.STAGING: frozenset({Role.LEAD}),
        Environment.PROD: frozenset({Role.LEAD}),
    },
    factor_weights={
        "blast_radius": 0.30,
        "environment_criticality": 0.40,
        "magnitude": 0.20,
        "recency": 0.10,
    },
    band_low_max=25.0,
    band_medium_max=60.0,
    recency_lookback_days=7,
    magnitude_full_delta=0.5,
    blast_radius_saturation=3,
)
GLOBEX_CONTEXT = TenantContext(
    tenant_id=_GLOBEX,
    policy=_GLOBEX_POLICY,
    graph=_GLOBEX_GRAPH,
    freeze_windows=[],
    config=_GLOBEX_CONFIG,
    change_history=[],
    incident_history=[],
)


TENANTS: dict[str, TenantContext] = {
    _ACME: ACME_CONTEXT,
    _GLOBEX: GLOBEX_CONTEXT,
}


@dataclass(frozen=True)
class Scenario:
    name: str
    request: ChangeRequest
    expected: Decision
    note: str


def _req(**kw) -> ChangeRequest:
    return ChangeRequest(**kw)


SCENARIOS: list[Scenario] = [
    Scenario(
        name="low_risk_dev_flag",
        expected=Decision.AUTO_APPROVE,
        note="dev flag flip, no dependents, no incidents -> low band -> auto-approve",
        request=_req(
            id="cr-001", tenant_id=_ACME,
            requester=Requester("u-dev", Role.DEVELOPER),
            service_id="notifications", key="beta_banner", kind=ChangeKind.FLAG,
            environment=Environment.DEV, current_value=False, proposed_value=True,
            window_start=_dt(2026, 6, 26), window_end=_dt(2026, 6, 26, 2),
        ),
    ),
    Scenario(
        name="high_blast_prod_config",
        expected=Decision.ROUTE,
        note="prod db-core config doubling: high blast + prod + full magnitude -> high band -> route",
        request=_req(
            id="cr-002", tenant_id=_ACME,
            requester=Requester("u-lead", Role.LEAD),
            service_id="db-core", key="db_pool_size", kind=ChangeKind.CONFIG,
            environment=Environment.PROD, current_value=20, proposed_value=40,
            window_start=_dt(2026, 7, 5), window_end=_dt(2026, 7, 5, 1),
        ),
    ),
    Scenario(
        name="freeze_window_collision",
        expected=Decision.DENY,
        note="prod change during the mid-year freeze -> hard deny",
        request=_req(
            id="cr-003", tenant_id=_ACME,
            requester=Requester("u-lead", Role.LEAD),
            service_id="gateway", key="checkout_v2", kind=ChangeKind.FLAG,
            environment=Environment.PROD, current_value=False, proposed_value=True,
            window_start=_dt(2026, 6, 26), window_end=_dt(2026, 6, 26, 1),
        ),
    ),
    Scenario(
        name="missing_prod_authority",
        expected=Decision.DENY,
        note="developer requesting a prod change -> authority deny",
        request=_req(
            id="cr-004", tenant_id=_ACME,
            requester=Requester("u-dev", Role.DEVELOPER),
            service_id="gateway", key="checkout_v2", kind=ChangeKind.FLAG,
            environment=Environment.PROD, current_value=False, proposed_value=True,
            window_start=_dt(2026, 7, 5), window_end=_dt(2026, 7, 5, 1),
        ),
    ),
    Scenario(
        name="recent_incident_service",
        expected=Decision.ROUTE,
        note="staging change to a recently-incident'd service -> medium band -> route",
        request=_req(
            id="cr-005", tenant_id=_ACME,
            requester=Requester("u-lead", Role.LEAD),
            service_id="payments", key="fraud_threshold", kind=ChangeKind.CONFIG,
            environment=Environment.STAGING, current_value=100.0, proposed_value=110.0,
            window_start=_dt(2026, 6, 26), window_end=_dt(2026, 6, 26, 1),
        ),
    ),
]

SCENARIOS_BY_NAME: dict[str, Scenario] = {s.name: s for s in SCENARIOS}
