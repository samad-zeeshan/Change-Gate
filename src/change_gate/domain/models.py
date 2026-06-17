"""
Frozen domain types: requests, policy, the dependency graph, and tenant context.

These are immutable value objects so the risk and decision layers stay pure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Mapping, Optional, Sequence


class Environment(str, Enum):
    DEV = "dev"
    STAGING = "staging"
    PROD = "prod"


class ChangeKind(str, Enum):
    FLAG = "flag"
    CONFIG = "config"


class Role(str, Enum):

    DEVELOPER = "developer"
    LEAD = "lead"
    ONCALL = "oncall"
    VIEWER = "viewer"


class RiskBand(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Decision(str, Enum):
    AUTO_APPROVE = "auto_approve"
    ROUTE = "route"
    DENY = "deny"


@dataclass(frozen=True)
class Service:

    id: str
    name: str
    traffic_fraction: float


@dataclass(frozen=True)
class DependencyGraph:

    services: Mapping[str, Service]
    depends_on: Mapping[str, frozenset[str]]

    def dependents_of(self, service_id: str) -> frozenset[str]:
        # depends_on is stored forward (who I rely on). Blast radius needs the
        # reverse edge, so scan for everyone who lists this service as a dep.
        out: set[str] = set()
        for a, deps in self.depends_on.items():
            if service_id in deps:
                out.add(a)
        return frozenset(out)


@dataclass(frozen=True)
class FreezeWindow:

    id: str
    name: str
    start: datetime
    end: datetime
    environments: frozenset[Environment] = field(default_factory=frozenset)
    reason: str = ""

    def covers(self, env: Environment) -> bool:
        # An empty environment set means the freeze applies everywhere, not nowhere.
        return not self.environments or env in self.environments


@dataclass(frozen=True)
class ChangeRecord:

    service_id: str
    key: str
    environment: Environment
    at: datetime
    decision: Decision


@dataclass(frozen=True)
class IncidentRecord:

    service_id: str
    at: datetime
    severity: str
    resolved: bool


@dataclass(frozen=True)
class ConfigValue:

    key: str
    environment: Environment
    kind: ChangeKind
    value: object


@dataclass(frozen=True)
class ChangePolicy:

    tenant_id: str

    env_criticality: Mapping[Environment, float]

    env_authority: Mapping[Environment, frozenset[Role]]

    factor_weights: Mapping[str, float]

    band_low_max: float
    band_medium_max: float

    recency_lookback_days: int

    magnitude_full_delta: float

    blast_radius_saturation: int

    auto_approve_max_band: RiskBand = RiskBand.LOW


@dataclass(frozen=True)
class Requester:
    id: str
    role: Role


@dataclass(frozen=True)
class ChangeRequest:

    id: str
    tenant_id: str
    requester: Requester
    service_id: str
    key: str
    kind: ChangeKind
    environment: Environment
    current_value: object
    proposed_value: object
    window_start: datetime
    window_end: datetime


@dataclass(frozen=True)
class TenantContext:

    tenant_id: str
    policy: ChangePolicy
    graph: DependencyGraph
    freeze_windows: Sequence[FreezeWindow]
    config: Mapping[tuple[str, Environment], ConfigValue]
    change_history: Sequence[ChangeRecord]
    incident_history: Sequence[IncidentRecord]

    def current_config(self, key: str, env: Environment) -> Optional[ConfigValue]:
        return self.config.get((key, env))
