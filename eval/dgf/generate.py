"""Generate synthetic governance projects in the shape of DGF-Bench (arXiv 2609.29345).

Each project is fully determined by its parameters and seed, so only those are committed.
"""

from __future__ import annotations

import json
import math
import random
from dataclasses import asdict, dataclass, replace
from datetime import timedelta
from pathlib import Path

from warden.data import seed as fixture
from warden.domain.models import (
    ChangeKind,
    ChangeRequest,
    ConfigValue,
    DependencyGraph,
    Environment,
    FreezeWindow,
    IncidentRecord,
    Requester,
    Role,
    Service,
    TenantContext,
)
from warden.domain.decision import validate_request
from warden.domain.risk import assess_risk

HERE = Path(__file__).resolve().parent


@dataclass(frozen=True)
class ProjectParams:
    id: str
    seed: int
    requests: int
    prod_share: float
    # How far true risk strays from what the engine can see. Near zero, the score
    # tracks real outcomes. At the top of the range it barely does.
    calibration_noise: float
    risky_base: float
    review: float
    exception_rate: float
    exception: float
    verification: float
    correction: float
    maintenance: float


@dataclass(frozen=True)
class LabelledRequest:
    request: ChangeRequest
    risky: bool


@dataclass
class Project:
    params: ProjectParams
    ctx: TenantContext
    requests: list[LabelledRequest]


def project_params(n: int = 300, seed: int = 2609) -> list[ProjectParams]:
    rng = random.Random(seed)
    out = []
    for i in range(1, n + 1):
        out.append(ProjectParams(
            id=f"dgf-{i:03d}", seed=rng.randrange(1, 2**31),
            requests=rng.randint(20, 400),
            prod_share=round(rng.uniform(0.15, 0.5), 3),
            calibration_noise=round(rng.uniform(0.05, 2.0), 3),
            risky_base=round(rng.uniform(-2.5, -0.5), 3),
            # Minutes. Review and correction ranges are guesses at a mid-size team,
            # not measurements, and the README says so.
            review=round(rng.uniform(8, 25), 2),
            exception_rate=round(rng.uniform(0.0, 0.3), 3),
            exception=round(rng.uniform(10, 40), 2),
            verification=round(rng.uniform(0.5, 4.0), 2),
            correction=round(rng.uniform(60, 480), 1),
            maintenance=round(rng.uniform(120, 1200), 1),
        ))
    return out


def _context(p: ProjectParams, rng: random.Random) -> TenantContext:
    tenant = p.id
    n_services = rng.randint(5, 12)
    ids = [f"svc-{k}" for k in range(n_services)]
    services = {s: Service(s, s, round(rng.uniform(0.02, 0.9), 2)) for s in ids}
    depends = {s: frozenset(rng.sample(ids[:k], min(k, rng.randint(0, 2))))
               for k, s in enumerate(ids)}
    config = {}
    for s in ids:
        for env in Environment:
            config[(f"{s}.flag", env)] = ConfigValue(f"{s}.flag", env, ChangeKind.FLAG, False)
            config[(f"{s}.limit", env)] = ConfigValue(f"{s}.limit", env, ChangeKind.CONFIG,
                                                      rng.randint(10, 200))
    start = fixture.EVAL_NOW + timedelta(days=rng.randint(-5, 20))
    freeze = [FreezeWindow(f"{tenant}-freeze", "release-freeze", start,
                           start + timedelta(days=rng.randint(2, 7)),
                           frozenset({Environment.PROD}), "synthetic freeze")]
    incidents = [IncidentRecord(rng.choice(ids), fixture.EVAL_NOW - timedelta(days=rng.randint(1, 30)),
                                rng.choice(["sev1", "sev2", "sev3"]), rng.random() < 0.8)
                 for _ in range(rng.randint(0, 4))]
    policy = replace(fixture.ACME_CONTEXT.policy, tenant_id=tenant)
    return TenantContext(tenant, policy, DependencyGraph(services, depends), freeze, config,
                         [], incidents)


def generate_project(p: ProjectParams) -> Project:
    rng = random.Random(p.seed)
    ctx = _context(p, rng)
    ids = list(ctx.graph.services)
    out = []
    for k in range(p.requests):
        svc = rng.choice(ids)
        r = rng.random()
        env = Environment.PROD if r < p.prod_share else (
            Environment.STAGING if r < p.prod_share + (1 - p.prod_share) / 2 else Environment.DEV)
        if rng.random() < 0.5:
            key, kind, cur, new = f"{svc}.flag", ChangeKind.FLAG, False, True
        else:
            key, kind = f"{svc}.limit", ChangeKind.CONFIG
            cur = ctx.config[(key, env)].value
            new = max(1, round(cur * (1 + rng.uniform(-0.5, 1.5))))
        role = rng.choices([Role.LEAD, Role.ONCALL, Role.DEVELOPER], [0.45, 0.2, 0.35])[0]
        start = fixture.EVAL_NOW + timedelta(days=rng.randint(0, 25), hours=rng.randint(0, 23))
        req = ChangeRequest(f"{p.id}-cr-{k:04d}", p.id, Requester(f"u-{k % 17}", role), svc,
                            key, kind, env, cur, new, start, start + timedelta(hours=2))
        risk = assess_risk(req, ctx, fixture.EVAL_NOW)
        # Ground truth: the engine's score explains part of the outcome and a hidden
        # factor the engine cannot see explains the rest.
        logit = 6 * (risk.score / 100 - 0.5) + p.risky_base + rng.gauss(0, p.calibration_noise)
        outage = rng.random() < 1 / (1 + math.exp(-logit))
        # A change inside a freeze or from someone without authority must not ship,
        # so it is never "safe", whatever its outage risk.
        violation = risk.hard_deny or not validate_request(req, ctx).ok
        out.append(LabelledRequest(req, outage or violation))
    return Project(p, ctx, out)


def write_params(params: list[ProjectParams], path: Path = HERE / "projects.json") -> None:
    path.write_text(json.dumps({"generator": "eval/dgf/generate.py", "seed": 2609,
                                "projects": [asdict(p) for p in params]}, indent=1) + "\n",
                    encoding="utf-8")


def write_sample(project: Project, path: Path = HERE / "sample-project.json") -> None:
    rows = [{"id": lr.request.id, "service": lr.request.service_id, "key": lr.request.key,
             "environment": lr.request.environment.value,
             "requester_role": lr.request.requester.role.value,
             "current": lr.request.current_value, "proposed": lr.request.proposed_value,
             "window_start": lr.request.window_start.isoformat(), "risky": lr.risky}
            for lr in project.requests]
    path.write_text(json.dumps({"params": asdict(project.params), "requests": rows},
                               indent=1) + "\n", encoding="utf-8")
