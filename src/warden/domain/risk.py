"""
Score the risk of a change request from independent factors and assign a band.

Pure functions only. Given the same request, tenant context, and clock, the
output is identical, which is what lets us fingerprint and audit a decision.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Sequence

from .models import (
    ChangeKind,
    ChangePolicy,
    ChangeRequest,
    Environment,
    RiskBand,
    TenantContext,
)

WEIGHTED_FACTORS = ("blast_radius", "environment_criticality", "magnitude", "recency")


@dataclass(frozen=True)
class FactorScore:

    name: str
    normalized: float
    weight: float
    raw: dict
    is_hard_deny: bool = False
    hard_deny_reason: str = ""

    @property
    def contribution(self) -> float:
        return round(self.normalized * self.weight, 6)


@dataclass(frozen=True)
class RiskAssessment:

    score: float
    band: RiskBand
    factors: tuple[FactorScore, ...]
    hard_deny: bool
    hard_deny_reasons: tuple[str, ...]
    inputs_fingerprint: str

    def factor(self, name: str) -> FactorScore:
        for f in self.factors:
            if f.name == name:
                return f
        raise KeyError(name)

    def to_breakdown(self) -> dict:
        return {
            "score": self.score,
            "band": self.band.value,
            "hard_deny": self.hard_deny,
            "hard_deny_reasons": list(self.hard_deny_reasons),
            "inputs_fingerprint": self.inputs_fingerprint,
            "factors": [
                {
                    "name": f.name,
                    "normalized": round(f.normalized, 4),
                    "weight": f.weight,
                    "contribution": f.contribution,
                    "raw": f.raw,
                    "is_hard_deny": f.is_hard_deny,
                    "hard_deny_reason": f.hard_deny_reason,
                }
                for f in self.factors
            ],
        }


def _reverse_reachable(ctx: TenantContext, service_id: str) -> set[str]:
    # Walk the dependents edge, not depends_on. We want everyone who breaks if
    # this service breaks, which is the transitive set of things pointing at it.
    affected: set[str] = set()
    frontier = [service_id]
    while frontier:
        current = frontier.pop()
        for dependent in ctx.graph.dependents_of(current):
            if dependent not in affected:
                affected.add(dependent)
                frontier.append(dependent)
    affected.discard(service_id)
    return affected


def blast_radius(request: ChangeRequest, ctx: TenantContext) -> FactorScore:
    affected = sorted(_reverse_reachable(ctx, request.service_id))
    count = len(affected)
    traffic = 0.0
    for sid in affected:
        svc = ctx.graph.services.get(sid)
        if svc is not None:
            traffic += svc.traffic_fraction
    traffic = min(1.0, round(traffic, 6))

    saturation = max(1, ctx.policy.blast_radius_saturation)
    count_norm = min(1.0, count / saturation)
    # Take whichever is worse: many small services or a few that carry real
    # traffic. A single dependent serving most users should still score high.
    normalized = max(count_norm, traffic)

    return FactorScore(
        name="blast_radius",
        normalized=normalized,
        weight=ctx.policy.factor_weights.get("blast_radius", 0.0),
        raw={
            "downstream_count": count,
            "affected_traffic_fraction": traffic,
            "affected_services": affected,
            "saturation_count": saturation,
        },
    )


def environment_criticality(request: ChangeRequest, ctx: TenantContext) -> FactorScore:
    weight_table = ctx.policy.env_criticality
    normalized = float(weight_table.get(request.environment, 0.0))
    return FactorScore(
        name="environment_criticality",
        normalized=min(1.0, max(0.0, normalized)),
        weight=ctx.policy.factor_weights.get("environment_criticality", 0.0),
        raw={
            "environment": request.environment.value,
            "criticality_weight": normalized,
        },
    )


def _overlaps(a_start: datetime, a_end: datetime, b_start: datetime, b_end: datetime) -> bool:
    return a_start <= b_end and b_start <= a_end


def freeze_collision(request: ChangeRequest, ctx: TenantContext, now: datetime) -> FactorScore:
    # Clamp the start to now. A window that opened in the past can only collide
    # over the part that is still ahead of us.
    eff_start = max(now, request.window_start)
    eff_end = request.window_end

    colliding: list[str] = []
    for fw in ctx.freeze_windows:
        if not fw.covers(request.environment):
            continue
        # Clamping can invert the window if it already closed. No time left, no collision.
        if eff_start > eff_end:
            continue
        if _overlaps(eff_start, eff_end, fw.start, fw.end):
            colliding.append(fw.name)

    collided = bool(colliding)
    reason = (
        f"change window collides with freeze window(s): {', '.join(colliding)}"
        if collided
        else ""
    )
    # Weight is 0 on purpose. Freeze is a hard deny, not something that feeds the
    # weighted score. It overrides the band entirely in assess_risk.
    return FactorScore(
        name="freeze_collision",
        normalized=1.0 if collided else 0.0,
        weight=0.0,
        raw={
            "effective_window": [eff_start.isoformat(), eff_end.isoformat()],
            "colliding_windows": colliding,
        },
        is_hard_deny=collided,
        hard_deny_reason=reason,
    )


_FLAG_FLIP_WEIGHT = {
    Environment.PROD: 1.0,
    Environment.STAGING: 0.6,
    Environment.DEV: 0.4,
}


def magnitude(request: ChangeRequest, ctx: TenantContext) -> FactorScore:
    if request.kind is ChangeKind.FLAG:
        flipped = bool(request.current_value) != bool(request.proposed_value)
        normalized = _FLAG_FLIP_WEIGHT.get(request.environment, 0.4) if flipped else 0.0
        raw = {
            "kind": "flag",
            "from": bool(request.current_value),
            "to": bool(request.proposed_value),
            "flipped": flipped,
        }
        return FactorScore(
            name="magnitude",
            normalized=normalized,
            weight=ctx.policy.factor_weights.get("magnitude", 0.0),
            raw=raw,
        )

    try:
        current = float(request.current_value)
        proposed = float(request.proposed_value)
    except (TypeError, ValueError):
        changed = request.current_value != request.proposed_value
        return FactorScore(
            name="magnitude",
            normalized=1.0 if changed else 0.0,
            weight=ctx.policy.factor_weights.get("magnitude", 0.0),
            raw={"kind": "config", "non_numeric": True, "changed": changed},
        )

    # Percent change is undefined from zero, so treat any move off zero as a full
    # delta rather than dividing and blowing up.
    if current == 0.0:
        delta = 0.0 if proposed == 0.0 else 1.0
    else:
        delta = abs(proposed - current) / abs(current)

    full = max(1e-9, ctx.policy.magnitude_full_delta)
    normalized = min(1.0, delta / full)
    return FactorScore(
        name="magnitude",
        normalized=normalized,
        weight=ctx.policy.factor_weights.get("magnitude", 0.0),
        raw={
            "kind": "config",
            "from": current,
            "to": proposed,
            "percent_delta": round(delta, 6),
            "full_delta_threshold": full,
        },
    )


def recency(request: ChangeRequest, ctx: TenantContext, now: datetime) -> FactorScore:
    lookback = now - timedelta(days=ctx.policy.recency_lookback_days)

    recent_incidents = [
        i for i in ctx.incident_history
        if i.service_id == request.service_id and lookback <= i.at <= now
    ]
    recent_changes = [
        c for c in ctx.change_history
        if c.service_id == request.service_id and c.key == request.key
        and lookback <= c.at <= now
    ]

    # Ladder from worst to mild: an open incident is the strongest signal, then a
    # resolved sev1, then any other recent incident. The service is already shaky.
    if any(not i.resolved for i in recent_incidents):
        incident_score = 1.0
    elif any(i.severity == "sev1" for i in recent_incidents):
        incident_score = 0.9
    elif recent_incidents:
        incident_score = 0.6
    else:
        incident_score = 0.0

    # Churn on the same key matters but never as much as an incident, so it is
    # capped at 0.5 and saturates at three recent changes.
    change_score = min(1.0, len(recent_changes) / 3.0) * 0.5

    normalized = max(incident_score, change_score)
    return FactorScore(
        name="recency",
        normalized=normalized,
        weight=ctx.policy.factor_weights.get("recency", 0.0),
        raw={
            "lookback_days": ctx.policy.recency_lookback_days,
            "recent_incident_count": len(recent_incidents),
            "unresolved_incident": any(not i.resolved for i in recent_incidents),
            "recent_change_count": len(recent_changes),
        },
    )


def band_for(score: float, policy: ChangePolicy) -> RiskBand:
    if score < policy.band_low_max:
        return RiskBand.LOW
    if score < policy.band_medium_max:
        return RiskBand.MEDIUM
    return RiskBand.HIGH


def _fingerprint(request: ChangeRequest, ctx: TenantContext, now: datetime) -> str:

    def _svc(s):
        return {"id": s.id, "name": s.name, "traffic": s.traffic_fraction}

    payload = {
        "request": {
            "service_id": request.service_id,
            "key": request.key,
            "kind": request.kind.value,
            "environment": request.environment.value,
            "current_value": request.current_value,
            "proposed_value": request.proposed_value,
            "window": [request.window_start.isoformat(), request.window_end.isoformat()],
        },
        "now": now.isoformat(),
        "policy": {
            "env_criticality": {k.value: v for k, v in ctx.policy.env_criticality.items()},
            "factor_weights": dict(sorted(ctx.policy.factor_weights.items())),
            "band_low_max": ctx.policy.band_low_max,
            "band_medium_max": ctx.policy.band_medium_max,
            "recency_lookback_days": ctx.policy.recency_lookback_days,
            "magnitude_full_delta": ctx.policy.magnitude_full_delta,
            "blast_radius_saturation": ctx.policy.blast_radius_saturation,
        },
        "graph": {
            "services": {k: _svc(v) for k, v in sorted(ctx.graph.services.items())},
            "depends_on": {k: sorted(v) for k, v in sorted(ctx.graph.depends_on.items())},
        },
        "freeze_windows": sorted(
            [
                [fw.id, fw.start.isoformat(), fw.end.isoformat(),
                 sorted(e.value for e in fw.environments)]
                for fw in ctx.freeze_windows
            ]
        ),
        "incidents": sorted(
            [[i.service_id, i.at.isoformat(), i.severity, i.resolved]
             for i in ctx.incident_history]
        ),
        "changes": sorted(
            [[c.service_id, c.key, c.environment.value, c.at.isoformat(), c.decision.value]
             for c in ctx.change_history]
        ),
    }
    # sort_keys and sorted collections make this stable across dict ordering, so
    # the same inputs always fingerprint the same. This is what ties an audit
    # entry back to the exact state it was decided on.
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def assess_risk(request: ChangeRequest, ctx: TenantContext, now: datetime) -> RiskAssessment:
    weighted: Sequence[FactorScore] = (
        blast_radius(request, ctx),
        environment_criticality(request, ctx),
        magnitude(request, ctx),
        recency(request, ctx, now),
    )
    freeze = freeze_collision(request, ctx, now)

    # Weighted average over the active factors, scaled to 0-100. Dividing by the
    # actual total weight means a policy that zeroes a factor still scores sanely.
    total_weight = sum(f.weight for f in weighted)
    if total_weight <= 0:
        score = 0.0
    else:
        score = sum(f.contribution for f in weighted) / total_weight * 100.0
    score = round(score, 2)

    band = band_for(score, ctx.policy)
    hard_deny = freeze.is_hard_deny
    reasons: list[str] = []
    if freeze.is_hard_deny:
        reasons.append(freeze.hard_deny_reason)
        # A freeze hit forces HIGH regardless of the computed score so the
        # decision layer routes or denies rather than auto-approving.
        band = RiskBand.HIGH

    return RiskAssessment(
        score=score,
        band=band,
        factors=(*weighted, freeze),
        hard_deny=hard_deny,
        hard_deny_reasons=tuple(reasons),
        inputs_fingerprint=_fingerprint(request, ctx, now),
    )
