"""
Turn a validated request and its risk assessment into one of approve, route, or deny.

Decision precedence lives here: malformed beats unauthorized beats hard deny beats band.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import (
    ChangeKind,
    ChangePolicy,
    ChangeRequest,
    Decision,
    Role,
    TenantContext,
)
from .risk import RiskAssessment


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    authorized: bool
    errors: tuple[str, ...]

    @property
    def malformed(self) -> bool:
        # Malformed means a real input problem, not just a permissions one. Errors
        # are tagged by prefix so we can tell a bad request from an unauthorized one.
        return not self.ok and bool([e for e in self.errors if not e.startswith("authority:")])


def validate_request(request: ChangeRequest, ctx: TenantContext) -> ValidationResult:
    errors: list[str] = []

    if request.requester.role is Role.VIEWER:
        errors.append("malformed: viewer role may not request changes")

    if request.kind is ChangeKind.FLAG:
        if not isinstance(request.proposed_value, bool):
            errors.append("malformed: flag change requires a boolean proposed_value")
    else:
        if isinstance(request.proposed_value, bool) or not _is_number(request.proposed_value):
            errors.append("malformed: config change requires a numeric proposed_value")

    if ctx.current_config(request.key, request.environment) is None:
        errors.append(
            f"malformed: unknown key '{request.key}' in environment "
            f"'{request.environment.value}'"
        )

    if request.window_end < request.window_start:
        errors.append("malformed: window_end precedes window_start")

    # Authority is checked even when the request is malformed so the caller gets
    # the full picture. decide() picks which failure to report.
    permitted = ctx.policy.env_authority.get(request.environment, frozenset())
    authorized = request.requester.role in permitted
    if not authorized:
        errors.append(
            f"authority: role '{request.requester.role.value}' is not permitted to "
            f"change environment '{request.environment.value}'"
        )

    ok = not errors
    return ValidationResult(ok=ok, authorized=authorized, errors=tuple(errors))


def _is_number(v: object) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


@dataclass(frozen=True)
class DecisionResult:
    decision: Decision
    reasons: tuple[str, ...]

    def to_dict(self) -> dict:
        return {"decision": self.decision.value, "reasons": list(self.reasons)}


def decide(
    request: ChangeRequest,
    ctx: TenantContext,
    validation: ValidationResult,
    assessment: RiskAssessment,
    policy: ChangePolicy | None = None,
) -> DecisionResult:
    policy = policy or ctx.policy
    reasons: list[str] = []

    # Order matters. We deny on the most fundamental problem first so the reason
    # is the most useful one. A malformed request is reported as malformed even
    # if the requester also lacks authority.
    if validation.malformed:
        reasons.extend(e for e in validation.errors if e.startswith("malformed:"))
        return DecisionResult(Decision.DENY, tuple(reasons))

    if not validation.authorized:
        reasons.extend(e for e in validation.errors if e.startswith("authority:"))
        return DecisionResult(Decision.DENY, tuple(reasons))

    if assessment.hard_deny:
        reasons.extend(assessment.hard_deny_reasons)
        return DecisionResult(Decision.DENY, tuple(reasons))

    # Auto-approve only up to the policy's ceiling band. Anything above it is
    # well formed and allowed but too risky to approve without a human.
    band_rank = {"low": 0, "medium": 1, "high": 2}
    if band_rank[assessment.band.value] <= band_rank[policy.auto_approve_max_band.value]:
        reasons.append(
            f"risk band '{assessment.band.value}' within auto-approve ceiling "
            f"'{policy.auto_approve_max_band.value}'; no hard constraints"
        )
        return DecisionResult(Decision.AUTO_APPROVE, tuple(reasons))

    reasons.append(
        f"risk band '{assessment.band.value}' (score {assessment.score}) exceeds the "
        f"auto-approve ceiling; routing to change lead with full breakdown"
    )
    return DecisionResult(Decision.ROUTE, tuple(reasons))
