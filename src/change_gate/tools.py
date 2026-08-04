"""
The tool surface: read context, validate, assess risk, and the four writes.

record_decision runs the gate and re-runs validation and risk so the stored
decision never trusts the agent's earlier reads. route_change, approve_change and
deny_change are the human side. Every write asks the action policy first.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from .audit import AuditEntry
from .clock import Clock, ensure_utc
from .db.repository import CrossTenantAccess, Repository
from .domain.decision import decide, validate_request
from .domain.models import ChangeRequest, Decision, Environment
from .domain.risk import RiskAssessment, assess_risk
from .policy import (
    ActionPolicy,
    PolicyDecision,
    PolicyDenied,
    ProposedAction,
    load_action_policy,
)
from .security import PERSONA_UNKNOWN, AuthPrincipal, AuthorizationError, authorize_write

# The state of a request is whatever its last successful decision entry says.
# Denied attempts are audited under other action names and never move the state.
_STATE_AFTER = {
    ("record_decision", Decision.AUTO_APPROVE.value): "auto_approved",
    ("record_decision", Decision.ROUTE.value): "routed",
    ("record_decision", Decision.DENY.value): "denied",
    ("route_change", "route"): "routed",
    ("approve_change", "approve"): "approved",
    ("deny_change", "deny"): "denied",
}


class ToolError(RuntimeError):
    pass


class ToolService:

    def __init__(
        self,
        repo: Repository,
        clock: Clock,
        principal: Optional[AuthPrincipal] = None,
        policy: Optional[ActionPolicy] = None,
    ) -> None:
        self.repo = repo
        self.clock = clock
        self.principal = principal
        self.policy = policy or load_action_policy()


    def get_change_request(self, request_id: str) -> dict:
        return _request_to_dict(self._require_request(request_id))

    def get_change_policy(self) -> dict:
        policy = self.repo.get_tenant_context().policy
        return {
            "tenant_id": policy.tenant_id,
            "env_criticality": {k.value: v for k, v in policy.env_criticality.items()},
            "env_authority": {
                k.value: sorted(r.value for r in v) for k, v in policy.env_authority.items()
            },
            "factor_weights": dict(policy.factor_weights),
            "band_low_max": policy.band_low_max,
            "band_medium_max": policy.band_medium_max,
            "recency_lookback_days": policy.recency_lookback_days,
            "magnitude_full_delta": policy.magnitude_full_delta,
            "blast_radius_saturation": policy.blast_radius_saturation,
            "auto_approve_max_band": policy.auto_approve_max_band.value,
        }

    def get_config_state(self, key: str, environment: str) -> dict:
        env = Environment(environment)
        cv = self.repo.get_config_state(key, env)
        if cv is None:
            raise ToolError(f"unknown key {key!r} in {environment!r}")
        return {
            "key": cv.key,
            "environment": cv.environment.value,
            "kind": cv.kind.value,
            "value": cv.value,
        }

    def get_dependency_graph(self) -> dict:
        graph = self.repo.get_tenant_context().graph
        return {
            "services": {
                sid: {"name": s.name, "traffic_fraction": s.traffic_fraction}
                for sid, s in graph.services.items()
            },
            "depends_on": {k: sorted(v) for k, v in graph.depends_on.items()},
        }

    def get_freeze_windows(self) -> dict:
        windows = self.repo.get_tenant_context().freeze_windows
        return {
            "freeze_windows": [
                {
                    "id": fw.id,
                    "name": fw.name,
                    "start": fw.start.isoformat(),
                    "end": fw.end.isoformat(),
                    "environments": sorted(e.value for e in fw.environments),
                    "reason": fw.reason,
                }
                for fw in windows
            ]
        }

    def get_recent_changes(self) -> dict:
        ctx = self.repo.get_tenant_context()
        return {
            "changes": [
                {
                    "service_id": c.service_id,
                    "key": c.key,
                    "environment": c.environment.value,
                    "at": c.at.isoformat(),
                    "decision": c.decision.value,
                }
                for c in ctx.change_history
            ],
            "incidents": [
                {
                    "service_id": i.service_id,
                    "at": i.at.isoformat(),
                    "severity": i.severity,
                    "resolved": i.resolved,
                }
                for i in ctx.incident_history
            ],
        }


    def validate_change_request(self, request_id: str) -> dict:
        req = self._require_request(request_id)
        ctx = self.repo.get_tenant_context()
        result = validate_request(req, ctx)
        return {
            "request_id": request_id,
            "ok": result.ok,
            "authorized": result.authorized,
            "malformed": result.malformed,
            "errors": list(result.errors),
        }


    def assess_change_risk(self, request_id: str, now: Optional[str] = None) -> dict:
        req = self._require_request(request_id)
        ctx = self.repo.get_tenant_context()
        moment = self._resolve_now(now)
        assessment = assess_risk(req, ctx, moment)
        return assessment.to_breakdown()


    def record_decision(
        self,
        request_id: str,
        *,
        now: Optional[str] = None,
        trace_id: str = "",
        explanation: str = "",
        force_route: bool = False,
    ) -> dict:
        req = self._require_request(request_id)
        ctx = self.repo.get_tenant_context()
        moment = self._resolve_now(now)

        validation = validate_request(req, ctx)
        assessment = assess_risk(req, ctx, moment)
        decision_result = decide(req, ctx, validation, assessment)
        decision = decision_result.decision
        reason_extra: list[str] = []
        # force_route is set when the agent ran degraded. We only ever downgrade an
        # auto-approve to a route, never the other way, so partial context can make
        # a decision safer but never riskier.
        if force_route and decision is Decision.AUTO_APPROVE:
            decision = Decision.ROUTE
            reason_extra.append(
                "degraded: agent had incomplete context; routing to human for safety"
            )

        self._authorize_scope("record_decision", decision, req, assessment, moment, trace_id)

        verdict = self._check_write("record_decision", decision.value, req, validation.ok,
                                    assessment, moment, trace_id)
        if not verdict.allowed and decision is Decision.AUTO_APPROVE:
            # Same one-way rule as the degraded path: a policy refusal can turn an
            # auto-approve into a route, and the route is checked again.
            decision = Decision.ROUTE
            reason_extra.append(f"{verdict.describe()}; routing to human instead")
            verdict = self._check_write("record_decision", decision.value, req,
                                        validation.ok, assessment, moment, trace_id)
        if not verdict.allowed:
            raise PolicyDenied(verdict)

        before = req.current_value
        after = before
        applied = False
        if decision is Decision.AUTO_APPROVE:
            cv = self.repo.apply_config_change(
                req.key, req.environment, before, req.proposed_value
            )
            after = cv.value
            applied = True

        all_reasons = list(decision_result.reasons) + reason_extra
        entry: AuditEntry = self.repo.append_audit(
            subject=self._subject(req),
            action="record_decision",
            environment=req.environment.value,
            decision=decision.value,
            risk_band=assessment.band.value,
            risk_score=assessment.score,
            before=before,
            after=after,
            reason="; ".join(all_reasons),
            risk_breakdown=assessment.to_breakdown(),
            request_id=request_id,
            trace_id=trace_id,
            timestamp=moment,
        )

        return {
            "request_id": request_id,
            "decision": decision.value,
            "reasons": all_reasons,
            "applied_config_change": applied,
            "before": before,
            "after": after,
            "explanation": explanation,
            "audit": {
                "seq": entry.seq,
                "entry_hash": entry.entry_hash,
                "prev_hash": entry.prev_hash,
            },
            "risk": assessment.to_breakdown(),
        }


    def route_change(self, request_id: str, *, reason: str = "", trace_id: str = "") -> dict:
        req = self._require_request(request_id)
        return self._human_side_write("route_change", "route", Decision.ROUTE, req,
                                      reason, trace_id, apply=False)

    def approve_change(self, request_id: str, *, reason: str = "", trace_id: str = "") -> dict:
        req = self._require_request(request_id)
        # Approving applies the change, so it needs the same scope an auto-approve
        # would, including change:approve:prod in prod.
        return self._human_side_write("approve_change", "approve", Decision.AUTO_APPROVE, req,
                                      reason, trace_id, apply=True)

    def deny_change(self, request_id: str, *, reason: str = "", trace_id: str = "") -> dict:
        req = self._require_request(request_id)
        return self._human_side_write("deny_change", "deny", Decision.DENY, req,
                                      reason, trace_id, apply=False)

    def request_state(self, request_id: str) -> str:
        state = "new"
        for entry in self.repo.audit_entries(request_id):
            state = _STATE_AFTER.get((entry.action, entry.decision), state)
        return state


    def _human_side_write(
        self,
        tool: str,
        action: str,
        scope_decision: Decision,
        req: ChangeRequest,
        reason: str,
        trace_id: str,
        *,
        apply: bool,
    ) -> dict:
        ctx = self.repo.get_tenant_context()
        moment = self.clock.now()
        validation = validate_request(req, ctx)
        assessment = assess_risk(req, ctx, moment)
        self._authorize_scope(tool, scope_decision, req, assessment, moment, trace_id)
        verdict = self._check_write(tool, action, req, validation.ok, assessment, moment,
                                    trace_id)
        if not verdict.allowed:
            raise PolicyDenied(verdict)

        before = req.current_value
        after = before
        if apply:
            after = self.repo.apply_config_change(
                req.key, req.environment, before, req.proposed_value
            ).value
        subject = self._subject(req)
        entry = self.repo.append_audit(
            subject=subject,
            action=tool,
            environment=req.environment.value,
            decision=action,
            risk_band=assessment.band.value,
            risk_score=assessment.score,
            before=before,
            after=after,
            reason=f"{action} by {subject}" + (f": {reason}" if reason else ""),
            risk_breakdown=assessment.to_breakdown(),
            request_id=req.id,
            trace_id=trace_id,
            timestamp=moment,
        )
        return {
            "request_id": req.id,
            "decision": action,
            "reasons": [reason] if reason else [],
            "applied_config_change": apply,
            "before": before,
            "after": after,
            "audit": {
                "seq": entry.seq,
                "entry_hash": entry.entry_hash,
                "prev_hash": entry.prev_hash,
            },
        }

    def _authorize_scope(
        self,
        tool: str,
        decision: Decision,
        req: ChangeRequest,
        assessment: RiskAssessment,
        moment: datetime,
        trace_id: str,
    ) -> None:
        if self.principal is None:
            return
        try:
            authorize_write(
                self.principal,
                decision=decision,
                environment=req.environment,
                tenant_id=req.tenant_id,
            )
        except AuthorizationError as exc:
            # Record the denied attempt before re-raising. A blocked write is
            # exactly the kind of thing the audit log exists to capture.
            self._audit_blocked(f"{tool}_denied", req, assessment, moment, trace_id,
                                f"authorization denied: {exc}")
            raise

    def _check_write(
        self,
        tool: str,
        action: str,
        req: ChangeRequest,
        request_valid: bool,
        assessment: RiskAssessment,
        moment: datetime,
        trace_id: str,
    ) -> PolicyDecision:
        # The single chokepoint. Every write builds the same structured proposal
        # and asks the policy before it touches config or writes its own entry.
        principal = self.principal
        proposed = ProposedAction(
            tool=tool,
            action=action,
            persona=principal.persona if principal else PERSONA_UNKNOWN,
            subject=principal.subject if principal else "",
            caller_tenant=principal.tenant_id if principal else "",
            request_tenant=req.tenant_id,
            environment=req.environment.value,
            state=self.request_state(req.id),
            freeze_active=assessment.factor("freeze_collision").is_hard_deny,
            request_valid=request_valid,
            requester_id=req.requester.id,
        )
        verdict = self.policy.check(proposed)
        if not verdict.allowed:
            self._audit_blocked("policy_denied", req, assessment, moment, trace_id,
                                f"{verdict.describe()} (tool {tool}, action {action})")
        return verdict

    def _audit_blocked(
        self,
        action: str,
        req: ChangeRequest,
        assessment: RiskAssessment,
        moment: datetime,
        trace_id: str,
        reason: str,
    ) -> AuditEntry:
        return self.repo.append_audit(
            subject=self._subject(req),
            action=action,
            environment=req.environment.value,
            decision="blocked",
            risk_band=assessment.band.value,
            risk_score=assessment.score,
            before=req.current_value,
            after=req.current_value,
            reason=reason,
            risk_breakdown=assessment.to_breakdown(),
            request_id=req.id,
            trace_id=trace_id,
            timestamp=moment,
        )

    def _subject(self, req: ChangeRequest) -> str:
        return self.principal.subject if self.principal else req.requester.id

    def _require_request(self, request_id: str) -> ChangeRequest:
        try:
            req = self.repo.get_change_request(request_id)
        except CrossTenantAccess:
            # Postgres RLS returns no row for another tenant's request. Answer the
            # same way here so the caller learns nothing, and audit the attempt.
            self.repo.append_audit(
                subject=self.principal.subject if self.principal else "anonymous",
                action="cross_tenant_denied",
                environment="",
                decision="blocked",
                risk_band="",
                risk_score=0.0,
                before=None,
                after=None,
                reason=f"request {request_id!r} belongs to another tenant",
                risk_breakdown={},
                request_id=request_id,
                trace_id="",
                timestamp=self.clock.now(),
            )
            req = None
        if req is None:
            raise ToolError(f"change request {request_id!r} not found")
        return req

    def _resolve_now(self, now: Optional[str]) -> datetime:
        if now:
            return ensure_utc(datetime.fromisoformat(now))
        return self.clock.now()


def _request_to_dict(req: ChangeRequest) -> dict:
    return {
        "id": req.id,
        "tenant_id": req.tenant_id,
        "requester": {"id": req.requester.id, "role": req.requester.role.value},
        "service_id": req.service_id,
        "key": req.key,
        "kind": req.kind.value,
        "environment": req.environment.value,
        "current_value": req.current_value,
        "proposed_value": req.proposed_value,
        "window_start": req.window_start.isoformat(),
        "window_end": req.window_end.isoformat(),
    }
