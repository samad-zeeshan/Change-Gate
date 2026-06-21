"""
The tool surface the agent calls: read context, validate, assess risk, record a decision.

record_decision is the only writer, and it re-runs validation and risk so the
stored decision never trusts the agent's earlier reads.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from .audit import AuditEntry
from .clock import Clock, ensure_utc
from .db.repository import Repository
from .domain.decision import decide, validate_request
from .domain.models import ChangeRequest, Decision, Environment
from .domain.risk import assess_risk
from .security import AuthPrincipal, AuthorizationError, authorize_write


class ToolError(RuntimeError):
    pass


class ToolService:

    def __init__(
        self,
        repo: Repository,
        clock: Clock,
        principal: Optional[AuthPrincipal] = None,
    ) -> None:
        self.repo = repo
        self.clock = clock
        self.principal = principal


    def get_change_request(self, request_id: str) -> dict:
        req = self.repo.get_change_request(request_id)
        if req is None:
            raise ToolError(f"change request {request_id!r} not found")
        return _request_to_dict(req)

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

        if self.principal is not None:
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
                self.repo.append_audit(
                    subject=self.principal.subject,
                    action="record_decision_denied",
                    environment=req.environment.value,
                    decision="blocked",
                    risk_band=assessment.band.value,
                    risk_score=assessment.score,
                    before=req.current_value,
                    after=req.current_value,
                    reason=f"authorization denied: {exc}",
                    risk_breakdown=assessment.to_breakdown(),
                    request_id=request_id,
                    trace_id=trace_id,
                    timestamp=moment,
                )
                raise

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
        subject = self.principal.subject if self.principal else req.requester.id
        entry: AuditEntry = self.repo.append_audit(
            subject=subject,
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


    def _require_request(self, request_id: str) -> ChangeRequest:
        req = self.repo.get_change_request(request_id)
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
