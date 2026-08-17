"""
The server side of the agent-to-tool boundary, shared by MCP and in-process calls.

Every call is resolved against the pinned registry, checked against the caller's
roles and its credential binding, and only then dispatched. A rejection is written
to the audit chain before the error goes back, and the call never runs.
"""

from __future__ import annotations

from typing import Callable, Optional

from .personas import PersonaMap, load_persona_map
from .security import BINDING_PARAMETER, BINDING_REQUEST, AuthorizationError
from .tool_registry import RejectedCall, ToolSpec, registry_for, resolve_call
from .tools import ToolService


class ToolDenied(AuthorizationError):
    pass


class ToolBoundary:

    def __init__(self, service: ToolService, persona_map: Optional[PersonaMap] = None, *,
                 binding: str = BINDING_REQUEST,
                 tenant_service: Optional[Callable[[str], ToolService]] = None) -> None:
        self.service = service
        self.persona_map = persona_map or load_persona_map()
        self.binding = binding
        self.tenant_service = tenant_service

    def admit(self, tool: str, args: object) -> ToolSpec:
        try:
            spec = resolve_call(tool, args, registry_for(self.binding))
        except RejectedCall as exc:
            self.audit_refusal("tool_call_rejected", args, str(exc))
            raise
        principal = self.service.principal
        if principal is None or not self.persona_map.may_call(principal, spec.name):
            persona = principal.persona if principal else "none"
            msg = f"persona {persona!r} holds no role that may call {spec.name}"
            self.audit_refusal("tool_denied", args, msg)
            raise ToolDenied(msg)
        if self.binding == BINDING_REQUEST and not principal.request_id:
            # Checked for reads as well as writes. An unbound token could otherwise
            # still read tenant context that no task asked for.
            msg = "credential is not bound to a change request"
            self.audit_refusal("unbound_credential", args, msg)
            raise ToolDenied(msg)
        if self.binding == BINDING_PARAMETER:
            tenant = args.get("tenant_id")
            if tenant not in principal.entitled_tenants():
                msg = f"tenant_id {tenant!r} is outside the credential's entitlement"
                self.audit_refusal("tenant_denied", args, msg)
                raise ToolDenied(msg)
        return spec

    def call(self, tool: str, args: dict) -> dict:
        spec = self.admit(tool, args)
        return self.dispatch(spec, args)

    def dispatch(self, spec: ToolSpec, args: dict) -> dict:
        kwargs = dict(args)
        service = self.service
        if self.binding == BINDING_PARAMETER:
            tenant = kwargs.pop("tenant_id")
            if tenant != service.repo.tenant_id and self.tenant_service is not None:
                service = self.tenant_service(tenant)
            if not spec.request_scoped:
                return getattr(service, spec.name)(**kwargs)
            return getattr(service, spec.name)(kwargs.pop("request_id"), **kwargs)
        if not spec.request_scoped:
            return getattr(service, spec.name)(**kwargs)
        # Names in the registry are ToolService method names. The request comes
        # from the credential, never from the arguments.
        return getattr(service, spec.name)(service.principal.request_id, **kwargs)

    def audit_refusal(self, action: str, args: object, reason: str) -> None:
        svc = self.service
        fields = args if isinstance(args, dict) else {}
        principal = svc.principal
        request_id = fields.get("request_id")
        if not isinstance(request_id, str):
            request_id = principal.request_id if principal else ""
        trace_id = fields.get("trace_id")
        svc.repo.append_audit(
            subject=principal.subject if principal else "anonymous",
            action=action,
            environment="",
            decision="blocked",
            risk_band="",
            risk_score=0.0,
            before=None,
            after=None,
            reason=reason,
            risk_breakdown={},
            request_id=request_id,
            trace_id=trace_id if isinstance(trace_id, str) else "",
            timestamp=svc.clock.now(),
        )
