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
from .sessions import RoleSessions
from .tool_registry import RejectedCall, ToolSpec, registry_for, resolve_call
from .tools import ToolService

CATALOG_TOOLS = ("list_roles", "learn_role")


class ToolDenied(AuthorizationError):
    pass


class ToolBoundary:

    def __init__(self, service: ToolService, persona_map: Optional[PersonaMap] = None, *,
                 binding: str = BINDING_REQUEST,
                 tenant_service: Optional[Callable[[str], ToolService]] = None,
                 sessions: Optional[RoleSessions] = None,
                 role_delivery: bool = True) -> None:
        self.service = service
        self.persona_map = persona_map or load_persona_map()
        self.binding = binding
        self.tenant_service = tenant_service
        self.sessions = sessions if sessions is not None else RoleSessions()
        self.role_delivery = role_delivery

    def learned(self) -> Optional[frozenset[str]]:
        # None means "no delivery": the caller holds every entitled role, which is
        # the v1 shape and how humans are always treated.
        principal = self.service.principal
        if not self.role_delivery or principal is None:
            return None
        return self.sessions.learned(principal)

    def admit(self, tool: str, args: object) -> ToolSpec:
        try:
            spec = resolve_call(tool, args, registry_for(self.binding))
        except RejectedCall as exc:
            self.audit_refusal("tool_call_rejected", args, str(exc))
            raise
        principal = self.service.principal
        unbound = principal is not None and not principal.request_id
        if self.binding == BINDING_REQUEST and unbound:
            # Checked for reads as well as writes. An unbound token could otherwise
            # still read tenant context that no task asked for.
            msg = "credential is not bound to a change request"
            self.audit_refusal("unbound_credential", args, msg)
            raise ToolDenied(msg)
        if principal is None or not self.persona_map.may_call(principal, spec.name,
                                                             self.learned()):
            persona = principal.persona if principal else "none"
            msg = f"persona {persona!r} holds no role that may call {spec.name}"
            self.audit_refusal("tool_denied", args, msg)
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
        if self.binding == BINDING_PARAMETER:
            kwargs.pop("tenant_id", None)
        if spec.name in CATALOG_TOOLS:
            return self.list_roles() if spec.name == "list_roles" else \
                self.learn_role(kwargs["role"], kwargs)
        service = self.service
        if self.binding == BINDING_PARAMETER:
            tenant = args["tenant_id"]
            if tenant != service.repo.tenant_id and self.tenant_service is not None:
                service = self.tenant_service(tenant)
            if spec.request_scoped:
                result = getattr(service, spec.name)(kwargs.pop("request_id"), **kwargs)
            else:
                result = getattr(service, spec.name)(**kwargs)
        elif spec.request_scoped:
            # Names in the registry are ToolService method names. The request comes
            # from the credential, never from the arguments.
            result = getattr(service, spec.name)(service.principal.request_id, **kwargs)
        else:
            result = getattr(service, spec.name)(**kwargs)
        self.sessions.note_call(self.service.principal, spec.name)
        return result

    def list_roles(self) -> dict:
        principal = self.service.principal
        pmap = self.persona_map
        learnable = sorted(pmap.learnable_for(principal)) if pmap.delivers(principal) else \
            sorted(pmap.entitled(principal))
        return {
            "learnable": learnable,
            "learned": sorted(self.learned() or ()),
            "roles": {r: {"tools": pmap.tools_of(r),
                          "requires": sorted((pmap.requires or {}).get(r, ()))}
                      for r in learnable},
        }

    def learn_role(self, role: str, args: dict) -> dict:
        principal = self.service.principal
        pmap = self.persona_map
        if not self.role_delivery or not pmap.delivers(principal):
            if role not in pmap.entitled(principal):
                self._refuse_role(args, f"role {role!r} is not held by this credential")
            return {"granted": role, "tools": pmap.tools_of(role)}
        if role not in pmap.learnable_for(principal):
            self._refuse_role(args, f"role {role!r} cannot be learned by {principal.persona}")
        missing = sorted((pmap.requires or {}).get(role, frozenset()) -
                         self.sessions.called(principal))
        if missing:
            # The prerequisite is what makes delivery a control. Without it an
            # injected instruction could learn a write role before any read ran.
            self._refuse_role(args, f"role {role!r} needs {missing} to have run first")
        self.sessions.grant(principal, role)
        self.audit_refusal("role_learned", args, f"learned role {role}", decision="granted")
        return {"granted": role, "tools": pmap.tools_of(role)}

    def _refuse_role(self, args: dict, msg: str) -> None:
        self.audit_refusal("role_denied", args, msg)
        raise ToolDenied(msg)

    def audit_refusal(self, action: str, args: object, reason: str,
                      decision: str = "blocked") -> None:
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
            decision=decision,
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
