"""
The server side of the agent-to-tool boundary, shared by MCP and in-process calls.

Every call is resolved against the pinned registry, then checked against the
caller's roles, and only then dispatched. A rejection is written to the audit
chain before the error goes back, and the call never runs.
"""

from __future__ import annotations

from typing import Optional

from .personas import PersonaMap, load_persona_map
from .security import AuthorizationError
from .tool_registry import RejectedCall, ToolSpec, resolve_call
from .tools import ToolService


class ToolDenied(AuthorizationError):
    pass


class ToolBoundary:

    def __init__(self, service: ToolService, persona_map: Optional[PersonaMap] = None) -> None:
        self.service = service
        self.persona_map = persona_map or load_persona_map()

    def admit(self, tool: str, args: object) -> ToolSpec:
        try:
            spec = resolve_call(tool, args)
        except RejectedCall as exc:
            self._audit("tool_call_rejected", args, str(exc))
            raise
        principal = self.service.principal
        if principal is None or not self.persona_map.may_call(principal, spec.name):
            persona = principal.persona if principal else "none"
            msg = f"persona {persona!r} holds no role that may call {spec.name}"
            self._audit("tool_denied", args, msg)
            raise ToolDenied(msg)
        return spec

    def call(self, tool: str, args: dict) -> dict:
        spec = self.admit(tool, args)
        # Names in the registry are ToolService method names, and resolution has
        # already limited args to the declared keyword arguments.
        return getattr(self.service, spec.name)(**args)

    def _audit(self, action: str, args: object, reason: str) -> None:
        svc = self.service
        fields = args if isinstance(args, dict) else {}
        request_id = fields.get("request_id")
        trace_id = fields.get("trace_id")
        svc.repo.append_audit(
            subject=svc.principal.subject if svc.principal else "anonymous",
            action=action,
            environment="",
            decision="blocked",
            risk_band="",
            risk_score=0.0,
            before=None,
            after=None,
            reason=reason,
            risk_breakdown={},
            request_id=request_id if isinstance(request_id, str) else "",
            trace_id=trace_id if isinstance(trace_id, str) else "",
            timestamp=svc.clock.now(),
        )
