
from __future__ import annotations

from .resilience import DomainToolError, ToolClient
from ..security import AuthorizationError
from ..tools import ToolError, ToolService


class InProcessToolClient:

    def __init__(self, service: ToolService) -> None:
        self._service = service
        self._dispatch = {
            "get_change_request": service.get_change_request,
            "get_change_policy": lambda **k: service.get_change_policy(),
            "get_config_state": service.get_config_state,
            "get_dependency_graph": lambda **k: service.get_dependency_graph(),
            "get_freeze_windows": lambda **k: service.get_freeze_windows(),
            "get_recent_changes": lambda **k: service.get_recent_changes(),
            "validate_change_request": service.validate_change_request,
            "assess_change_risk": service.assess_change_risk,
            "record_decision": service.record_decision,
        }

    def call(self, tool: str, **kwargs) -> dict:
        fn = self._dispatch.get(tool)
        if fn is None:
            raise DomainToolError(f"unknown tool {tool!r}")
        try:
            return fn(**kwargs)
        except (ToolError, AuthorizationError, KeyError, ValueError) as exc:
            raise DomainToolError(str(exc)) from exc


__all__ = ["InProcessToolClient", "ToolClient"]
