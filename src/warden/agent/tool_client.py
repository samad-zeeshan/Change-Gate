
from __future__ import annotations

from .resilience import DomainToolError, ToolClient
from ..boundary import ToolBoundary
from ..security import AuthorizationError
from ..tool_registry import RejectedCall
from ..tools import ToolError, ToolService


class InProcessToolClient:

    def __init__(self, service: ToolService) -> None:
        self._service = service
        # Offline calls cross the same boundary an MCP call does: resolution
        # against the registry, then the caller's roles, then the tool.
        self._boundary = ToolBoundary(service)

    def call(self, tool: str, **kwargs) -> dict:
        try:
            return self._boundary.call(tool, kwargs)
        except (ToolError, AuthorizationError, RejectedCall, KeyError, ValueError) as exc:
            raise DomainToolError(str(exc)) from exc


__all__ = ["InProcessToolClient", "ToolClient"]
