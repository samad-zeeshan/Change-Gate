"""Per-credential role sessions: which roles a task credential has learned and which tools it has called."""

from __future__ import annotations

from dataclasses import dataclass, field

from .security import AuthPrincipal


def session_key(principal: AuthPrincipal) -> str:
    # One task is one session. A credential re-issued for the same subject and
    # request keeps what was learned, and the learnable list still bounds it.
    if principal.request_id:
        return f"{principal.subject}:{principal.request_id}"
    return principal.token_id or principal.subject


@dataclass
class RoleSessions:
    learned_roles: dict[str, set[str]] = field(default_factory=dict)
    called_tools: dict[str, set[str]] = field(default_factory=dict)

    def learned(self, principal: AuthPrincipal) -> frozenset[str]:
        return frozenset(self.learned_roles.get(session_key(principal), ()))

    def called(self, principal: AuthPrincipal) -> frozenset[str]:
        return frozenset(self.called_tools.get(session_key(principal), ()))

    def grant(self, principal: AuthPrincipal, role: str) -> None:
        self.learned_roles.setdefault(session_key(principal), set()).add(role)

    def note_call(self, principal: AuthPrincipal, tool: str) -> None:
        self.called_tools.setdefault(session_key(principal), set()).add(tool)
