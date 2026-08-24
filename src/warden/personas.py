"""
Map a validated token to a persona (human or agent) and the gate roles it holds.

The persona comes from azp, the client the IdP issued the token to. The IdP signs
that claim, so a caller cannot choose its own persona.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Mapping, Optional

from .policy import default_policy_path, load_policy_document
from .security import PERSONA_AGENT, PERSONA_HUMAN, PERSONA_UNKNOWN, AuthPrincipal

# Every known persona holds this role. It carries only list_roles and learn_role.
CATALOG_ROLE = "catalog"


@dataclass(frozen=True)
class PersonaMap:
    agent_clients: frozenset[str]
    agent_roles: frozenset[str]
    human_clients: frozenset[str]
    human_base_roles: frozenset[str]
    human_role_claim: str
    human_role_map: Mapping[str, frozenset[str]]
    tool_roles: Mapping[str, frozenset[str]]
    learnable: Mapping[str, frozenset[str]] = None
    requires: Mapping[str, frozenset[str]] = None

    @classmethod
    def from_policy(cls, doc: dict) -> "PersonaMap":
        agent = doc["personas"]["agent"]
        human = doc["personas"]["human"]
        agent_clients = frozenset(agent["clients"])
        human_clients = frozenset(human["clients"])
        # One client, one persona. A client in both lists would let the same
        # token read as either, which is the confusion this module exists to stop.
        both = agent_clients & human_clients
        if both:
            raise ValueError(f"clients listed for both personas: {sorted(both)}")
        return cls(
            agent_clients=agent_clients,
            agent_roles=frozenset(agent["roles"]),
            human_clients=human_clients,
            human_base_roles=frozenset(human["base_roles"]),
            human_role_claim=human["role_claim"],
            human_role_map={k: frozenset(v) for k, v in human["role_map"].items()},
            tool_roles={k: frozenset(v["roles"]) for k, v in doc["tools"].items()},
            learnable={p: frozenset(cfg["learnable"])
                       for p, cfg in doc.get("role_delivery", {}).items()},
            requires={r: frozenset(tools)
                      for cfg in doc.get("role_delivery", {}).values()
                      for r, tools in cfg.get("requires", {}).items()},
        )

    def resolve(self, claims: dict) -> tuple[str, frozenset[str]]:
        azp = str(claims.get("azp") or "")
        if azp in self.agent_clients:
            # The agent's roles are fixed by policy. Any role claim on its token
            # is ignored rather than merged in.
            return PERSONA_AGENT, frozenset()
        if azp in self.human_clients:
            return PERSONA_HUMAN, self._mapped_roles(claims.get(self.human_role_claim))
        return PERSONA_UNKNOWN, frozenset()

    def _mapped_roles(self, raw) -> frozenset[str]:
        if isinstance(raw, str):
            names = raw.split()
        elif isinstance(raw, (list, tuple)):
            names = [str(r) for r in raw]
        else:
            names = []
        out: set[str] = set()
        for name in names:
            out |= self.human_role_map.get(name, frozenset())
        return frozenset(out)

    def entitled(self, principal: AuthPrincipal) -> frozenset[str]:
        if principal.persona == PERSONA_AGENT:
            return self.agent_roles
        if principal.persona == PERSONA_HUMAN:
            grantable = frozenset().union(*self.human_role_map.values())
            return self.human_base_roles | (principal.gate_roles & grantable)
        return frozenset()

    def delivers(self, principal: AuthPrincipal) -> bool:
        return principal.persona in (self.learnable or {})

    def learnable_for(self, principal: AuthPrincipal) -> frozenset[str]:
        listed = (self.learnable or {}).get(principal.persona, frozenset())
        return listed & self.entitled(principal)

    def roles_for(self, principal: AuthPrincipal,
                  learned: Optional[frozenset[str]] = None) -> frozenset[str]:
        entitled = self.entitled(principal)
        if learned is not None and self.delivers(principal):
            # Under delivery only learned roles count, and only those the policy
            # lets this persona learn. The entitlement stays the ceiling.
            return learned & self.learnable_for(principal)
        return entitled

    def may_call(self, principal: AuthPrincipal, tool: str,
                 learned: Optional[frozenset[str]] = None) -> bool:
        allowed = self.tool_roles.get(tool)
        if not allowed:
            return False
        if CATALOG_ROLE in allowed and self.entitled(principal):
            return True
        return bool(self.roles_for(principal, learned) & allowed)

    def tools_of(self, role: str) -> list[str]:
        return sorted(t for t, roles in self.tool_roles.items() if role in roles)


@lru_cache(maxsize=8)
def _cached(path: str) -> PersonaMap:
    return PersonaMap.from_policy(load_policy_document(Path(path)))


def load_persona_map(path: Optional[Path] = None) -> PersonaMap:
    return _cached(str(path or default_policy_path()))
