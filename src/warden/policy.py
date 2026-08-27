"""
The action policy: one check every writing tool runs before it has an effect.

Policy lives in the versioned file policy/warden.policy.json, never in a
prompt. Rules are read top to bottom, the first match wins, and anything no rule
matches gets the file's default, which is deny. Set WARDEN_POLICY to point
at a different file.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional

from .security import AuthorizationError

# Facts a rule may test. Keeping the set closed means a typo in the policy file
# is a load error instead of a condition that silently never matches.
TEXT_FACTS = ("tool", "action", "persona", "environment", "state")
BOOL_FACTS = ("tenant_match", "freeze_active", "request_valid", "self_approval")
EFFECTS = ("allow", "deny")


def default_policy_path() -> Path:
    override = os.getenv("WARDEN_POLICY")
    if override:
        return Path(override)
    # src/warden/policy.py -> repo root. The Docker image keeps the same
    # layout under /app, so this resolves there too.
    return Path(__file__).resolve().parents[2] / "policy" / "warden.policy.json"


def load_policy_document(path: Optional[Path] = None) -> dict:
    path = path or default_policy_path()
    return json.loads(Path(path).read_text(encoding="utf-8"))


def policy_sha256(doc: dict) -> str:
    # Same canonical form policy/verify.py hashes, so the two can be compared.
    blob = json.dumps(doc, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@lru_cache(maxsize=8)
def _governing(path: str, version: str) -> tuple[tuple[str, str], ...]:
    doc = load_policy_document(Path(path))
    record = {"policy_version": version, "policy_sha256": "", "verifier_version": "",
              "verifier_output_hash": "", "verifier_result": "unverified"}
    if doc.get("version") != version:
        return tuple(record.items())
    record["policy_sha256"] = policy_sha256(doc)
    ver_path = Path(path).parent / "verification.json"
    if ver_path.exists():
        ver = json.loads(ver_path.read_text(encoding="utf-8"))
        # A verification only counts for the exact file it checked.
        if ver.get("new_sha256") == record["policy_sha256"]:
            record.update(verifier_version=ver["verifier_version"],
                          verifier_output_hash=ver["output_hash"],
                          verifier_result=ver["result"])
    return tuple(record.items())


def governing_record(policy: "ActionPolicy") -> dict:
    """The policy version in force, its hash, and the verifier run that approved it."""
    return dict(_governing(str(default_policy_path()), policy.version))


@dataclass(frozen=True)
class ProposedAction:
    # Structured facts only. There is deliberately no free-text field here, so
    # nothing the agent read (a request description, a tool result) can reach
    # the decision.
    tool: str
    action: str
    persona: str
    subject: str
    caller_tenant: str
    request_tenant: str
    environment: str
    state: str
    freeze_active: bool
    request_valid: bool
    requester_id: str

    def facts(self) -> dict:
        return {
            "tool": self.tool,
            "action": self.action,
            "persona": self.persona,
            "environment": self.environment,
            "state": self.state,
            "tenant_match": self.caller_tenant == self.request_tenant,
            "freeze_active": self.freeze_active,
            "request_valid": self.request_valid,
            "self_approval": bool(self.subject) and self.subject == self.requester_id,
        }


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    rule_id: str
    reason: str
    policy_version: str

    def describe(self) -> str:
        return f"policy {self.policy_version} rule {self.rule_id}: {self.reason}"


class PolicyDenied(AuthorizationError):

    def __init__(self, decision: PolicyDecision) -> None:
        super().__init__(decision.describe())
        self.decision = decision
        self.rule_id = decision.rule_id


@dataclass(frozen=True)
class _Rule:
    id: str
    effect: str
    when: tuple[tuple[str, object], ...]
    reason: str

    def matches(self, facts: dict) -> bool:
        for name, cond in self.when:
            value = facts[name]
            if isinstance(cond, dict):
                if "in" in cond and value not in cond["in"]:
                    return False
                if "not_in" in cond and value in cond["not_in"]:
                    return False
            elif value != cond:
                return False
        return True


class ActionPolicy:

    def __init__(self, version: str, rules: list[_Rule], default: str) -> None:
        self.version = version
        self.rules = tuple(rules)
        self.default = default

    @classmethod
    def from_document(cls, doc: dict) -> "ActionPolicy":
        default = doc.get("default")
        if default not in EFFECTS:
            raise ValueError(f"policy default must be one of {EFFECTS}, got {default!r}")
        rules: list[_Rule] = []
        seen: set[str] = set()
        for raw in doc.get("rules", []):
            rid = raw["id"]
            if rid in seen:
                raise ValueError(f"duplicate policy rule id {rid!r}")
            seen.add(rid)
            if raw["effect"] not in EFFECTS:
                raise ValueError(f"rule {rid!r}: effect must be one of {EFFECTS}")
            when = []
            for name, cond in raw["when"].items():
                if name in BOOL_FACTS:
                    if not isinstance(cond, bool):
                        raise ValueError(f"rule {rid!r}: {name} needs true or false")
                elif name in TEXT_FACTS:
                    if isinstance(cond, dict):
                        if set(cond) - {"in", "not_in"} or len(cond) != 1:
                            raise ValueError(f"rule {rid!r}: {name} needs 'in' or 'not_in'")
                        cond = {k: frozenset(v) for k, v in cond.items()}
                    elif not isinstance(cond, str):
                        raise ValueError(f"rule {rid!r}: {name} needs a string or in/not_in")
                else:
                    raise ValueError(f"rule {rid!r}: unknown condition field {name!r}")
                when.append((name, cond))
            rules.append(_Rule(rid, raw["effect"], tuple(when), raw["reason"]))
        return cls(str(doc["version"]), rules, default)

    def check(self, proposed: ProposedAction) -> PolicyDecision:
        facts = proposed.facts()
        for rule in self.rules:
            if rule.matches(facts):
                return PolicyDecision(rule.effect == "allow", rule.id, rule.reason, self.version)
        return PolicyDecision(
            self.default == "allow", "default",
            f"no rule matched; policy default is {self.default}", self.version,
        )


@lru_cache(maxsize=8)
def _cached(path: str) -> ActionPolicy:
    return ActionPolicy.from_document(load_policy_document(Path(path)))


def load_action_policy(path: Optional[Path] = None) -> ActionPolicy:
    return _cached(str(path or default_policy_path()))
