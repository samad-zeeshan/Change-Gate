"""Check a policy update with z3: it may not allow any call the previous version denied, unless listed.

The idea follows ActGov (arXiv 2609.24446), which verifies each policy update by SMT counterexample checking.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from itertools import count
from pathlib import Path

import z3

HERE = Path(__file__).resolve().parent
HISTORY = HERE / "history"
VERIFIER_VERSION = "1"

PERSONAS = ("agent", "human", "unknown")
ACTIONS = ("auto_approve", "route", "deny", "approve")
ENVIRONMENTS = ("dev", "staging", "prod")
STATES = ("new", "routed", "auto_approved", "denied", "approved")
BOOL_FACTS = ("tenant_match", "freeze_active", "request_valid", "self_approval")
CATALOG_ROLE = "catalog"
# Which action each write tool can propose. record_decision is the only one with a
# choice, and leaving this out would report tuples no tool can produce.
TOOL_ACTIONS = {
    "record_decision": ("auto_approve", "route", "deny"),
    "route_change": ("route",),
    "approve_change": ("approve",),
    "deny_change": ("deny",),
}
MAX_COUNTEREXAMPLES = 200
# z3 keeps enum sort names global to its context, so each check gets fresh ones.
_SPACE_IDS = count()


class _Space:
    """One z3 variable per fact, over the union of both policies' vocabularies."""

    def __init__(self, docs: list[dict]) -> None:
        tools = sorted({t for d in docs for t in d["tools"]})
        realm = sorted({r for d in docs for r in d["personas"]["human"]["role_map"]})
        self.domains = {"persona": PERSONAS, "tool": tuple(tools), "action": ACTIONS,
                        "environment": ENVIRONMENTS, "state": STATES}
        self.enum = {}
        self.vals = {}
        sid = next(_SPACE_IDS)
        for name, values in self.domains.items():
            sort, consts = z3.EnumSort(f"{name}_t{sid}", list(values))
            self.enum[name] = z3.Const(name, sort)
            self.vals[name] = dict(zip(values, consts))
        self.bools = {b: z3.Bool(b) for b in BOOL_FACTS}
        self.realm = {r: z3.Bool(f"realm_{r}") for r in realm}

    def eq(self, name: str, value: str):
        if value not in self.vals[name]:
            return z3.BoolVal(False)
        return self.enum[name] == self.vals[name][value]

    def one_of(self, name: str, values) -> z3.BoolRef:
        return z3.Or([self.eq(name, v) for v in values] or [z3.BoolVal(False)])


def _roles_expr(doc: dict, space: _Space, persona: str, role: str):
    """True when the persona can hold `role` under this policy."""
    personas = doc["personas"]
    if persona == "agent":
        held = set(personas["agent"]["roles"])
        delivery = doc.get("role_delivery", {}).get("agent")
        if delivery is not None:
            # Under delivery the agent can only ever hold what it may learn.
            held &= set(delivery["learnable"])
        return z3.BoolVal(role in held)
    if persona == "human":
        human = personas["human"]
        options = [z3.BoolVal(role in human["base_roles"])]
        options += [space.realm[r] for r, roles in human["role_map"].items() if role in roles]
        return z3.Or(options)
    return z3.BoolVal(False)


def _permitted(doc: dict, space: _Space):
    per_tool = []
    for tool in space.domains["tool"]:
        spec = doc["tools"].get(tool)
        if spec is None:
            per_tool.append(z3.And(space.eq("tool", tool), z3.BoolVal(False)))
            continue
        per_persona = []
        for persona in ("agent", "human"):
            if CATALOG_ROLE in spec["roles"]:
                holds = z3.BoolVal(True)
            else:
                holds = z3.Or([_roles_expr(doc, space, persona, r) for r in spec["roles"]]
                              or [z3.BoolVal(False)])
            per_persona.append(z3.And(space.eq("persona", persona), holds))
        per_tool.append(z3.And(space.eq("tool", tool), z3.Or(per_persona)))
    return z3.Or(per_tool)


def _condition(space: _Space, name: str, cond):
    if name in BOOL_FACTS:
        return space.bools[name] == z3.BoolVal(bool(cond))
    if isinstance(cond, dict):
        if "in" in cond:
            return space.one_of(name, cond["in"])
        return z3.Not(space.one_of(name, cond["not_in"]))
    return space.eq(name, cond)


def _policy_allows(doc: dict, space: _Space):
    # First match wins, so the rules fold into nested if-then-else from the bottom.
    decision = z3.BoolVal(doc["default"] == "allow")
    for rule in reversed(doc["rules"]):
        match = z3.And([_condition(space, n, c) for n, c in rule["when"].items()]
                       or [z3.BoolVal(True)])
        decision = z3.If(match, z3.BoolVal(rule["effect"] == "allow"), decision)
    return decision


def _allowed(doc: dict, space: _Space):
    writes = [t for t in space.domains["tool"] if doc["tools"].get(t, {}).get("writes")]
    is_write = space.one_of("tool", writes)
    return z3.And(_permitted(doc, space), z3.Or(z3.Not(is_write), _policy_allows(doc, space)))


def _consistent(space: _Space):
    # A write tool only proposes its own actions, and a read proposes none that
    # the policy would see, so its action is pinned to keep counterexamples unique.
    parts = []
    for tool in space.domains["tool"]:
        actions = TOOL_ACTIONS.get(tool, ("route",))
        parts.append(z3.Implies(space.eq("tool", tool), space.one_of("action", actions)))
    return z3.And(parts)


def _listed(space: _Space, approved: list[dict]):
    terms = []
    for item in approved:
        conds = [space.eq(k, item[k]) for k in ("persona", "tool", "environment", "state")
                 if item.get(k, "*") != "*"]
        terms.append(z3.And(conds) if conds else z3.BoolVal(True))
    return z3.Or(terms) if terms else z3.BoolVal(False)


def new_allows(old: dict, new: dict, approved: list[dict] | None = None) -> list[dict]:
    """Every (persona, tool, environment, state) the new policy allows and the old denied."""
    space = _Space([old, new])
    solver = z3.Solver()
    solver.add(_consistent(space))
    solver.add(_allowed(new, space), z3.Not(_allowed(old, space)))
    solver.add(z3.Not(_listed(space, approved or [])))
    found = []
    while len(found) < MAX_COUNTEREXAMPLES and solver.check() == z3.sat:
        model = solver.model()
        tup = {k: str(model.eval(space.enum[k], model_completion=True))
               for k in ("persona", "tool", "environment", "state")}
        found.append(tup)
        solver.add(z3.Not(z3.And([space.eq(k, v) for k, v in tup.items()])))
    return sorted(found, key=lambda t: (t["persona"], t["tool"], t["environment"], t["state"]))


def _hash(obj) -> str:
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def verify(old: dict, new: dict, approved: list[dict]) -> dict:
    unlisted = new_allows(old, new, approved)
    report = {
        "verifier_version": VERIFIER_VERSION,
        "z3_version": z3.get_version_string(),
        "old_version": old["version"],
        "new_version": new["version"],
        "old_sha256": _hash(old),
        "new_sha256": _hash(new),
        "approved_new_allows": approved,
        "listed_and_found": new_allows(old, new) if approved else [],
        "unlisted_new_allows": unlisted,
        "result": "pass" if not unlisted else "fail",
    }
    report["output_hash"] = _hash(report)
    return report


def load_history(directory: Path = HISTORY) -> list[dict]:
    docs = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(directory.glob("*.json"))]
    return sorted(docs, key=lambda d: d["version"])


def previous_version(history: list[dict]) -> dict:
    return history[-2] if len(history) > 1 else history[-1]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--policy", default=str(HERE / "warden.policy.json"))
    ap.add_argument("--changes", default=str(HERE / "changes.json"))
    ap.add_argument("--out", default=str(HERE / "verification.json"))
    ap.add_argument("--check", action="store_true",
                    help="fail if the committed output differs from a fresh run")
    args = ap.parse_args()

    new = json.loads(Path(args.policy).read_text(encoding="utf-8"))
    history = load_history()
    if history[-1] != new:
        print(f"policy {new['version']} is not the last snapshot in policy/history/")
        return 1
    changes = json.loads(Path(args.changes).read_text(encoding="utf-8"))
    report = verify(previous_version(history), new, changes["approved_new_allows"])
    out = Path(args.out)
    if args.check:
        committed = json.loads(out.read_text(encoding="utf-8"))
        if committed != report:
            print("policy/verification.json is stale; rerun python -m policy.verify")
            return 1
    else:
        out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"{report['old_version']} -> {report['new_version']}: {report['result']}, "
          f"{len(report['unlisted_new_allows'])} unlisted new allows, "
          f"output {report['output_hash'][:12]}")
    for t in report["unlisted_new_allows"]:
        print(f"  new allow: {t}")
    return 0 if report["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
