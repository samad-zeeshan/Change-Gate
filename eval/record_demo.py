"""Record the runs the demo page replays: two decisions, every attack in the corpus, and one audit chain.

Writes site/data/replay.json and replay.js (the same data for pages opened from disk).
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from eval.redteam import (
    InProcessTransport,
    World,
    agent_actor,
    as_jsonable,
    in_process_client,
    load_cases,
    run_case,
)
from warden.agent.graph import run_task
from warden.agent.llm import DeterministicExplainer
from warden.agent.resilience import CallMetrics, ResilientToolClient
from warden.agent.resolving_client import ResolvingToolClient
from warden.agent.state import AgentDeps
from warden.audit import AuditLog
from warden.data import seed
from warden.personas import load_persona_map

ROOT = Path(__file__).resolve().parents[1]
SITE_DATA = ROOT / "site" / "data"


class _Tap:
    """Records each tool call the agent makes, in order, with how it ended."""

    def __init__(self, inner) -> None:
        self.inner = inner
        self.calls: list[dict] = []

    def call(self, tool: str, **kwargs) -> dict:
        try:
            result = self.inner.call(tool, **kwargs)
        except Exception as exc:  # noqa: BLE001
            self.calls.append({"tool": tool, "args": kwargs, "ok": False, "error": str(exc)})
            raise
        self.calls.append({"tool": tool, "args": kwargs, "ok": True,
                           "result": _trim(tool, result)})
        return result


def _trim(tool: str, result: dict) -> dict:
    keep = {
        "get_change_request": ("id", "key", "environment", "current_value", "proposed_value",
                               "requester"),
        "validate_change_request": ("ok", "authorized", "errors"),
        "assess_change_risk": ("score", "band", "hard_deny", "hard_deny_reasons"),
        "record_decision": ("decision", "reasons", "applied_config_change", "before", "after"),
        "learn_role": ("granted", "tools"),
    }.get(tool)
    if keep is None:
        return {"keys": sorted(result)[:6]}
    return {k: result.get(k) for k in keep if k in result}


def _decision(rid: str, audit: AuditLog) -> dict:
    case = {"id": rid, "target": {"template": {"cr-001": "dev_low",
                                               "cr-003": "prod_freeze"}[rid]}}
    world = World.for_case(case)
    world.audit = audit
    for repo in world.repos.values():
        repo._audit = audit
    # The seed request itself, not a copy, so the page shows the ids people know.
    actor = agent_actor(rid)
    tap = _Tap(in_process_client(world, actor, "request"))
    client = ResilientToolClient(ResolvingToolClient(tap), metrics=CallMetrics())
    final = run_task(rid, seed.EVAL_NOW.isoformat(),
                     AgentDeps(client=client, explainer=DeterministicExplainer(),
                               trace_id=f"demo-{rid}"))
    risk = final.get("risk") or {}
    return {
        "request_id": rid,
        "decision": final.get("terminal_decision"),
        "explanation": final.get("explanation"),
        "reasons": (final.get("decision") or {}).get("reasons", []),
        "risk": {"score": risk.get("score"), "band": risk.get("band"),
                 "factors": [{"name": f["name"], "normalized": f["normalized"]}
                             for f in risk.get("factors", [])]},
        "calls": tap.calls,
    }


def _chain(audit: AuditLog) -> list[dict]:
    # The exact bytes each hash was computed over, so the page can recompute them
    # with the browser's SHA-256 and show the chain break when a field changes.
    out = []
    for e in audit.for_tenant("acme"):
        blob = json.dumps(e.chained_payload(), sort_keys=True, separators=(",", ":"),
                          default=str)
        out.append({"seq": e.seq, "action": e.action, "decision": e.decision,
                    "request_id": e.request_id, "prev_hash": e.prev_hash,
                    "entry_hash": e.entry_hash, "blob": blob})
    return out


def _attack(case: dict, transport, pmap) -> dict:
    r = run_case(case, transport, pmap, include_events=True)
    inj = case["injections"]
    return {
        "id": case["id"], "title": case["title"], "goal": case["goal"],
        "channel": case["channel"], "family": case.get("family", ""),
        "injected": {"description": case["target"].get("description", ""),
                     "tool_result": inj.get("tool_result", []),
                     "tool_description": inj.get("tool_description", {}),
                     "rogue_tools": inj.get("rogue_tools", {}),
                     "sampling_message": inj.get("sampling_message", [])},
        "attacker": r["attacker"],
        "events": r["events"],
        "steered": r["steered_calls"],
        "audit": r["audit"],
        "attack_succeeded": r["attack_succeeded"],
        "audit_chain_verified": r["audit_chain_verified"],
    }


def _counters() -> dict:
    red = json.loads((ROOT / "eval" / "redteam-results.json").read_text(encoding="utf-8"))
    v1 = json.loads((ROOT / "eval" / "baseline-v1.json").read_text(encoding="utf-8"))
    http = red["runs"]["http"]["summary"]["overall"]
    return {
        "source": "eval/redteam-results.json, eval/baseline-v1.json",
        "cases": http["cases"],
        "attacks_succeeded": http["attack_successes"],
        "unsafe_auto_approvals": http["unsafe_auto_approvals"],
        "cross_tenant_reads": http["cross_tenant_reads"],
        "audit_gaps": http["audit_gaps"],
        "reachable_writes_now": http["open_privilege_tenant"],
        "reachable_writes_v1": v1["runs"]["http"]["open_privilege_tenant"],
        "v1_cases": v1["cases"],
        "ablation_attacks_succeeded": red["runs"]["ablation"]["summary"]["overall"][
            "attack_successes"],
    }


def main() -> None:
    audit = AuditLog()
    safe = _decision("cr-001", audit)
    dangerous = _decision("cr-003", audit)
    pmap = load_persona_map()
    transport = InProcessTransport()
    attacks = [_attack(c, transport, pmap) for c in load_cases()]
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True,
                            text=True, cwd=ROOT).stdout.strip()
    data = as_jsonable({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "commit": commit,
        "recorded_with": "python -m eval.record_demo (in-process transport, same code as MCP)",
        "safe": safe,
        "dangerous": dangerous,
        "chain": _chain(audit),
        "attacks": attacks,
        "counters": _counters(),
    })
    SITE_DATA.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, separators=(",", ":"))
    (SITE_DATA / "replay.json").write_text(text + "\n", encoding="utf-8")
    (SITE_DATA / "replay.js").write_text(
        "window.DEMO_DATA = window.DEMO_DATA || {};\nwindow.DEMO_DATA.replay = " + text + ";\n",
        encoding="utf-8")
    print(f"{len(attacks)} attacks, chain of {len(data['chain'])}, "
          f"{len(text) // 1024} KB")


if __name__ == "__main__":
    main()
