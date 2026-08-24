"""Measure open privilege at every stage of the agent's workflow, not only at the end.

Writes eval/stage-privilege.json for three setups: v1 tenant token, request-bound, request-bound with delivery.
"""

from __future__ import annotations

import json
from pathlib import Path

from eval.redteam import (
    IdFiller,
    World,
    agent_actor,
    in_process_client,
    load_cases,
    probe_open_privilege,
)
from warden.agent.llm import DeterministicExplainer
from warden.agent.resilience import CallMetrics, ResilientToolClient
from warden.agent.resolving_client import ResolvingToolClient
from warden.agent.state import AgentDeps
from warden.data import seed
from warden.security import BINDING_PARAMETER, BINDING_REQUEST
from warden.tool_registry import registry_for

STAGES = ("issued", "fetch", "validate", "assess", "decide", "explain")
CONFIGS = {
    "v1-tenant-token": (BINDING_PARAMETER, False),
    "request-bound": (BINDING_REQUEST, False),
    "request-bound+delivery": (BINDING_REQUEST, True),
}


def _snapshot(world: World, actor, binding: str, delivery: bool) -> dict:
    reachable = probe_open_privilege(world, actor, binding, True, delivery)
    return {
        "writes": len(reachable),
        "on_target": sum(1 for r in reachable if r["task_target"]),
        "dangerous": sum(1 for r in reachable if r["dangerous"]),
        "tools": sorted({r["tool"] for r in reachable}),
    }


def measure_case(case: dict, config: str) -> dict:
    from warden.agent.graph import build_agent

    binding, delivery = CONFIGS[config]
    world = World.for_case(case)
    actor = agent_actor(world.target.id if binding == BINDING_REQUEST else "")
    inner = in_process_client(world, actor, binding, role_delivery=delivery)
    client = ResilientToolClient(ResolvingToolClient(inner, registry=registry_for(binding)),
                                 metrics=CallMetrics())
    if binding == BINDING_PARAMETER:
        client = IdFiller(client, actor.principal.tenant_id, world.target.id)
    deps = AgentDeps(client=client, explainer=DeterministicExplainer(), trace_id="stages")

    row = {"issued": _snapshot(world, actor, binding, delivery)}
    initial = {"request_id": world.target.id, "now": seed.EVAL_NOW.isoformat(), "notes": []}
    # stream() hands back control after each node, which is where the probe runs.
    # The graph itself is the one the agent always uses.
    for update in build_agent().stream(initial, config={"configurable": {"deps": deps}},
                                       stream_mode="updates"):
        (node,) = update
        if node in STAGES:
            row[node] = _snapshot(world, actor, binding, delivery)
    return row


def summarise_stages(rows_by_config: dict[str, dict[str, dict]]) -> dict:
    out = {}
    for config, rows in rows_by_config.items():
        out[config] = {
            stage: {k: sum(r[stage][k] for r in rows.values() if stage in r)
                    for k in ("writes", "on_target", "dangerous")}
            for stage in STAGES
        }
    return out


def main() -> None:
    import platform
    from datetime import datetime, timezone

    here = Path(__file__).resolve().parent
    cases = [c for c in load_cases() if c["attacker"]["persona"] == "agent"]
    rows = {config: {c["id"]: measure_case(c, config) for c in cases} for config in CONFIGS}
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "cases": len(cases),
        "stages": list(STAGES),
        "summary": summarise_stages(rows),
        "cases_by_config": rows,
    }
    (here / "stage-privilege.json").write_text(json.dumps(data, indent=2) + "\n",
                                               encoding="utf-8")
    print(json.dumps(data["summary"], indent=2))


if __name__ == "__main__":
    main()
