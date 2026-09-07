"""Wall-clock latency per decision, in-process and over MCP HTTP, with and without the LLM explanation.

One decision is a full agent run: learn roles, read, assess, record, explain. Writes eval/latency.json.
"""

from __future__ import annotations

import json
import math
import time
from pathlib import Path

from eval.redteam import HttpTransport, World, agent_actor, in_process_client, nominal_decision
from warden.agent.graph import run_task
from warden.agent.llm import DeterministicExplainer, LocalExplainer
from warden.agent.resilience import CallMetrics, ResilientToolClient
from warden.agent.resolving_client import ResolvingToolClient
from warden.agent.state import AgentDeps
from warden.data import seed

TEMPLATES = ("dev_low", "prod_route", "prod_freeze", "prod_unauthorized", "staging_route")
HERE = Path(__file__).resolve().parent


def percentiles(samples: list[float]) -> dict:
    # Nearest rank, so every reported value is a time that was actually measured.
    xs = sorted(samples)

    def rank(p: float):
        return xs[max(0, math.ceil(p / 100 * len(xs)) - 1)]

    return {"p50": rank(50), "p95": rank(95), "p99": rank(99)}


def measure(transport: str, explainer, n: int, http: HttpTransport | None = None) -> dict:
    times, wrong = [], 0
    for i in range(n):
        case = {"id": f"lat-{i:04d}", "target": {"template": TEMPLATES[i % len(TEMPLATES)]}}
        world = World.for_case(case)
        actor = agent_actor(world.target.id)
        started = time.perf_counter()
        if transport == "http":
            http.begin_case(world, {})
            inner = http.client_for(actor)
        else:
            inner = in_process_client(world, actor, "request")
        client = ResilientToolClient(ResolvingToolClient(inner), metrics=CallMetrics())
        final = run_task(world.target.id, seed.EVAL_NOW.isoformat(),
                         AgentDeps(client=client, explainer=explainer, trace_id=case["id"]))
        times.append((time.perf_counter() - started) * 1000)
        if transport == "http":
            http.end_case()
        wrong += final.get("terminal_decision") != nominal_decision(world.target)
    return {"n": n, "wrong_decisions": wrong,
            "ms": {k: round(v, 1) for k, v in percentiles(times).items()},
            "mean_ms": round(sum(times) / n, 1)}


def main() -> None:
    import argparse
    import platform
    from datetime import datetime, timezone

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--n-http", type=int, default=100)
    ap.add_argument("--n-llm", type=int, default=30)
    args = ap.parse_args()

    local = LocalExplainer()
    http = HttpTransport()
    http.start()
    try:
        results = {
            "inprocess": {"no_llm": measure("inprocess", DeterministicExplainer(), args.n),
                          "llm": measure("inprocess", local, args.n_llm)},
            "http": {"no_llm": measure("http", DeterministicExplainer(), args.n_http, http),
                     "llm": measure("http", local, args.n_llm, http)},
        }
    finally:
        http.stop()
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "machine": f"{platform.system()} {platform.release()}, {platform.machine()}",
        "explainer": {"no_llm": "deterministic template",
                      "llm": "qwen/qwen3.5-9b in LM Studio on the same machine, reasoning off, "
                             "two calls per decision (explanation and routing message)"},
        "http_note": "MCP over streamable HTTP on 127.0.0.1, one session per tool call, "
                     "task credential exchange included",
        "results": results,
    }
    (HERE / "latency.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
