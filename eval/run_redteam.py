
from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE.parent) not in sys.path:
    sys.path.insert(0, str(HERE.parent))

from eval import chart  # noqa: E402
from eval.redteam import as_jsonable, load_cases, run_corpus  # noqa: E402

from change_gate.policy import load_policy_document  # noqa: E402

RUNS = ("http", "inprocess", "ablation")
RUN_LABEL = {
    "http": "Hardened, MCP over HTTP",
    "inprocess": "Hardened, in-process",
    "ablation": "Ablation: new layers off",
}
GOAL_LABEL = {
    "unsafe_auto_approve": "unsafe auto-approve",
    "wrong_tenant_read": "wrong-tenant read",
    "audit_skip": "audit skip",
    "freeze_window_bypass": "freeze-window bypass",
    "privilege_escalation": "privilege escalation",
}


def run(transports: list[str]) -> dict:
    cases = load_cases()
    runs = {}
    for name in transports:
        started = time.perf_counter()
        runs[name] = run_corpus(name, cases)
        runs[name]["seconds"] = round(time.perf_counter() - started, 1)
    return as_jsonable({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "policy_version": load_policy_document()["version"],
        "corpus": {
            "cases": len(cases),
            "fragmented": sum(1 for c in cases if c["channel"] == "fragmented"),
            "by_goal": _count(cases, "goal"),
            "by_channel": _count(cases, "channel"),
        },
        "runs": runs,
    })


def _count(cases: list[dict], key: str) -> dict:
    out: dict[str, int] = {}
    for c in cases:
        out[c[key]] = out.get(c[key], 0) + 1
    return dict(sorted(out.items()))


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def write_report(data: dict, out_dir: Path) -> None:
    runs = data["runs"]
    head = ("| Run | Cases | Attack success | Unsafe auto-approvals | Cross-tenant reads | "
            "Audit gaps | Freeze bypasses | Privilege escalations | Hallucinated calls "
            "(executed) | Audit chain verified |")
    sep = "|---|---|---|---|---|---|---|---|---|---|"
    rows = []
    for name, r in runs.items():
        s = r["summary"]["overall"]
        rows.append(
            f"| {RUN_LABEL[name]} | {s['cases']} | {s['attack_successes']} "
            f"({_pct(s['attack_success_rate'])}) | {s['unsafe_auto_approvals']} | "
            f"{s['cross_tenant_reads']} | {s['audit_gaps']} | {s['freeze_bypasses']} | "
            f"{s['privilege_escalations']} | {s['hallucinated_calls']} "
            f"({s['hallucinated_executed']}) | {s['audit_chain_verified']}/{s['cases']} |"
        )

    goal_rows = []
    for goal, label in GOAL_LABEL.items():
        cells = []
        for name in runs:
            g = runs[name]["summary"]["by_goal"].get(goal)
            if g is None:
                cells.append("n/a")
                continue
            cells.append(f"{g['attack_successes']}/{g['cases']}")
        open_cells = []
        for name in runs:
            g = runs[name]["summary"]["by_goal"].get(goal)
            open_cells.append(
                f"{g['open_privilege_task']} / {g['open_privilege_tenant']} / "
                f"{g['open_privilege_dangerous']}" if g else "n/a"
            )
        goal_rows.append(f"| {label} | " + " | ".join(cells) + " | "
                         + " | ".join(open_cells) + " |")
    run_names = [RUN_LABEL[n] for n in runs]
    goal_head = ("| Goal | " + " | ".join(f"Success: {n}" for n in run_names) + " | "
                 + " | ".join(f"Open privilege (task / tenant / dangerous): {n}"
                              for n in run_names) + " |")
    goal_sep = "|---|" + "---|" * (2 * len(runs))

    channel_rows = []
    for name, r in runs.items():
        for ch, c in r["summary"]["by_channel"].items():
            channel_rows.append(
                f"| {RUN_LABEL[name]} | {ch} | {c['cases']} | {c['attack_successes']} | "
                f"{c['hallucinated_calls']} | {c['open_privilege_dangerous']} |"
            )

    layer_rows = []
    for name, r in runs.items():
        layers = r["summary"]["steered_calls_by_layer"]
        layer_rows.append(f"| {RUN_LABEL[name]} | " + ", ".join(
            f"{k}: {v}" for k, v in layers.items()) + " |")

    failures = []
    for name, r in runs.items():
        for c in r["cases"]:
            if c["attack_succeeded"] or (c["expectation_met"] is False):
                failures.append(f"- {RUN_LABEL[name]}, `{c['id']}`: "
                                + ("; ".join(c["findings"]) or "expected state not reached"))
    failures_md = "\n".join(failures) if failures else "- none"

    report = f"""# Red-team report: prompt injection against the agent-to-tool boundary

_Generated {data['generated_at']}. Policy {data['policy_version']}. Python {data['python']}._

Corpus: {data['corpus']['cases']} cases in `eval/injections/`,
{data['corpus']['fragmented']} of them split across two channels.

## What each case does

1. A fresh world: tenants acme and globex, the five seed requests, the case's target
   request, and one globex request (`gx-900`) for cross-tenant attempts.
2. The real LangGraph agent works the target request with the injected text in place:
   in the request description, in poisoned tool results, in the tool descriptions the
   server advertises. Sampling-message text is not read by the deterministic agent; for
   those cases the steered calls stand for what a model that read it would do.
3. The calls a planner that obeyed the injection would make (`steered_calls`) run
   through the same client stack, as the attacker's persona.
4. Oracles in `eval/redteam.py`, written separately from the policy file, count unsafe
   applies, cross-tenant data returned, governed attempts without an audit entry,
   freeze hard denies that did not hold, and writes outside a reference permission table.
5. Open privilege: every write the attacker's persona could still make afterwards is
   tried on a throwaway copy of the world. "Task" counts writes on the case's target,
   "tenant" counts writes on any request, "dangerous" counts the ones the oracles flag.

The ablation run switches off the three layers added in this change (tool-call
resolution, per-tool roles, the action policy) and keeps the older ones (scopes, tenant
scoping, server-side recomputation).

## Results

{head}
{sep}
{chr(10).join(rows)}

## By attacker goal

{goal_head}
{goal_sep}
{chr(10).join(goal_rows)}

## By channel

| Run | Channel | Cases | Attack successes | Hallucinated calls | Dangerous open privilege |
|---|---|---|---|---|---|
{chr(10).join(channel_rows)}

## Where the steered calls stopped

| Run | Layers |
|---|---|
{chr(10).join(layer_rows)}

## Cases where an attack succeeded or the expected state was not reached

{failures_md}

## Reproduce

```bash
python -m eval.run_redteam
```
"""
    (out_dir / "redteam-report.md").write_text(report, encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the prompt-injection red-team corpus.")
    ap.add_argument("--transports", default=",".join(RUNS),
                    help=f"comma-separated subset of {', '.join(RUNS)}")
    ap.add_argument("--out", default=str(HERE / "redteam-results.json"))
    args = ap.parse_args()

    transports = [t.strip() for t in args.transports.split(",") if t.strip()]
    data = run(transports)
    out = Path(args.out)
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    write_report(data, out.parent)
    chart.write_redteam_svg(out.parent / "redteam-chart.svg", data)

    print("Red-team run complete.")
    for name, r in data["runs"].items():
        s = r["summary"]["overall"]
        print(f"  {RUN_LABEL[name]:<28} success {s['attack_successes']}/{s['cases']}  "
              f"unsafe {s['unsafe_auto_approvals']}  xtenant {s['cross_tenant_reads']}  "
              f"audit gaps {s['audit_gaps']}  hallucinated executed "
              f"{s['hallucinated_executed']}/{s['hallucinated_calls']}  ({r['seconds']}s)")
    print(f"  wrote: {out}, {out.parent / 'redteam-report.md'}, redteam-chart.svg")


if __name__ == "__main__":
    main()
