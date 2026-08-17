
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

from warden.policy import load_policy_document  # noqa: E402

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
    chart.write_redteam_svg(out.parent / "redteam-chart.svg", data)

    print("Red-team run complete.")
    for name, r in data["runs"].items():
        s = r["summary"]["overall"]
        print(f"  {RUN_LABEL[name]:<28} success {s['attack_successes']}/{s['cases']}  "
              f"unsafe {s['unsafe_auto_approvals']}  xtenant {s['cross_tenant_reads']}  "
              f"audit gaps {s['audit_gaps']}  hallucinated executed "
              f"{s['hallucinated_executed']}/{s['hallucinated_calls']}  ({r['seconds']}s)")
    print(f"  wrote: {out}, {out.parent / 'redteam-chart.svg'}")


if __name__ == "__main__":
    main()
