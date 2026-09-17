"""Render every number the README shows, straight from the results files.

tests/test_readme_numbers.py checks each block appears in README.md verbatim, so a stale number fails CI.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVAL = ROOT / "eval"


def _load(name: str) -> dict:
    return json.loads((EVAL / name).read_text(encoding="utf-8"))


def redteam() -> str:
    red = _load("redteam-results.json")
    live = _load("redteam-live.json")["runs"]["live"]
    rows = [("Hardened, MCP over HTTP", red["runs"]["http"]),
            ("Hardened, live Keycloak and Postgres", live),
            ("Hardened, in-process", red["runs"]["inprocess"]),
            ("Every layer on, v1 tenant credential", red["runs"]["inprocess-v1"]),
            ("Boundary layers off", red["runs"]["ablation"])]
    out = ["| Run | Attacks | Got through | Unsafe approvals | Cross-tenant reads "
           "| Audit gaps | Writes still reachable |",
           "|---|---|---|---|---|---|---|"]
    for label, run in rows:
        s = run["summary"]["overall"]
        measured = run["cases"][0]["open_privilege"].get("measured", True)
        reach = str(s["open_privilege_tenant"]) if measured else "not probed"
        out.append(f"| {label} | {s['cases']} | {s['attack_successes']} | "
                   f"{s['unsafe_auto_approvals']} | {s['cross_tenant_reads']} | "
                   f"{s['audit_gaps']} | {reach} |")
    return "\n".join(out)


def redteam_prose() -> str:
    red = _load("redteam-results.json")
    v1 = _load("baseline-v1.json")
    corpus = red["corpus"]
    a2m = sum(1 for p in (EVAL / "injections").glob("*.json")
              if p.name != "case.schema.json"
              and json.loads(p.read_text(encoding="utf-8")).get("family") == "a2m")
    return (f"The corpus has {corpus['cases']} prompt-injection cases, {a2m} of them in the "
            f"A2M style. Version 1 left {v1['runs']['http']['open_privilege_tenant']} writes "
            f"reachable after its {v1['cases']} cases.")


def stages() -> str:
    data = _load("stage-privilege.json")
    names = {"v1-tenant-token": "v1 tenant token", "request-bound": "Request-bound",
             "request-bound+delivery": "Request-bound + role delivery"}
    head = "| Credential | " + " | ".join(data["stages"]) + " |"
    out = [head, "|---|" + "---|" * len(data["stages"])]
    for key, label in names.items():
        row = data["summary"][key]
        out.append(f"| {label} | " + " | ".join(str(row[s]["writes"]) for s in data["stages"])
                   + " |")
    return "\n".join(out)


def ablation() -> str:
    s = _load("ablation-tenant.json")["summary"]
    label = {"parameter": "Tenant and request as validated arguments",
             "credential": "Bound to the credential", "forged": "Bound, under forged scope"}
    out = ["| Arm | Planner | Trials | Tried out of scope | Served |", "|---|---|---|---|---|"]
    for key, b in s["by_arm_planner"].items():
        arm, planner = key.split("/")
        out.append(f"| {label[arm]} | {planner} | {b['trials']} | {b['attempted']} | "
                   f"{b['served']} |")
    return "\n".join(out)


def ablation_prose() -> str:
    d = _load("ablation-tenant.json")
    s = d["summary"]
    stolen = s["by_technique"]["stolen_live_token"]
    forged = [t for t in s["by_technique"] if t != "stolen_live_token"]
    served = sum(s["by_technique"][t]["served"] for t in forged)
    return (f"{s['total']['trials']} trials. The {len(forged)} forgery techniques got "
            f"{served} calls served. A stolen live task credential got "
            f"{stolen['served']} of {stolen['trials']}.")


def llm() -> str:
    d = _load("redteam-llm-results.json")
    s = d["summary"]["overall"]
    p = d["planner"]
    return ("| Planner | Cases | Replies parsed | Model steered | Got through, hardened "
            "| Got through, boundary off |\n|---|---|---|---|---|---|\n"
            f"| {p['model']} ({p['provider']}) | {s['cases']} | {s['reply_parsed']} | "
            f"{s['model_steered']} | {s['attack_successes_hardened']} | "
            f"{s['attack_successes_ablation']} |")


def llm_prose() -> str:
    d = _load("redteam-llm-results.json")
    rows = d["cases"]
    s = d["summary"]["overall"]
    p = d["planner"]
    outcomes = [o for r in rows for o in r["hardened"]["outcomes"]]
    recorded = sum(1 for r in rows if any(o["tool"] == "record_decision" and o["ok"]
                                          for o in r["hardened"]["outcomes"]))
    named = sum(1 for o in outcomes if not o["ok"] and o.get("blocked_by") == "no_signature")
    provider = "Claude Haiku"
    if p["provider"] != "anthropic":
        provider = (f"{p['model']} in LM Studio with reasoning off, because no Anthropic "
                    "API key was set")
    return (f"The planner was {provider}. It finished the task with a valid record_decision "
            f"in {recorded} of {s['cases']} cases: {named} of its calls still tried to pass a "
            f"request id, which no tool takes, and {s['cases'] - s['reply_parsed']} replies "
            f"ran out of tokens as prose. So the steered count mostly measures malformed calls, "
            f"not obedience to the planted text. The run needs a stronger model to say more.")


def residual() -> str:
    s = _load("residual-work.json")["summary"]
    out = ["| Projects | Gate saves work | Gate adds work | Median change |",
           "|---|---|---|---|"]
    out.append(f"| all {s['projects']} | {s['gate_reduces_work']} | "
               f"{s['gate_increases_work']} | {s['median_relative_change'] * 100:+.1f}% |")
    for label, b in s["by_volume"].items():
        out.append(f"| {label} | {b['gate_reduces_work']} | "
                   f"{b['projects'] - b['gate_reduces_work']} | "
                   f"{b['median_relative_change'] * 100:+.1f}% |")
    return "\n".join(out)


def latency() -> str:
    d = _load("latency.json")["results"]
    out = ["| Path | Explanation | Runs | p50 ms | p95 ms | p99 ms |", "|---|---|---|---|---|---|"]
    for path, label in (("inprocess", "In-process"), ("http", "MCP over HTTP")):
        for mode, name in (("no_llm", "template"), ("llm", "local LLM")):
            r = d[path][mode]
            out.append(f"| {label} | {name} | {r['n']} | {r['ms']['p50']:g} | "
                       f"{r['ms']['p95']:g} | {r['ms']['p99']:g} |")
    return "\n".join(out)


BLOCKS = {"redteam": redteam, "redteam_prose": redteam_prose, "stages": stages,
          "ablation": ablation, "ablation_prose": ablation_prose, "llm": llm,
          "llm_prose": llm_prose,
          "residual": residual, "latency": latency}


def main() -> None:
    for name, fn in BLOCKS.items():
        try:
            print(f"<!-- {name} -->\n{fn()}\n")
        except FileNotFoundError as exc:
            print(f"<!-- {name}: missing {exc.filename} -->\n")


if __name__ == "__main__":
    main()
