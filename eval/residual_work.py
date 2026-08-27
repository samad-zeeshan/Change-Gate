"""Does the gate reduce total human work? Counted over 300 synthetic projects.

Follows the substitution condition in arXiv 2609.29345: count exceptions, verification, correction and maintenance, not only review.
"""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass
from pathlib import Path

from eval.dgf.generate import (
    Project,
    generate_project,
    project_params,
    write_params,
    write_sample,
)
from warden.data import seed as fixture
from warden.domain.decision import decide, validate_request
from warden.domain.risk import assess_risk

HERE = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Costs:
    review: float
    exception_rate: float
    exception: float
    verification: float
    correction: float
    maintenance: float

    @classmethod
    def of(cls, p) -> "Costs":
        return cls(p.review, p.exception_rate, p.exception, p.verification, p.correction,
                   p.maintenance)


def run_gate_on_project(project: Project) -> list[str]:
    # The same deterministic core the server runs, without the transport around it.
    out = []
    for lr in project.requests:
        validation = validate_request(lr.request, project.ctx)
        risk = assess_risk(lr.request, project.ctx, fixture.EVAL_NOW)
        out.append(decide(lr.request, project.ctx, validation, risk).decision.value)
    return out


def human_work(decisions: list[str], risky: list[bool], c: Costs) -> tuple[float, float, dict]:
    """Minutes of human work without the gate and with it, and where the latter goes.

    Without the gate a person reviews every request, and their own misses are not
    charged, which favours the manual baseline.
    """
    n = len(decisions)
    auto = [r for d, r in zip(decisions, risky) if d == "auto_approve"]
    deny = [r for d, r in zip(decisions, risky) if d == "deny"]
    routed = sum(1 for d in decisions if d == "route")
    parts = {
        "review": routed * c.review,
        "verification": len(auto) * c.verification,
        "correction": sum(auto) * c.correction,
        # A safe change the gate denied comes back to a person for review.
        "rework": sum(1 for r in deny if not r) * c.review,
        "exceptions": c.exception_rate * (len(auto) + len(deny)) * c.exception,
        "maintenance": c.maintenance,
    }
    return n * c.review, sum(parts.values()), parts


def threshold_holds(decisions: list[str], risky: list[bool], c: Costs) -> bool:
    """The residual-work threshold written as one inequality.

    Review saved on the requests the gate closes correctly must exceed what it
    adds: verification, correction of bad auto-approvals, exceptions, upkeep.
    """
    n_auto = sum(1 for d in decisions if d == "auto_approve")
    n_deny = sum(1 for d in decisions if d == "deny")
    auto_risky = sum(1 for d, r in zip(decisions, risky) if d == "auto_approve" and r)
    deny_safe = sum(1 for d, r in zip(decisions, risky) if d == "deny" and not r)
    saved = (n_auto + n_deny - deny_safe) * c.review
    added = (n_auto * c.verification + auto_risky * c.correction
             + c.exception_rate * (n_auto + n_deny) * c.exception + c.maintenance)
    return saved > added


def project_row(project: Project) -> dict:
    decisions = run_gate_on_project(project)
    risky = [lr.risky for lr in project.requests]
    costs = Costs.of(project.params)
    manual, gate, parts = human_work(decisions, risky, costs)
    n = len(decisions)
    auto = decisions.count("auto_approve")
    return {
        "id": project.params.id,
        "requests": n,
        "calibration_noise": project.params.calibration_noise,
        "exception_rate": project.params.exception_rate,
        "automation_share": round((auto + decisions.count("deny")) / n, 4),
        "auto_approved": auto,
        "routed": decisions.count("route"),
        "denied": decisions.count("deny"),
        "risky": sum(risky),
        "risky_auto_approved": sum(1 for d, r in zip(decisions, risky)
                                   if d == "auto_approve" and r),
        "miss_rate": round(sum(1 for d, r in zip(decisions, risky)
                               if d == "auto_approve" and r) / max(1, auto), 4),
        "correction_minutes": project.params.correction,
        "manual_minutes": round(manual, 1),
        "gate_minutes": round(gate, 1),
        "gate_parts": {k: round(v, 1) for k, v in parts.items()},
        "relative_change": round(gate / manual - 1, 4),
        "reduces_work": gate < manual,
        "threshold_holds": threshold_holds(decisions, risky, costs),
    }


def _bins(rows: list[dict], key: str, edges: list[tuple[str, float, float]]) -> dict:
    out = {}
    for label, lo, hi in edges:
        sub = [r for r in rows if r.get(key) is not None and lo <= r[key] < hi]
        out[label] = {
            "projects": len(sub),
            "gate_reduces_work": sum(1 for r in sub if r["reduces_work"]),
            "median_relative_change": round(statistics.median(
                [r["relative_change"] for r in sub]), 4) if sub else None,
        }
    return out


def summarise_projects(rows: list[dict]) -> dict:
    inf = float("inf")
    return {
        "projects": len(rows),
        "gate_reduces_work": sum(1 for r in rows if r["reduces_work"]),
        "gate_increases_work": sum(1 for r in rows if not r["reduces_work"]),
        "median_relative_change": round(statistics.median(
            [r["relative_change"] for r in rows]), 4),
        "median_automation_share": round(statistics.median(
            [r["automation_share"] for r in rows]), 4),
        "by_exception_rate": _bins(rows, "exception_rate", [
            ("under 10%", 0, 0.1), ("10 to 20%", 0.1, 0.2), ("20% and up", 0.2, inf)]),
        "by_calibration": _bins(rows, "calibration_noise", [
            ("well calibrated (noise < 0.5)", 0, 0.5), ("middling (0.5 to 1.2)", 0.5, 1.2),
            ("poorly calibrated (noise >= 1.2)", 1.2, inf)]),
        "by_volume": _bins(rows, "requests", [
            ("under 60 requests", 0, 60), ("60 to 200", 60, 200), ("over 200", 200, inf)]),
        # The two that separate the outcomes most in this model: how often an
        # auto-approval was a bad change, and what fixing one costs.
        "by_miss_rate": _bins(rows, "miss_rate", [
            ("under 2% of auto-approvals risky", 0, 0.02), ("2 to 5%", 0.02, 0.05),
            ("5% and up", 0.05, inf)]),
        "by_correction_cost": _bins(rows, "correction_minutes", [
            ("under 2 hours per bad change", 0, 120), ("2 to 5 hours", 120, 300),
            ("5 hours and up", 300, inf)]),
    }


def write_plot(rows: list[dict], path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    matplotlib.rcParams["svg.hashsalt"] = "warden"
    groups = [("noise < 0.5", "#2563eb", 0, 0.5), ("0.5 to 1.2", "#d97706", 0.5, 1.2),
              ("noise >= 1.2", "#dc2626", 1.2, 99)]
    fig, ax = plt.subplots(figsize=(7.5, 4.2), dpi=100)
    for label, color, lo, hi in groups:
        sub = [r for r in rows if lo <= r["calibration_noise"] < hi]
        ax.scatter([r["exception_rate"] * 100 for r in sub],
                   [r["relative_change"] * 100 for r in sub],
                   s=[8 + r["requests"] / 12 for r in sub], c=color, alpha=0.55,
                   label=f"calibration {label}", edgecolors="none")
    ax.axhline(0, color="#111827", linewidth=0.8)
    ax.set_xlabel("Exception rate on gate-handled requests (%)")
    ax.set_ylabel("Human work with the gate vs without (%)")
    ax.set_title("Each dot is one synthetic project. Below the line the gate saves work.",
                 fontsize=10)
    ax.legend(fontsize=8, frameon=False, loc="upper left")
    ax.grid(alpha=0.2)
    fig.tight_layout()
    fig.savefig(path, format="svg", metadata={"Date": None})
    plt.close(fig)


def main() -> None:
    import platform
    from datetime import datetime, timezone

    params = project_params(300, seed=2609)
    write_params(params)
    projects = (generate_project(p) for p in params)
    rows = []
    for i, project in enumerate(projects):
        if i == 0:
            write_sample(project)
        rows.append(project_row(project))
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "method": "arXiv 2609.29345 substitution condition, cost model in eval/residual_work.py",
        "summary": summarise_projects(rows),
        "projects": rows,
    }
    (HERE / "residual-work.json").write_text(json.dumps(data, indent=2) + "\n",
                                             encoding="utf-8")
    write_plot(rows, HERE / "residual-work.svg")
    print(json.dumps(data["summary"], indent=2))


if __name__ == "__main__":
    main()
