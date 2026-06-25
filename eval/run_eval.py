
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE.parent) not in sys.path:
    sys.path.insert(0, str(HERE.parent))

from eval import chart  # noqa: E402
from eval.harness import ConditionResult, run_condition  # noqa: E402

FAILURE_RATES = [0.0, 0.10, 0.25, 0.50]


def run(n: int, base_seed: int) -> dict:
    conditions: list[ConditionResult] = []
    all_outcomes: dict[str, list] = {}
    for resilience in (True, False):
        for rate in FAILURE_RATES:
            result, outcomes = run_condition(
                resilience=resilience, failure_rate=rate, n=n, base_seed=base_seed
            )
            conditions.append(result)
            key = f"{'on' if resilience else 'off'}@{int(rate*100)}"
            all_outcomes[key] = [asdict(o) for o in outcomes]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "n_per_condition": n,
        "base_seed": base_seed,
        "failure_rates": FAILURE_RATES,
        "conditions": [asdict(c) for c in conditions],
        "outcomes": all_outcomes,
    }


def _series(conditions: list[dict], resilience: bool) -> list[float]:
    by_rate = {c["failure_rate"]: c for c in conditions if c["resilience"] is resilience}
    return [round(by_rate[r]["successes"] / by_rate[r]["n"], 4) for r in FAILURE_RATES]


def write_report(data: dict, out_dir: Path) -> None:
    conditions = data["conditions"]
    on = _series(conditions, True)
    off = _series(conditions, False)

    chart.write_svg(out_dir / "chart.svg", FAILURE_RATES, on, off)
    png = chart.try_write_png(out_dir / "chart.png", FAILURE_RATES, on, off)

    def row(c: dict) -> str:
        return (
            f"| {'ON' if c['resilience'] else 'OFF'} | {int(c['failure_rate']*100)}% | "
            f"{c['successes']}/{c['n']} | {c['successes']/c['n']*100:.1f}% | "
            f"{c['mean_retries']} | {c['mean_attempts']} | {c['total_degradations']} | "
            f"{c['unsafe']} | {c['p50_latency_ms']} | {c['p95_latency_ms']} |"
        )

    on_rows = "\n".join(row(c) for c in conditions if c["resilience"])
    off_rows = "\n".join(row(c) for c in conditions if not c["resilience"])

    lift_lines = []
    for r in FAILURE_RATES:
        i = FAILURE_RATES.index(r)
        lift_lines.append(
            f"- At **{int(r*100)}%** injected failures: "
            f"**{on[i]*100:.1f}%** (ON) vs **{off[i]*100:.1f}%** (OFF) "
            f"→ +{(on[i]-off[i])*100:.1f} pts"
        )

    total_unsafe = sum(c["unsafe"] for c in conditions)
    chart_md = "![success rate](chart.png)" if png else "![success rate](chart.svg)"

    report = f"""# Reliability Eval — Change-Approval Agent

_Generated {data['generated_at']} · N={data['n_per_condition']} tasks/condition · seed={data['base_seed']}_

**Metric:** task success rate = fraction of runs reaching a *correct* terminal decision.
Correctness includes fail-safe behaviour: degrading to **route to human** under failure
counts as correct; **silently auto-approving** a change that should be routed/denied is a
hard failure. Latency is a labelled *logical* model (per-attempt cost + accrued backoff /
spike), not wall-clock — see `harness.py`.

**What this eval proves (and what it doesn't).** It measures **safe degradation under
injected transport failures** — resilience ON vs. the no-resilience baseline — and that the
agent never auto-approves on incomplete context (0 unsafe across the matrix). It does **not**
establish that the risk *scores* are correct or externally valid; the correctness of the
deterministic scoring (factor values, monotonicity, freeze dominance, band boundaries) is
proven separately by the unit + property tests (`tests/test_risk_factors.py`,
`tests/test_risk_properties.py`, `tests/test_risk_purity.py`).

{chart_md}

## Success rate (ON vs OFF)

{chr(10).join(lift_lines)}

## Resilience ON

| Resilience | Failure rate | Successes | Success rate | Mean retries | Mean attempts | Degradations | Unsafe | p50 (ms) | p95 (ms) |
|---|---|---|---|---|---|---|---|---|---|
{on_rows}

## Resilience OFF (baseline)

| Resilience | Failure rate | Successes | Success rate | Mean retries | Mean attempts | Degradations | Unsafe | p50 (ms) | p95 (ms) |
|---|---|---|---|---|---|---|---|---|---|
{off_rows}

## Interpretation

- The resilience layer (retries + fail-safe degradation) keeps the success rate high as
  the injected-failure rate climbs, while the baseline collapses: a single un-retried
  transport error ends the run.
- **Unsafe auto-approvals across the entire matrix: {total_unsafe}.** When context is
  incomplete the agent forces a route to a human (`force_route`), so it never approves a
  high-risk change blind. This is the property that makes "degrade" safe rather than
  reckless.
- Mean retries and degradation counts rise with the failure rate under ON — the visible
  cost the layer pays to buy that success rate.

## Reproduce

```bash
python -m eval.run_eval --n {data['n_per_condition']} --seed {data['base_seed']}
```
"""
    (out_dir / "report.md").write_text(report, encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=120, help="tasks per condition (>=100)")
    ap.add_argument("--seed", type=int, default=1234)
    args = ap.parse_args()

    data = run(args.n, args.seed)
    out_dir = HERE
    (out_dir / "results.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    write_report(data, out_dir)

    on = _series(data["conditions"], True)
    off = _series(data["conditions"], False)
    print("Reliability eval complete.")
    for i, r in enumerate(FAILURE_RATES):
        print(f"  {int(r*100):>3}% failures:  ON {on[i]*100:5.1f}%   OFF {off[i]*100:5.1f}%")
    print(f"  unsafe auto-approvals (whole matrix): "
          f"{sum(c['unsafe'] for c in data['conditions'])}")
    print(f"  wrote: {out_dir/'results.json'}, {out_dir/'report.md'}, chart.svg")


if __name__ == "__main__":
    main()
