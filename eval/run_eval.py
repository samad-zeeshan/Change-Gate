
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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=120, help="tasks per condition (>=100)")
    ap.add_argument("--seed", type=int, default=1234)
    args = ap.parse_args()

    data = run(args.n, args.seed)
    out_dir = HERE
    (out_dir / "results.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

    on = _series(data["conditions"], True)
    off = _series(data["conditions"], False)
    chart.write_svg(out_dir / "chart.svg", FAILURE_RATES, on, off)
    print("Reliability eval complete.")
    for i, r in enumerate(FAILURE_RATES):
        print(f"  {int(r*100):>3}% failures:  ON {on[i]*100:5.1f}%   OFF {off[i]*100:5.1f}%")
    print(f"  unsafe auto-approvals (whole matrix): "
          f"{sum(c['unsafe'] for c in data['conditions'])}")
    print(f"  wrote: {out_dir/'results.json'}, chart.svg")


if __name__ == "__main__":
    main()
