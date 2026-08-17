"""Copy the v1 red-team summary out of git history into eval/baseline-v1.json.

The v1 open-privilege figure is quoted next to the new one, so it has to come from a file too.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

V1_COMMIT = "1923a14"
HERE = Path(__file__).resolve().parent


def main() -> None:
    raw = subprocess.run(["git", "show", f"{V1_COMMIT}:eval/redteam-results.json"],
                         capture_output=True, text=True, check=True, cwd=HERE.parent).stdout
    v1 = json.loads(raw)
    out = {
        "source_commit": V1_COMMIT,
        "source_file": "eval/redteam-results.json",
        "generated_at": v1["generated_at"],
        "policy_version": v1["policy_version"],
        "cases": v1["corpus"]["cases"],
        "runs": {name: run["summary"]["overall"] for name, run in v1["runs"].items()},
    }
    (HERE / "baseline-v1.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(out["runs"]["http"], indent=2))


if __name__ == "__main__":
    main()
