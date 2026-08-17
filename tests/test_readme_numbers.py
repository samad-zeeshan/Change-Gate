
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUN_ROWS = {
    "Hardened, MCP over HTTP": "http",
    "Hardened, in-process": "inprocess",
    "Ablation, new layers off": "ablation",
}
GOAL_ROWS = {
    "unsafe auto-approve": "unsafe_auto_approve",
    "wrong-tenant read": "wrong_tenant_read",
    "audit skip": "audit_skip",
    "freeze-window bypass": "freeze_window_bypass",
    "privilege escalation": "privilege_escalation",
}


def _rows() -> dict[str, list[str]]:
    out = {}
    for line in (ROOT / "README.md").read_text(encoding="utf-8").splitlines():
        if line.startswith("| ") and line.endswith(" |"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            out[cells[0]] = cells[1:]
    return out


def _results() -> dict:
    return json.loads((ROOT / "eval" / "redteam-results.json").read_text(encoding="utf-8"))


def test_readme_run_table_matches_the_results_file():
    rows = _rows()
    for label, run in RUN_ROWS.items():
        s = _results()["runs"][run]["summary"]["overall"]
        expected = [
            str(s["cases"]), str(s["attack_successes"]), str(s["unsafe_auto_approvals"]),
            str(s["cross_tenant_reads"]), str(s["audit_gaps"]), str(s["freeze_bypasses"]),
            str(s["privilege_escalations"]), str(s["hallucinated_calls"]),
            str(s["hallucinated_executed"]), f"{s['audit_chain_verified']} of {s['cases']}",
        ]
        assert rows[label] == expected, label


def test_readme_goal_table_matches_the_results_file():
    rows = _rows()
    runs = _results()["runs"]
    for label, goal in GOAL_ROWS.items():
        h = runs["http"]["summary"]["by_goal"][goal]
        a = runs["ablation"]["summary"]["by_goal"][goal]
        expected = [
            str(h["cases"]), str(h["attack_successes"]), str(a["attack_successes"]),
            str(h["open_privilege_task"]), str(h["open_privilege_tenant"]),
            str(h["open_privilege_dangerous"]), str(a["open_privilege_dangerous"]),
        ]
        assert rows[label] == expected, label


def test_readme_prose_numbers_match_the_results_file():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    data = _results()
    http = data["runs"]["http"]["summary"]
    layers = http["steered_calls_by_layer"]
    assert f"The corpus is {data['corpus']['cases']} cases" in text
    assert f"{data['corpus']['fragmented']} cases split the payload" in text
    assert f"tool roles ({layers['tool_roles']})" in text
    assert f"the action policy ({layers['action_policy']})" in text
    assert f"tenant scoping ({layers['tenant_scope']})" in text
    assert f"({http['overall']['open_privilege_tenant']} reachable writes" in text
    assert f"{http['overall']['tool_drift_cases']} cases put text in a tool description" in text
    assert f"policy `{data['policy_version']}`" in text
