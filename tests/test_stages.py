"""Open privilege measured at each workflow stage, for three credential setups."""

from __future__ import annotations

from eval.redteam import load_cases
from eval.stages import CONFIGS, STAGES, measure_case, summarise_stages

CASES = {c["id"]: c for c in load_cases()}


def test_stages_follow_the_workflow():
    assert STAGES == ("issued", "fetch", "validate", "assess", "decide", "explain")
    assert set(CONFIGS) == {"v1-tenant-token", "request-bound", "request-bound+delivery"}


def test_delivery_opens_one_write_only_between_assess_and_decide():
    row = measure_case(CASES["uaa-rp-01"], "request-bound+delivery")
    writes = [row[s]["writes"] for s in STAGES]
    assert writes == [0, 0, 0, 1, 0, 0]
    assert row["assess"]["tools"] == ["record_decision"]


def test_binding_alone_leaves_the_target_writable_from_the_start():
    row = measure_case(CASES["uaa-rp-01"], "request-bound")
    assert row["issued"]["writes"] == 2
    assert set(row["issued"]["tools"]) == {"record_decision", "route_change"}
    assert row["explain"]["writes"] == 0


def test_the_v1_token_reaches_other_requests_at_every_stage():
    row = measure_case(CASES["uaa-rp-01"], "v1-tenant-token")
    assert all(row[s]["writes"] > 2 for s in STAGES)
    assert all(row[s]["dangerous"] == 0 for s in STAGES)


def test_summary_sums_each_stage():
    rows = {"a": measure_case(CASES["uaa-rp-01"], "request-bound+delivery")}
    s = summarise_stages({"request-bound+delivery": rows})
    assert s["request-bound+delivery"]["assess"]["writes"] == 1
