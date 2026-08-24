"""Tenant isolation ablation: validated parameter, request-bound credential, forged scope."""

from __future__ import annotations

import json

import pytest

from eval.ablation_tenant import (
    ARMS,
    TECHNIQUES,
    AblationContext,
    load_pretexts,
    plan_size,
    run_forgery,
    run_llm,
    run_scripted,
    summarise,
)

PRETEXTS = {p["id"]: p for p in load_pretexts()}


@pytest.fixture(scope="module")
def ctx():
    c = AblationContext(transports=("inprocess",))
    c.start()
    yield c
    c.stop()


def test_pretexts_cover_other_tenants_and_other_requests():
    kinds = [p["kind"] for p in PRETEXTS.values()]
    assert kinds.count("foreign") >= 12 and kinds.count("sibling") >= 12
    for p in PRETEXTS.values():
        assert p["resource"]["request_id"] != p["task_id"]


def test_the_plan_has_at_least_300_trials():
    size = plan_size(transports=("inprocess", "http"), planners=("scripted", "llm"))
    assert size["total"] >= 300
    assert set(size["by_arm"]) == set(ARMS)


def test_a_validated_tenant_parameter_serves_the_foreign_read(ctx):
    trial = run_scripted("parameter", "inprocess", PRETEXTS["wtr-rp-01"], ctx)
    assert trial["attempted"] is True
    assert trial["served"] is True


def test_the_bound_credential_has_no_signature_for_it(ctx):
    trial = run_scripted("credential", "inprocess", PRETEXTS["wtr-rp-01"], ctx)
    assert trial["attempted"] is True
    assert trial["served"] is False
    assert trial["blocked_by"] == "no_signature"


def test_a_sibling_write_is_served_by_parameters_and_refused_by_binding(ctx):
    sibling = next(p for p in PRETEXTS.values()
                   if p["kind"] == "sibling" and p["call"]["tool"] == "route_change")
    assert run_scripted("parameter", "inprocess", sibling, ctx)["served"] is True
    assert run_scripted("credential", "inprocess", sibling, ctx)["served"] is False


@pytest.mark.parametrize("technique", [t for t in TECHNIQUES if t != "stolen_live_token"])
def test_every_forgery_is_refused(ctx, technique):
    trial = run_forgery(technique, "inprocess", PRETEXTS["wtr-rp-01"], ctx)
    assert trial["served"] is False, trial
    assert trial["blocked_by"]


def test_a_stolen_live_credential_is_honoured(ctx):
    # Binding cannot tell a thief from the task the credential was issued to.
    # Sender-constrained tokens would, and they are not implemented here.
    trial = run_forgery("stolen_live_token", "inprocess", PRETEXTS["wtr-rp-01"], ctx)
    assert trial["served"] is True


def test_llm_arm_counts_attempts_and_what_was_served(ctx):
    def planner(messages):
        text = json.dumps(messages)
        if "tenant_id" in text:
            return json.dumps([{"tool": "get_change_request",
                                "args": {"tenant_id": "globex", "request_id": "gx-900"}}])
        return json.dumps([{"tool": "get_change_request", "args": {"request_id": "gx-900"}}])

    rows = run_llm(PRETEXTS["wtr-rp-01"], planner, ctx)
    by_arm = {r["arm"]: r for r in rows}
    assert by_arm["parameter"]["attempted"] and by_arm["parameter"]["served"]
    assert by_arm["credential"]["attempted"] and not by_arm["credential"]["served"]


def test_summary_reports_served_over_attempted_and_over_trials(ctx):
    trials = [run_scripted(arm, "inprocess", p, ctx)
              for arm in ("parameter", "credential") for p in list(PRETEXTS.values())[:4]]
    s = summarise(trials)
    block = s["by_arm"]["parameter"]
    assert {"trials", "attempted", "served", "refused_by"} <= set(block)
    assert block["trials"] == 4
