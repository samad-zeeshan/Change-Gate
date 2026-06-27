
from __future__ import annotations

import pytest

from eval.harness import classify, run_condition


def test_classify_rules():
    assert classify("auto_approve", "auto_approve") == ("correct", True)
    assert classify("deny", "route") == ("safe_degrade", True)
    assert classify("route", "auto_approve") == ("unsafe", False)
    assert classify("auto_approve", "deny") == ("wrong", False)
    assert classify("route", None) == ("failed", False)


def test_no_failures_all_correct():
    result, outcomes = run_condition(resilience=True, failure_rate=0.0, n=25, base_seed=1)
    assert result.success_rate == 1.0
    assert all(o.outcome == "correct" for o in outcomes)


def test_resilience_beats_baseline_under_failure():
    on, _ = run_condition(resilience=True, failure_rate=0.5, n=60, base_seed=42)
    off, _ = run_condition(resilience=False, failure_rate=0.5, n=60, base_seed=42)
    assert on.success_rate > off.success_rate
    assert on.success_rate >= 0.9
    assert off.success_rate < 0.5


@pytest.mark.parametrize("rate", [0.1, 0.25, 0.5])
def test_never_unsafe_auto_approve_under_failure(rate):
    on, _ = run_condition(resilience=True, failure_rate=rate, n=80, base_seed=7)
    off, _ = run_condition(resilience=False, failure_rate=rate, n=80, base_seed=7)
    assert on.unsafe == 0
    assert off.unsafe == 0


def test_retries_and_degradations_rise_with_failure_rate():
    low, _ = run_condition(resilience=True, failure_rate=0.1, n=60, base_seed=3)
    high, _ = run_condition(resilience=True, failure_rate=0.5, n=60, base_seed=3)
    assert high.mean_retries > low.mean_retries
