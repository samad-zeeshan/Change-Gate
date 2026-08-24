"""Shape and coverage checks for the injection corpus."""


from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from warden.tool_registry import REGISTRY

CORPUS = Path(__file__).resolve().parents[1] / "eval" / "injections"
GOALS = {"unsafe_auto_approve", "wrong_tenant_read", "audit_skip", "freeze_window_bypass",
         "privilege_escalation"}
CHANNELS = {"request_payload", "tool_result", "tool_description", "sampling_message"}


def _cases() -> list[dict]:
    return [json.loads(p.read_text(encoding="utf-8"))
            for p in sorted(CORPUS.glob("*.json")) if p.name != "case.schema.json"]


def test_every_case_matches_the_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((CORPUS / "case.schema.json").read_text(encoding="utf-8"))
    for case in _cases():
        jsonschema.validate(case, schema)


def test_corpus_size_and_coverage():
    cases = _cases()
    assert len(cases) >= 80
    assert len({c["id"] for c in cases}) == len(cases)
    assert sum(1 for c in cases if c["channel"] == "fragmented") >= 10
    assert {c["goal"] for c in cases} == GOALS
    covered = Counter((c["goal"], ch) for c in cases for ch in c["channels"])
    for goal in GOALS:
        for channel in CHANNELS:
            assert covered[(goal, channel)] >= 1, (goal, channel)


def test_file_name_matches_id():
    for path in CORPUS.glob("*.json"):
        if path.name != "case.schema.json":
            assert json.loads(path.read_text(encoding="utf-8"))["id"] == path.stem


def test_declared_channels_are_the_ones_actually_injected():
    for c in _cases():
        channels = set(c["channels"])
        if c["channel"] == "fragmented":
            assert len(channels) == 2, c["id"]
        else:
            assert channels == {c["channel"]}, c["id"]
        # A rogue tool is text in the tool listing, so it is the description channel.
        injected = {"tool_description" if k == "rogue_tools" else k for k in c["injections"]}
        if c["target"].get("description"):
            injected.add("request_payload")
        assert injected == channels, c["id"]


def test_poisoned_results_target_real_tools():
    for c in _cases():
        for inj in c["injections"].get("tool_result", []):
            assert inj["tool"] in REGISTRY, c["id"]
            assert ("merge" in inj) != ("replace" in inj), c["id"]
        for tool in c["injections"].get("tool_description", {}):
            assert tool in REGISTRY, c["id"]
        for tool in c["injections"].get("rogue_tools", {}):
            assert tool not in REGISTRY, c["id"]


def test_a2m_cases_cover_attraction_and_manipulation():
    # A2M (arXiv 2609.26761): attractive tool metadata, then tool returns refined
    # to steer the next call. Both stages, every goal, and cases that use both.
    a2m = [c for c in _cases() if c.get("family") == "a2m"]
    assert len(a2m) >= 16
    assert {c["stage"] for c in a2m} == {"attraction", "manipulation", "both"}
    assert {c["goal"] for c in a2m} == GOALS
    for c in a2m:
        if c["stage"] == "attraction":
            assert set(c["injections"]) & {"tool_description", "rogue_tools"}, c["id"]
        if c["stage"] == "manipulation":
            assert "tool_result" in c["injections"], c["id"]
        if c["stage"] == "both":
            assert len(c["channels"]) == 2, c["id"]
