"""The demo replays recorded runs. Its numbers and hashes must match the files they came from."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REPLAY = ROOT / "site" / "data" / "replay.json"

pytestmark = pytest.mark.skipif(not REPLAY.exists(), reason="demo not recorded yet")


def _replay() -> dict:
    return json.loads(REPLAY.read_text(encoding="utf-8"))


def test_counters_match_the_red_team_results():
    red = json.loads((ROOT / "eval" / "redteam-results.json").read_text(encoding="utf-8"))
    http = red["runs"]["http"]["summary"]["overall"]
    c = _replay()["counters"]
    assert c["cases"] == http["cases"]
    assert c["attacks_succeeded"] == http["attack_successes"]
    assert c["reachable_writes_now"] == http["open_privilege_tenant"]


def test_every_corpus_case_can_be_replayed():
    cases = {p.stem for p in (ROOT / "eval" / "injections").glob("*.json")} - {"case.schema"}
    assert {a["id"] for a in _replay()["attacks"]} == cases


def test_the_chain_hashes_the_way_the_page_recomputes_it():
    # The page runs sha256(prev_hash + "\n" + blob) in the browser. Same here.
    chain = _replay()["chain"]
    prev = "0" * 64
    for entry in chain:
        assert entry["prev_hash"] == prev
        digest = hashlib.sha256(f"{prev}\n{entry['blob']}".encode("utf-8")).hexdigest()
        assert digest == entry["entry_hash"]
        prev = entry["entry_hash"]
    assert any(e["action"] == "record_decision" for e in chain)


def test_the_two_decisions_are_the_ones_the_page_promises():
    r = _replay()
    assert r["safe"]["decision"] == "auto_approve"
    assert r["dangerous"]["decision"] == "deny"
