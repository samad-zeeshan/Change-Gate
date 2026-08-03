# Working notes for the demo page

Written before `index.html`. Everything on the page has to trace back to something here,
and everything here has to trace back to a file in this repo.

## What this actually does, in one sentence

It is a guard that stands in front of every settings change to a company's live software,
works out how dangerous the change is, and then either waves it through, hands it to a
person, or blocks it outright.

## Who has the problem, and the moment they are stuck

Priya is on call. At 01:40 a request lands: turn on a switch called `checkout_v2` in the
live shop. She has to answer in a couple of minutes. To answer well she would need to know
what else breaks if the gateway breaks, whether that service had an incident this week,
whether the company is inside its mid-year change freeze, and whether the person asking is
even allowed to touch production. All four answers live in four different places, and none
of them are open at 01:40. So she approves it, because saying no costs more than saying
yes, and the safe changes look exactly like the dangerous ones at the moment they are asked
for.

That framing comes straight from the repo README: "Most outages start with a change someone
made. A flag flip in prod, a timeout bumped a little too far, a config edit during a freeze
window. The safe changes and the dangerous ones look almost identical at the moment they
are requested." (`README.md` lines 9 to 11.)

## What people did before this existed

A person answered the question by hand each time, from memory, at whatever hour the request
arrived. The reasoning went in a chat message that nobody could find later, and there was
no record you could check afterwards to see what was known at the moment of the decision.
Change-Gate replaces that with a rule that always runs the same way and always writes down
what it saw.

## Numbers that exist in this repo

| Number | Where it comes from | How it was measured |
| --- | --- | --- |
| Risk 14.0, band low, for `cr-001` | Captured run, `docs/data/gate.json` | Ran `python -m change_gate.agent.main cr-001` at commit 0493941 on 2026-07-27, Windows 11, Python 3.14.4, in-memory backend, no Docker. |
| Risk 50.0, band high, for `cr-003` | Captured run, `docs/data/gate.json` | Same run. |
| Weights 0.35 blast radius, 0.30 environment, 0.20 size, 0.15 recent trouble | `src/change_gate/data/seed.py` lines 97 to 102 | Policy constants for the `acme` tenant. Read from the file, also echoed in the captured run. |
| Bands: under 30 low, under 65 medium, else high | `src/change_gate/data/seed.py` lines 103 to 104 | Same policy constants. |
| Freeze window 2026-06-20 to 2026-06-30, production only | `src/change_gate/data/seed.py` lines 65 to 74 | Fixture data for the `acme` tenant. |
| 118 of 120 correct with retries on, at a 50 percent injected failure rate | `eval/chart.svg` (encodes 98.33 percent) and `README.md` line 76 | Re-ran `eval.harness.run_condition` at N=120 per condition, seed 1234, on 2026-07-27. Reproduced the committed chart exactly. |
| 2 of 120 correct with retries off, same failure rate | `eval/chart.svg` (encodes 1.67 percent) and `README.md` line 76 | Same re-run. |
| 0 unsafe auto-approvals across 960 runs | `eval/harness.py` `classify()` and `eval/run_eval.py` | 8 conditions (retries on and off, at 0, 10, 25, 50 percent failure) times 120 runs. Counted the `unsafe` outcome, which is defined as approving something that should have been routed or denied. |
| 44 tests over scoring, decision rules and the audit chain, all passing | `tests/test_risk_factors.py`, `tests/test_risk_properties.py`, `tests/test_risk_purity.py`, `tests/test_decision_routing.py`, `tests/test_audit.py` | `python -m pytest` on those five files, 2026-07-27, same machine. 44 passed. The rest of the suite was not run: `test_auth.py` and `test_oauth_pkce.py` need PyJWT, which is not installed here, and `test_isolation.py` needs Postgres. |
| Audit chain verifies as written, fails after one stored field is edited | `src/change_gate/audit.py` `verify_chain()` | Captured in `docs/data/gate.json` under `tamper_check`: verified true as stored, false after changing one decision field in entry 1, true again after putting it back. |

Numbers deliberately **not** used on the page: the latency figures in `eval/harness.py`.
They are a labelled logical model (a fixed per-attempt cost plus accrued backoff), not
wall-clock timing, and putting a millisecond number on a page invites the reader to think
it was timed. `eval/run_eval.py` says so itself.

## What it does not do

- It has never been pointed at a real company's changes. Everything in the demo comes from
  the fixture in `src/change_gate/data/seed.py`: two tenants, eight services, five change
  requests.
- The reliability eval proves it fails safely when connections break. It does not prove the
  risk scores agree with what an experienced on-call engineer would say. There is no set of
  human-labelled changes to check against, so that claim is not made.
- The weights and the thresholds were chosen by hand and written into the policy. They were
  not fitted to any record of which changes actually caused outages.
- The freeze window is the only absolute block. Everything else is a number compared with a
  threshold, so a change can score 29.9 and go straight through.
- The multi-tenant database separation and the login checks need Docker, Postgres and
  Keycloak running. The captured run on this page uses the offline in-memory path only, so
  it demonstrates the deciding, not the database separation.

## Format chosen

**Stored run.** This is Python with a LangGraph workflow, a database layer and an OAuth
server. None of it can honestly run in a reader's browser. The real agent was run locally
against `cr-001` and `cr-003`, and every field the page shows was captured to
`docs/data/gate.json`. The page replays that capture and says so on the badge.

Both requests were decided in one session against the same tenant, so the two audit entries
are sequence 1 and 2 of a single chain and the second one carries the first one's hash. The
repo's own `scripts/demo.ps1` runs them as two separate processes, where each would be
sequence 1. Nothing else differs.

## Signature element

**The freeze band, drawn to scale.** A single time axis for late June 2026 with the
production freeze drawn as a hatched brass wall from June 20 to June 30, the clock the run
used marked on it, and the two requested change windows plotted as blocks on a development
lane and a production lane. It fits because the freeze rule is the one thing in this project
that overrides everything else: a two hour slot lands inside a ten day wall and the answer is
no, whatever the score says. Drawing both to the same scale is the whole argument in one
picture, and it is a time axis with intervals rather than anything hanging off a value rule.
