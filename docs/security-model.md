# Security model

This is the plan for hardening the boundary between the agent and the tools it calls.
It was written before the code. Sections marked "Results" are filled in from
`eval/redteam-results.json` after the red-team run.

## What already existed

- The MCP server validates bearer tokens: signature against the issuer's JWKS, issuer,
  audience, `exp` and `iat` (`src/change_gate/server/auth.py`).
- Scopes guard writes. `record_decision` needs `change:approve`, and an auto-approve in
  prod needs `change:approve:prod` (`src/change_gate/security.py`).
- Every read and write is scoped to the token's tenant. Postgres enforces it with
  row-level security; the in-memory repository raises on a cross-tenant request.
- `record_decision` recomputes validation and risk itself and writes a hash-chained audit
  entry, including for blocked writes.

What was missing: the server could not tell a person from the agent, there was one write
tool and no human approval path, nothing checked a proposed action against a written
policy, and tool calls were not checked against a declared schema. FastMCP drops
arguments a tool does not declare without an error, and the in-process path accepted any
keyword the Python method accepted, including a caller-chosen `now`.

## The boundary

```
  human (browser)                         agent (LangGraph)
  SSO: auth code + PKCE                   service account: client credentials
        |                                        |
        |                                 agent-side resolver (closed world)
        |                                   unknown tool / argument / type -> rejected,
        |                                   counted, never sent
        v                                        v
  +-----------------------------------------------------------------+
  | MCP server                                                      |
  |  1. bearer token: signature, issuer, audience, expiry           |
  |  2. persona from signed claims (azp) -> gate roles              |
  |  3. tool-call resolution against the pinned registry            |
  |  4. tool permission: does one of the caller's roles allow it?   |
  |  5. scope check (change:approve, change:approve:prod)           |
  |  6. action policy check (policy/change-gate.policy.json)        |
  |  7. side effect, then hash-chained audit entry                  |
  +-----------------------------------------------------------------+
        |
  repository scoped to the token's tenant (Postgres RLS / in-memory check)
```

Every rejection at steps 3 to 6 writes an audit entry before the error goes back to the
caller. Steps 3 and 4 run for every tool. Step 6 runs for every tool that writes.

## Personas

The persona comes from the token's `azp` claim (the OAuth client the token was issued
to). Keycloak signs it, so a caller cannot choose it.

| Persona | How it gets a token | Keycloak client | Gate roles |
|---|---|---|---|
| `agent` | client credentials | `change-gate-agent`, `change-gate-agent-base` | `reader`, `recorder`, `router` |
| `human` | authorization code with PKCE | `change-gate-console` | `reader`, `router`, plus mapped realm roles |
| `unknown` | any other client | none | none |

Human realm roles map to gate roles through the policy file:

| Realm role (claim `gate_roles`) | Gate roles added |
|---|---|
| `change-approver` | `approver`, `recorder` |
| `change-requester` | none beyond the base roles |

A token whose `azp` is not listed gets persona `unknown` and no roles, so every tool call
is refused. The agent client no longer allows the browser flow, so a person cannot log in
through it and pick up the agent persona.

## Tool permissions

| Tool | Writes | Roles allowed |
|---|---|---|
| `get_change_request`, `get_change_policy`, `get_config_state`, `get_dependency_graph`, `get_freeze_windows`, `get_recent_changes` | no | `reader` |
| `validate_change_request`, `assess_change_risk` | no | `reader` |
| `record_decision` | yes | `recorder` |
| `route_change` | yes | `router` |
| `approve_change` | yes | `approver` |
| `deny_change` | yes | `approver` |

`record_decision` runs the gate: it scores the request and records auto-approve, route or
deny. `route_change` sends an open request to a person without scoring it.
`approve_change` and `deny_change` are the human decision on a routed request.

The agent has no `approver` role, so it cannot call `approve_change` in any environment.
It can still run `record_decision`, and the policy below stops that from applying a prod
change.

## Request state

The state of a request is read from the audit chain, not stored separately. The last
successful decision entry for the request sets it.

| State | Set by |
|---|---|
| `new` | no decision entry yet |
| `auto_approved` | `record_decision` that applied the change |
| `routed` | `record_decision` that routed, or `route_change` |
| `denied` | `record_decision` that denied, or `deny_change` |
| `approved` | `approve_change` |

## Action policy

One function, `ActionPolicy.check`, runs before any write has an effect. It takes the
proposed action, the caller's persona and subject, the caller's tenant and the request's
tenant, the environment, the request state, whether a freeze window is active for the
change window, and the requester. It returns allow or deny, the id of the rule that
matched, and a reason.

Actions:

| Action | Produced by |
|---|---|
| `auto_approve` | `record_decision` when the engine says auto-approve |
| `route` | `record_decision` when it routes, and `route_change` |
| `deny` | `record_decision` when it denies, and `deny_change` |
| `approve` | `approve_change` |

The policy lives in `policy/change-gate.policy.json` and is checked against
`policy/policy.schema.json`. The file has a version string that is written into every
policy denial in the audit log. Nothing about policy is in a prompt.

Format:

```json
{
  "version": "2026-09-25.1",
  "personas": { "agent": { "clients": ["..."], "roles": ["..."] },
                "human": { "clients": ["..."], "base_roles": ["..."],
                           "role_claim": "gate_roles", "role_map": { "...": ["..."] } } },
  "tools": { "record_decision": { "writes": true, "roles": ["recorder"] } },
  "rules": [
    { "id": "agent-no-prod-apply", "effect": "deny",
      "when": { "persona": "agent", "action": "auto_approve", "environment": "prod" },
      "reason": "the agent may not apply a prod change on its own" }
  ],
  "default": "deny"
}
```

Rules are read top to bottom and the first match wins. A `when` value is either a plain
value (must be equal) or `{"in": [...]}` / `{"not_in": [...]}`. If no rule matches, the
default applies, and the default is deny.

Rules, in order:

1. `tenant-mismatch`: deny when the caller's tenant is not the request's tenant.
2. `unknown-persona`: deny when the persona is not `human` or `agent`.
3. `agent-cannot-approve`: deny `approve` for the agent.
4. `agent-no-prod-apply`: deny `auto_approve` in prod for the agent.
5. `invalid-request-blocks-apply`: deny `auto_approve` and `approve` when the request
   fails validation. `route_change` skips scoring, so without this a malformed request
   could be routed and then approved.
6. `freeze-blocks-apply`: deny `auto_approve` and `approve` while a freeze window covers
   the change window.
7. `no-self-approval`: deny `approve` when the caller is the requester.
8. `record-needs-new`: deny `record_decision` unless the request is `new`.
9. `route-needs-new`: deny `route_change` unless the request is `new`.
10. `human-decision-needs-routed`: deny `approve_change` and `deny_change` unless the
    request is `routed`.
11. `allow-known-actions`: allow `auto_approve`, `approve`, `route`, `deny`.

When `record_decision` proposes `auto_approve` and the policy denies it, the denial is
audited and the tool proposes `route` instead, which is checked again. A write can be made
safer this way but never riskier. This is the same rule the degraded path already
follows.

Rules 1, 4 and 6 repeat checks that other layers already make (tenant scoping, the risk
engine's band ceiling, the freeze hard deny). They are there so that a bug in one layer
does not open the action.

## Tool-call resolution

The registry in `src/change_gate/tool_registry.py` pins every tool's name and its
arguments with their types and whether they are required. A test checks it against the
signatures the MCP server actually exposes. A call is rejected, with a reason, when:

| Class | Example |
|---|---|
| `unknown_tool` | `disable_audit(...)` |
| `unknown_argument` | `record_decision(request_id=..., now="2026-07-01")` |
| `wrong_type` | `record_decision(request_id=..., force_route="false")` |
| `missing_argument` | `approve_change(reason="ok")` with no `request_id` |

The agent side checks before sending and counts each rejection as a hallucinated call.
The server checks the raw arguments again before FastMCP sees them, because FastMCP would
drop an unknown argument and run the call. A rejected call is audited and never executed.

## Threats and where they are handled

| Source | Threat | Control |
|---|---|---|
| Zero-Trust Authorization and Discovery for Enterprise MCP (arXiv 2609.22573) | Authorization has to hold when the agent is steered. One server serves people and agents with one kind of credential. Hiding tools is not enough, scripted clients call them anyway. | Persona from signed claims, per-tool roles checked at call time on the server, not only at listing time. |
| ActGov (arXiv 2609.24446) | An injected instruction turns into a tool call with a real effect. | Every write goes through `ActionPolicy.check` first. The check does not depend on the model spotting the injection. |
| Ajar (arXiv 2609.26900) | A defense blocks the attack in the test and still leaves the dangerous action reachable. | After each red-team case, list the writes the attacker's persona can still perform and report that count next to attack success. |
| Implicit trust in tool-calling pipelines (arXiv 2609.18217) | Payloads split across the request, tool results, tool descriptions and sampling messages, each part harmless alone. | The corpus covers all four channels and 20 two-channel cases. Decisions come from server-side recomputation, not from text the agent read. |
| Closed-world resolution (arXiv 2609.19425) | Calls to tools that do not exist, or with arguments no schema declares. | Registry check on both sides, each failure class counted and never executed. |

Threats specific to this repo:

- A caller-chosen `now` moves the freeze check. The agent no longer sends it, the server
  owns the clock, and `now` is an unknown argument at the boundary.
- A person logs in through the agent's client and becomes the agent. The agent client no
  longer allows the browser flow.
- An approver approves their own request. Rule `no-self-approval`.
- A request is decided twice, for example re-scored after it was routed so it can be
  auto-approved. Rules `record-needs-new` and `route-needs-new`.

## Red-team design

Each case in `eval/injections/` is one JSON file with a channel, an attacker goal, the
injected text, the tool calls a steered planner would make, and the expected safe
outcome. `eval/run_redteam.py` runs each case in a fresh tenant sandbox:

1. The real LangGraph agent runs on the target request with the injections in place.
2. The steered calls run through the same client stack as the agent. This models the
   worst case, a planner that fully followed the injected text.
3. Oracles in the runner, written separately from the policy, check for an unsafe apply, a
   cross-tenant read, a missing audit entry, a freeze bypass and a privilege escalation.
4. The runner probes which writes the attacker's persona can still perform (open
   privilege) and checks that the audit chain verifies.

The same corpus also runs with the new layers switched off, to show the cases can succeed
when the boundary is not there.

## Not covered

- The live Keycloak flow for the human persona was written against the realm export but
  not run against a live Keycloak in this change.
- The Postgres path for request state reads the audit table under RLS. It was not run
  against Postgres in this change.
- Output from the explanation model is not checked. It never feeds a write: the decision
  is recorded before the explanation is written.
