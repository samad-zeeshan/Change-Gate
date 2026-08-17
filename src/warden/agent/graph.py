"""
The LangGraph agent: fetch, validate, assess risk, decide, explain.

Any node can short-circuit to the fail sink, and a degraded run forces routing.
"""

from __future__ import annotations

from typing import Any

from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, START, StateGraph

from .. import telemetry
from .resilience import DomainToolError, ToolUnavailable
from .state import AgentDeps, AgentState


def _deps(config: RunnableConfig) -> AgentDeps:
    return config["configurable"]["deps"]


def _note(state: AgentState, msg: str) -> list:
    notes = list(state.get("notes", []))
    notes.append(msg)
    return notes


def node_fetch(state: AgentState, config: RunnableConfig) -> dict:
    deps = _deps(config)
    rid = state["request_id"]
    out: dict[str, Any] = {}
    # No call names the request. The task credential is bound to it, so the
    # server supplies it and injected text has no argument to redirect.
    with telemetry.span("agent.fetch", tool="fetch", request_id=rid) as sp:
        # The third field is "critical". Losing the request or the dependency
        # graph degrades the run (and later forces a route), but missing freeze or
        # recent-change data is only a warning since the assessment still holds.
        reads = {
            "request": ("get_change_request", {}, True),
            "policy": ("get_change_policy", {}, False),
            "graph": ("get_dependency_graph", {}, True),
            "freeze": ("get_freeze_windows", {}, False),
            "recent": ("get_recent_changes", {}, False),
        }
        degraded = bool(state.get("degraded"))
        notes = list(state.get("notes", []))
        for key, (tool, kwargs, critical) in reads.items():
            try:
                out[key] = deps.client.call(tool, **kwargs)
            except ToolUnavailable as exc:
                out[key] = None
                if deps.degrade_on_failure:
                    if critical:
                        degraded = True
                        notes.append(f"degraded: {tool} unavailable ({exc.last_error})")
                    else:
                        notes.append(f"warn: {tool} unavailable, continuing")
                else:
                    sp.set("outcome", "failed")
                    return {**out, "failed": True,
                            "error": f"{tool} unavailable", "notes": notes}
            except DomainToolError as exc:
                sp.set("outcome", "failed")
                return {**out, "failed": True, "error": str(exc),
                        "notes": _note(state, f"domain error in {tool}: {exc}")}
        sp.set("outcome", "degraded" if degraded else "ok")
        out["degraded"] = degraded
        out["notes"] = notes
    return out


def node_validate(state: AgentState, config: RunnableConfig) -> dict:
    deps = _deps(config)
    rid = state["request_id"]
    with telemetry.span("agent.validate", tool="validate_change_request", request_id=rid) as sp:
        try:
            validation = deps.client.call("validate_change_request")
            sp.set("outcome", "ok")
            return {"validation": validation}
        except ToolUnavailable as exc:
            if deps.degrade_on_failure:
                sp.set("outcome", "degraded")
                return {"degraded": True,
                        "notes": _note(state, f"degraded: validate unavailable ({exc.last_error})")}
            sp.set("outcome", "failed")
            return {"failed": True, "error": "validate unavailable"}
        except DomainToolError as exc:
            return {"failed": True, "error": str(exc)}


def node_risk(state: AgentState, config: RunnableConfig) -> dict:
    deps = _deps(config)
    rid = state["request_id"]
    with telemetry.span("agent.risk", tool="assess_change_risk", request_id=rid) as sp:
        try:
            # No now= here. The server owns the clock, so a caller cannot move the
            # freeze check by picking its own instant.
            risk = deps.client.call("assess_change_risk")
            sp.set("risk.band", risk.get("band"))
            sp.set("outcome", "ok")
            return {"risk": risk}
        except ToolUnavailable as exc:
            if deps.degrade_on_failure:
                sp.set("outcome", "degraded")
                return {"degraded": True,
                        "notes": _note(state, f"degraded: risk unavailable ({exc.last_error})")}
            sp.set("outcome", "failed")
            return {"failed": True, "error": "risk unavailable"}
        except DomainToolError as exc:
            return {"failed": True, "error": str(exc)}


def node_decide(state: AgentState, config: RunnableConfig) -> dict:
    deps = _deps(config)
    rid = state["request_id"]
    degraded = bool(state.get("degraded"))
    with telemetry.span("agent.decide", tool="record_decision", request_id=rid,
                        degraded=degraded) as sp:
        try:
            # force_route carries the degraded flag downstream. If we ran on
            # incomplete context, an auto-approve gets bumped to a human route
            # instead of silently shipping on partial data.
            result = deps.client.call(
                "record_decision",
                trace_id=deps.trace_id,
                force_route=degraded,
            )
            sp.set("decision", result.get("decision"))
            sp.set("outcome", "ok")
            return {"decision": result, "terminal_decision": result["decision"]}
        except ToolUnavailable as exc:
            sp.set("outcome", "failed")
            return {"failed": True,
                    "error": f"record_decision unavailable ({exc.last_error})"}
        except DomainToolError as exc:
            return {"failed": True, "error": str(exc)}


def node_explain(state: AgentState, config: RunnableConfig) -> dict:
    deps = _deps(config)
    risk = state.get("risk")
    decision = state.get("decision")
    request = state.get("request")
    if not (risk and decision and request):
        return {}
    with telemetry.span("agent.explain", tool="llm"):
        explanation = deps.explainer.explain_risk(risk, request, decision)
        routing = deps.explainer.draft_routing_message(risk, request, decision)
    return {"explanation": explanation, "routing_message": routing}


def node_fail(state: AgentState, config: RunnableConfig) -> dict:
    return {"terminal_decision": None}


def _route_after(state: AgentState) -> str:
    return "fail" if state.get("failed") else "continue"


def build_agent():
    g = StateGraph(AgentState)
    g.add_node("fetch", node_fetch)
    g.add_node("validate", node_validate)
    g.add_node("assess", node_risk)
    g.add_node("decide", node_decide)
    g.add_node("explain", node_explain)
    g.add_node("fail", node_fail)

    g.add_edge(START, "fetch")
    for src, dst in [("fetch", "validate"), ("validate", "assess"), ("assess", "decide")]:
        g.add_conditional_edges(src, _route_after, {"continue": dst, "fail": "fail"})
    g.add_conditional_edges("decide", _route_after, {"continue": "explain", "fail": "fail"})
    g.add_edge("explain", END)
    g.add_edge("fail", END)
    return g.compile()


_COMPILED = None


def run_task(request_id: str, now: str, deps: AgentDeps) -> AgentState:
    global _COMPILED
    if _COMPILED is None:
        _COMPILED = build_agent()
    initial: AgentState = {"request_id": request_id, "now": now, "notes": []}
    with telemetry.span("agent.run", request_id=request_id, trace_id=deps.trace_id):
        final = _COMPILED.invoke(initial, config={"configurable": {"deps": deps}})
    return final
