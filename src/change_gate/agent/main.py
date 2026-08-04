
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime

from .. import telemetry
from ..clock import FixedClock, ensure_utc
from ..data import seed
from ..db.repository import InMemoryRepository
from ..security import (
    SCOPE_APPROVE,
    SCOPE_APPROVE_PROD,
    SCOPE_READ,
    AuthPrincipal,
)
from ..tools import ToolService
from .graph import run_task
from .llm import get_explainer
from .resilience import CallMetrics, ResilientToolClient
from .resolving_client import ResolvingToolClient
from .state import AgentDeps
from .tool_client import InProcessToolClient


def _build_deps(args) -> AgentDeps:
    explainer = get_explainer()
    if args.mcp_url:
        from .mcp_client import MCPToolClient

        token = os.environ.get("CHANGE_GATE_ACCESS_TOKEN", "")
        if not token:
            sys.exit("CHANGE_GATE_ACCESS_TOKEN is required with --mcp-url")
        inner = MCPToolClient(args.mcp_url, token)
    else:
        principal = AuthPrincipal(
            subject=f"agent-{args.tenant}",
            tenant_id=args.tenant,
            role="lead",
            scopes=frozenset({SCOPE_READ, SCOPE_APPROVE, SCOPE_APPROVE_PROD}),
        )
        repo = InMemoryRepository(args.tenant)
        # --now pins the in-process server clock, the same job CHANGE_GATE_NOW does
        # for the real server. The agent itself never sends a time.
        clock = FixedClock(ensure_utc(datetime.fromisoformat(args.now)))
        service = ToolService(repo, clock, principal=principal)
        inner = InProcessToolClient(service)

    # The resolver sits under the retry layer: a call that does not match the
    # registry is refused before it is sent, and a refusal is never retried.
    client = ResilientToolClient(
        ResolvingToolClient(inner), metrics=CallMetrics(), enabled=not args.no_resilience,
        sleep=__import__("time").sleep,
    )
    return AgentDeps(
        client=client,
        explainer=explainer,
        degrade_on_failure=not args.no_resilience,
        trace_id=f"cli-{args.request_id}",
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the change-approval agent on one request.")
    ap.add_argument("request_id", help="change request id, e.g. cr-002")
    ap.add_argument("--tenant", default="acme")
    ap.add_argument("--mcp-url", default=None, help="MCP server URL (uses OAuth token from env)")
    ap.add_argument("--now", default=seed.EVAL_NOW.isoformat(),
                    help="injected clock instant (ISO-8601)")
    ap.add_argument("--no-resilience", action="store_true", help="disable retries/degradation")
    args = ap.parse_args()

    telemetry.setup_telemetry("change-gate-agent")
    try:
        deps = _build_deps(args)
        final = run_task(args.request_id, args.now, deps)

        print("=" * 70)
        print(f"Request : {args.request_id}  (tenant={args.tenant})")
        if final.get("failed"):
            print(f"Outcome : FAILED — {final.get('error')}")
            sys.exit(2)
        print(f"Decision: {final['terminal_decision'].upper()}"
              + ("  [degraded → routed to human]" if final.get("degraded") else ""))
        risk = final.get("risk") or {}
        if risk:
            print(f"Risk    : {risk['score']} ({risk['band']})")
        print(f"Why     : {final.get('explanation', '')}")
        print(f"Routing : {final.get('routing_message', '')}")
        if final.get("decision", {}).get("audit"):
            print(f"Audit   : seq={final['decision']['audit']['seq']} "
                  f"hash={final['decision']['audit']['entry_hash'][:16]}…")
        print("=" * 70)
    finally:
        telemetry.shutdown()


if __name__ == "__main__":
    main()
