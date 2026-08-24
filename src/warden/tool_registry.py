"""
The pinned tool registry and closed-world resolution of tool calls.

A call to a tool that is not here, or with an argument, type or omission the
signature does not allow, is rejected before anything runs. The server builds its
MCP tool descriptions from this file, and a test checks the advertised schemas
against it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

REJECT_KINDS = ("unknown_tool", "unknown_argument", "wrong_type", "missing_argument")

# Arguments that pick which tenant or which request a call acts on. None of the
# tools below take one. The server reads both from the task credential.
RESOURCE_ARGS = ("tenant_id", "request_id")


@dataclass(frozen=True)
class Param:
    name: str
    type: str
    required: bool = False


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    params: tuple[Param, ...] = ()
    writes: bool = False
    request_scoped: bool = False

    def param(self, name: str) -> Param | None:
        for p in self.params:
            if p.name == name:
                return p
        return None


_HUMAN_SIDE = (Param("reason", "string"), Param("trace_id", "string"))

REGISTRY: dict[str, ToolSpec] = {
    spec.name: spec
    for spec in (
        ToolSpec("get_change_request", "Read the change request this task is bound to.",
                 request_scoped=True),
        ToolSpec("get_change_policy", "Read the tenant's risk policy."),
        ToolSpec("get_config_state", "Read the current value of the key the request changes.",
                 request_scoped=True),
        ToolSpec("get_dependency_graph", "Read the tenant's service dependency graph."),
        ToolSpec("get_freeze_windows", "Read the tenant's change freeze windows."),
        ToolSpec("get_recent_changes", "Read recent changes and incidents."),
        ToolSpec("validate_change_request",
                 "Check the request's shape and the requester's authority.",
                 request_scoped=True),
        ToolSpec("assess_change_risk", "Score the request with the deterministic risk engine.",
                 request_scoped=True),
        ToolSpec("record_decision",
                 "Run the gate on the new request and record auto-approve, route or deny.",
                 (Param("explanation", "string"), Param("force_route", "boolean"),
                  Param("trace_id", "string")),
                 writes=True, request_scoped=True),
        ToolSpec("route_change", "Send the new request to a person without scoring it.",
                 _HUMAN_SIDE, writes=True, request_scoped=True),
        ToolSpec("approve_change", "Human approval of the routed request. Applies the change.",
                 _HUMAN_SIDE, writes=True, request_scoped=True),
        ToolSpec("deny_change", "Human denial of the routed request.", _HUMAN_SIDE,
                 writes=True, request_scoped=True),
        ToolSpec("list_roles", "List the roles this credential may learn and what each holds."),
        ToolSpec("learn_role", "Learn one role and receive its tools for this task.",
                 (Param("role", "string", True),)),
    )
}


def _with_ids(spec: ToolSpec) -> ToolSpec:
    ids = [Param("tenant_id", "string", True)]
    if spec.request_scoped:
        ids.append(Param("request_id", "string", True))
    return ToolSpec(spec.name, spec.description, tuple(ids) + spec.params, spec.writes,
                    spec.request_scoped)


# The v1 shape with the tenant added as a validated argument. It exists so the
# ablation can measure the pattern the request binding replaces.
PARAMETER_REGISTRY: dict[str, ToolSpec] = {n: _with_ids(s) for n, s in REGISTRY.items()}


def registry_for(binding: str) -> dict[str, ToolSpec]:
    return PARAMETER_REGISTRY if binding == "parameter" else REGISTRY


class RejectedCall(Exception):

    def __init__(self, kind: str, tool: str, detail: str, names: tuple[str, ...] = ()) -> None:
        super().__init__(f"hallucinated call rejected ({kind}): {tool}: {detail}")
        self.kind = kind
        self.tool = tool
        self.detail = detail
        self.names = names

    @property
    def names_a_resource(self) -> bool:
        # Every unknown argument tries to pick a tenant or request. Under request
        # binding no signature can express that, which is a different finding
        # from a model inventing a tool or a flag.
        resource_like = set(RESOURCE_ARGS) | {"tenant"}
        return self.kind == "unknown_argument" and bool(self.names) and \
            set(self.names) <= resource_like


def _type_ok(expected: str, value: object) -> bool:
    # bool is a subclass of int in Python, and "false" is a truthy string. Both
    # are exactly the loose values a model produces, so neither passes here.
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    return False


def resolve_call(
    tool: str, args: object, registry: Mapping[str, ToolSpec] = REGISTRY
) -> ToolSpec:
    spec = registry.get(tool) if isinstance(tool, str) else None
    if spec is None:
        raise RejectedCall("unknown_tool", str(tool), "no such tool in the registry")
    if not isinstance(args, Mapping):
        raise RejectedCall("wrong_type", tool, "arguments must be an object")

    unknown = sorted(k for k in args if spec.param(k) is None)
    if unknown:
        raise RejectedCall("unknown_argument", tool, f"does not take {unknown}", tuple(unknown))
    missing = sorted(p.name for p in spec.params if p.required and p.name not in args)
    if missing:
        raise RejectedCall("missing_argument", tool, f"requires {missing}")
    for name, value in args.items():
        p = spec.param(name)
        if not _type_ok(p.type, value):
            raise RejectedCall("wrong_type", tool,
                               f"{name} must be {p.type}, got {type(value).__name__}")
    return spec


def diff_advertised(
    advertised: Mapping[str, dict], registry: Mapping[str, ToolSpec] = REGISTRY
) -> list[str]:
    # Compare a server's tools/list answer with the pinned registry. A change in
    # a description is reported too: descriptions are text the model reads, so a
    # server that rewrites one is a channel for injected instructions.
    drift: list[str] = []
    for name in sorted(set(advertised) - set(registry)):
        drift.append(f"{name}: advertised but not in the registry")
    for name in sorted(set(registry) - set(advertised)):
        drift.append(f"{name}: in the registry but not advertised")
    for name in sorted(set(advertised) & set(registry)):
        spec = registry[name]
        tool = advertised[name]
        if (tool.get("description") or "") != spec.description:
            drift.append(f"{name}: description differs from the pinned text")
        props = (tool.get("inputSchema") or {}).get("properties", {})
        extra = sorted(set(props) - {p.name for p in spec.params})
        gone = sorted({p.name for p in spec.params} - set(props))
        if extra:
            drift.append(f"{name}: advertises unknown arguments {extra}")
        if gone:
            drift.append(f"{name}: no longer advertises {gone}")
    return drift
