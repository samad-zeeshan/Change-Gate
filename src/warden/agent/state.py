"""State carried between graph nodes and the dependencies each run needs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, TypedDict

from .llm import Explainer
from .resilience import ToolClient


class AgentState(TypedDict, total=False):
    request_id: str
    now: str
    request: Optional[dict]
    policy: Optional[dict]
    graph: Optional[dict]
    freeze: Optional[dict]
    recent: Optional[dict]
    validation: Optional[dict]
    risk: Optional[dict]
    decision: Optional[dict]
    explanation: str
    routing_message: str
    terminal_decision: Optional[str]
    degraded: bool
    failed: bool
    error: str
    notes: list


@dataclass
class AgentDeps:

    client: ToolClient
    explainer: Explainer
    degrade_on_failure: bool = True
    trace_id: str = ""
