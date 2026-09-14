"""Explainers that turn a recorded decision into plain words. None of them can change it."""

from __future__ import annotations

import os
from typing import Protocol


class Explainer(Protocol):
    def explain_risk(self, breakdown: dict, request: dict, decision: dict) -> str: ...
    def draft_routing_message(self, breakdown: dict, request: dict, decision: dict) -> str: ...


def _factor(breakdown: dict, name: str) -> dict:
    for f in breakdown.get("factors", []):
        if f["name"] == name:
            return f
    return {"normalized": 0.0, "raw": {}}


class DeterministicExplainer:

    def explain_risk(self, breakdown: dict, request: dict, decision: dict) -> str:
        br = _factor(breakdown, "blast_radius")
        rec = _factor(breakdown, "recency")
        parts = [
            f"Risk score {breakdown['score']} ({breakdown['band']} band).",
            f"Blast radius: {br['raw'].get('downstream_count', 0)} downstream service(s), "
            f"~{br['raw'].get('affected_traffic_fraction', 0):.0%} of traffic.",
            f"Environment '{request['environment']}' criticality weight "
            f"{_factor(breakdown, 'environment_criticality')['normalized']:.2f}.",
        ]
        if rec["raw"].get("recent_incident_count"):
            parts.append(
                f"Recency: {rec['raw']['recent_incident_count']} recent incident(s) on "
                f"this service within the lookback window."
            )
        if breakdown.get("hard_deny"):
            parts.append("HARD DENY: " + "; ".join(breakdown.get("hard_deny_reasons", [])))
        return " ".join(parts)

    def draft_routing_message(self, breakdown: dict, request: dict, decision: dict) -> str:
        return (
            f"[warden] {decision['decision'].upper()} — {request['key']} in "
            f"{request['environment']} (service {request['service_id']}). "
            f"Risk {breakdown['score']}/{breakdown['band']}. "
            f"Reason: {'; '.join(decision.get('reasons', []))}. "
            f"Requested by {request['requester']['id']} ({request['requester']['role']})."
        )


class _ModelExplainer:
    """Shared prompts. Subclasses supply one completion call and the fallback holds."""

    def __init__(self) -> None:
        self._fallback = DeterministicExplainer()

    def _call(self, system: str, user: str) -> str:
        raise NotImplementedError

    def _complete(self, system: str, user: str, fallback: str) -> str:
        try:
            return self._call(system, user).strip() or fallback
        except Exception:  # noqa: BLE001 - never let explanation failure break the workflow
            return fallback

    def explain_risk(self, breakdown: dict, request: dict, decision: dict) -> str:
        fallback = self._fallback.explain_risk(breakdown, request, decision)
        system = (
            "You explain a change-management risk assessment to an engineer. The score and "
            "band are FINAL and computed deterministically; never recompute or dispute them. "
            "Explain in 2-3 sentences why the score is what it is, citing the factors."
        )
        return self._complete(system, f"breakdown={breakdown}\nrequest={request}", fallback)

    def draft_routing_message(self, breakdown: dict, request: dict, decision: dict) -> str:
        fallback = self._fallback.draft_routing_message(breakdown, request, decision)
        system = (
            "Draft a concise routing message to an on-call change lead. Include the decision, "
            "key, environment, risk band/score and the reason. Do not alter any number."
        )
        return self._complete(system, f"breakdown={breakdown}\ndecision={decision}", fallback)


class AnthropicExplainer(_ModelExplainer):

    def __init__(self, model: str | None = None) -> None:
        import anthropic

        super().__init__()
        self._client = anthropic.Anthropic()
        self._model = model or os.getenv("WARDEN_LLM_MODEL", "claude-haiku-4-5-20251001")

    def _call(self, system: str, user: str) -> str:
        msg = self._client.messages.create(
            model=self._model, max_tokens=400, system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(block.text for block in msg.content if block.type == "text")


class LocalExplainer(_ModelExplainer):
    """A model behind an OpenAI-compatible endpoint, such as LM Studio."""

    def __init__(self, base_url: str = "http://127.0.0.1:1234/v1",
                 model: str = "qwen/qwen3.5-9b", timeout: float = 120.0) -> None:
        super().__init__()
        self._url = f"{base_url.rstrip('/')}/chat/completions"
        self._model = model
        self._timeout = timeout

    def _call(self, system: str, user: str) -> str:
        import httpx

        # reasoning_effort none: without it qwen3.5 spends the whole budget
        # thinking and returns an empty answer.
        resp = httpx.post(self._url, timeout=self._timeout, json={
            "model": self._model, "temperature": 0, "max_tokens": 300,
            "reasoning_effort": "none",
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}]})
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"] or ""


def get_explainer() -> Explainer:
    if os.getenv("WARDEN_USE_LLM") == "1" and os.getenv("ANTHROPIC_API_KEY"):
        try:
            return AnthropicExplainer()
        except Exception:  # noqa: BLE001
            return DeterministicExplainer()
    return DeterministicExplainer()
