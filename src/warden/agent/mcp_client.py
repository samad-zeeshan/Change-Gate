"""MCP client for the agent: one streamable-HTTP session per tool call.

Transport errors map onto the resilience types so refusals are never retried.
"""


from __future__ import annotations

import json
from typing import Any

from .resilience import (
    DomainToolError,
    ToolMalformedResponse,
    ToolServerError,
    ToolTimeout,
)


def fetch_task_credential(mcp_url: str, idp_token: str, request_id: str,
                          timeout: float = 10.0) -> str:
    import httpx

    url = mcp_url.rstrip("/").removesuffix("/mcp") + "/credentials/task"
    resp = httpx.post(url, json={"request_id": request_id}, timeout=timeout,
                      headers={"Authorization": f"Bearer {idp_token}"})
    if resp.status_code != 200:
        raise DomainToolError(f"task credential refused ({resp.status_code}): {resp.text}")
    return resp.json()["access_token"]


class MCPToolClient:

    def __init__(self, base_url: str, access_token: str) -> None:
        self.base_url = base_url
        self.access_token = access_token

    def call(self, tool: str, **kwargs) -> dict:  # pragma: no cover - needs live server
        import anyio

        return anyio.from_thread.run(self._acall, tool, kwargs) if _in_worker_thread() \
            else anyio.run(self._acall, tool, kwargs)

    async def _acall(self, tool: str, kwargs: dict) -> dict:  # pragma: no cover
        import httpx
        from mcp import ClientSession
        from mcp.client.streamable_http import streamablehttp_client

        headers = {"Authorization": f"Bearer {self.access_token}"}
        try:
            try:
                async with streamablehttp_client(self.base_url, headers=headers) as (
                    read, write, _,
                ):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        result = await session.call_tool(tool, kwargs)
            except BaseExceptionGroup as group:
                # The transport runs in a task group, which wraps whatever is
                # raised inside it. Hand the one real error to the handlers below.
                raise _unwrap(group) from None
            # Parsed outside the transport context for the same reason: a
            # DomainToolError raised in there reaches the caller as a group.
            return _parse_result(result)
        except httpx.TimeoutException as exc:
            raise ToolTimeout(str(exc)) from exc
        except httpx.HTTPStatusError as exc:
            if 500 <= exc.response.status_code < 600:
                raise ToolServerError(str(exc)) from exc
            raise DomainToolError(str(exc)) from exc
        except (json.JSONDecodeError, ValueError) as exc:
            raise ToolMalformedResponse(str(exc)) from exc


def _in_worker_thread() -> bool:  # pragma: no cover
    import threading

    return threading.current_thread() is not threading.main_thread()


def _unwrap(exc: BaseException) -> BaseException:
    while isinstance(exc, BaseExceptionGroup) and len(exc.exceptions) == 1:
        exc = exc.exceptions[0]
    return exc


def _parse_result(result: Any) -> dict:
    # A tool the server refused (bad call, missing role, policy) comes back as
    # isError. That is a real answer, so it must not look like a transport
    # failure the resilience layer would retry.
    if getattr(result, "isError", False):
        texts = [getattr(b, "text", "") for b in getattr(result, "content", []) or []]
        raise DomainToolError(" ".join(t for t in texts if t) or "tool error")
    payload = getattr(result, "structuredContent", None)
    if not payload:
        payload = _payload_from_text(result)
    # A plain dict return carries a ToolError as data, not as isError.
    if isinstance(payload, dict) and payload.get("kind") == "tool_error":
        raise DomainToolError(str(payload.get("error", "tool error")))
    return payload


def _payload_from_text(result: Any) -> dict:
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            try:
                return json.loads(text)
            except json.JSONDecodeError as exc:
                raise ToolMalformedResponse(f"non-JSON tool result: {text[:80]}") from exc
    raise ToolMalformedResponse("empty tool result")
