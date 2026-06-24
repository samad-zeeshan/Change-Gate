
from __future__ import annotations

import json
from typing import Any

from .resilience import (
    DomainToolError,
    ToolMalformedResponse,
    ToolServerError,
    ToolTimeout,
)


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
            async with streamablehttp_client(self.base_url, headers=headers) as (
                read, write, _,
            ):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool(tool, kwargs)
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


def _parse_result(result: Any) -> dict:  # pragma: no cover
    structured = getattr(result, "structuredContent", None)
    if structured:
        return structured
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            try:
                return json.loads(text)
            except json.JSONDecodeError as exc:
                raise ToolMalformedResponse(f"non-JSON tool result: {text[:80]}") from exc
    raise ToolMalformedResponse("empty tool result")
