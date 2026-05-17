from __future__ import annotations

from typing import Any

from app.credential_redaction import redact_mcp_tool_call_action_params
from app.schemas import ActionType, AgentEvent, Source

TOOLS_LIST_INTENT = "Observed MCP tools/list response."
TOOLS_CALL_INTENT = "Observed MCP tools/call request."


def _frame_method(frame: dict[str, Any]) -> str | None:
    method = frame.get("method")
    return method if isinstance(method, str) and method else None


def _extract_tools(frame: dict[str, Any], *, request_method: str | None = None) -> list[dict[str, Any]]:
    frame_method = _frame_method(frame)
    result = frame.get("result")
    if isinstance(result, dict) and (request_method == "tools/list" or frame_method == "tools/list"):
        tools = result.get("tools")
        if isinstance(tools, list):
            return [tool for tool in tools if isinstance(tool, dict)]

    params = frame.get("params")
    if isinstance(params, dict) and frame_method == "tools/list":
        tools = params.get("tools")
        if isinstance(tools, list):
            return [tool for tool in tools if isinstance(tool, dict)]

    return []


def _pick_schema(tool: dict[str, Any], camel_key: str, snake_key: str) -> dict[str, Any]:
    schema = tool.get(camel_key)
    if isinstance(schema, dict):
        return schema

    schema = tool.get(snake_key)
    if isinstance(schema, dict):
        return schema

    return {}


def normalize_tools_list_frame(
    frame: dict[str, Any],
    server_id: str,
    session_id: str,
    agent_id: str,
    request_method: str | None = None,
) -> list[AgentEvent]:
    tools = _extract_tools(frame, request_method=request_method)
    if not tools:
        return []

    events: list[AgentEvent] = []
    for tool in tools:
        tool_name = tool.get("name")
        if not isinstance(tool_name, str) or not tool_name.strip():
            continue

        description = tool.get("description")
        normalized_description = description if isinstance(description, str) else ""

        events.append(
            AgentEvent(
                source=Source.MCP,
                agent_id=agent_id,
                session_id=session_id,
                intent_text=TOOLS_LIST_INTENT,
                action_type=ActionType.TOOL_REGISTER,
                action_params={
                    "server_id": server_id,
                    "tool_name": tool_name,
                    "description": normalized_description,
                    "input_schema": _pick_schema(tool, "inputSchema", "input_schema"),
                    "output_schema": _pick_schema(tool, "outputSchema", "output_schema"),
                },
                raw=frame,
            )
        )

    return events


def normalize_tools_call_frame(
    frame: dict[str, Any],
    server_id: str,
    session_id: str,
    agent_id: str,
) -> list[AgentEvent]:
    if _frame_method(frame) != "tools/call":
        return []

    params = frame.get("params")
    if not isinstance(params, dict):
        return []

    tool_name = params.get("name")
    arguments = params.get("arguments")
    action_params: dict[str, Any] = {
        "server_id": server_id,
        "tool_name": tool_name if isinstance(tool_name, str) else "unknown",
        "arguments": arguments if isinstance(arguments, (dict, list)) else {},
    }
    sanitized_params, _ = redact_mcp_tool_call_action_params(action_params)

    return [
        AgentEvent(
            source=Source.MCP,
            agent_id=agent_id,
            session_id=session_id,
            intent_text=TOOLS_CALL_INTENT,
            action_type=ActionType.TOOL_CALL,
            action_params=sanitized_params,
            raw=None,
        )
    ]
