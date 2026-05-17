from __future__ import annotations

from app.mcp_normalizer import TOOLS_CALL_INTENT, TOOLS_LIST_INTENT, normalize_tools_call_frame, normalize_tools_list_frame


def test_tools_list_result_creates_tool_register_events() -> None:
    frame = {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "tools": [
                {
                    "name": "read_file",
                    "description": "Reads a file from disk.",
                    "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
                },
                {
                    "name": "list_files",
                    "description": "Lists directory contents.",
                    "inputSchema": {"type": "object"},
                    "outputSchema": {"type": "array", "items": {"type": "string"}},
                },
            ]
        },
    }

    events = normalize_tools_list_frame(
        frame,
        server_id="filesystem-mcp",
        session_id="tap-demo-001",
        agent_id="mcp-tap-demo",
        request_method="tools/list",
    )

    assert len(events) == 2
    assert events[0].intent_text == TOOLS_LIST_INTENT
    assert events[0].action_params["server_id"] == "filesystem-mcp"
    assert events[0].action_params["tool_name"] == "read_file"
    assert events[0].action_params["input_schema"] == {
        "type": "object",
        "properties": {"path": {"type": "string"}},
    }
    assert events[1].action_params["output_schema"] == {
        "type": "array",
        "items": {"type": "string"},
    }


def test_missing_description_becomes_empty_string() -> None:
    frame = {
        "jsonrpc": "2.0",
        "result": {
            "tools": [
                {
                    "name": "list_notes",
                    "inputSchema": {"type": "object"},
                }
            ]
        },
    }

    events = normalize_tools_list_frame(
        frame,
        server_id="notes-mcp",
        session_id="tap-demo-001",
        agent_id="mcp-tap-demo",
        request_method="tools/list",
    )

    assert len(events) == 1
    assert events[0].action_params["description"] == ""


def test_non_tools_frame_returns_empty_list() -> None:
    frame = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "serverInfo": {"name": "notes-mcp", "version": "1.0.0"},
        },
    }

    events = normalize_tools_list_frame(
        frame,
        server_id="notes-mcp",
        session_id="tap-demo-001",
        agent_id="mcp-tap-demo",
    )

    assert events == []


def test_non_tools_list_frame_with_tools_array_is_ignored() -> None:
    frame = {
        "jsonrpc": "2.0",
        "method": "resources/list",
        "result": {
            "tools": [
                {
                    "name": "list_notes",
                    "description": "Lists notes.",
                }
            ]
        },
    }

    events = normalize_tools_list_frame(
        frame,
        server_id="notes-mcp",
        session_id="tap-demo-003",
        agent_id="mcp-tap-demo",
    )

    assert events == []


def test_server_and_session_are_preserved_for_params_tools() -> None:
    frame = {
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {
            "tools": [
                {
                    "name": "list_notes",
                    "description": "Lists notes.",
                    "input_schema": {"type": "object"},
                }
            ]
        },
    }

    events = normalize_tools_list_frame(
        frame,
        server_id="notes-mcp",
        session_id="tap-demo-002",
        agent_id="agent-observer",
    )

    assert len(events) == 1
    assert events[0].session_id == "tap-demo-002"
    assert events[0].agent_id == "agent-observer"
    assert events[0].action_params["server_id"] == "notes-mcp"
    assert events[0].action_params["input_schema"] == {"type": "object"}


def test_tools_call_request_creates_redacted_tool_call_event() -> None:
    raw_secret = "sk-1234567890abcdefABCDEF1234567890"
    frame = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "export_notes",
            "arguments": {"api_key": raw_secret, "format": "json"},
        },
    }

    events = normalize_tools_call_frame(
        frame,
        server_id="notes-mcp",
        session_id="tap-demo-004",
        agent_id="agent-observer",
    )

    assert len(events) == 1
    assert events[0].intent_text == TOOLS_CALL_INTENT
    assert events[0].action_type == "tool_call"
    assert events[0].action_params["server_id"] == "notes-mcp"
    assert events[0].action_params["tool_name"] == "export_notes"
    assert events[0].action_params["arguments"]["api_key"] == "[REDACTED:OPENAI_KEY]"
    assert events[0].action_params["credential_findings"][0]["param_path"] == "params.arguments.api_key"
    assert events[0].raw is None


def test_non_tools_call_request_returns_empty_list() -> None:
    events = normalize_tools_call_frame(
        {"jsonrpc": "2.0", "id": 7, "method": "initialize", "params": {}},
        server_id="notes-mcp",
        session_id="tap-demo-005",
        agent_id="agent-observer",
    )

    assert events == []
