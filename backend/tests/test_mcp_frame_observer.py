from __future__ import annotations

from app.mcp_frame_observer import McpFrameObserver, request_id_key


def _observer(*, max_pending_request_methods: int = 1024) -> McpFrameObserver:
    return McpFrameObserver(
        server_id="notes-mcp",
        session_id="observer-test-session",
        agent_id="observer-test-agent",
        max_pending_request_methods=max_pending_request_methods,
    )


def _tools_list_response(jsonrpc_id: int | str) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": jsonrpc_id,
        "result": {
            "tools": [
                {
                    "name": "list_notes",
                    "description": "Lists notes.",
                    "inputSchema": {"type": "object"},
                }
            ]
        },
    }


def test_request_id_keys_keep_numeric_and_string_ids_distinct() -> None:
    assert request_id_key(1) == ("int", 1)
    assert request_id_key("1") == ("str", "1")
    assert request_id_key(1) != request_id_key("1")


def test_observer_correlates_numeric_and_string_ids_without_collision() -> None:
    observer = _observer()

    observer.observe_client_frame({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    observer.observe_client_frame({"jsonrpc": "2.0", "id": "1", "method": "initialize", "params": {}})

    string_response = observer.observe_server_frame(_tools_list_response("1"))
    numeric_response = observer.observe_server_frame(_tools_list_response(1))

    assert string_response.method == "initialize"
    assert string_response.events == []
    assert numeric_response.method == "tools/list"
    assert len(numeric_response.events) == 1
    assert numeric_response.events[0].action_params["tool_name"] == "list_notes"


def test_notification_without_id_does_not_enter_pending_map() -> None:
    observer = _observer()

    observed = observer.observe_client_frame(
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
    )

    assert observed.method == "notifications/initialized"
    assert observed.events == []
    assert observer.pending_request_count == 0


def test_pending_request_method_cap_evicts_oldest_unmatched_request() -> None:
    observer = _observer(max_pending_request_methods=2)

    for request_id in range(3):
        observer.observe_client_frame({"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": {}})

    evicted_response = observer.observe_server_frame(_tools_list_response(0))
    retained_response = observer.observe_server_frame(_tools_list_response(2))

    assert evicted_response.method is None
    assert evicted_response.events == []
    assert retained_response.method == "tools/list"
    assert len(retained_response.events) == 1


def test_tools_list_response_normalizes_when_correlated_to_prior_request() -> None:
    observer = _observer()

    observer.observe_client_frame({"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}})
    observed = observer.observe_server_frame(_tools_list_response(7))

    assert observed.method == "tools/list"
    assert len(observed.events) == 1
    event = observed.events[0]
    assert event.source == "mcp"
    assert event.action_type == "tool_register"
    assert event.action_params["server_id"] == "notes-mcp"
    assert event.action_params["tool_name"] == "list_notes"


def test_tools_call_request_normalizes_directly() -> None:
    observer = _observer()

    observed = observer.observe_client_frame(
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {"name": "list_notes", "arguments": {"limit": 2}},
        }
    )

    assert observed.method == "tools/call"
    assert len(observed.events) == 1
    event = observed.events[0]
    assert event.source == "mcp"
    assert event.action_type == "tool_call"
    assert event.action_params["server_id"] == "notes-mcp"
    assert event.action_params["tool_name"] == "list_notes"
    assert event.action_params["arguments"] == {"limit": 2}


def test_unmatched_tools_list_response_does_not_create_event() -> None:
    observer = _observer()

    observed = observer.observe_server_frame(_tools_list_response(99))

    assert observed.method is None
    assert observed.events == []
