from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import time
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Sequence

ROOT_DIR = Path(__file__).resolve().parents[1]
SESSION_ID = "http-mcp-relay-smoke-001"
SERVER_ID = "fixture-http-notes-mcp"
EXPECTED_TOOLS = {"list_notes", "echo_note"}
EXPECTED_NOTE_TEXT = "Review the local MCP relay smoke."


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_port(port: int, *, timeout_seconds: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    raise RuntimeError(f"timed out waiting for 127.0.0.1:{port}")


def _request_json(url: str) -> Any:
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def _post_json(url: str, payload: dict[str, Any]) -> tuple[int, Any | None]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        body = response.read()
        if not body:
            return response.status, None
        return response.status, json.loads(body.decode("utf-8"))


def _terminate(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def _client_frames() -> list[dict[str, Any]]:
    return [
        {
            "jsonrpc": "2.0",
            "id": "init-1",
            "method": "initialize",
            "params": {"clientInfo": {"name": "aiwatch-http-relay-smoke", "version": "0.1.0"}},
        },
        {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        },
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "list_notes",
                "arguments": {"limit": 2},
            },
        },
    ]


def run_smoke(*, backend_url: str, python_executable: str | None = None) -> int:
    executable = python_executable or sys.executable
    session_id = f"{SESSION_ID}-{uuid.uuid4().hex[:8]}"
    fixture_port = _free_port()
    relay_port = _free_port()
    fixture_url = f"http://127.0.0.1:{fixture_port}/mcp"
    relay_url = f"http://127.0.0.1:{relay_port}/mcp"

    fixture_process = subprocess.Popen(
        [
            executable,
            str(ROOT_DIR / "scripts" / "http_mcp_fixture_server.py"),
            "--host",
            "127.0.0.1",
            "--port",
            str(fixture_port),
        ],
        cwd=ROOT_DIR,
        stdout=subprocess.DEVNULL,
        stderr=sys.stderr,
    )
    relay_process: subprocess.Popen[Any] | None = None
    try:
        _wait_for_port(fixture_port)
        relay_process = subprocess.Popen(
            [
                executable,
                str(ROOT_DIR / "scripts" / "aiwatch_http_mcp_relay.py"),
                "--listen-host",
                "127.0.0.1",
                "--listen-port",
                str(relay_port),
                "--relay-path",
                "/mcp",
                "--upstream-url",
                fixture_url,
                "--backend-url",
                backend_url,
                "--server-id",
                SERVER_ID,
                "--session-id",
                session_id,
            ],
            cwd=ROOT_DIR,
            stdout=subprocess.DEVNULL,
            stderr=sys.stderr,
        )
        _wait_for_port(relay_port)

        responses_by_method: dict[str, tuple[int, Any | None]] = {}
        for frame in _client_frames():
            status, response = _post_json(relay_url, frame)
            method = frame["method"]
            responses_by_method[method] = (status, response)
            print(f"[client] {method} -> HTTP {status}")
            if response is not None:
                print(f"[client] {json.dumps(response, sort_keys=True)}")

        tools_list_status, tools_list_response = responses_by_method["tools/list"]
        if tools_list_status != 200 or not isinstance(tools_list_response, dict):
            print("Expected successful MCP tools/list response from fixture through relay.", file=sys.stderr)
            return 1

        tools_call_status, tools_call_response = responses_by_method["tools/call"]
        if tools_call_status != 200 or not isinstance(tools_call_response, dict):
            print("Expected successful MCP tools/call response from fixture through relay.", file=sys.stderr)
            return 1

        result = tools_call_response.get("result")
        content = result.get("content") if isinstance(result, dict) else None
        content_text = "\n".join(
            item.get("text", "")
            for item in content
            if isinstance(item, dict) and isinstance(item.get("text"), str)
        ) if isinstance(content, list) else ""
        if EXPECTED_NOTE_TEXT not in content_text:
            print("Expected fixture MCP tool response text was not returned through the relay.", file=sys.stderr)
            print(json.dumps(tools_call_response, indent=2), file=sys.stderr)
            return 1

        expected_events_seen = False
        events: list[dict[str, Any]] = []
        smoke_events: list[dict[str, Any]] = []
        for _ in range(20):
            events = _request_json(f"{backend_url}/v1/events")
            smoke_events = [event for event in events if event.get("session_id") == session_id]
            observed_tool_names = {
                event.get("action_params", {}).get("tool_name")
                for event in smoke_events
                if event.get("action_type") == "tool_register"
                and event.get("action_params", {}).get("server_id") == SERVER_ID
            }
            observed_call = _observed_tool_call_event(smoke_events)
            if EXPECTED_TOOLS.issubset(observed_tool_names) and observed_call is not None:
                expected_events_seen = True
                break
            time.sleep(0.25)

        alerts = _request_json(f"{backend_url}/v1/alerts")
        smoke_alerts = [alert for alert in alerts if alert.get("session_id") == session_id]

        if not expected_events_seen:
            print(f"Expected fresh HTTP relay observation events not found for session {session_id}.", file=sys.stderr)
            print(json.dumps(smoke_events or events, indent=2), file=sys.stderr)
            return 1

        tool_call_event = _observed_tool_call_event(smoke_events)
        if tool_call_event is None:
            print(f"Expected tools/call observation not found for session {session_id}.", file=sys.stderr)
            print(json.dumps(smoke_events, indent=2), file=sys.stderr)
            return 1

        observation = _tool_call_observation_summary(tool_call_event)
        if observation["direction"] != "client_to_server" or observation["status"] != "success":
            print("Expected routed tools/call observation to record direction and success.", file=sys.stderr)
            print(json.dumps(tool_call_event, indent=2), file=sys.stderr)
            return 1
        if smoke_alerts:
            print("Unexpected alerts for benign HTTP MCP relay smoke:", file=sys.stderr)
            print(json.dumps(smoke_alerts, indent=2), file=sys.stderr)
            return 1

        print("HTTP MCP relay smoke upstream response: list_notes returned fixture notes")
        print(f"HTTP MCP relay smoke observed tools: {', '.join(sorted(EXPECTED_TOOLS))}")
        print("HTTP MCP relay smoke observed event:")
        print(json.dumps(observation, indent=2, sort_keys=True))
        print("HTTP MCP relay smoke observed alerts: 0")
        return 0
    finally:
        if relay_process is not None:
            _terminate(relay_process)
        _terminate(fixture_process)


def _observed_tool_call_event(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    for event in events:
        action_params = event.get("action_params")
        if (
            event.get("action_type") == "tool_call"
            and isinstance(action_params, dict)
            and action_params.get("server_id") == SERVER_ID
            and action_params.get("tool_name") == "list_notes"
        ):
            return event
    return None


def _tool_call_observation_summary(event: dict[str, Any]) -> dict[str, Any]:
    action_params = event.get("action_params")
    if not isinstance(action_params, dict):
        action_params = {}
    upstream = action_params.get("upstream")
    if not isinstance(upstream, dict):
        upstream = {}
    return {
        "session_id": event.get("session_id"),
        "timestamp": event.get("timestamp"),
        "action_type": event.get("action_type"),
        "server_id": action_params.get("server_id"),
        "tool_name": action_params.get("tool_name"),
        "direction": action_params.get("direction"),
        "status": action_params.get("status"),
        "upstream_contacted": upstream.get("contacted"),
        "upstream_http_status": upstream.get("http_status"),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the local POST JSON HTTP MCP relay smoke.")
    parser.add_argument("--backend-url", default="http://127.0.0.1:7330")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return run_smoke(backend_url=args.backend_url)


if __name__ == "__main__":
    raise SystemExit(main())
