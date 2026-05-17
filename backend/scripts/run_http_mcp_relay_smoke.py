from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Sequence

ROOT_DIR = Path(__file__).resolve().parents[1]
SESSION_ID = "http-mcp-relay-smoke-001"
SERVER_ID = "fixture-http-notes-mcp"
EXPECTED_TOOLS = {"list_notes", "echo_note"}


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
                SESSION_ID,
            ],
            cwd=ROOT_DIR,
            stdout=subprocess.DEVNULL,
            stderr=sys.stderr,
        )
        _wait_for_port(relay_port)

        for frame in _client_frames():
            status, response = _post_json(relay_url, frame)
            method = frame["method"]
            print(f"[client] {method} -> HTTP {status}")
            if response is not None:
                print(f"[client] {json.dumps(response, sort_keys=True)}")

        expected_tools_seen = False
        tools: list[dict[str, Any]] = []
        for _ in range(20):
            tools = _request_json(f"{backend_url}/v1/tools")
            observed_tool_names = {
                item.get("tool_name")
                for item in tools
                if item.get("server_id") == SERVER_ID
            }
            if EXPECTED_TOOLS.issubset(observed_tool_names):
                expected_tools_seen = True
                break
            time.sleep(0.25)

        alerts = _request_json(f"{backend_url}/v1/alerts")
        smoke_alerts = [alert for alert in alerts if alert.get("session_id") == SESSION_ID]

        if not expected_tools_seen:
            print(f"Expected HTTP fixture tools not found for {SERVER_ID}.", file=sys.stderr)
            print(json.dumps(tools, indent=2), file=sys.stderr)
            return 1
        if smoke_alerts:
            print("Unexpected alerts for benign HTTP MCP relay smoke:", file=sys.stderr)
            print(json.dumps(smoke_alerts, indent=2), file=sys.stderr)
            return 1

        print(f"HTTP MCP relay smoke observed tools: {', '.join(sorted(EXPECTED_TOOLS))}")
        print("HTTP MCP relay smoke observed alerts: 0")
        return 0
    finally:
        if relay_process is not None:
            _terminate(relay_process)
        _terminate(fixture_process)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the local POST JSON HTTP MCP relay smoke.")
    parser.add_argument("--backend-url", default="http://127.0.0.1:7330")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return run_smoke(backend_url=args.backend_url)


if __name__ == "__main__":
    raise SystemExit(main())
