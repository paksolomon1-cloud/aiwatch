from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Sequence

ROOT_DIR = Path(__file__).resolve().parents[1]
SERVER_ID = "modelcontextprotocol-sequential-thinking"
SESSION_ID = "stdio-real-package-sequential-thinking-001"
DEFAULT_PACKAGE = "@modelcontextprotocol/server-sequential-thinking@2025.7.1"


def _client_requests() -> list[dict[str, object]]:
    return [
        {
            "jsonrpc": "2.0",
            "id": "init-1",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "aiwatch-real-package-smoke", "version": "0.1.0"},
            },
        },
        {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        },
        {
            "jsonrpc": "2.0",
            "id": "tools-list-1",
            "method": "tools/list",
            "params": {},
        },
    ]


def _default_npx_executable() -> str:
    return shutil.which("npx.cmd") or shutil.which("npx") or "npx"


def build_tap_command(
    *,
    backend_url: str,
    python_executable: str | None = None,
    npx_executable: str | None = None,
    package: str = DEFAULT_PACKAGE,
    root_dir: Path | None = None,
    log_raw_frames: bool = False,
) -> list[str]:
    resolved_root = root_dir or ROOT_DIR
    executable = python_executable or sys.executable
    tap_script = resolved_root / "scripts" / "aiwatch_stdio_tap.py"

    command = [
        executable,
        str(tap_script),
        "--server-id",
        SERVER_ID,
        "--session-id",
        SESSION_ID,
        "--backend-url",
        backend_url,
    ]
    if log_raw_frames:
        command.append("--log-raw-frames")

    command.extend(["--", npx_executable or _default_npx_executable(), "-y", package])
    return command


def _request_json(backend_url: str, path: str) -> Any:
    request = urllib.request.Request(
        f"{backend_url}{path}",
        headers={"Accept": "application/json"},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def _objects_for_server(items: object, server_id: str) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        return []
    return [
        item
        for item in items
        if isinstance(item, dict) and item.get("server_id") == server_id
    ]


def _alerts_for_session(items: object, session_id: str) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        return []
    return [
        item
        for item in items
        if isinstance(item, dict) and item.get("session_id") == session_id
    ]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a no-token real MCP package through the AIWatch stdio wrapper."
    )
    parser.add_argument("--backend-url", default="http://127.0.0.1:7330")
    parser.add_argument(
        "--package",
        default=DEFAULT_PACKAGE,
        help="MCP npm package spec to run behind the tap.",
    )
    parser.add_argument("--log-raw-frames", action="store_true")
    parser.add_argument("--timeout", type=float, default=45.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    tap_command = build_tap_command(
        backend_url=args.backend_url,
        package=args.package,
        log_raw_frames=args.log_raw_frames,
    )
    request_lines = "\n".join(json.dumps(frame) for frame in _client_requests()) + "\n"

    try:
        process = subprocess.Popen(
            tap_command,
            cwd=ROOT_DIR,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        stdout_data, stderr_data = process.communicate(input=request_lines, timeout=args.timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        sys.stderr.write("Real MCP package smoke timed out; killed wrapper process.\n")
        return 1

    for line in stdout_data.splitlines():
        if line.strip():
            print(f"[client] {line}")

    if stderr_data:
        sys.stderr.write(stderr_data)
        if not stderr_data.endswith("\n"):
            sys.stderr.write("\n")
        sys.stderr.flush()

    if process.returncode != 0:
        sys.stderr.write(f"Real MCP package smoke failed with exit code {process.returncode}.\n")
        return process.returncode

    try:
        tools = _request_json(args.backend_url, "/v1/tools")
        alerts = _request_json(args.backend_url, "/v1/alerts")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        sys.stderr.write(f"Real MCP package smoke could not verify backend state: {error}\n")
        return 1

    observed_tools = _objects_for_server(tools, SERVER_ID)
    if not observed_tools:
        sys.stderr.write(f"No tool registry rows found for server_id={SERVER_ID}.\n")
        return 1

    smoke_alerts = _alerts_for_session(alerts, SESSION_ID)
    if smoke_alerts:
        rule_ids = ", ".join(str(alert.get("rule_id", "")) for alert in smoke_alerts)
        sys.stderr.write(f"Unexpected alerts for {SESSION_ID}: {rule_ids}\n")
        return 1

    tool_names = ", ".join(sorted(str(tool.get("tool_name", "")) for tool in observed_tools))
    response_count = len([line for line in stdout_data.splitlines() if line.strip()])
    print(f"Real MCP package smoke completed with {response_count} protocol responses.")
    print(f"Observed tools for {SERVER_ID}: {tool_names}")
    print(f"Observed alerts for {SESSION_ID}: 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
