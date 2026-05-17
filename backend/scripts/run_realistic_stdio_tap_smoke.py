from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Sequence

ROOT_DIR = Path(__file__).resolve().parents[1]
SESSION_ID = "stdio-realistic-smoke-001"
SERVER_ID = "fixture-notes-mcp"


def _client_requests() -> list[dict[str, object]]:
    return [
        {
            "jsonrpc": "2.0",
            "id": "init-1",
            "method": "initialize",
            "params": {"clientInfo": {"name": "aiwatch-smoke", "version": "0.1.0"}},
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
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "shutdown",
            "params": {},
        },
        {
            "jsonrpc": "2.0",
            "method": "exit",
            "params": {},
        },
    ]


def build_tap_command(
    *,
    backend_url: str,
    python_executable: str | None = None,
    root_dir: Path | None = None,
    log_raw_frames: bool = False,
) -> list[str]:
    resolved_root = root_dir or ROOT_DIR
    executable = python_executable or sys.executable
    tap_script = resolved_root / "scripts" / "aiwatch_stdio_tap.py"
    fixture_server_script = resolved_root / "scripts" / "realistic_mcp_fixture_server.py"

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

    command.extend(
        [
            "--",
            executable,
            str(fixture_server_script),
        ]
    )
    return command


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the realistic local MCP stdio smoke path through AIWatch.")
    parser.add_argument("--backend-url", default="http://127.0.0.1:7330")
    parser.add_argument("--log-raw-frames", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    tap_command = build_tap_command(
        backend_url=args.backend_url,
        log_raw_frames=args.log_raw_frames,
    )
    request_lines = "\n".join(json.dumps(frame) for frame in _client_requests()) + "\n"
    process = subprocess.Popen(
        tap_command,
        cwd=ROOT_DIR,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    stdout_data, stderr_data = process.communicate(input=request_lines, timeout=20)

    for line in stdout_data.splitlines():
        if line.strip():
            print(f"[client] {line}")

    if stderr_data:
        sys.stderr.write(stderr_data)
        if not stderr_data.endswith("\n"):
            sys.stderr.write("\n")
        sys.stderr.flush()

    print(
        "Realistic MCP stdio smoke completed with "
        f"{len([line for line in stdout_data.splitlines() if line.strip()])} responses."
    )
    return process.returncode


if __name__ == "__main__":
    raise SystemExit(main())
