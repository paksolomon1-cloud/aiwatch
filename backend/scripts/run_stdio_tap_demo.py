from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.frame_log import DEFAULT_FRAME_LOG_PATH

SESSION_ID = "stdio-demo-001"
SERVER_ID = "fake-notes-mcp"


def _client_requests() -> list[dict[str, object]]:
    return [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]


def build_tap_command(
    *,
    python_executable: str | None = None,
    root_dir: Path | None = None,
) -> list[str]:
    resolved_root = root_dir or ROOT_DIR
    executable = python_executable or sys.executable
    tap_script = resolved_root / "scripts" / "aiwatch_stdio_tap.py"
    fake_server_script = resolved_root / "scripts" / "fake_mcp_server.py"
    return [
        executable,
        str(tap_script),
        "--server-id",
        SERVER_ID,
        "--session-id",
        SESSION_ID,
        "--log-raw-frames",
        "--",
        executable,
        str(fake_server_script),
    ]


def main() -> int:
    tap_command = build_tap_command()
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
        f"Stdio tap demo completed with {len([line for line in stdout_data.splitlines() if line.strip()])} "
        f"responses. Frame log: {DEFAULT_FRAME_LOG_PATH}"
    )
    return process.returncode


if __name__ == "__main__":
    raise SystemExit(main())
