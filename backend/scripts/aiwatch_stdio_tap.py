from __future__ import annotations

import argparse
from datetime import datetime
import json
import re
import subprocess
import sys
import threading
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Sequence

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.frame_log import DEFAULT_FRAME_LOG_PATH, append_frame_log, build_frame_log_entry
from app.credential_redaction import redact_json_like
from app.mcp_normalizer import normalize_tools_call_frame, normalize_tools_list_frame

DEFAULT_BACKEND_URL = "http://127.0.0.1:7330"
_SESSION_SERVER_ID_PATTERN = re.compile(r"[^A-Za-z0-9_-]+")


def _stderr(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _sanitize_session_component(value: str) -> str:
    sanitized = _SESSION_SERVER_ID_PATTERN.sub("-", value.strip()).strip("-")
    return sanitized or "server"


def _generate_session_id(server_id: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    suffix = uuid.uuid4().hex[:8]
    return f"stdio-{_sanitize_session_component(server_id)}-{timestamp}-{suffix}"


def _request_id_key(value: Any) -> tuple[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, str):
        return ("str", value)
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, int):
        return ("int", value)
    if isinstance(value, float):
        return ("float", value)
    return (type(value).__name__, repr(value))


def _parse_frame(raw_line: str, *, direction: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(raw_line)
    except json.JSONDecodeError:
        _stderr(f"[aiwatch] invalid {direction} JSON forwarded")
        return None

    if not isinstance(parsed, dict):
        _stderr(f"[aiwatch] non-object {direction} JSON forwarded")
        return None

    return parsed


def _post_event(backend_url: str, event_payload: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{backend_url}/v1/events",
        data=json.dumps(event_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def _ingest_tools_list(
    *,
    backend_url: str,
    frame: dict[str, Any],
    server_id: str,
    session_id: str,
    agent_id: str,
    request_method: str | None,
) -> tuple[int, int]:
    events = normalize_tools_list_frame(
        frame=frame,
        server_id=server_id,
        session_id=session_id,
        agent_id=agent_id,
        request_method=request_method,
    )
    if not events:
        return (0, 0)

    total_alerts = 0
    for event in events:
        response = _post_event(backend_url, event.model_dump(mode="json"))
        total_alerts += int(response.get("alerts_created", 0))

    return (len(events), total_alerts)


def _ingest_tools_call(
    *,
    backend_url: str,
    frame: dict[str, Any],
    server_id: str,
    session_id: str,
    agent_id: str,
) -> tuple[int, int]:
    events = normalize_tools_call_frame(
        frame=frame,
        server_id=server_id,
        session_id=session_id,
        agent_id=agent_id,
    )
    if not events:
        return (0, 0)

    total_alerts = 0
    for event in events:
        response = _post_event(backend_url, event.model_dump(mode="json"))
        total_alerts += int(response.get("alerts_created", 0))

    return (len(events), total_alerts)


def run_tap(
    *,
    server_argv: Sequence[str],
    server_id: str,
    session_id: str | None,
    agent_id: str,
    backend_url: str,
    log_path: Path,
    log_raw_frames: bool,
) -> int:
    resolved_session_id = session_id if session_id is not None else _generate_session_id(server_id)
    if session_id is None:
        _stderr(f"[aiwatch] generated session_id={resolved_session_id}")

    request_methods: dict[tuple[str, Any], str] = {}
    request_methods_lock = threading.Lock()
    backend_unavailable_logged = False
    server_reader_errors: list[BaseException] = []
    upstream_command = list(server_argv)

    upstream = subprocess.Popen(
        upstream_command,
        shell=False,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        encoding="utf-8",
        bufsize=1,
        cwd=ROOT_DIR,
    )

    if upstream.stdin is None or upstream.stdout is None:
        _stderr("[aiwatch] failed to open stdio pipes for upstream server")
        return 1

    def _server_reader() -> None:
        nonlocal backend_unavailable_logged
        try:
            while True:
                raw_server_line = upstream.stdout.readline()
                if raw_server_line == "":
                    break

                server_line = raw_server_line.rstrip("\r\n")
                parsed_server = _parse_frame(server_line, direction="server_to_client")
                response_method: str | None = None

                if parsed_server is not None:
                    response_id_key = _request_id_key(parsed_server.get("id"))
                    if response_id_key is not None:
                        with request_methods_lock:
                            response_method = request_methods.pop(response_id_key, None)

                    if log_raw_frames:
                        append_frame_log(
                            log_path,
                            build_frame_log_entry(
                                session_id=resolved_session_id,
                                server_id=server_id,
                                direction="server_to_client",
                                raw_line=server_line,
                                frame=redact_json_like(parsed_server),
                                method=response_method,
                            ),
                        )

                sys.stdout.write(server_line)
                sys.stdout.write("\n")
                sys.stdout.flush()

                if parsed_server is None:
                    continue

                try:
                    tool_count, alerts_created = _ingest_tools_list(
                        backend_url=backend_url,
                        frame=parsed_server,
                        server_id=server_id,
                        session_id=resolved_session_id,
                        agent_id=agent_id,
                        request_method=response_method,
                    )
                except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
                    if not backend_unavailable_logged:
                        _stderr("[aiwatch] backend unavailable; frames forwarded but not recorded")
                        backend_unavailable_logged = True
                else:
                    if tool_count > 0:
                        _stderr(f"[aiwatch] captured tools/list: {tool_count} tools, alerts={alerts_created}")
        except BaseException as error:
            server_reader_errors.append(error)

    server_reader = threading.Thread(target=_server_reader, name="aiwatch-stdio-server-reader")
    server_reader.start()

    try:
        for raw_client_line in sys.stdin:
            client_line = raw_client_line.rstrip("\r\n")
            if not client_line:
                continue

            parsed_client = _parse_frame(client_line, direction="client_to_server")
            client_method: str | None = None
            if parsed_client is not None:
                client_method = parsed_client.get("method") if isinstance(parsed_client.get("method"), str) else None
                client_id_key = _request_id_key(parsed_client.get("id"))
                if client_method is not None and client_id_key is not None:
                    with request_methods_lock:
                        request_methods[client_id_key] = client_method

            if log_raw_frames and parsed_client is not None:
                append_frame_log(
                    log_path,
                    build_frame_log_entry(
                        session_id=resolved_session_id,
                        server_id=server_id,
                        direction="client_to_server",
                        raw_line=client_line,
                        frame=redact_json_like(parsed_client),
                        method=client_method if isinstance(client_method, str) else None,
                    ),
                )

            upstream.stdin.write(client_line)
            upstream.stdin.write("\n")
            upstream.stdin.flush()

            if parsed_client is None:
                continue

            try:
                tool_call_count, alerts_created = _ingest_tools_call(
                    backend_url=backend_url,
                    frame=parsed_client,
                    server_id=server_id,
                    session_id=resolved_session_id,
                    agent_id=agent_id,
                )
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
                if not backend_unavailable_logged:
                    _stderr("[aiwatch] backend unavailable; frames forwarded but not recorded")
                    backend_unavailable_logged = True
            else:
                if tool_call_count > 0:
                    _stderr(f"[aiwatch] captured tools/call: {tool_call_count} calls, alerts={alerts_created}")
    finally:
        if upstream.stdin and not upstream.stdin.closed:
            upstream.stdin.close()
        upstream.wait(timeout=10)
        server_reader.join(timeout=10)

    if server_reader_errors:
        raise server_reader_errors[0]

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-id", required=True)
    parser.add_argument(
        "--session-id",
        help="Session id for captured events. If omitted, AIWatch generates one for this tap process.",
    )
    parser.add_argument("--agent-id", default="aiwatch-stdio-tap")
    parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL)
    parser.add_argument("--log-path", default=str(DEFAULT_FRAME_LOG_PATH))
    parser.add_argument(
        "--log-raw-frames",
        action="store_true",
        help="Write raw JSON-RPC frames to a local JSONL file for demo/debug use.",
    )
    parser.add_argument(
        "server_argv",
        nargs="+",
        help="Upstream MCP-like server argv. Use -- before the server command.",
    )
    return parser


def _normalized_server_argv(raw_server_argv: Sequence[str]) -> list[str]:
    server_argv = list(raw_server_argv)
    if server_argv and server_argv[0] == "--":
        server_argv = server_argv[1:]
    return server_argv


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    server_argv = _normalized_server_argv(args.server_argv)
    if not server_argv:
        parser.error("missing upstream server argv after --")

    return run_tap(
        server_argv=server_argv,
        server_id=args.server_id,
        session_id=args.session_id,
        agent_id=args.agent_id,
        backend_url=args.backend_url,
        log_path=Path(args.log_path),
        log_raw_frames=args.log_raw_frames,
    )


if __name__ == "__main__":
    raise SystemExit(main())
