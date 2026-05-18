from __future__ import annotations

import argparse
from datetime import datetime
import io
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
from app.enforcement import (
    annotate_enforcement_decision,
    evaluate_enforcement,
    resolve_enforcement_mode,
)
from app.mcp_frame_observer import DEFAULT_MAX_PENDING_REQUEST_METHODS, McpFrameObserver
from app.schemas import AgentEvent

DEFAULT_BACKEND_URL = "http://127.0.0.1:7330"
MAX_FRAME_BYTES = 1024 * 1024
MAX_PENDING_REQUEST_METHODS = DEFAULT_MAX_PENDING_REQUEST_METHODS
UPSTREAM_WAIT_TIMEOUT_SECONDS = 10
UPSTREAM_TERMINATE_TIMEOUT_SECONDS = 1
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


def _raw_line_size(raw_line: bytes | str) -> int:
    if isinstance(raw_line, bytes):
        return len(raw_line)
    return len(raw_line.encode("utf-8", errors="replace"))


def _ends_with_newline(raw_line: bytes | str) -> bool:
    if isinstance(raw_line, bytes):
        return raw_line.endswith((b"\n", b"\r"))
    return raw_line.endswith(("\n", "\r"))


def _read_frame_line(stream: Any) -> tuple[bytes | str, bool]:
    try:
        raw_line = stream.readline(MAX_FRAME_BYTES + 1)
    except TypeError:
        raw_line = stream.readline()

    if raw_line in ("", b""):
        return raw_line, False

    oversized = _raw_line_size(raw_line) > MAX_FRAME_BYTES
    return raw_line, oversized


def _drain_oversized_line(stream: Any, sink: Any) -> None:
    while True:
        try:
            chunk = stream.readline(MAX_FRAME_BYTES + 1)
        except TypeError:
            chunk = stream.readline()
        if chunk in ("", b""):
            break
        sink(chunk)
        if _ends_with_newline(chunk):
            break


def _write_stdout_raw(raw_line: bytes | str) -> None:
    sys.stdout.write(_decode_frame_line(raw_line))


def _write_upstream_raw(stdin: Any, raw_line: bytes | str) -> None:
    if isinstance(raw_line, bytes):
        try:
            stdin.write(raw_line)
        except TypeError:
            stdin.write(raw_line.decode("utf-8", errors="replace"))
        return

    _write_upstream_line(stdin, raw_line)


def _forward_oversized_server_line(stream: Any, raw_line: bytes | str) -> None:
    _write_stdout_raw(raw_line)
    if not _ends_with_newline(raw_line):
        _drain_oversized_line(stream, _write_stdout_raw)
    sys.stdout.flush()


def _forward_oversized_client_line(stream: Any, stdin: Any, raw_line: bytes | str) -> None:
    _write_upstream_raw(stdin, raw_line)
    if not _ends_with_newline(raw_line):
        _drain_oversized_line(stream, lambda chunk: _write_upstream_raw(stdin, chunk))
    stdin.flush()


def _decode_frame_line(raw_line: bytes | str) -> str:
    if isinstance(raw_line, bytes):
        return raw_line.decode("utf-8", errors="replace")
    return raw_line


def _encode_for_upstream(line: str) -> bytes:
    return line.encode("utf-8", errors="replace")


def _write_upstream_line(stdin: Any, line: str) -> None:
    if isinstance(stdin, io.TextIOBase):
        stdin.write(line)
        return
    try:
        stdin.write(_encode_for_upstream(line))
    except TypeError:
        stdin.write(line)


def _cleanup_upstream(upstream: subprocess.Popen[Any]) -> None:
    try:
        upstream.wait(timeout=UPSTREAM_WAIT_TIMEOUT_SECONDS)
        return
    except subprocess.TimeoutExpired:
        _stderr("[aiwatch] upstream did not exit after stdin close; terminating")

    upstream.terminate()
    try:
        upstream.wait(timeout=UPSTREAM_TERMINATE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        _stderr("[aiwatch] upstream did not terminate; killing")
        upstream.kill()
        upstream.wait(timeout=UPSTREAM_TERMINATE_TIMEOUT_SECONDS)


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


def _post_observed_events(*, backend_url: str, events: Sequence[AgentEvent]) -> tuple[int, int]:
    if not events:
        return (0, 0)

    total_alerts = 0
    for event in events:
        response = _post_event(backend_url, event.model_dump(mode="json"))
        total_alerts += int(response.get("alerts_created", 0))

    return (len(events), total_alerts)


def _mcp_denial_response(frame: dict[str, Any], decision: Any) -> str:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": frame.get("id"),
            "error": {
                "code": -32000,
                "message": f"AIWatch denied routed MCP tools/call: {decision.rule_id}.",
                "data": {
                    "enforcement_mode": decision.enforcement_mode,
                    "rule_id": decision.rule_id,
                    "reason": decision.reason,
                },
            },
        }
    )


def run_tap(
    *,
    server_argv: Sequence[str],
    server_id: str,
    session_id: str | None,
    agent_id: str,
    backend_url: str,
    log_path: Path,
    log_raw_frames: bool,
    enforcement_mode: str | None = None,
) -> int:
    resolved_session_id = session_id if session_id is not None else _generate_session_id(server_id)
    if session_id is None:
        _stderr(f"[aiwatch] generated session_id={resolved_session_id}")
    resolved_enforcement_mode = resolve_enforcement_mode(enforcement_mode)

    observer = McpFrameObserver(
        server_id=server_id,
        session_id=resolved_session_id,
        agent_id=agent_id,
        max_pending_request_methods=MAX_PENDING_REQUEST_METHODS,
    )
    backend_unavailable_logged = False
    server_reader_errors: list[BaseException] = []
    upstream_command = list(server_argv)

    upstream = subprocess.Popen(
        upstream_command,
        shell=False,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        bufsize=0,
        cwd=ROOT_DIR,
    )

    if upstream.stdin is None or upstream.stdout is None:
        _stderr("[aiwatch] failed to open stdio pipes for upstream server")
        return 1

    def _server_reader() -> None:
        nonlocal backend_unavailable_logged
        try:
            while True:
                raw_server_line, oversized_server_line = _read_frame_line(upstream.stdout)
                if raw_server_line in ("", b""):
                    break

                server_line = _decode_frame_line(raw_server_line).rstrip("\r\n")
                parsed_server = None
                if oversized_server_line:
                    _stderr("[aiwatch] oversized server_to_client frame forwarded without recording")
                    _forward_oversized_server_line(upstream.stdout, raw_server_line)
                    continue
                else:
                    parsed_server = _parse_frame(server_line, direction="server_to_client")
                response_method: str | None = None
                observed_server_events: Sequence[AgentEvent] = []

                if parsed_server is not None:
                    observed_server = observer.observe_server_frame(parsed_server)
                    response_method = observed_server.method
                    observed_server_events = observed_server.events

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
                    tool_count, alerts_created = _post_observed_events(
                        backend_url=backend_url,
                        events=observed_server_events,
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
        while True:
            raw_client_line, oversized_client_line = _read_frame_line(sys.stdin)
            if raw_client_line in ("", b""):
                break
            client_line = _decode_frame_line(raw_client_line).rstrip("\r\n")
            if not client_line:
                continue

            parsed_client = None
            if oversized_client_line:
                _stderr("[aiwatch] oversized client_to_server frame forwarded without recording")
                _forward_oversized_client_line(sys.stdin, upstream.stdin, raw_client_line)
                continue
            else:
                parsed_client = _parse_frame(client_line, direction="client_to_server")
            client_method: str | None = None
            observed_client_events: Sequence[AgentEvent] = []
            if parsed_client is not None:
                observed_client = observer.observe_client_frame(parsed_client)
                client_method = observed_client.method
                observed_client_events = observed_client.events

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

            enforcement_decision = evaluate_enforcement(
                observed_client_events,
                enforcement_mode=resolved_enforcement_mode,
            )
            if enforcement_decision.should_deny:
                observed_client_events = [
                    annotate_enforcement_decision(event, enforcement_decision)
                    for event in observed_client_events
                ]
                denial_line = _mcp_denial_response(parsed_client, enforcement_decision)
                sys.stdout.write(denial_line)
                sys.stdout.write("\n")
                sys.stdout.flush()
                try:
                    _post_observed_events(backend_url=backend_url, events=observed_client_events)
                except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
                    if not backend_unavailable_logged:
                        _stderr("[aiwatch] backend unavailable; denied frame not recorded")
                        backend_unavailable_logged = True
                _stderr(f"[aiwatch] denied tools/call rule={enforcement_decision.rule_id}")
                continue

            _write_upstream_line(upstream.stdin, f"{client_line}\n")
            upstream.stdin.flush()

            if parsed_client is None:
                continue

            try:
                tool_call_count, alerts_created = _post_observed_events(
                    backend_url=backend_url,
                    events=observed_client_events,
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
        _cleanup_upstream(upstream)
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
        "--enforcement-mode",
        choices=["observe", "deny"],
        help="Override AIWATCH_ENFORCEMENT_MODE for this wrapper process.",
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
        enforcement_mode=args.enforcement_mode,
    )


if __name__ == "__main__":
    raise SystemExit(main())
