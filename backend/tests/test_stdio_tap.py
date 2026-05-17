from __future__ import annotations

import io
import json
import queue
import re
import urllib.error
from pathlib import Path

import scripts.aiwatch_stdio_tap as tap_module
from app.frame_log import append_frame_log, build_frame_log_entry
from app.mcp_normalizer import normalize_tools_list_frame
from scripts.aiwatch_stdio_tap import build_parser as build_tap_parser, run_tap
from scripts.fake_mcp_server import SERVER_NAME, handle_frame
from scripts.realistic_mcp_fixture_server import (
    SERVER_NAME as REALISTIC_SERVER_NAME,
    handle_frame as handle_realistic_frame,
)
from scripts.run_realistic_stdio_tap_smoke import build_tap_command as build_realistic_smoke_command
from scripts.run_real_mcp_package_smoke import (
    DEFAULT_PACKAGE as REAL_PACKAGE_SMOKE_PACKAGE,
    SERVER_ID as REAL_PACKAGE_SMOKE_SERVER_ID,
    SESSION_ID as REAL_PACKAGE_SMOKE_SESSION_ID,
    build_tap_command as build_real_package_smoke_command,
)
from scripts.run_stdio_tap_demo import build_tap_command


class _ScriptedStdout:
    def __init__(self) -> None:
        self._lines: queue.Queue[str | None] = queue.Queue()

    def push_batch(self, frames: list[str]) -> None:
        for frame in frames:
            self._lines.put(f"{frame}\n")

    def close(self) -> None:
        self._lines.put(None)

    def readline(self) -> str:
        line = self._lines.get()
        return "" if line is None else line


class _RecordingStdin:
    def __init__(self, scripted_stdout: _ScriptedStdout, server_batches: list[list[str]]) -> None:
        self._scripted_stdout = scripted_stdout
        self._server_batches = list(server_batches)
        self._buffer = ""
        self.closed = False
        self.writes: list[str] = []

    def write(self, text: str) -> int:
        self.writes.append(text)
        self._buffer += text
        while "\n" in self._buffer:
            _, self._buffer = self._buffer.split("\n", 1)
            if self._server_batches:
                self._scripted_stdout.push_batch(self._server_batches.pop(0))
        return len(text)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        while self._server_batches:
            self._scripted_stdout.push_batch(self._server_batches.pop(0))
        self._scripted_stdout.close()


def _run_tap_with_scripted_server(
    monkeypatch,
    tmp_path: Path,
    *,
    client_lines: list[str],
    server_batches: list[list[str]],
    post_event=None,
    server_id: str = "fake-notes-mcp",
    session_id: str | None = "stdio-demo-001",
    log_raw_frames: bool = False,
) -> tuple[int, str, str, dict[str, object]]:
    captured: dict[str, object] = {}

    class FakePopen:
        def __init__(self, args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            scripted_stdout = _ScriptedStdout()
            self.stdin = _RecordingStdin(scripted_stdout, server_batches)
            self.stdout = scripted_stdout

        def wait(self, timeout=None):
            captured["wait_timeout"] = timeout
            return 0

    monkeypatch.setattr("scripts.aiwatch_stdio_tap.subprocess.Popen", FakePopen)
    if post_event is not None:
        monkeypatch.setattr("scripts.aiwatch_stdio_tap._post_event", post_event)

    monkeypatch.setattr("sys.stdin", io.StringIO("\n".join(client_lines) + "\n"))
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    monkeypatch.setattr("sys.stdout", stdout_buffer)
    monkeypatch.setattr("sys.stderr", stderr_buffer)

    result = run_tap(
        server_argv=["python-test", "fake_mcp_server.py"],
        server_id=server_id,
        session_id=session_id,
        agent_id="aiwatch-stdio-tap",
        backend_url="http://127.0.0.1:7330",
        log_path=tmp_path / "frames.jsonl",
        log_raw_frames=log_raw_frames,
    )
    return result, stdout_buffer.getvalue(), stderr_buffer.getvalue(), captured


def test_stdio_tap_posts_events_to_backend_events_route(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self) -> bytes:
            return b'{"status":"ok","alerts_created":0}'

    def fake_urlopen(request, timeout=None):
        captured["url"] = request.full_url
        captured["method"] = request.get_method()
        captured["body"] = request.data.decode("utf-8")
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(tap_module.urllib.request, "urlopen", fake_urlopen)

    response = tap_module._post_event(
        "http://127.0.0.1:7330",
        {
            "source": "mcp",
            "agent_id": "stdio-tap-test",
            "session_id": "stdio-tap-route-test",
            "action_type": "tool_call",
            "action_params": {"tool_name": "list_notes", "arguments": {}},
        },
    )

    assert response["status"] == "ok"
    assert captured["url"] == "http://127.0.0.1:7330/v1/events"
    assert captured["method"] == "POST"
    assert captured["timeout"] == 10
    assert json.loads(str(captured["body"]))["session_id"] == "stdio-tap-route-test"


def test_fake_server_initialize_response_contains_server_info() -> None:
    request = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}

    response = handle_frame(request)

    assert response is not None
    parsed = json.loads(json.dumps(response))
    assert parsed["result"]["serverInfo"]["name"] == SERVER_NAME


def test_fake_server_tools_list_response_contains_two_tools() -> None:
    request = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}

    response = handle_frame(request)

    assert response is not None
    parsed = json.loads(json.dumps(response))
    assert len(parsed["result"]["tools"]) == 2


def test_fake_tools_list_normalizes_into_two_tool_register_events() -> None:
    response = handle_frame({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    assert response is not None

    events = normalize_tools_list_frame(
        response,
        server_id="fake-notes-mcp",
        session_id="stdio-demo-001",
        agent_id="aiwatch-stdio-tap",
        request_method="tools/list",
    )

    assert len(events) == 2
    assert all(event.source == "mcp" for event in events)
    assert all(event.action_type == "tool_register" for event in events)
    assert all(event.action_params["server_id"] == "fake-notes-mcp" for event in events)
    tool_names = {str(event.action_params["tool_name"]) for event in events}
    assert {"list_notes", "export_notes"} == tool_names
    export_event = next(event for event in events if event.action_params["tool_name"] == "export_notes")
    assert "Before returning" in str(export_event.action_params["description"])


def test_frame_log_helper_writes_jsonl_entry(tmp_path: Path) -> None:
    log_path = tmp_path / "frames.jsonl"
    frame = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    raw_line = json.dumps(frame)
    entry = build_frame_log_entry(
        session_id="stdio-demo-001",
        server_id="fake-notes-mcp",
        direction="client_to_server",
        raw_line=raw_line,
        frame=frame,
    )

    append_frame_log(log_path, entry)

    written = log_path.read_text(encoding="utf-8").strip()
    parsed = json.loads(written)
    assert parsed["direction"] == "client_to_server"
    assert parsed["method"] == "tools/list"
    assert parsed["raw_hash"]
    assert parsed["frame"]["method"] == "tools/list"


def test_stdio_tap_parser_collects_server_argv_after_separator() -> None:
    parser = build_tap_parser()

    args = parser.parse_args(
        [
            "--server-id",
            "fake-notes-mcp",
            "--session-id",
            "stdio-demo-001",
            "--",
            "python-test",
            "fake_mcp_server.py",
        ]
    )

    assert args.server_id == "fake-notes-mcp"
    assert args.session_id == "stdio-demo-001"
    assert args.log_raw_frames is False
    assert args.server_argv == ["python-test", "fake_mcp_server.py"]


def test_stdio_tap_parser_allows_omitted_session_id() -> None:
    parser = build_tap_parser()

    args = parser.parse_args(
        [
            "--server-id",
            "fake-notes-mcp",
            "--",
            "python-test",
            "fake_mcp_server.py",
        ]
    )

    assert args.server_id == "fake-notes-mcp"
    assert args.session_id is None
    assert args.server_argv == ["python-test", "fake_mcp_server.py"]


def test_stdio_tap_launches_upstream_with_shell_false(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    class FakePopen:
        def __init__(self, args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            self.stdin = io.StringIO()
            self.stdout = io.StringIO("")

        def wait(self, timeout=None):
            captured["wait_timeout"] = timeout
            return 0

    monkeypatch.setattr("scripts.aiwatch_stdio_tap.subprocess.Popen", FakePopen)
    monkeypatch.setattr("sys.stdin", io.StringIO(""))

    result = run_tap(
        server_argv=["python-test", "fake_mcp_server.py"],
        server_id="fake-notes-mcp",
        session_id="stdio-demo-001",
        agent_id="aiwatch-stdio-tap",
        backend_url="http://127.0.0.1:7330",
        log_path=tmp_path / "frames.jsonl",
        log_raw_frames=False,
    )

    assert result == 0
    assert captured["args"] == ["python-test", "fake_mcp_server.py"]
    assert captured["kwargs"]["shell"] is False


def test_run_stdio_tap_demo_builds_absolute_shell_safe_command() -> None:
    command = build_tap_command(python_executable="python-test")

    assert command[0] == "python-test"
    assert Path(command[1]).is_absolute()
    assert command[2:6] == ["--server-id", "fake-notes-mcp", "--session-id", "stdio-demo-001"]
    assert "--log-raw-frames" in command
    assert "--" in command
    separator_index = command.index("--")
    assert command[separator_index + 1] == "python-test"
    assert Path(command[separator_index + 2]).is_absolute()


def test_tools_list_response_with_matching_id_normalizes_exactly_once(
    monkeypatch,
    tmp_path: Path,
) -> None:
    posted_events: list[dict[str, object]] = []

    def fake_post_event(_backend_url: str, event_payload: dict[str, object]) -> dict[str, object]:
        posted_events.append(event_payload)
        return {"alerts_created": 0}

    client_line = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    server_line = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
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
    )

    result, stdout_text, stderr_text, _ = _run_tap_with_scripted_server(
        monkeypatch,
        tmp_path,
        client_lines=[client_line],
        server_batches=[[server_line]],
        post_event=fake_post_event,
    )

    assert result == 0
    assert stdout_text.splitlines() == [server_line]
    assert len(posted_events) == 1
    assert posted_events[0]["session_id"] == "stdio-demo-001"
    assert posted_events[0]["action_params"]["tool_name"] == "list_notes"
    assert "[aiwatch] captured tools/list: 1 tools, alerts=0" in stderr_text
    assert "[aiwatch]" not in stdout_text


def test_tools_call_request_posts_redacted_tool_call_event(monkeypatch, tmp_path: Path) -> None:
    posted_events: list[dict[str, object]] = []

    def fake_post_event(_backend_url: str, event_payload: dict[str, object]) -> dict[str, object]:
        posted_events.append(event_payload)
        return {"alerts_created": 1}

    raw_secret = "sk-1234567890abcdefABCDEF1234567890"
    client_line = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "export_notes",
                "arguments": {"api_key": raw_secret, "format": "json"},
            },
        }
    )
    server_line = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "result": {"content": [{"type": "text", "text": "ok"}], "isError": False},
        }
    )

    result, stdout_text, stderr_text, _ = _run_tap_with_scripted_server(
        monkeypatch,
        tmp_path,
        client_lines=[client_line],
        server_batches=[[server_line]],
        post_event=fake_post_event,
    )

    assert result == 0
    assert stdout_text.splitlines() == [server_line]
    assert len(posted_events) == 1
    assert posted_events[0]["action_type"] == "tool_call"
    assert posted_events[0]["action_params"]["tool_name"] == "export_notes"
    assert posted_events[0]["action_params"]["arguments"]["api_key"] == "[REDACTED:OPENAI_KEY]"
    assert raw_secret not in json.dumps(posted_events[0])
    assert "[aiwatch] captured tools/call: 1 calls, alerts=1" in stderr_text
    assert raw_secret not in stdout_text
    assert raw_secret not in stderr_text


def test_tools_call_raw_frame_log_redacts_credential_values(monkeypatch, tmp_path: Path) -> None:
    def fake_post_event(_backend_url: str, _event_payload: dict[str, object]) -> dict[str, object]:
        return {"alerts_created": 1}

    raw_secret = "ghp_1234567890abcdefABCDEF1234567890abcdef"
    client_line = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "export_notes",
                "arguments": {"access_token": raw_secret},
            },
        }
    )
    server_line = json.dumps({"jsonrpc": "2.0", "id": 3, "result": {"isError": False}})

    result, _stdout_text, _stderr_text, _ = _run_tap_with_scripted_server(
        monkeypatch,
        tmp_path,
        client_lines=[client_line],
        server_batches=[[server_line]],
        post_event=fake_post_event,
        log_raw_frames=True,
    )

    assert result == 0
    log_text = (tmp_path / "frames.jsonl").read_text(encoding="utf-8")
    assert raw_secret not in log_text
    assert "[REDACTED:GITHUB_TOKEN]" in log_text


def test_server_to_client_raw_frame_log_redacts_echoed_credential_values(monkeypatch, tmp_path: Path) -> None:
    raw_secret = "sk-1234567890abcdefABCDEF1234567890"
    client_line = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "initialize", "params": {}})
    server_line = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": f"echoed credential {raw_secret}",
                    }
                ]
            },
        }
    )

    result, _stdout_text, _stderr_text, _ = _run_tap_with_scripted_server(
        monkeypatch,
        tmp_path,
        client_lines=[client_line],
        server_batches=[[server_line]],
        log_raw_frames=True,
    )

    assert result == 0
    log_text = (tmp_path / "frames.jsonl").read_text(encoding="utf-8")
    assert raw_secret not in log_text
    assert "[REDACTED:OPENAI_KEY]" in log_text


def test_omitted_session_id_generates_one_and_reuses_it_for_tap_process(
    monkeypatch,
    tmp_path: Path,
) -> None:
    posted_events: list[dict[str, object]] = []

    def fake_post_event(_backend_url: str, event_payload: dict[str, object]) -> dict[str, object]:
        posted_events.append(event_payload)
        return {"alerts_created": 0}

    client_line = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    server_line = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": [
                    {
                        "name": "list_notes",
                        "description": "Lists notes.",
                    },
                    {
                        "name": "export_notes",
                        "description": "Exports notes.",
                    },
                ]
            },
        }
    )

    result, stdout_text, stderr_text, _ = _run_tap_with_scripted_server(
        monkeypatch,
        tmp_path,
        client_lines=[client_line],
        server_batches=[[server_line]],
        post_event=fake_post_event,
        server_id="fixture notes/mcp",
        session_id=None,
    )

    assert result == 0
    assert stdout_text.splitlines() == [server_line]
    assert "[aiwatch]" not in stdout_text
    assert len(posted_events) == 2

    generated_session_ids = {str(event["session_id"]) for event in posted_events}
    assert len(generated_session_ids) == 1

    generated_session_id = next(iter(generated_session_ids))
    assert re.fullmatch(r"stdio-fixture-notes-mcp-\d{8}-\d{6}-[0-9a-f]{8}", generated_session_id)
    assert f"[aiwatch] generated session_id={generated_session_id}" in stderr_text


def test_non_tools_list_response_with_tools_array_does_not_normalize(
    monkeypatch,
    tmp_path: Path,
) -> None:
    posted_events: list[dict[str, object]] = []

    def fake_post_event(_backend_url: str, event_payload: dict[str, object]) -> dict[str, object]:
        posted_events.append(event_payload)
        return {"alerts_created": 0}

    client_line = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "initialize", "params": {}})
    server_line = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "result": {
                "tools": [
                    {
                        "name": "list_notes",
                        "description": "Lists notes.",
                    }
                ]
            },
        }
    )

    result, stdout_text, stderr_text, _ = _run_tap_with_scripted_server(
        monkeypatch,
        tmp_path,
        client_lines=[client_line],
        server_batches=[[server_line]],
        post_event=fake_post_event,
    )

    assert result == 0
    assert stdout_text.splitlines() == [server_line]
    assert posted_events == []
    assert "captured tools/list" not in stderr_text


def test_numeric_and_string_ids_correlate_without_collision(monkeypatch, tmp_path: Path) -> None:
    posted_events: list[dict[str, object]] = []

    def fake_post_event(_backend_url: str, event_payload: dict[str, object]) -> dict[str, object]:
        posted_events.append(event_payload)
        return {"alerts_created": 0}

    client_lines = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
        json.dumps({"jsonrpc": "2.0", "id": "1", "method": "initialize", "params": {}}),
    ]
    server_batches = [
        [],
        [
            json.dumps({"jsonrpc": "2.0", "id": "1", "result": {"serverInfo": {"name": "fake-notes-mcp"}}}),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "tools": [
                            {
                                "name": "list_notes",
                                "description": "Lists notes.",
                            }
                        ]
                    },
                }
            ),
        ],
    ]

    result, stdout_text, stderr_text, _ = _run_tap_with_scripted_server(
        monkeypatch,
        tmp_path,
        client_lines=client_lines,
        server_batches=server_batches,
        post_event=fake_post_event,
    )

    assert result == 0
    assert len(posted_events) == 1
    assert posted_events[0]["action_params"]["tool_name"] == "list_notes"
    assert "[aiwatch] captured tools/list: 1 tools, alerts=0" in stderr_text
    assert len(stdout_text.splitlines()) == 2


def test_notification_without_id_does_not_break_pending_request_correlation(
    monkeypatch,
    tmp_path: Path,
) -> None:
    posted_events: list[dict[str, object]] = []

    def fake_post_event(_backend_url: str, event_payload: dict[str, object]) -> dict[str, object]:
        posted_events.append(event_payload)
        return {"alerts_created": 0}

    client_line = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    notification_line = json.dumps({"jsonrpc": "2.0", "method": "progress", "params": {"step": "fetching"}})
    response_line = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": [
                    {
                        "name": "list_notes",
                        "description": "Lists notes.",
                    }
                ]
            },
        }
    )

    result, stdout_text, _stderr_text, _ = _run_tap_with_scripted_server(
        monkeypatch,
        tmp_path,
        client_lines=[client_line],
        server_batches=[[notification_line, response_line]],
        post_event=fake_post_event,
    )

    assert result == 0
    assert len(posted_events) == 1
    assert stdout_text.splitlines() == [notification_line, response_line]


def test_malformed_server_json_is_forwarded_and_does_not_crash(monkeypatch, tmp_path: Path) -> None:
    posted_events: list[dict[str, object]] = []

    def fake_post_event(_backend_url: str, event_payload: dict[str, object]) -> dict[str, object]:
        posted_events.append(event_payload)
        return {"alerts_created": 0}

    client_line = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    malformed_line = "not-json"
    response_line = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": [
                    {
                        "name": "list_notes",
                        "description": "Lists notes.",
                    }
                ]
            },
        }
    )

    result, stdout_text, stderr_text, _ = _run_tap_with_scripted_server(
        monkeypatch,
        tmp_path,
        client_lines=[client_line],
        server_batches=[[malformed_line, response_line]],
        post_event=fake_post_event,
    )

    assert result == 0
    assert stdout_text.splitlines() == [malformed_line, response_line]
    assert len(posted_events) == 1
    assert "[aiwatch] invalid server_to_client JSON forwarded" in stderr_text


def test_unmatched_response_with_tools_array_is_forwarded_without_normalizing(
    monkeypatch,
    tmp_path: Path,
) -> None:
    posted_events: list[dict[str, object]] = []

    def fake_post_event(_backend_url: str, event_payload: dict[str, object]) -> dict[str, object]:
        posted_events.append(event_payload)
        return {"alerts_created": 0}

    client_line = json.dumps({"jsonrpc": "2.0", "id": 9, "method": "initialize", "params": {}})
    response_line = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 999,
            "result": {
                "tools": [
                    {
                        "name": "list_notes",
                        "description": "Lists notes.",
                    }
                ]
            },
        }
    )

    result, stdout_text, stderr_text, _ = _run_tap_with_scripted_server(
        monkeypatch,
        tmp_path,
        client_lines=[client_line],
        server_batches=[[response_line]],
        post_event=fake_post_event,
    )

    assert result == 0
    assert stdout_text.splitlines() == [response_line]
    assert posted_events == []
    assert "captured tools/list" not in stderr_text


def test_backend_post_failure_does_not_stop_protocol_forwarding(monkeypatch, tmp_path: Path) -> None:
    def failing_post_event(_backend_url: str, _event_payload: dict[str, object]) -> dict[str, object]:
        raise urllib.error.URLError("backend down")

    client_lines = [
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        json.dumps({"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": {}}),
    ]
    server_batches = [
        [
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": {
                        "tools": [
                            {
                                "name": "list_notes",
                                "description": "Lists notes.",
                            }
                        ]
                    },
                }
            )
        ],
        [json.dumps({"jsonrpc": "2.0", "id": 3, "result": {"serverInfo": {"name": "fake-notes-mcp"}}})],
    ]

    result, stdout_text, stderr_text, _ = _run_tap_with_scripted_server(
        monkeypatch,
        tmp_path,
        client_lines=client_lines,
        server_batches=server_batches,
        post_event=failing_post_event,
    )

    assert result == 0
    assert len(stdout_text.splitlines()) == 2
    assert "[aiwatch] backend unavailable; frames forwarded but not recorded" in stderr_text


def test_realistic_fixture_supports_initialize_tools_list_and_tool_call() -> None:
    initialize_response = handle_realistic_frame({"jsonrpc": "2.0", "id": "init-1", "method": "initialize"})
    tools_list_response = handle_realistic_frame({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tool_call_response = handle_realistic_frame(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "list_notes", "arguments": {"limit": 2}},
        }
    )

    assert initialize_response is not None
    assert initialize_response["result"]["serverInfo"]["name"] == REALISTIC_SERVER_NAME
    assert tools_list_response is not None
    assert len(tools_list_response["result"]["tools"]) == 2
    poisoned_tool = next(tool for tool in tools_list_response["result"]["tools"] if tool["name"] == "export_notes_bundle")
    assert "Before returning" in poisoned_tool["description"]
    assert tool_call_response is not None
    assert tool_call_response["result"]["isError"] is False
    assert "Review MCP tool registry drift alerts." in tool_call_response["result"]["content"][0]["text"]


def test_run_realistic_stdio_tap_smoke_builds_backend_aware_command() -> None:
    command = build_realistic_smoke_command(
        backend_url="http://localhost:9000",
        python_executable="python-test",
        log_raw_frames=True,
    )

    assert command[0] == "python-test"
    assert Path(command[1]).is_absolute()
    assert command[2:6] == ["--server-id", "fixture-notes-mcp", "--session-id", "stdio-realistic-smoke-001"]
    assert "--backend-url" in command
    backend_index = command.index("--backend-url")
    assert command[backend_index + 1] == "http://localhost:9000"
    assert "--log-raw-frames" in command
    separator_index = command.index("--")
    assert command[separator_index + 1] == "python-test"
    assert Path(command[separator_index + 2]).name == "realistic_mcp_fixture_server.py"


def test_run_real_mcp_package_smoke_builds_shell_safe_npx_command() -> None:
    command = build_real_package_smoke_command(
        backend_url="http://localhost:9000",
        python_executable="python-test",
        npx_executable="npx-test",
        package=REAL_PACKAGE_SMOKE_PACKAGE,
        log_raw_frames=True,
    )

    assert command[0] == "python-test"
    assert Path(command[1]).is_absolute()
    assert command[2:6] == ["--server-id", REAL_PACKAGE_SMOKE_SERVER_ID, "--session-id", REAL_PACKAGE_SMOKE_SESSION_ID]
    assert "--backend-url" in command
    backend_index = command.index("--backend-url")
    assert command[backend_index + 1] == "http://localhost:9000"
    assert "--log-raw-frames" in command
    separator_index = command.index("--")
    assert command[separator_index + 1 :] == ["npx-test", "-y", REAL_PACKAGE_SMOKE_PACKAGE]


def test_claude_code_wrapper_example_json_is_valid_and_uses_argv_shape() -> None:
    example_path = Path(__file__).resolve().parents[2] / "docs" / "examples" / "claude-code-aiwatch-mcp.example.json"

    parsed = json.loads(example_path.read_text(encoding="utf-8"))

    server = parsed["mcpServers"]["aiwatch-fixture-notes"]
    assert server["type"] == "stdio"
    assert server["command"] == "py"
    assert isinstance(server["args"], list)
    assert "--" in server["args"]

    args = server["args"]
    separator_index = args.index("--")

    assert "--server-id" in args
    assert args[args.index("--server-id") + 1] == "fixture-notes-mcp"
    assert "--session-id" not in args
    assert "--backend-url" in args
    assert args[args.index("--backend-url") + 1] == "${AIWATCH_BACKEND_URL:-http://127.0.0.1:7330}"
    assert args[1].endswith("/backend/scripts/aiwatch_stdio_tap.py")
    assert args[separator_index + 1] == "py"
    assert args[separator_index + 2] == "-3.12"
    assert args[separator_index + 3].endswith("/backend/scripts/realistic_mcp_fixture_server.py")
