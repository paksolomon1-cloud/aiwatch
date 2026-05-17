from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Iterator

import pytest

from scripts import aiwatch_http_mcp_relay as relay_module


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextmanager
def _running_server(server: ThreadingHTTPServer) -> Iterator[ThreadingHTTPServer]:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _wait_for(predicate: Callable[[], bool], *, timeout_seconds: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("timed out waiting for condition")


def _post(url: str, body: bytes, headers: dict[str, str] | None = None) -> tuple[int, bytes, dict[str, str]]:
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read(), dict(response.headers.items())
    except urllib.error.HTTPError as error:
        return error.code, error.read(), dict(error.headers.items())


def _get(url: str) -> tuple[int, bytes]:
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload).encode("utf-8")


@contextmanager
def _backend_server() -> Iterator[tuple[str, list[dict[str, Any]]]]:
    events: list[dict[str, Any]] = []

    class BackendHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:
            if self.path != "/v1/events":
                self._send_json(404, {"detail": "Not found"})
                return
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            events.append(json.loads(body))
            self._send_json({"status": "ok", "alerts_created": 0, "alerts": []})

        def log_message(self, _format: str, *_args: Any) -> None:
            return None

        def _send_json(self, payload_or_status: int | dict[str, Any], payload: dict[str, Any] | None = None) -> None:
            if isinstance(payload_or_status, int):
                status = payload_or_status
                resolved_payload = payload or {}
            else:
                status = 200
                resolved_payload = payload_or_status
            response_body = json.dumps(resolved_payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(response_body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), BackendHandler)
    with _running_server(server):
        yield f"http://127.0.0.1:{server.server_port}", events


@contextmanager
def _upstream_server(
    response_fn: Callable[[dict[str, Any], BaseHTTPRequestHandler], tuple[int, dict[str, str], bytes]],
) -> Iterator[tuple[str, list[dict[str, Any]]]]:
    calls: list[dict[str, Any]] = []

    class UpstreamHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            frame = json.loads(body)
            calls.append(
                {
                    "path": self.path,
                    "headers": dict(self.headers.items()),
                    "body": body,
                    "frame": frame,
                }
            )
            status, headers, response_body = response_fn(frame, self)
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(response_body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(response_body)

        def log_message(self, _format: str, *_args: Any) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    with _running_server(server):
        yield f"http://127.0.0.1:{server.server_port}/mcp", calls


@contextmanager
def _relay_server(
    *,
    upstream_url: str,
    backend_url: str = "http://127.0.0.1:9",
    stderr: io.StringIO | None = None,
    max_request_body_bytes: int = relay_module.MAX_RELAY_REQUEST_BODY_BYTES,
    max_response_body_bytes: int = relay_module.MAX_UPSTREAM_RESPONSE_BODY_BYTES,
    max_response_forward_bytes: int = relay_module.MAX_UPSTREAM_RESPONSE_FORWARD_BYTES,
) -> Iterator[tuple[str, io.StringIO]]:
    stderr_buffer = stderr or io.StringIO()
    server = relay_module.build_relay_server(
        listen_host="127.0.0.1",
        listen_port=0,
        relay_path="/mcp",
        upstream_url=upstream_url,
        backend_url=backend_url,
        server_id="fixture-http-notes-mcp",
        session_id="http-relay-test-session",
        stderr=stderr_buffer,
        max_request_body_bytes=max_request_body_bytes,
        max_response_body_bytes=max_response_body_bytes,
        max_response_forward_bytes=max_response_forward_bytes,
        upstream_timeout_seconds=2,
        backend_post_timeout_seconds=0.2,
    )
    with _running_server(server):
        yield f"http://127.0.0.1:{server.server_port}/mcp", stderr_buffer


def _initialize_response(frame: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": frame.get("id"),
        "result": {
            "protocolVersion": "2025-06-18",
            "serverInfo": {"name": "fixture-http-notes-mcp", "version": "0.1.0"},
            "capabilities": {"tools": {"listChanged": False}},
        },
    }


def _tools_list_response(frame: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": frame.get("id"),
        "result": {
            "tools": [
                {
                    "name": "list_notes",
                    "description": "Lists local fixture notes.",
                    "inputSchema": {"type": "object"},
                },
                {
                    "name": "echo_note",
                    "description": "Echoes a note.",
                    "inputSchema": {"type": "object"},
                },
            ]
        },
    }


def _tool_call_response(frame: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": frame.get("id"),
        "result": {"content": [{"type": "text", "text": "ok"}], "isError": False},
    }


def _default_upstream_response(
    frame: dict[str, Any],
    _handler: BaseHTTPRequestHandler,
) -> tuple[int, dict[str, str], bytes]:
    method = frame.get("method")
    if method == "initialize":
        return 200, {"Content-Type": "application/json"}, _json_bytes(_initialize_response(frame))
    if method == "notifications/initialized":
        return 202, {"Content-Type": "application/json"}, b""
    if method == "tools/list":
        return 200, {"Content-Type": "application/json"}, _json_bytes(_tools_list_response(frame))
    if method == "tools/call":
        return 200, {"Content-Type": "application/json"}, _json_bytes(_tool_call_response(frame))
    return (
        200,
        {"Content-Type": "application/json"},
        _json_bytes({"jsonrpc": "2.0", "id": frame.get("id"), "error": {"code": -32601, "message": "no"}}),
    )


def test_fixed_upstream_validation_rejects_non_local_or_arbitrary_upstreams() -> None:
    assert relay_module.validate_upstream_url("http://127.0.0.1:7332/mcp") == "http://127.0.0.1:7332/mcp"
    assert relay_module.validate_upstream_url("http://localhost:7332/mcp") == "http://localhost:7332/mcp"

    with pytest.raises(ValueError, match="localhost|loopback"):
        relay_module.validate_upstream_url("http://example.com/mcp")
    with pytest.raises(ValueError, match="http"):
        relay_module.validate_upstream_url("https://127.0.0.1:7332/mcp")
    with pytest.raises(ValueError, match="credentials"):
        relay_module.validate_upstream_url("http://user:secret@127.0.0.1:7332/mcp")
    with pytest.raises(ValueError, match="query"):
        relay_module.validate_upstream_url("http://127.0.0.1:7332/mcp?upstream=http://example.com")


def test_relay_does_not_use_request_query_or_header_to_select_upstream() -> None:
    with _upstream_server(_default_upstream_response) as (upstream_url, calls):
        with _relay_server(upstream_url=upstream_url) as (relay_url, _stderr):
            status, body, _headers = _post(
                f"{relay_url}?upstream=http://127.0.0.1:1/mcp",
                _json_bytes({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                headers={"X-Upstream-Url": "http://127.0.0.1:1/mcp"},
            )

    assert status == 200
    assert json.loads(body)["result"]["serverInfo"]["name"] == "fixture-http-notes-mcp"
    assert len(calls) == 1
    assert calls[0]["path"] == "/mcp"


def test_wrong_path_and_non_post_are_rejected() -> None:
    with _upstream_server(_default_upstream_response) as (upstream_url, calls):
        with _relay_server(upstream_url=upstream_url) as (relay_url, _stderr):
            base_url = relay_url.rsplit("/", 1)[0]
            get_status, _get_body = _get(relay_url)
            post_status, _post_body, _headers = _post(
                f"{base_url}/wrong",
                _json_bytes({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            )

    assert get_status == 405
    assert post_status == 404
    assert calls == []


def test_oversized_inbound_request_returns_413_and_creates_no_event() -> None:
    with _backend_server() as (backend_url, backend_events):
        with _upstream_server(_default_upstream_response) as (upstream_url, upstream_calls):
            with _relay_server(
                upstream_url=upstream_url,
                backend_url=backend_url,
                max_request_body_bytes=64,
            ) as (relay_url, _stderr):
                status, body, _headers = _post(
                    relay_url,
                    _json_bytes(
                        {
                            "jsonrpc": "2.0",
                            "id": 3,
                            "method": "tools/call",
                            "params": {"name": "list_notes", "arguments": {"payload": "x" * 200}},
                        }
                    ),
                )

    assert status == 413
    assert json.loads(body) == {"detail": "Request body too large"}
    assert backend_events == []
    assert upstream_calls == []


def test_malformed_json_request_returns_400_and_does_not_forward() -> None:
    with _backend_server() as (backend_url, backend_events):
        with _upstream_server(_default_upstream_response) as (upstream_url, upstream_calls):
            with _relay_server(upstream_url=upstream_url, backend_url=backend_url) as (relay_url, _stderr):
                status, body, _headers = _post(relay_url, b"{not-json")

    assert status == 400
    assert json.loads(body) == {"detail": "Request body must be valid JSON"}
    assert backend_events == []
    assert upstream_calls == []


def test_backend_unavailable_does_not_prevent_forwarding_or_log_sensitive_values() -> None:
    raw_secret = "sk-1234567890abcdefABCDEF1234567890"
    stderr = io.StringIO()
    backend_url = f"http://127.0.0.1:{_free_port()}"
    with _upstream_server(_default_upstream_response) as (upstream_url, upstream_calls):
        with _relay_server(upstream_url=upstream_url, backend_url=backend_url, stderr=stderr) as (relay_url, _stderr):
            status, body, _headers = _post(
                relay_url,
                _json_bytes(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {"name": "list_notes", "arguments": {"api_key": raw_secret}},
                    }
                ),
                headers={
                    "Authorization": "Bearer SHOULD_NOT_LOG",
                    "Cookie": "session=SHOULD_NOT_LOG",
                },
            )
            _wait_for(lambda: "backend unavailable" in stderr.getvalue())

    assert status == 200
    assert json.loads(body)["result"]["isError"] is False
    assert len(upstream_calls) == 1
    assert "Authorization" not in upstream_calls[0]["headers"]
    assert "Cookie" not in upstream_calls[0]["headers"]
    stderr_text = stderr.getvalue()
    assert "backend unavailable" in stderr_text
    assert raw_secret not in stderr_text
    assert "SHOULD_NOT_LOG" not in stderr_text
    assert "Authorization" not in stderr_text
    assert "Cookie" not in stderr_text


def test_tools_call_post_creates_normalized_event_sent_to_backend_events_route() -> None:
    raw_secret = "sk-1234567890abcdefABCDEF1234567890"
    with _backend_server() as (backend_url, backend_events):
        with _upstream_server(_default_upstream_response) as (upstream_url, _upstream_calls):
            with _relay_server(upstream_url=upstream_url, backend_url=backend_url) as (relay_url, _stderr):
                status, _body, _headers = _post(
                    relay_url,
                    _json_bytes(
                        {
                            "jsonrpc": "2.0",
                            "id": 3,
                            "method": "tools/call",
                            "params": {"name": "list_notes", "arguments": {"api_key": raw_secret}},
                        }
                    ),
                )
                _wait_for(lambda: len(backend_events) == 1)

    assert status == 200
    event = backend_events[0]
    assert event["source"] == "mcp"
    assert event["action_type"] == "tool_call"
    assert event["action_params"]["server_id"] == "fixture-http-notes-mcp"
    assert event["action_params"]["tool_name"] == "list_notes"
    assert event["action_params"]["arguments"]["api_key"] == "[REDACTED:OPENAI_KEY]"
    assert raw_secret not in json.dumps(event)


def test_tools_list_request_and_json_response_create_tool_register_events() -> None:
    with _backend_server() as (backend_url, backend_events):
        with _upstream_server(_default_upstream_response) as (upstream_url, _upstream_calls):
            with _relay_server(upstream_url=upstream_url, backend_url=backend_url) as (relay_url, _stderr):
                status, _body, _headers = _post(
                    relay_url,
                    _json_bytes({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
                )
                _wait_for(lambda: len(backend_events) == 2)

    assert status == 200
    assert [event["action_type"] for event in backend_events] == ["tool_register", "tool_register"]
    assert {event["action_params"]["tool_name"] for event in backend_events} == {"list_notes", "echo_note"}


def test_string_id_initialize_with_tools_array_and_notification_do_not_poison_numeric_tools_list() -> None:
    def response_fn(frame: dict[str, Any], _handler: BaseHTTPRequestHandler) -> tuple[int, dict[str, str], bytes]:
        if frame.get("method") == "notifications/initialized":
            return 202, {"Content-Type": "application/json"}, b""
        if frame.get("method") == "initialize":
            return 200, {"Content-Type": "application/json"}, _json_bytes(_tools_list_response(frame))
        return _default_upstream_response(frame, _handler)

    with _backend_server() as (backend_url, backend_events):
        with _upstream_server(response_fn) as (upstream_url, _upstream_calls):
            with _relay_server(upstream_url=upstream_url, backend_url=backend_url) as (relay_url, _stderr):
                _post(
                    relay_url,
                    _json_bytes({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
                )
                _post(
                    relay_url,
                    _json_bytes({"jsonrpc": "2.0", "id": "1", "method": "initialize", "params": {}}),
                )
                _post(
                    relay_url,
                    _json_bytes({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
                )
                _wait_for(lambda: len(backend_events) == 2)

    assert {event["action_params"]["tool_name"] for event in backend_events} == {"list_notes", "echo_note"}


def test_oversized_upstream_json_response_is_forwarded_without_recording() -> None:
    response_payload = _tools_list_response({"nested": "id"})
    response_payload["result"]["tools"][0]["description"] = "x" * 200
    response_body = _json_bytes(response_payload)
    stderr = io.StringIO()

    def response_fn(_frame: dict[str, Any], _handler: BaseHTTPRequestHandler) -> tuple[int, dict[str, str], bytes]:
        return 200, {"Content-Type": "application/json"}, response_body

    with _backend_server() as (backend_url, backend_events):
        with _upstream_server(response_fn) as (upstream_url, _upstream_calls):
            with _relay_server(
                upstream_url=upstream_url,
                backend_url=backend_url,
                stderr=stderr,
                max_response_body_bytes=64,
                max_response_forward_bytes=4096,
            ) as (relay_url, _stderr):
                status, body, _headers = _post(
                    relay_url,
                    _json_bytes({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
                )

    assert status == 200
    assert body == response_body
    assert backend_events == []
    assert "oversized upstream response forwarded without recording" in stderr.getvalue()
