from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
import ipaddress
import json
import socket
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping, Sequence

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.enforcement import (
    ENFORCEMENT_MODE_OBSERVE,
    annotate_enforcement_decision,
    evaluate_enforcement,
    resolve_enforcement_mode,
)
from app.mcp_frame_observer import DEFAULT_MAX_PENDING_REQUEST_METHODS, McpFrameObserver
from app.schemas import AgentEvent

DEFAULT_BACKEND_URL = "http://127.0.0.1:7330"
DEFAULT_LISTEN_HOST = "127.0.0.1"
DEFAULT_LISTEN_PORT = 7331
DEFAULT_RELAY_PATH = "/mcp"
DEFAULT_AGENT_ID = "aiwatch-http-mcp-relay"
MAX_RELAY_REQUEST_BODY_BYTES = 1024 * 1024
MAX_UPSTREAM_RESPONSE_BODY_BYTES = 1024 * 1024
MAX_UPSTREAM_RESPONSE_FORWARD_BYTES = 4 * 1024 * 1024
UPSTREAM_TIMEOUT_SECONDS = 10
BACKEND_POST_TIMEOUT_SECONDS = 10
SAFE_REQUEST_HEADERS = {
    "accept",
    "content-type",
    "mcp-session-id",
    "mcp-protocol-version",
}
SAFE_RESPONSE_HEADERS = {
    "content-type",
    "mcp-session-id",
    "mcp-protocol-version",
}


@dataclass(frozen=True)
class RelayConfig:
    relay_path: str
    upstream_url: str
    backend_url: str
    server_id: str
    session_id: str
    agent_id: str
    max_request_body_bytes: int = MAX_RELAY_REQUEST_BODY_BYTES
    max_response_body_bytes: int = MAX_UPSTREAM_RESPONSE_BODY_BYTES
    max_response_forward_bytes: int = MAX_UPSTREAM_RESPONSE_FORWARD_BYTES
    upstream_timeout_seconds: float = UPSTREAM_TIMEOUT_SECONDS
    backend_post_timeout_seconds: float = BACKEND_POST_TIMEOUT_SECONDS
    enforcement_mode: str = ENFORCEMENT_MODE_OBSERVE


@dataclass(frozen=True)
class UpstreamResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes
    oversized_for_observation: bool = False


class RelayHttpError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        self.status = status
        self.detail = detail


class UpstreamUnavailable(Exception):
    def __init__(self, status: int, detail: str) -> None:
        self.status = status
        self.detail = detail


class AiWatchHttpMcpRelayServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        config: RelayConfig,
        *,
        stderr: Any | None = None,
    ) -> None:
        super().__init__(server_address, AiWatchHttpMcpRelayHandler)
        self.config = config
        self.observer = McpFrameObserver(
            server_id=config.server_id,
            session_id=config.session_id,
            agent_id=config.agent_id,
            max_pending_request_methods=DEFAULT_MAX_PENDING_REQUEST_METHODS,
        )
        self.stderr = stderr if stderr is not None else sys.stderr
        self.backend_unavailable_logged = False
        self.backend_log_lock = threading.Lock()


class AiWatchHttpMcpRelayHandler(BaseHTTPRequestHandler):
    server: AiWatchHttpMcpRelayServer
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        self._send_error_response(405, "Method not allowed")

    def do_PUT(self) -> None:
        self._send_error_response(405, "Method not allowed")

    def do_DELETE(self) -> None:
        self._send_error_response(405, "Method not allowed")

    def do_PATCH(self) -> None:
        self._send_error_response(405, "Method not allowed")

    def do_POST(self) -> None:
        config = self.server.config
        if urllib.parse.urlsplit(self.path).path != config.relay_path:
            self._send_error_response(404, "Not found")
            return

        try:
            body = _read_request_body(self, config.max_request_body_bytes)
            client_frame = _parse_json_rpc_object(body)
        except RelayHttpError as error:
            self._send_error_response(error.status, error.detail)
            return

        observed_client = self.server.observer.observe_client_frame(client_frame)
        client_events = observed_client.events
        enforcement_decision = evaluate_enforcement(
            client_events,
            enforcement_mode=config.enforcement_mode,
        )
        if enforcement_decision.should_annotate:
            client_events = [
                annotate_enforcement_decision(event, enforcement_decision)
                for event in client_events
            ]
        if enforcement_decision.should_deny:
            _post_observed_events(self.server, client_events)
            self._send_mcp_denial_response(client_frame, enforcement_decision)
            denial_label = enforcement_decision.rule_id or enforcement_decision.reason or "manual_enforcement"
            _stderr(
                self.server,
                f"[aiwatch-http-relay] denied tools/call rule={denial_label}",
            )
            return

        try:
            upstream_response = _forward_to_upstream(
                upstream_url=config.upstream_url,
                body=body,
                incoming_headers=self.headers,
                timeout_seconds=config.upstream_timeout_seconds,
                max_response_body_bytes=config.max_response_body_bytes,
                max_response_forward_bytes=config.max_response_forward_bytes,
            )
        except UpstreamUnavailable as error:
            self._send_error_response(error.status, error.detail)
            _post_observed_events(self.server, client_events)
            return

        server_events: Sequence[AgentEvent] = []
        if upstream_response.oversized_for_observation:
            _stderr(self.server, "[aiwatch-http-relay] oversized upstream response forwarded without recording")
        else:
            server_frame = _parse_upstream_response_frame(upstream_response, self.server)
            if server_frame is not None:
                observed_server = self.server.observer.observe_server_frame(server_frame)
                server_events = observed_server.events

        self._send_upstream_response(upstream_response)
        _post_observed_events(self.server, [*client_events, *server_events])

    def log_message(self, _format: str, *_args: Any) -> None:
        return None

    def _send_error_response(self, status: int, detail: str) -> None:
        payload = json.dumps({"detail": detail}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def _send_mcp_denial_response(self, frame: dict[str, Any], decision: Any) -> None:
        denial_label = decision.rule_id or decision.reason or "manual_enforcement"
        data = {
            "enforcement_mode": decision.enforcement_mode,
            "reason": decision.reason,
        }
        if decision.rule_id is not None:
            data["rule_id"] = decision.rule_id
        if decision.tool_name is not None:
            data["tool_name"] = decision.tool_name
        if decision.tool_fingerprint is not None:
            data["tool_fingerprint"] = decision.tool_fingerprint
        if decision.quarantine_reason is not None:
            data["quarantine_reason"] = decision.quarantine_reason
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": frame.get("id"),
                "error": {
                    "code": -32000,
                    "message": f"AIWatch denied routed MCP tools/call: {denial_label}.",
                    "data": data,
                },
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def _send_upstream_response(self, upstream_response: UpstreamResponse) -> None:
        self.send_response(upstream_response.status)
        for header_name, header_value in _safe_response_headers(upstream_response.headers).items():
            self.send_header(header_name, header_value)
        self.send_header("Content-Length", str(len(upstream_response.body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(upstream_response.body)


def validate_upstream_url(raw_url: str) -> str:
    parsed = urllib.parse.urlsplit(raw_url)
    if parsed.scheme != "http":
        raise ValueError("upstream URL must use http")
    if parsed.username or parsed.password:
        raise ValueError("upstream URL must not include credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("upstream URL must not include query or fragment")
    if not parsed.hostname or not _is_local_hostname(parsed.hostname):
        raise ValueError("upstream URL must point to localhost or loopback")
    if not parsed.path or parsed.path == "/":
        raise ValueError("upstream URL must include an MCP endpoint path")
    return urllib.parse.urlunsplit(parsed)


def build_relay_server(
    *,
    listen_host: str,
    listen_port: int,
    relay_path: str,
    upstream_url: str,
    backend_url: str,
    server_id: str,
    session_id: str | None,
    agent_id: str = DEFAULT_AGENT_ID,
    stderr: Any | None = None,
    max_request_body_bytes: int = MAX_RELAY_REQUEST_BODY_BYTES,
    max_response_body_bytes: int = MAX_UPSTREAM_RESPONSE_BODY_BYTES,
    max_response_forward_bytes: int = MAX_UPSTREAM_RESPONSE_FORWARD_BYTES,
    upstream_timeout_seconds: float = UPSTREAM_TIMEOUT_SECONDS,
    backend_post_timeout_seconds: float = BACKEND_POST_TIMEOUT_SECONDS,
    enforcement_mode: str | None = None,
) -> AiWatchHttpMcpRelayServer:
    if listen_host not in {"127.0.0.1", "localhost", "::1"} and not _is_loopback_ip(listen_host):
        raise ValueError("listen host must be localhost or loopback")
    normalized_path = _normalize_relay_path(relay_path)
    normalized_upstream = validate_upstream_url(upstream_url)
    resolved_session_id = session_id or _generate_session_id(server_id)
    resolved_enforcement_mode = resolve_enforcement_mode(enforcement_mode)
    config = RelayConfig(
        relay_path=normalized_path,
        upstream_url=normalized_upstream,
        backend_url=backend_url,
        server_id=server_id,
        session_id=resolved_session_id,
        agent_id=agent_id,
        max_request_body_bytes=max_request_body_bytes,
        max_response_body_bytes=max_response_body_bytes,
        max_response_forward_bytes=max_response_forward_bytes,
        upstream_timeout_seconds=upstream_timeout_seconds,
        backend_post_timeout_seconds=backend_post_timeout_seconds,
        enforcement_mode=resolved_enforcement_mode,
    )
    return AiWatchHttpMcpRelayServer((listen_host, listen_port), config, stderr=stderr)


def serve_relay(
    *,
    listen_host: str,
    listen_port: int,
    relay_path: str,
    upstream_url: str,
    backend_url: str,
    server_id: str,
    session_id: str | None,
    agent_id: str = DEFAULT_AGENT_ID,
    enforcement_mode: str | None = None,
) -> None:
    server = build_relay_server(
        listen_host=listen_host,
        listen_port=listen_port,
        relay_path=relay_path,
        upstream_url=upstream_url,
        backend_url=backend_url,
        server_id=server_id,
        session_id=session_id,
        agent_id=agent_id,
        enforcement_mode=enforcement_mode,
    )
    _stderr(
        server,
        (
            "[aiwatch-http-relay] listening on "
            f"http://{listen_host}:{server.server_port}{server.config.relay_path}"
        ),
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()


def _read_request_body(handler: BaseHTTPRequestHandler, max_body_bytes: int) -> bytes:
    content_type = handler.headers.get("Content-Type", "")
    if "application/json" not in content_type.lower():
        raise RelayHttpError(415, "Content-Type must be application/json")

    raw_length = handler.headers.get("Content-Length")
    if raw_length is None:
        raise RelayHttpError(411, "Content-Length required")
    try:
        content_length = int(raw_length)
    except ValueError as error:
        raise RelayHttpError(400, "Invalid Content-Length") from error
    if content_length < 0:
        raise RelayHttpError(400, "Invalid Content-Length")
    if content_length > max_body_bytes:
        raise RelayHttpError(413, "Request body too large")
    return handler.rfile.read(content_length)


def _parse_json_rpc_object(body: bytes) -> dict[str, Any]:
    if not body:
        raise RelayHttpError(400, "Request body must be a JSON-RPC object")
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise RelayHttpError(400, "Request body must be valid JSON") from error
    if not isinstance(parsed, dict):
        raise RelayHttpError(400, "Request body must be a JSON-RPC object")
    return parsed


def _forward_to_upstream(
    *,
    upstream_url: str,
    body: bytes,
    incoming_headers: Mapping[str, str],
    timeout_seconds: float,
    max_response_body_bytes: int,
    max_response_forward_bytes: int,
) -> UpstreamResponse:
    request = urllib.request.Request(
        upstream_url,
        data=body,
        headers=_safe_request_headers(incoming_headers),
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            response_body, oversized = _read_upstream_body(
                response,
                max_response_body_bytes=max_response_body_bytes,
                max_response_forward_bytes=max_response_forward_bytes,
            )
            return UpstreamResponse(
                status=response.status,
                headers=dict(response.headers.items()),
                body=response_body,
                oversized_for_observation=oversized,
            )
    except urllib.error.HTTPError as error:
        response_body, oversized = _read_upstream_body(
            error,
            max_response_body_bytes=max_response_body_bytes,
            max_response_forward_bytes=max_response_forward_bytes,
        )
        return UpstreamResponse(
            status=error.code,
            headers=dict(error.headers.items()),
            body=response_body,
            oversized_for_observation=oversized,
        )
    except TimeoutError as error:
        raise UpstreamUnavailable(504, "Upstream MCP endpoint timed out") from error
    except (urllib.error.URLError, socket.timeout) as error:
        raise UpstreamUnavailable(502, "Upstream MCP endpoint unavailable") from error


def _read_upstream_body(
    response: Any,
    *,
    max_response_body_bytes: int,
    max_response_forward_bytes: int,
) -> tuple[bytes, bool]:
    body = response.read(max_response_forward_bytes + 1)
    if len(body) > max_response_forward_bytes:
        raise UpstreamUnavailable(502, "Upstream MCP response too large")
    return body, len(body) > max_response_body_bytes


def _parse_upstream_response_frame(
    upstream_response: UpstreamResponse,
    server: AiWatchHttpMcpRelayServer,
) -> dict[str, Any] | None:
    content_type = upstream_response.headers.get("Content-Type", "")
    if "application/json" not in content_type.lower() or not upstream_response.body:
        return None
    try:
        parsed = json.loads(upstream_response.body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        _stderr(server, "[aiwatch-http-relay] invalid upstream JSON forwarded without recording")
        return None
    if not isinstance(parsed, dict):
        _stderr(server, "[aiwatch-http-relay] non-object upstream JSON forwarded without recording")
        return None
    return parsed


def _post_observed_events(server: AiWatchHttpMcpRelayServer, events: Sequence[AgentEvent]) -> tuple[int, int]:
    if not events:
        return (0, 0)

    total_alerts = 0
    posted_count = 0
    for event in events:
        try:
            response = _post_event(
                server.config.backend_url,
                event.model_dump(mode="json"),
                timeout_seconds=server.config.backend_post_timeout_seconds,
            )
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            _log_backend_unavailable_once(server)
            continue
        posted_count += 1
        total_alerts += int(response.get("alerts_created", 0))
    return (posted_count, total_alerts)


def _post_event(backend_url: str, event_payload: dict[str, Any], *, timeout_seconds: float) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{backend_url}/v1/events",
        data=json.dumps(event_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        return json.loads(response.read().decode("utf-8"))


def _safe_request_headers(headers: Mapping[str, str]) -> dict[str, str]:
    safe_headers: dict[str, str] = {}
    for name, value in headers.items():
        normalized = name.lower()
        if normalized in SAFE_REQUEST_HEADERS:
            safe_headers[name] = value
    safe_headers.setdefault("Content-Type", "application/json")
    safe_headers.setdefault("Accept", "application/json")
    return safe_headers


def _safe_response_headers(headers: Mapping[str, str]) -> dict[str, str]:
    safe_headers: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in SAFE_RESPONSE_HEADERS:
            safe_headers[name] = value
    if not any(name.lower() == "content-type" for name in safe_headers):
        safe_headers["Content-Type"] = "application/json"
    return safe_headers


def _log_backend_unavailable_once(server: AiWatchHttpMcpRelayServer) -> None:
    with server.backend_log_lock:
        if server.backend_unavailable_logged:
            return
        _stderr(server, "[aiwatch-http-relay] backend unavailable; MCP traffic forwarded but not recorded")
        server.backend_unavailable_logged = True


def _stderr(server: AiWatchHttpMcpRelayServer, message: str) -> None:
    print(message, file=server.stderr, flush=True)


def _is_local_hostname(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    return _is_loopback_ip(hostname)


def _is_loopback_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _normalize_relay_path(path: str) -> str:
    if not path.startswith("/"):
        path = f"/{path}"
    parsed = urllib.parse.urlsplit(path)
    if parsed.query or parsed.fragment:
        raise ValueError("relay path must not include query or fragment")
    return parsed.path


def _generate_session_id(server_id: str) -> str:
    safe_server_id = "".join(char if char.isalnum() or char in {"-", "_"} else "-" for char in server_id).strip("-")
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    suffix = uuid.uuid4().hex[:8]
    return f"http-{safe_server_id or 'server'}-{timestamp}-{suffix}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a local POST JSON MCP relay for one fixed upstream endpoint.")
    parser.add_argument("--listen-host", default=DEFAULT_LISTEN_HOST)
    parser.add_argument("--listen-port", type=int, default=DEFAULT_LISTEN_PORT)
    parser.add_argument("--relay-path", default=DEFAULT_RELAY_PATH)
    parser.add_argument("--upstream-url", required=True)
    parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL)
    parser.add_argument("--server-id", required=True)
    parser.add_argument("--session-id")
    parser.add_argument("--agent-id", default=DEFAULT_AGENT_ID)
    parser.add_argument(
        "--enforcement-mode",
        choices=["observe", "deny"],
        help="Override AIWATCH_ENFORCEMENT_MODE for this relay process.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        serve_relay(
            listen_host=args.listen_host,
            listen_port=args.listen_port,
            relay_path=args.relay_path,
            upstream_url=args.upstream_url,
            backend_url=args.backend_url,
            server_id=args.server_id,
            session_id=args.session_id,
            agent_id=args.agent_id,
            enforcement_mode=args.enforcement_mode,
        )
    except ValueError as error:
        print(f"[aiwatch-http-relay] configuration error: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
