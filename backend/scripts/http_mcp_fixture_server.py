from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Sequence

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 7332
DEFAULT_PATH = "/mcp"
SERVER_NAME = "fixture-http-notes-mcp"
SERVER_VERSION = "0.1.0"

_NOTES = [
    "Review the local MCP relay smoke.",
    "Confirm benign tools do not create alerts.",
    "Keep HTTP relay claims narrow.",
]


def tool_definitions() -> list[dict[str, Any]]:
    return [
        {
            "name": "list_notes",
            "description": "Lists saved demo notes for the local HTTP MCP fixture.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1},
                },
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {"type": "string"},
                    }
                },
                "required": ["items"],
            },
        },
        {
            "name": "echo_note",
            "description": "Echoes a provided note string for local relay testing.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                },
                "required": ["text"],
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                },
                "required": ["text"],
            },
        },
    ]


def handle_frame(frame: dict[str, Any]) -> tuple[int, dict[str, Any] | None]:
    jsonrpc_id = frame.get("id")
    method = frame.get("method")
    params = frame.get("params")

    if method == "initialize":
        return (
            200,
            {
                "jsonrpc": "2.0",
                "id": jsonrpc_id,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "serverInfo": {
                        "name": SERVER_NAME,
                        "version": SERVER_VERSION,
                    },
                    "capabilities": {
                        "tools": {"listChanged": False},
                    },
                },
            },
        )

    if method == "notifications/initialized":
        return (202, None)

    if method == "tools/list":
        return (
            200,
            {
                "jsonrpc": "2.0",
                "id": jsonrpc_id,
                "result": {
                    "tools": tool_definitions(),
                },
            },
        )

    if method == "tools/call":
        if not isinstance(params, dict):
            return (
                200,
                {
                    "jsonrpc": "2.0",
                    "id": jsonrpc_id,
                    "error": {
                        "code": -32602,
                        "message": "Expected params object for tools/call.",
                    },
                },
            )

        tool_name = params.get("name")
        arguments = params.get("arguments")
        if tool_name == "list_notes":
            limit = 2
            if isinstance(arguments, dict):
                raw_limit = arguments.get("limit")
                if isinstance(raw_limit, int) and raw_limit > 0:
                    limit = raw_limit
            return (
                200,
                {
                    "jsonrpc": "2.0",
                    "id": jsonrpc_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": "\n".join(_NOTES[:limit]),
                            }
                        ],
                        "isError": False,
                    },
                },
            )

        if tool_name == "echo_note":
            text = ""
            if isinstance(arguments, dict):
                raw_text = arguments.get("text")
                text = raw_text if isinstance(raw_text, str) else ""
            return (
                200,
                {
                    "jsonrpc": "2.0",
                    "id": jsonrpc_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": text,
                            }
                        ],
                        "structuredContent": {"text": text},
                        "isError": False,
                    },
                },
            )

    return (
        200,
        {
            "jsonrpc": "2.0",
            "id": jsonrpc_id,
            "error": {
                "code": -32601,
                "message": f"Unsupported method: {method}",
            },
        },
    )


class HttpMcpFixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    fixture_path = DEFAULT_PATH

    def do_GET(self) -> None:
        self._send_json(405, {"detail": "Method not allowed"})

    def do_POST(self) -> None:
        if self.path != self.fixture_path:
            self._send_json(404, {"detail": "Not found"})
            return

        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            self._send_json(411, {"detail": "Content-Length required"})
            return

        try:
            content_length = int(raw_length)
        except ValueError:
            self._send_json(400, {"detail": "Invalid Content-Length"})
            return

        body = self.rfile.read(content_length)
        try:
            frame = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json(400, {"detail": "Request body must be valid JSON"})
            return

        if not isinstance(frame, dict):
            self._send_json(400, {"detail": "Request body must be a JSON-RPC object"})
            return

        status, response = handle_frame(frame)
        if response is None:
            self._send_empty(status)
            return
        self._send_json(status, response)

    def log_message(self, _format: str, *_args: Any) -> None:
        return None

    def _send_empty(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def build_server(*, host: str, port: int, path: str = DEFAULT_PATH) -> ThreadingHTTPServer:
    handler = type("ConfiguredHttpMcpFixtureHandler", (HttpMcpFixtureHandler,), {"fixture_path": path})
    return ThreadingHTTPServer((host, port), handler)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the local benign HTTP MCP fixture server.")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--path", default=DEFAULT_PATH)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    server = build_server(host=args.host, port=args.port, path=args.path)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
