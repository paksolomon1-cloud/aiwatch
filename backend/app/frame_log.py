from __future__ import annotations

import json
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent
# Demo-only raw JSON-RPC frame logs. Entries can contain sensitive tool metadata
# or payloads, so only write them for explicit local demo/debug flows.
DEFAULT_FRAME_LOG_PATH = BASE_DIR / ".aiwatch_demo" / "frames.jsonl"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def frame_raw_hash(raw_line: str) -> str:
    return sha256(raw_line.encode("utf-8")).hexdigest()


def extract_method(frame: dict[str, Any]) -> str | None:
    method = frame.get("method")
    if isinstance(method, str) and method:
        return method

    request_method = frame.get("request_method")
    if isinstance(request_method, str) and request_method:
        return request_method

    return None


def build_frame_log_entry(
    *,
    session_id: str,
    server_id: str,
    direction: str,
    raw_line: str,
    frame: dict[str, Any],
    method: str | None = None,
) -> dict[str, Any]:
    return {
        "timestamp": _utc_now(),
        "session_id": session_id,
        "server_id": server_id,
        "direction": direction,
        "method": method or extract_method(frame),
        "jsonrpc_id": frame.get("id"),
        "raw_hash": frame_raw_hash(raw_line),
        "frame": frame,
    }


def append_frame_log(log_path: Path, entry: dict[str, Any]) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True))
        handle.write("\n")
