from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.credential_redaction import redact_json_like
from app.demo_events import demo_seed_items, extended_demo_seed_items
from app.schemas import AgentEvent, Alert, ToolFingerprint, ToolObservation
from app.storage import (
    clear_db,
    count_alerts,
    count_events,
    count_tools,
    get_tool_fingerprint,
    get_tool_history,
    get_session_alerts,
    get_session_events,
    ingest_event,
    insert_audit_record,
    init_db,
    DuplicateEventIdError,
    list_audit_records as load_audit_records,
    list_alerts as load_alerts,
    list_events as load_events,
    list_tools as load_tools,
)
from app.veea_audit import build_veea_audit_timeline, lobstertrap_record_to_veea_audit_envelope

DEV_MODE_TRUTHY_VALUES = {"1", "true", "yes", "on"}
MAX_EVENT_REQUEST_BODY_BYTES = 4 * 1024 * 1024
LOBSTERTRAP_ACTIVE_THRESHOLD_SECONDS = 5 * 60
LOBSTERTRAP_SUGGESTED_INGEST_COMMAND = (
    "py -3.12 scripts\\aiwatch.py ingest-lobstertrap-audit --file <jsonl> "
    "--backend-url http://127.0.0.1:7330"
)
LOBSTERTRAP_DEMO_INGEST_COMMAND = (
    "py -3.12 scripts\\aiwatch.py ingest-demo-lobstertrap-audit --backend-url http://127.0.0.1:7330"
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="AIWatch", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Accept", "Content-Type"],
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={"detail": jsonable_encoder(redact_json_like(exc.errors()))},
    )


def _store_event_and_alerts(event: AgentEvent) -> list[Alert]:
    return ingest_event(event)


def _request_validation_error(errors: list[dict[str, object]]) -> RequestValidationError:
    return RequestValidationError(errors)


def _body_loc_error(error: dict[str, object]) -> dict[str, object]:
    normalized = dict(error)
    normalized.pop("url", None)
    loc = normalized.get("loc", ())
    if isinstance(loc, str):
        loc = (loc,)
    elif not isinstance(loc, tuple):
        loc = tuple(loc) if isinstance(loc, list) else ()
    normalized["loc"] = ("body", *loc)
    return normalized


def _json_decode_error(error: json.JSONDecodeError | UnicodeDecodeError) -> RequestValidationError:
    if isinstance(error, json.JSONDecodeError):
        message = error.msg
        position = error.pos
    else:
        message = str(error)
        position = 0

    return _request_validation_error(
        [
            {
                "type": "json_invalid",
                "loc": ("body", position),
                "msg": "JSON decode error",
                "input": {},
                "ctx": {"error": message},
            }
        ]
    )


async def _read_event_request_body(request: Request) -> bytes:
    raw_content_length = request.headers.get("content-length")
    if raw_content_length is not None:
        try:
            if int(raw_content_length) > MAX_EVENT_REQUEST_BODY_BYTES:
                raise HTTPException(status_code=413, detail="Request body too large")
        except ValueError:
            pass

    body_chunks: list[bytes] = []
    total_bytes = 0
    async for chunk in request.stream():
        total_bytes += len(chunk)
        if total_bytes > MAX_EVENT_REQUEST_BODY_BYTES:
            raise HTTPException(status_code=413, detail="Request body too large")
        body_chunks.append(chunk)

    return b"".join(body_chunks)


def _parse_agent_event(raw_body: bytes) -> AgentEvent:
    if not raw_body:
        raise _request_validation_error(
            [
                {
                    "type": "missing",
                    "loc": ("body",),
                    "msg": "Field required",
                    "input": None,
                }
            ]
        )

    try:
        payload = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise _json_decode_error(error) from None

    try:
        return AgentEvent.model_validate(payload)
    except ValidationError as error:
        raise _request_validation_error([_body_loc_error(item) for item in error.errors()]) from None


def _parse_json_payload(raw_body: bytes) -> object:
    if not raw_body:
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")

    try:
        return json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Malformed JSON") from None


def _dev_mode_enabled() -> bool:
    return os.environ.get("AIWATCH_DEV_MODE", "").strip().lower() in DEV_MODE_TRUTHY_VALUES


def _require_dev_mode() -> None:
    if not _dev_mode_enabled():
        raise HTTPException(status_code=404, detail="Not Found")


def _audit_record_timestamp(record: dict[str, object]) -> str:
    timestamp = record.get("timestamp") or record.get("created_at")
    return timestamp if isinstance(timestamp, str) else ""


def _parse_audit_datetime(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _audit_record_tie_key(record: dict[str, object]) -> tuple[str, str, str, str]:
    stable_id = record.get("id") or record.get("request_id") or record.get("rule_id")

    aiwatch = record.get("aiwatch")
    if isinstance(aiwatch, dict):
        stable_id = aiwatch.get("event_id") or aiwatch.get("alert_id") or stable_id

    lobstertrap = record.get("lobstertrap")
    if isinstance(lobstertrap, dict):
        stable_id = lobstertrap.get("request_id") or stable_id

    return (
        str(record.get("source", "")),
        str(record.get("layer", "")),
        str(record.get("event_type", "")),
        str(stable_id or ""),
    )


def _api_aiwatch_audit_records() -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for record in build_veea_audit_timeline(load_events(), load_alerts()):
        api_record = dict(record)
        aiwatch = api_record.get("aiwatch")
        if isinstance(aiwatch, dict):
            stable_id = aiwatch.get("event_id") or aiwatch.get("alert_id")
            if stable_id:
                api_record["id"] = f"aiwatch:{stable_id}"
        api_record.setdefault("created_at", api_record.get("timestamp"))
        records.append(api_record)
    return records


def _sort_audit_timeline_desc(records: list[dict[str, object]]) -> list[dict[str, object]]:
    stable_records = sorted(records, key=_audit_record_tie_key)
    return sorted(stable_records, key=_audit_record_timestamp, reverse=True)


def _combined_audit_records(*, lobstertrap_limit: int | None = 100) -> list[dict[str, object]]:
    return [
        *load_audit_records(limit=lobstertrap_limit),
        *_api_aiwatch_audit_records(),
    ]


def _is_deny_record(record: dict[str, object]) -> bool:
    action = str(record.get("action") or "").upper()
    decision = str(record.get("decision") or "").lower()
    return action == "DENY" or decision == "block"


def _is_human_review_or_quarantine_record(record: dict[str, object]) -> bool:
    action = str(record.get("action") or "").upper()
    decision = str(record.get("decision") or "").lower()
    return action in {"HUMAN_REVIEW", "QUARANTINE"} or decision in {"review", "quarantine"}


def _record_action(record: dict[str, object]) -> str:
    return str(record.get("action") or "").upper()


def _lobstertrap_status(records: list[dict[str, object]]) -> dict[str, object]:
    lobstertrap_records = [record for record in records if record.get("source") == "lobstertrap"]
    sorted_records = _sort_audit_timeline_desc(lobstertrap_records)
    latest_record = sorted_records[0] if sorted_records else None
    latest_record_at = latest_record.get("timestamp") if latest_record else None
    latest_record_datetime = _parse_audit_datetime(latest_record_at)
    seconds_since_last_record = (
        max(0, int((datetime.now(timezone.utc) - latest_record_datetime).total_seconds()))
        if latest_record_datetime is not None
        else None
    )

    if not lobstertrap_records:
        status = "no_records"
    elif seconds_since_last_record is None:
        status = "inactive"
    elif seconds_since_last_record <= LOBSTERTRAP_ACTIVE_THRESHOLD_SECONDS:
        status = "active"
    else:
        status = "stale"

    response: dict[str, object] = {
        "source": "lobstertrap",
        "configured": bool(lobstertrap_records),
        "status": status,
        "total_records": len(lobstertrap_records),
        "deny_count": sum(1 for record in lobstertrap_records if _record_action(record) == "DENY"),
        "human_review_count": sum(
            1 for record in lobstertrap_records if _record_action(record) == "HUMAN_REVIEW"
        ),
        "quarantine_count": sum(1 for record in lobstertrap_records if _record_action(record) == "QUARANTINE"),
        "allow_count": sum(1 for record in lobstertrap_records if _record_action(record) == "ALLOW"),
        "redacted_count": sum(1 for record in lobstertrap_records if record.get("redacted") is True),
        "last_record_at": latest_record_at if isinstance(latest_record_at, str) else None,
        "last_decision": latest_record.get("action") if latest_record else None,
        "last_rule_id": latest_record.get("rule_id") if latest_record else None,
        "last_summary": latest_record.get("summary") if latest_record else None,
        "suggested_ingest_command": LOBSTERTRAP_SUGGESTED_INGEST_COMMAND,
        "demo_ingest_command": LOBSTERTRAP_DEMO_INGEST_COMMAND,
    }

    if seconds_since_last_record is not None:
        response["seconds_since_last_record"] = seconds_since_last_record

    return response


def _source_layer_breakdown(records: list[dict[str, object]]) -> list[dict[str, object]]:
    counts: dict[tuple[str, str], int] = {}
    for record in records:
        key = (str(record.get("source") or "unknown"), str(record.get("layer") or "unknown"))
        counts[key] = counts.get(key, 0) + 1

    return [
        {"source": source, "layer": layer, "count": count}
        for (source, layer), count in sorted(counts.items())
    ]


def _audit_summary(records: list[dict[str, object]]) -> dict[str, object]:
    sorted_records = _sort_audit_timeline_desc(records)
    return {
        "total_records": len(records),
        "aiwatch_mcp_records": sum(
            1 for record in records if record.get("source") == "aiwatch" and record.get("layer") == "mcp_tool"
        ),
        "lobstertrap_records": sum(1 for record in records if record.get("source") == "lobstertrap"),
        "deny_count": sum(1 for record in records if _is_deny_record(record)),
        "human_review_quarantine_count": sum(
            1 for record in records if _is_human_review_or_quarantine_record(record)
        ),
        "redacted_count": sum(1 for record in records if record.get("redacted") is True),
        "most_recent_timestamp": _audit_record_timestamp(sorted_records[0]) if sorted_records else None,
        "source_layer_breakdown": _source_layer_breakdown(records),
    }


@app.get("/")
def root() -> dict[str, str]:
    return {
        "name": "AIWatch",
        "status": "running",
        "message": "AIWatch observes MCP traffic routed through the AIWatch wrapper.",
    }


@app.post("/v1/events")
async def create_event(request: Request) -> dict[str, object]:
    event = _parse_agent_event(await _read_event_request_body(request))
    try:
        alerts = _store_event_and_alerts(event)
    except DuplicateEventIdError:
        raise HTTPException(status_code=409, detail="event_id already exists") from None
    return {
        "status": "ok",
        "event_id": event.event_id,
        "alerts_created": len(alerts),
        "alerts": alerts,
    }


@app.post("/v1/integrations/lobstertrap/audit")
async def ingest_lobstertrap_audit(request: Request) -> dict[str, object]:
    payload = _parse_json_payload(await _read_event_request_body(request))

    if isinstance(payload, dict) and "records" in payload:
        raw_records = payload["records"]
        if not isinstance(raw_records, list):
            raise HTTPException(status_code=400, detail="records must be a list")
    elif isinstance(payload, dict):
        raw_records = [payload]
    else:
        raise HTTPException(status_code=400, detail="Expected a JSON object or batch records object")

    accepted = 0
    rejected = 0
    stored_record_ids: list[int] = []

    for raw_record in raw_records:
        if not isinstance(raw_record, dict):
            rejected += 1
            continue

        envelope = lobstertrap_record_to_veea_audit_envelope(raw_record)
        stored_record_ids.append(insert_audit_record(envelope))
        accepted += 1

    return {
        "status": "ok",
        "accepted": accepted,
        "rejected": rejected,
        "stored_record_ids": stored_record_ids,
    }


@app.get("/v1/integrations/lobstertrap/status")
def read_lobstertrap_status() -> dict[str, object]:
    return _lobstertrap_status(load_audit_records(limit=None))


@app.get("/v1/events", response_model=list[AgentEvent])
def read_events() -> list[AgentEvent]:
    return load_events()


@app.get("/v1/alerts", response_model=list[Alert])
def read_alerts() -> list[Alert]:
    return load_alerts()


@app.get("/v1/tools", response_model=list[ToolFingerprint])
def read_tools() -> list[ToolFingerprint]:
    return load_tools()


@app.get("/v1/tools/{fingerprint_id}", response_model=ToolFingerprint)
def read_tool(fingerprint_id: str) -> ToolFingerprint:
    tool = get_tool_fingerprint(fingerprint_id)
    if tool is None:
        raise HTTPException(status_code=404, detail="Tool fingerprint not found")
    return tool


@app.get("/v1/tools/{fingerprint_id}/history", response_model=list[ToolObservation])
def read_tool_history(fingerprint_id: str) -> list[ToolObservation]:
    tool = get_tool_fingerprint(fingerprint_id)
    if tool is None:
        raise HTTPException(status_code=404, detail="Tool fingerprint not found")
    return get_tool_history(fingerprint_id)


@app.get("/v1/sessions/{session_id}/replay")
def replay_session(session_id: str) -> dict[str, object]:
    events = get_session_events(session_id)
    alerts = get_session_alerts(session_id)
    if not events and not alerts:
        raise HTTPException(status_code=404, detail="Session not found")

    return {
        "session_id": session_id,
        "events": events,
        "alerts": alerts,
    }


@app.get("/v1/audit/timeline")
def read_audit_timeline(limit: int = Query(100, ge=1, le=1000)) -> list[dict[str, object]]:
    records = _combined_audit_records(lobstertrap_limit=limit)
    return _sort_audit_timeline_desc(records)[:limit]


@app.get("/v1/audit/summary")
def read_audit_summary() -> dict[str, object]:
    return _audit_summary(_combined_audit_records(lobstertrap_limit=None))


@app.delete("/v1/dev/clear")
def clear_local_database() -> dict[str, str]:
    # Dev-only endpoint. Do not expose this in production without authentication.
    _require_dev_mode()
    clear_db()
    return {
        "status": "ok",
        "message": "local database cleared",
    }


@app.post("/v1/dev/seed-demo")
def seed_demo(clear: bool = True, extended: bool = False) -> dict[str, object]:
    # Dev-only endpoint. Do not expose this in production without authentication.
    _require_dev_mode()
    if clear:
        clear_db()

    items: list[dict[str, object]] = []
    total_alerts = 0
    seed_items = extended_demo_seed_items() if extended else demo_seed_items()

    for item in seed_items:
        event = AgentEvent(**item.payload)
        alerts = _store_event_and_alerts(event)
        rule_ids = [alert.rule_id for alert in alerts]
        total_alerts += len(alerts)
        items.append(
            {
                "name": item.name,
                "event_id": event.event_id,
                "alerts_created": len(alerts),
                "rule_ids": rule_ids,
            }
        )

    return {
        "status": "ok",
        "events_created": len(items),
        "alerts_created": total_alerts,
        "tools_observed": count_tools(),
        "items": items,
    }


@app.get("/v1/health")
def health() -> dict[str, int | str]:
    return {
        "status": "healthy",
        "storage": "sqlite",
        "events": count_events(),
        "alerts": count_alerts(),
    }
