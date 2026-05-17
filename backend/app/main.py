from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager

from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi import FastAPI, HTTPException, Request
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
    init_db,
    DuplicateEventIdError,
    list_alerts as load_alerts,
    list_events as load_events,
    list_tools as load_tools,
)

DEV_MODE_TRUTHY_VALUES = {"1", "true", "yes", "on"}
MAX_EVENT_REQUEST_BODY_BYTES = 4 * 1024 * 1024


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


def _dev_mode_enabled() -> bool:
    return os.environ.get("AIWATCH_DEV_MODE", "").strip().lower() in DEV_MODE_TRUTHY_VALUES


def _require_dev_mode() -> None:
    if not _dev_mode_enabled():
        raise HTTPException(status_code=404, detail="Not Found")


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
