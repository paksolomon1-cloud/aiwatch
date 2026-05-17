from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

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
def create_event(event: AgentEvent) -> dict[str, object]:
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
    return {
        "session_id": session_id,
        "events": get_session_events(session_id),
        "alerts": get_session_alerts(session_id),
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
