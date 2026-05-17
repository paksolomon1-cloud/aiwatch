from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


def _new_uuid() -> str:
    return str(uuid4())


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_to_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class Source(StrEnum):
    MCP = "mcp"
    CODING_AGENT = "coding_agent"
    HTTP = "http"


class ActionType(StrEnum):
    TOOL_CALL = "tool_call"
    TOOL_REGISTER = "tool_register"
    SHELL_EXEC = "shell_exec"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NET_EGRESS = "net_egress"
    OTHER = "other"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AgentEvent(BaseModel):
    """Normalized runtime event for AIWatch detections."""

    # AgentEvent is the unifying schema for both MCP server events and
    # coding-agent events so detections can run on one shared event model.
    event_id: str = Field(default_factory=_new_uuid)
    timestamp: datetime = Field(default_factory=_utc_now)
    agent_id: str = "local-agent"
    session_id: str = "default-session"
    source: Source
    intent_text: str | None = None
    action_type: ActionType
    action_params: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] | None = None
    parent_event_id: str | None = None

    @field_validator("timestamp", mode="after")
    @classmethod
    def _normalize_timestamp(cls, value: datetime) -> datetime:
        return _normalize_to_utc(value)


class AlertEvidence(BaseModel):
    intent_text: str | None = None
    action_summary: str
    matched_patterns: list[str] = Field(default_factory=list)
    files_referenced: list[str] = Field(default_factory=list)
    destinations: list[str] = Field(default_factory=list)
    tool_name: str | None = None
    server_id: str | None = None
    current_server_id: str | None = None
    fingerprint_id: str | None = None
    previous_description_hash: str | None = None
    current_description_hash: str | None = None
    previous_schema_hash: str | None = None
    current_schema_hash: str | None = None
    previous_description_excerpt: str | None = None
    current_description_excerpt: str | None = None
    other_server_ids: list[str] = Field(default_factory=list)
    matching_fingerprint_ids: list[str] = Field(default_factory=list)
    credential_findings: list[dict[str, Any]] = Field(default_factory=list)


class Alert(BaseModel):
    alert_id: str = Field(default_factory=_new_uuid)
    created_at: datetime = Field(default_factory=_utc_now)
    severity: Severity
    rule_id: str
    source: Source
    agent_id: str
    session_id: str
    event_ids: list[str]
    summary: str
    rationale: str
    evidence: AlertEvidence
    decision: Literal["log", "block"] = "log"

    @field_validator("created_at", mode="after")
    @classmethod
    def _normalize_created_at(cls, value: datetime) -> datetime:
        return _normalize_to_utc(value)


class ToolFingerprint(BaseModel):
    fingerprint_id: str
    server_id: str
    tool_name: str
    description: str
    name_hash: str
    description_hash: str
    schema_hash: str
    first_seen: datetime
    last_seen: datetime
    observation_count: int
    drift_count: int = 0
    latest_event_id: str | None = None

    @field_validator("first_seen", "last_seen", mode="after")
    @classmethod
    def _normalize_tool_timestamps(cls, value: datetime) -> datetime:
        return _normalize_to_utc(value)


class ToolObservation(BaseModel):
    event_id: str
    fingerprint_id: str
    observed_at: datetime
    agent_id: str
    session_id: str
    server_id: str
    tool_name: str
    description: str
    name_hash: str
    description_hash: str
    schema_hash: str
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] = Field(default_factory=dict)

    @field_validator("observed_at", mode="after")
    @classmethod
    def _normalize_observed_at(cls, value: datetime) -> datetime:
        return _normalize_to_utc(value)
