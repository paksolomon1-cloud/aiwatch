from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

from app.schemas import ActionType, AgentEvent, Alert, AlertEvidence, Severity, Source, ToolFingerprint, ToolObservation
from app.storage import (
    find_tools_by_name,
    get_tool_fingerprint,
    insert_tool_observation,
    upsert_tool_fingerprint,
)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_schema_payload(action_params: dict[str, Any]) -> dict[str, Any]:
    normalized_input = action_params.get("input_schema")
    normalized_output = action_params.get("output_schema")
    return {
        "input_schema": normalized_input if isinstance(normalized_input, dict) else {},
        "output_schema": normalized_output if isinstance(normalized_output, dict) else {},
    }


def _schema_hash(action_params: dict[str, Any]) -> tuple[str, dict[str, Any], dict[str, Any]]:
    input_schema = action_params.get("input_schema")
    output_schema = action_params.get("output_schema")
    normalized_input = input_schema if isinstance(input_schema, dict) else {}
    normalized_output = output_schema if isinstance(output_schema, dict) else {}
    schema_payload = _canonical_schema_payload(
        {
            "input_schema": normalized_input,
            "output_schema": normalized_output,
        }
    )
    canonical_schema = json.dumps(schema_payload, sort_keys=True, separators=(",", ":"))
    return _sha256(canonical_schema), normalized_input, normalized_output


def _derive_server_id(event: AgentEvent) -> str:
    server_id = event.action_params.get("server_id")
    if isinstance(server_id, str) and server_id.strip():
        return server_id

    if event.agent_id.strip():
        return event.agent_id

    return "unknown-server"


def _description_excerpt(description: str, *, limit: int = 160) -> str:
    trimmed = description.strip()
    if len(trimmed) <= limit:
        return trimmed
    return f"{trimmed[: limit - 3]}..."


def _action_summary(tool_name: str) -> str:
    return f"tool_register: {tool_name}"


def build_tool_observation(event: AgentEvent) -> ToolObservation | None:
    if event.source != Source.MCP or event.action_type != ActionType.TOOL_REGISTER:
        return None

    tool_name = event.action_params.get("tool_name")
    description = event.action_params.get("description")
    if not isinstance(tool_name, str) or not tool_name.strip():
        return None
    normalized_description = description if isinstance(description, str) else ""

    server_id = _derive_server_id(event)
    fingerprint_id = _sha256(f"{server_id}::{tool_name}")
    schema_hash, input_schema, output_schema = _schema_hash(event.action_params)

    return ToolObservation(
        event_id=event.event_id,
        fingerprint_id=fingerprint_id,
        observed_at=event.timestamp,
        agent_id=event.agent_id,
        session_id=event.session_id,
        server_id=server_id,
        tool_name=tool_name,
        description=normalized_description,
        name_hash=_sha256(tool_name),
        description_hash=_sha256(normalized_description),
        schema_hash=schema_hash,
        input_schema=input_schema,
        output_schema=output_schema,
    )


def observe_tool_registration(
    event: AgentEvent,
    *,
    connection: sqlite3.Connection | None = None,
) -> list[Alert]:
    observation = build_tool_observation(event)
    if observation is None:
        return []

    previous = get_tool_fingerprint(observation.fingerprint_id, connection=connection)
    other_tools = find_tools_by_name(
        observation.tool_name,
        exclude_server_id=observation.server_id,
        connection=connection,
    )

    description_changed = previous is not None and previous.description_hash != observation.description_hash
    schema_changed = previous is not None and previous.schema_hash != observation.schema_hash
    drifted = description_changed or schema_changed

    drift_count = (previous.drift_count if previous is not None else 0) + (1 if drifted else 0)
    current_tool = ToolFingerprint(
        fingerprint_id=observation.fingerprint_id,
        server_id=observation.server_id,
        tool_name=observation.tool_name,
        description=observation.description,
        name_hash=observation.name_hash,
        description_hash=observation.description_hash,
        schema_hash=observation.schema_hash,
        first_seen=previous.first_seen if previous is not None else observation.observed_at,
        last_seen=observation.observed_at,
        observation_count=(previous.observation_count if previous is not None else 0) + 1,
        drift_count=drift_count,
        latest_event_id=event.event_id,
    )

    insert_tool_observation(observation, connection=connection)
    upsert_tool_fingerprint(current_tool, connection=connection)

    alerts: list[Alert] = []

    if drifted and previous is not None:
        alerts.append(
            Alert(
                severity=Severity.MEDIUM,
                rule_id="R-MCP-002",
                source=event.source,
                agent_id=event.agent_id,
                session_id=event.session_id,
                event_ids=[event.event_id],
                summary="MCP tool definition drift detected",
                rationale=(
                    "The same MCP server re-registered an existing tool name with a different "
                    "description or schema hash."
                ),
                evidence=AlertEvidence(
                    intent_text=event.intent_text,
                    action_summary=_action_summary(observation.tool_name),
                    tool_name=observation.tool_name,
                    server_id=observation.server_id,
                    fingerprint_id=observation.fingerprint_id,
                    previous_description_hash=previous.description_hash,
                    current_description_hash=observation.description_hash,
                    previous_schema_hash=previous.schema_hash,
                    current_schema_hash=observation.schema_hash,
                    previous_description_excerpt=_description_excerpt(previous.description),
                    current_description_excerpt=_description_excerpt(observation.description),
                ),
                decision="log",
            )
        )

    if other_tools:
        alerts.append(
            Alert(
                severity=Severity.HIGH,
                rule_id="R-MCP-004",
                source=event.source,
                agent_id=event.agent_id,
                session_id=event.session_id,
                event_ids=[event.event_id],
                summary="MCP tool name shadowing detected",
                rationale=(
                    "The same MCP tool name is now registered by multiple server IDs, which "
                    "creates ambiguous tool identity and increases spoofing risk."
                ),
                evidence=AlertEvidence(
                    intent_text=event.intent_text,
                    action_summary=_action_summary(observation.tool_name),
                    tool_name=observation.tool_name,
                    server_id=observation.server_id,
                    current_server_id=observation.server_id,
                    fingerprint_id=observation.fingerprint_id,
                    other_server_ids=[tool.server_id for tool in other_tools],
                    matching_fingerprint_ids=[tool.fingerprint_id for tool in other_tools]
                    + [observation.fingerprint_id],
                ),
                decision="log",
            )
        )

    return alerts
