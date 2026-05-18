from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from app.credential_redaction import redact_json_like
from app.schemas import AgentEvent, Alert, Source

VEEA_AIWATCH_AUDIT_SCHEMA = "veea.aiwatch.audit.v1"
VEEA_AIWATCH_SOURCE = "aiwatch"
VEEA_AIWATCH_LAYER = "mcp_tool"
VEEA_SECURITY_ALERT_EVENT_TYPE = "security_alert"
VEEA_MCP_OBSERVATION_EVENT_TYPE = "mcp_observation"
AIWATCH_MCP_DETECTOR = "deterministic_mcp"
AIWATCH_UNSPECIFIED_TRANSPORT = "routed_mcp_unspecified"


def is_mcp_alert(alert: Alert) -> bool:
    return alert.source == Source.MCP or alert.rule_id.startswith("R-MCP-")


def is_mcp_event(event: AgentEvent) -> bool:
    return event.source == Source.MCP


def _primary_event_id(alert: Alert) -> str | None:
    return alert.event_ids[0] if alert.event_ids else None


def _contains_redacted_marker(value: Any) -> bool:
    if isinstance(value, str):
        return value.startswith("[REDACTED:")
    if isinstance(value, dict):
        return any(_contains_redacted_marker(child) for child in value.values())
    if isinstance(value, list):
        return any(_contains_redacted_marker(child) for child in value)
    return False


def _safe_evidence(alert: Alert) -> tuple[dict[str, Any], bool]:
    evidence = alert.evidence.model_dump(mode="json")
    redacted_evidence = redact_json_like(evidence)
    redacted = redacted_evidence != evidence or _contains_redacted_marker(redacted_evidence)
    return redacted_evidence, redacted


def _safe_event_evidence(event: AgentEvent) -> tuple[dict[str, Any], bool]:
    event_payload = event.model_dump(mode="json")
    evidence = {
        "intent_text": event_payload["intent_text"],
        "action_params": event_payload["action_params"],
        "raw": event_payload["raw"],
        "parent_event_id": event_payload["parent_event_id"],
    }
    redacted_evidence = redact_json_like(evidence)
    redacted = redacted_evidence != evidence or _contains_redacted_marker(redacted_evidence)
    return redacted_evidence, redacted


def _extract_server_id(action_params: dict[str, Any]) -> str | None:
    server_id = action_params.get("server_id")
    return server_id if isinstance(server_id, str) else None


def _extract_tool_name(action_params: dict[str, Any]) -> str | None:
    tool_name = action_params.get("tool_name")
    if isinstance(tool_name, str):
        return tool_name

    params = action_params.get("params")
    if isinstance(params, dict):
        params_tool_name = params.get("name")
        if isinstance(params_tool_name, str):
            return params_tool_name

    return None


def alert_to_veea_audit_envelope(alert: Alert) -> dict[str, Any]:
    evidence, redacted = _safe_evidence(alert)
    alert_payload = alert.model_dump(mode="json")
    event_id = _primary_event_id(alert)

    return {
        "schema": VEEA_AIWATCH_AUDIT_SCHEMA,
        "source": VEEA_AIWATCH_SOURCE,
        "layer": VEEA_AIWATCH_LAYER,
        "event_type": VEEA_SECURITY_ALERT_EVENT_TYPE,
        "rule_id": alert.rule_id,
        "severity": alert_payload["severity"],
        "decision": alert.decision,
        "summary": alert.summary,
        "rationale": alert.rationale,
        "timestamp": alert_payload["created_at"],
        "server_id": evidence.get("server_id") or evidence.get("current_server_id"),
        "tool_name": evidence.get("tool_name"),
        "session_id": alert.session_id,
        "agent_id": alert.agent_id,
        "redacted": redacted,
        "evidence": evidence,
        "aiwatch": {
            "alert_id": alert.alert_id,
            "event_id": event_id,
            "event_ids": list(alert.event_ids),
            "source": alert_payload["source"],
            "transport": AIWATCH_UNSPECIFIED_TRANSPORT,
            "detector": AIWATCH_MCP_DETECTOR,
        },
    }


def event_to_veea_audit_envelope(event: AgentEvent) -> dict[str, Any]:
    event_payload = event.model_dump(mode="json")
    evidence, redacted = _safe_event_evidence(event)
    action_params = evidence.get("action_params")
    if not isinstance(action_params, dict):
        action_params = {}

    return {
        "schema": VEEA_AIWATCH_AUDIT_SCHEMA,
        "source": VEEA_AIWATCH_SOURCE,
        "layer": VEEA_AIWATCH_LAYER,
        "event_type": VEEA_MCP_OBSERVATION_EVENT_TYPE,
        "observation_type": event_payload["action_type"],
        "timestamp": event_payload["timestamp"],
        "server_id": _extract_server_id(action_params),
        "tool_name": _extract_tool_name(action_params),
        "session_id": event.session_id,
        "agent_id": event.agent_id,
        "redacted": redacted,
        "evidence": evidence,
        "aiwatch": {
            "event_id": event.event_id,
            "source": event_payload["source"],
            "transport": AIWATCH_UNSPECIFIED_TRANSPORT,
            "detector": None,
        },
    }


def build_veea_audit_envelopes(alerts: Iterable[Alert]) -> list[dict[str, Any]]:
    return [alert_to_veea_audit_envelope(alert) for alert in alerts if is_mcp_alert(alert)]


def build_veea_observation_envelopes(events: Iterable[AgentEvent]) -> list[dict[str, Any]]:
    return [event_to_veea_audit_envelope(event) for event in events if is_mcp_event(event)]


def _timeline_sort_key(envelope: dict[str, Any]) -> tuple[str, str, str]:
    aiwatch = envelope.get("aiwatch")
    aiwatch_payload = aiwatch if isinstance(aiwatch, dict) else {}
    stable_id = aiwatch_payload.get("event_id") or aiwatch_payload.get("alert_id") or ""
    return (str(envelope.get("timestamp", "")), str(envelope.get("event_type", "")), str(stable_id))


def build_veea_audit_timeline(
    events: Iterable[AgentEvent],
    alerts: Iterable[Alert],
) -> list[dict[str, Any]]:
    envelopes = [*build_veea_observation_envelopes(events), *build_veea_audit_envelopes(alerts)]
    return sorted(envelopes, key=_timeline_sort_key)


def render_veea_audit_jsonl(envelopes: Iterable[dict[str, Any]]) -> str:
    lines = [json.dumps(envelope, sort_keys=True, separators=(",", ":")) for envelope in envelopes]
    return "".join(f"{line}\n" for line in lines)


def write_veea_audit_jsonl(envelopes: Iterable[dict[str, Any]], output_path: Path) -> int:
    rendered = render_veea_audit_jsonl(envelopes)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    return 0 if not rendered else rendered.count("\n")
