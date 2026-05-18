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
VEEA_LOBSTERTRAP_AUDIT_SCHEMA = "veea.lobstertrap.audit.v1"
VEEA_LOBSTERTRAP_SOURCE = "lobstertrap"
VEEA_LOBSTERTRAP_LAYER = "llm_prompt_response"
VEEA_SECURITY_ALERT_EVENT_TYPE = "security_alert"
VEEA_MCP_OBSERVATION_EVENT_TYPE = "mcp_observation"
VEEA_LLM_INSPECTION_EVENT_TYPE = "llm_inspection"
AIWATCH_MCP_DETECTOR = "deterministic_mcp"
AIWATCH_UNSPECIFIED_TRANSPORT = "routed_mcp_unspecified"
LOBSTERTRAP_DETECTOR = "deterministic_prompt_response"


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


def _string_value(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _pick_string(payload: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _nested_dict(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    return value if isinstance(value, dict) else {}


def _safe_evidence(alert: Alert) -> tuple[dict[str, Any], bool]:
    evidence = alert.evidence.model_dump(mode="json")
    redacted_evidence = redact_json_like(evidence)
    redacted = redacted_evidence != evidence or _contains_redacted_marker(redacted_evidence)
    return redacted_evidence, redacted


def _safe_lobstertrap_evidence(record: dict[str, Any]) -> dict[str, Any]:
    evidence_keys = [
        "request_id",
        "direction",
        "action",
        "verdict",
        "rule_name",
        "rule_id",
        "matched_rule",
        "deny_message",
        "metadata",
        "prompt",
        "token_count",
        "declared_headers",
        "mismatches",
        "agent_id",
    ]
    evidence = {key: record[key] for key in evidence_keys if key in record}

    lobstertrap_report = record.get("_lobstertrap")
    if isinstance(lobstertrap_report, dict):
        evidence["_lobstertrap"] = lobstertrap_report

    return redact_json_like(evidence)


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


def _lobstertrap_action(record: dict[str, Any]) -> str | None:
    action = _pick_string(record, "action", "verdict")
    if action:
        return action

    lobstertrap_report = _nested_dict(record, "_lobstertrap")
    action = _pick_string(lobstertrap_report, "verdict", "action")
    if action:
        return action

    for section_key in ("ingress", "egress"):
        section = _nested_dict(record, section_key)
        action = _pick_string(section, "action", "verdict")
        if action:
            return action

        report_section = _nested_dict(lobstertrap_report, section_key)
        action = _pick_string(report_section, "action", "verdict")
        if action:
            return action

    return None


def _lobstertrap_rule_id(record: dict[str, Any]) -> str | None:
    rule_id = _pick_string(record, "rule_name", "rule_id", "matched_rule", "rule")
    if rule_id:
        return rule_id

    lobstertrap_report = _nested_dict(record, "_lobstertrap")
    for section_key in ("ingress", "egress"):
        section = _nested_dict(record, section_key)
        rule_id = _pick_string(section, "rule_name", "rule_id", "matched_rule", "rule")
        if rule_id:
            return rule_id

        report_section = _nested_dict(lobstertrap_report, section_key)
        rule_id = _pick_string(report_section, "rule_name", "rule_id", "matched_rule", "rule")
        if rule_id:
            return rule_id

    return None


def _lobstertrap_decision(action: str | None) -> str | None:
    if action is None:
        return None

    normalized = action.strip().upper()
    if normalized == "ALLOW":
        return "allow"
    if normalized == "LOG":
        return "log"
    if normalized in {"DENY", "QUARANTINE"}:
        return "block"
    if normalized == "HUMAN_REVIEW":
        return "review"
    return normalized.lower()


def _lobstertrap_summary(action: str | None, rule_id: str | None, direction: str | None) -> str:
    parts = ["Lobster Trap prompt/response inspection"]
    if direction:
        parts.append(f"direction={direction}")
    if action:
        parts.append(f"action={action}")
    if rule_id:
        parts.append(f"rule={rule_id}")
    return "; ".join(parts)


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


def lobstertrap_record_to_veea_audit_envelope(record: dict[str, Any]) -> dict[str, Any]:
    evidence = _safe_lobstertrap_evidence(record)
    action = _lobstertrap_action(record)
    rule_id = _lobstertrap_rule_id(record)
    direction = _pick_string(record, "direction")
    request_id = _pick_string(record, "request_id")
    agent_id = _pick_string(record, "agent_id")

    declared_headers = record.get("declared_headers")
    if agent_id is None and isinstance(declared_headers, dict):
        agent_id = _string_value(declared_headers.get("agent_id"))

    envelope: dict[str, Any] = {
        "schema": VEEA_LOBSTERTRAP_AUDIT_SCHEMA,
        "source": VEEA_LOBSTERTRAP_SOURCE,
        "layer": VEEA_LOBSTERTRAP_LAYER,
        "event_type": VEEA_LLM_INSPECTION_EVENT_TYPE,
        "direction": direction,
        "action": action,
        "decision": _lobstertrap_decision(action),
        "rule_id": rule_id,
        "summary": _lobstertrap_summary(action, rule_id, direction),
        "request_id": request_id,
        "agent_id": agent_id,
        "redacted": True,
        "evidence": evidence,
        "lobstertrap": {
            "request_id": request_id,
            "direction": direction,
            "detector": LOBSTERTRAP_DETECTOR,
        },
    }

    timestamp = _pick_string(record, "timestamp")
    if timestamp is not None:
        envelope["timestamp"] = timestamp

    return envelope


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


def build_unified_veea_audit_timeline(
    aiwatch_envelopes: Iterable[dict[str, Any]],
    lobstertrap_records: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    envelopes = [
        *aiwatch_envelopes,
        *(lobstertrap_record_to_veea_audit_envelope(record) for record in lobstertrap_records),
    ]
    return sorted(envelopes, key=_unified_timeline_sort_key)


def read_jsonl_objects(input_path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(input_path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue

        try:
            payload = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{input_path}:{line_number}: invalid JSONL: {error.msg}") from error

        if not isinstance(payload, dict):
            raise ValueError(f"{input_path}:{line_number}: expected JSON object")
        records.append(payload)

    return records


def _unified_timeline_sort_key(envelope: dict[str, Any]) -> tuple[int, str, str, str, str, str]:
    timestamp = envelope.get("timestamp")
    timestamp_text = timestamp if isinstance(timestamp, str) else ""
    source = str(envelope.get("source", ""))
    layer = str(envelope.get("layer", ""))
    event_type = str(envelope.get("event_type", ""))
    stable_id = (
        str(envelope.get("request_id") or "")
        or str(envelope.get("server_id") or "")
        or str(envelope.get("tool_name") or "")
    )

    aiwatch = envelope.get("aiwatch")
    if isinstance(aiwatch, dict):
        stable_id = str(aiwatch.get("event_id") or aiwatch.get("alert_id") or stable_id)

    lobstertrap = envelope.get("lobstertrap")
    if isinstance(lobstertrap, dict):
        stable_id = str(lobstertrap.get("request_id") or stable_id)

    return (0 if timestamp_text else 1, timestamp_text, source, layer, event_type, stable_id)


def render_veea_audit_jsonl(envelopes: Iterable[dict[str, Any]]) -> str:
    lines = [json.dumps(envelope, sort_keys=True, separators=(",", ":")) for envelope in envelopes]
    return "".join(f"{line}\n" for line in lines)


def write_veea_audit_jsonl(envelopes: Iterable[dict[str, Any]], output_path: Path) -> int:
    rendered = render_veea_audit_jsonl(envelopes)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    return 0 if not rendered else rendered.count("\n")
