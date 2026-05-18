from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from app.credential_redaction import redact_json_like
from app.schemas import Alert, Source

VEEA_AIWATCH_AUDIT_SCHEMA = "veea.aiwatch.audit.v1"
VEEA_AIWATCH_SOURCE = "aiwatch"
VEEA_AIWATCH_LAYER = "mcp_tool"
VEEA_SECURITY_ALERT_EVENT_TYPE = "security_alert"
AIWATCH_MCP_DETECTOR = "deterministic_mcp"
AIWATCH_UNSPECIFIED_TRANSPORT = "routed_mcp_unspecified"


def is_mcp_alert(alert: Alert) -> bool:
    return alert.source == Source.MCP or alert.rule_id.startswith("R-MCP-")


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


def build_veea_audit_envelopes(alerts: Iterable[Alert]) -> list[dict[str, Any]]:
    return [alert_to_veea_audit_envelope(alert) for alert in alerts if is_mcp_alert(alert)]


def render_veea_audit_jsonl(envelopes: Iterable[dict[str, Any]]) -> str:
    lines = [json.dumps(envelope, sort_keys=True, separators=(",", ":")) for envelope in envelopes]
    return "".join(f"{line}\n" for line in lines)


def write_veea_audit_jsonl(envelopes: Iterable[dict[str, Any]], output_path: Path) -> int:
    rendered = render_veea_audit_jsonl(envelopes)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    return 0 if not rendered else rendered.count("\n")
