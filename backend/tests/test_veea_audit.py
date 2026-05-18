from __future__ import annotations

import json
from pathlib import Path

from app.cli import main as cli_main
from app.demo_events import malicious_coding_event, poisoned_mcp_event
from app.detector import detect_alerts
from app.schemas import ActionType, AgentEvent, Source
from app.storage import clear_db, ingest_event, init_db, list_alerts, list_events
from app.veea_audit import (
    build_veea_audit_envelopes,
    build_veea_audit_timeline,
    build_veea_observation_envelopes,
)


def _configure_test_db(monkeypatch, tmp_path: Path) -> Path:
    db_path = tmp_path / "aiwatch-veea-audit.db"
    monkeypatch.setenv("AIWATCH_DB_PATH", str(db_path))
    init_db()
    clear_db()
    return db_path


def _credential_tool_call_event(raw_secret: str) -> AgentEvent:
    return AgentEvent(
        event_id="veea-audit-r-mcp-005-event",
        source=Source.MCP,
        agent_id="mcp-client",
        session_id="veea-audit-credential-session",
        action_type=ActionType.TOOL_CALL,
        action_params={
            "server_id": "notes-mcp",
            "tool_name": "export_notes",
            "arguments": {
                "api_key": raw_secret,
                "format": "json",
            },
        },
        raw={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "export_notes",
                "arguments": {"api_key": raw_secret},
            },
        },
    )


def test_veea_audit_mapper_exports_mcp_alert_envelope() -> None:
    [alert] = detect_alerts(
        poisoned_mcp_event(
            agent_id="mcp-client",
            session_id="veea-audit-poisoned-session",
            server_id="fixture-notes-mcp",
        )
    )

    [envelope] = build_veea_audit_envelopes([alert])

    assert envelope["schema"] == "veea.aiwatch.audit.v1"
    assert envelope["source"] == "aiwatch"
    assert envelope["layer"] == "mcp_tool"
    assert envelope["event_type"] == "security_alert"
    assert envelope["rule_id"] == "R-MCP-001"
    assert envelope["timestamp"]
    assert envelope["server_id"] == "fixture-notes-mcp"
    assert envelope["tool_name"] == "list_notes"
    assert envelope["aiwatch"]["alert_id"] == alert.alert_id
    assert envelope["aiwatch"]["event_id"] == alert.event_ids[0]
    assert envelope["aiwatch"]["transport"] == "routed_mcp_unspecified"
    assert envelope["aiwatch"]["detector"] == "deterministic_mcp"


def test_veea_audit_export_filters_non_mcp_alerts() -> None:
    [coding_alert] = detect_alerts(malicious_coding_event())[:1]

    assert build_veea_audit_envelopes([coding_alert]) == []


def test_veea_audit_mapper_exports_mcp_observation_envelope() -> None:
    event = poisoned_mcp_event(
        agent_id="mcp-client",
        session_id="veea-audit-observation-session",
        server_id="fixture-notes-mcp",
    )

    [envelope] = build_veea_observation_envelopes([event])

    assert envelope["schema"] == "veea.aiwatch.audit.v1"
    assert envelope["source"] == "aiwatch"
    assert envelope["layer"] == "mcp_tool"
    assert envelope["event_type"] == "mcp_observation"
    assert envelope["observation_type"] == "tool_register"
    assert envelope["timestamp"]
    assert envelope["server_id"] == "fixture-notes-mcp"
    assert envelope["tool_name"] == "list_notes"
    assert envelope["session_id"] == "veea-audit-observation-session"
    assert envelope["agent_id"] == "mcp-client"
    assert envelope["redacted"] is False
    assert envelope["evidence"]["action_params"]["tool_name"] == "list_notes"
    assert envelope["aiwatch"] == {
        "event_id": event.event_id,
        "source": "mcp",
        "transport": "routed_mcp_unspecified",
        "detector": None,
    }


def test_veea_audit_timeline_exports_mcp_observation_and_alert_in_order(
    monkeypatch,
    tmp_path: Path,
) -> None:
    _configure_test_db(monkeypatch, tmp_path)
    event = poisoned_mcp_event(
        agent_id="mcp-client",
        session_id="veea-audit-timeline-session",
        server_id="fixture-notes-mcp",
    )

    ingest_event(event)

    timeline = build_veea_audit_timeline(list_events(), list_alerts())

    assert [envelope["event_type"] for envelope in timeline] == ["mcp_observation", "security_alert"]
    assert timeline[0]["aiwatch"]["event_id"] == event.event_id
    assert timeline[1]["rule_id"] == "R-MCP-001"

    clear_db()


def test_veea_audit_timeline_filters_non_mcp_observations_and_alerts(
    monkeypatch,
    tmp_path: Path,
) -> None:
    _configure_test_db(monkeypatch, tmp_path)

    ingest_event(malicious_coding_event())

    assert build_veea_audit_timeline(list_events(), list_alerts()) == []

    clear_db()


def test_veea_audit_export_preserves_redaction_without_raw_secret(monkeypatch, tmp_path: Path) -> None:
    _configure_test_db(monkeypatch, tmp_path)
    raw_secret = "sk-1234567890abcdefABCDEF1234567890"

    ingest_event(_credential_tool_call_event(raw_secret))

    [envelope] = build_veea_audit_envelopes(list_alerts())
    rendered = json.dumps(envelope, sort_keys=True)

    assert envelope["rule_id"] == "R-MCP-005"
    assert envelope["redacted"] is True
    assert envelope["server_id"] == "notes-mcp"
    assert envelope["tool_name"] == "export_notes"
    assert raw_secret not in rendered
    assert "[REDACTED:OPENAI_KEY]" in rendered

    clear_db()


def test_veea_audit_timeline_preserves_event_and_alert_redaction(
    monkeypatch,
    tmp_path: Path,
) -> None:
    _configure_test_db(monkeypatch, tmp_path)
    raw_secret = "sk-1234567890abcdefABCDEF1234567890"

    ingest_event(_credential_tool_call_event(raw_secret))

    timeline = build_veea_audit_timeline(list_events(), list_alerts())
    rendered = json.dumps(timeline, sort_keys=True)

    assert [envelope["event_type"] for envelope in timeline] == ["mcp_observation", "security_alert"]
    assert all(envelope["redacted"] is True for envelope in timeline)
    assert raw_secret not in rendered
    assert "[REDACTED:OPENAI_KEY]" in rendered

    clear_db()


def test_export_veea_audit_cli_writes_valid_jsonl(monkeypatch, tmp_path: Path, capsys) -> None:
    _configure_test_db(monkeypatch, tmp_path)
    raw_secret = "sk-1234567890abcdefABCDEF1234567890"
    output_path = tmp_path / "veea-aiwatch-audit.jsonl"

    ingest_event(_credential_tool_call_event(raw_secret))

    assert cli_main(["export-veea-audit", "--out", str(output_path)]) == 0
    output = capsys.readouterr().out
    lines = output_path.read_text(encoding="utf-8").splitlines()

    assert "Exported 1 AIWatch MCP alert audit envelopes" in output
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["schema"] == "veea.aiwatch.audit.v1"
    assert payload["rule_id"] == "R-MCP-005"
    assert payload["redacted"] is True
    assert raw_secret not in lines[0]
    assert "[REDACTED:OPENAI_KEY]" in lines[0]

    clear_db()


def test_export_veea_audit_cli_timeline_writes_valid_jsonl(monkeypatch, tmp_path: Path, capsys) -> None:
    _configure_test_db(monkeypatch, tmp_path)
    raw_secret = "sk-1234567890abcdefABCDEF1234567890"
    output_path = tmp_path / "veea-aiwatch-timeline.jsonl"

    ingest_event(_credential_tool_call_event(raw_secret))

    assert cli_main(["export-veea-audit", "--timeline", "--out", str(output_path)]) == 0
    output = capsys.readouterr().out
    lines = output_path.read_text(encoding="utf-8").splitlines()

    assert "Exported 2 AIWatch MCP audit timeline records" in output
    assert len(lines) == 2
    payloads = [json.loads(line) for line in lines]
    assert [payload["event_type"] for payload in payloads] == ["mcp_observation", "security_alert"]
    assert payloads[0]["observation_type"] == "tool_call"
    assert payloads[1]["rule_id"] == "R-MCP-005"
    assert raw_secret not in "\n".join(lines)
    assert "[REDACTED:OPENAI_KEY]" in "\n".join(lines)

    clear_db()


def test_export_veea_audit_cli_handles_empty_alerts(monkeypatch, tmp_path: Path, capsys) -> None:
    _configure_test_db(monkeypatch, tmp_path)
    output_path = tmp_path / "empty-veea-aiwatch-audit.jsonl"

    assert cli_main(["export-veea-audit", "--out", str(output_path)]) == 0
    output = capsys.readouterr().out

    assert output_path.read_text(encoding="utf-8") == ""
    assert "Exported 0 AIWatch MCP alert audit envelopes" in output

    clear_db()


def test_export_veea_audit_cli_timeline_handles_empty_database(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    _configure_test_db(monkeypatch, tmp_path)
    output_path = tmp_path / "empty-veea-aiwatch-timeline.jsonl"

    assert cli_main(["export-veea-audit", "--timeline", "--out", str(output_path)]) == 0
    output = capsys.readouterr().out

    assert output_path.read_text(encoding="utf-8") == ""
    assert "Exported 0 AIWatch MCP audit timeline records" in output

    clear_db()
