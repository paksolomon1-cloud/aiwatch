from __future__ import annotations

import json
import pytest
import sqlite3
from pathlib import Path

from app.schemas import ActionType, AgentEvent, Source
import app.storage as storage_module
import app.tool_registry as tool_registry_module
from app.demo_events import benign_coding_event, malicious_coding_event
from app.demo_events import mcp_registry_baseline_event, mcp_registry_drift_event, poisoned_mcp_event
from app.detector import detect_alerts
from app.storage import (
    clear_db,
    get_tool_fingerprint,
    get_tool_history,
    get_session_alerts,
    get_session_events,
    ingest_event,
    init_db,
    insert_alert,
    insert_event,
    list_alerts,
    list_events,
    list_tools,
)


def _configure_test_db(monkeypatch, tmp_path: Path) -> Path:
    db_path = tmp_path / "aiwatch-test.db"
    monkeypatch.setenv("AIWATCH_DB_PATH", str(db_path))
    return db_path


def test_init_db_creates_tables(monkeypatch, tmp_path: Path) -> None:
    db_path = _configure_test_db(monkeypatch, tmp_path)

    init_db()

    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()

    table_names = {row[0] for row in rows}
    assert {"events", "alerts", "tool_fingerprints", "tool_observations"}.issubset(table_names)


def test_insert_event_then_list_events_returns_event(monkeypatch, tmp_path: Path) -> None:
    _configure_test_db(monkeypatch, tmp_path)
    init_db()
    clear_db()
    event = benign_coding_event()

    insert_event(event)
    events = list_events()

    assert len(events) == 1
    assert events[0].event_id == event.event_id
    assert events[0].action_params == event.action_params


def test_insert_alert_then_list_alerts_returns_alert(monkeypatch, tmp_path: Path) -> None:
    _configure_test_db(monkeypatch, tmp_path)
    init_db()
    clear_db()
    event = malicious_coding_event()
    alert = detect_alerts(event)[0]

    insert_alert(alert)
    alerts = list_alerts()

    assert len(alerts) == 1
    assert alerts[0].alert_id == alert.alert_id
    assert alerts[0].rule_id == alert.rule_id


def test_get_session_events_filters_by_session_id(monkeypatch, tmp_path: Path) -> None:
    _configure_test_db(monkeypatch, tmp_path)
    init_db()
    clear_db()
    matching_event = benign_coding_event()
    matching_event.session_id = "match-session"
    other_event = benign_coding_event()
    other_event.session_id = "other-session"

    insert_event(matching_event)
    insert_event(other_event)
    session_events = get_session_events("match-session")

    assert len(session_events) == 1
    assert session_events[0].session_id == "match-session"


def test_get_session_alerts_filters_by_session_id(monkeypatch, tmp_path: Path) -> None:
    _configure_test_db(monkeypatch, tmp_path)
    init_db()
    clear_db()
    matching_event = malicious_coding_event()
    matching_event.session_id = "match-session"
    other_event = malicious_coding_event()
    other_event.session_id = "other-session"
    matching_alert = detect_alerts(matching_event)[0]
    other_alert = detect_alerts(other_event)[0]

    insert_alert(matching_alert)
    insert_alert(other_alert)
    session_alerts = get_session_alerts("match-session")

    assert len(session_alerts) == 1
    assert session_alerts[0].session_id == "match-session"


def test_clear_db_removes_all_rows(monkeypatch, tmp_path: Path) -> None:
    _configure_test_db(monkeypatch, tmp_path)
    init_db()
    clear_db()
    event = benign_coding_event()
    alert = detect_alerts(malicious_coding_event())[0]

    insert_event(event)
    insert_alert(alert)
    clear_db()

    assert list_events() == []
    assert list_alerts() == []


def test_ingest_event_rolls_back_when_alert_persistence_fails_after_event_insert(
    monkeypatch,
    tmp_path: Path,
) -> None:
    _configure_test_db(monkeypatch, tmp_path)
    init_db()
    clear_db()

    event = malicious_coding_event()
    original_insert_alert = storage_module.insert_alert
    calls = {"count": 0}

    def fail_on_second_alert(alert, *, connection=None):
        calls["count"] += 1
        if calls["count"] == 2:
            raise RuntimeError("forced alert insert failure")
        return original_insert_alert(alert, connection=connection)

    monkeypatch.setattr(storage_module, "insert_alert", fail_on_second_alert)

    with pytest.raises(RuntimeError, match="forced alert insert failure"):
        ingest_event(event)

    assert list_events() == []
    assert list_alerts() == []


def test_ingest_event_rolls_back_when_registry_current_row_update_fails(
    monkeypatch,
    tmp_path: Path,
) -> None:
    _configure_test_db(monkeypatch, tmp_path)
    init_db()
    clear_db()

    event = mcp_registry_baseline_event()
    observation = tool_registry_module.build_tool_observation(event)
    assert observation is not None

    def fail_upsert_tool_fingerprint(tool, *, connection=None):
        raise RuntimeError("forced registry current row failure")

    monkeypatch.setattr(tool_registry_module, "upsert_tool_fingerprint", fail_upsert_tool_fingerprint)

    with pytest.raises(RuntimeError, match="forced registry current row failure"):
        ingest_event(event)

    assert list_events() == []
    assert get_tool_fingerprint(observation.fingerprint_id) is None
    assert get_tool_history(observation.fingerprint_id) == []


def test_ingest_event_rolls_back_when_registry_history_write_fails(
    monkeypatch,
    tmp_path: Path,
) -> None:
    _configure_test_db(monkeypatch, tmp_path)
    init_db()
    clear_db()

    event = mcp_registry_baseline_event()
    observation = tool_registry_module.build_tool_observation(event)
    assert observation is not None

    def fail_insert_tool_observation(observation, *, connection=None):
        raise RuntimeError("forced registry history failure")

    monkeypatch.setattr(tool_registry_module, "insert_tool_observation", fail_insert_tool_observation)

    with pytest.raises(RuntimeError, match="forced registry history failure"):
        ingest_event(event)

    assert list_events() == []
    assert get_tool_fingerprint(observation.fingerprint_id) is None
    assert get_tool_history(observation.fingerprint_id) == []
    assert list_alerts() == []


def test_ingest_event_rolls_back_when_alert_insert_fails_after_registry_update(
    monkeypatch,
    tmp_path: Path,
) -> None:
    _configure_test_db(monkeypatch, tmp_path)
    init_db()
    clear_db()

    baseline_event = mcp_registry_baseline_event()
    ingest_event(baseline_event)

    observation = tool_registry_module.build_tool_observation(baseline_event)
    assert observation is not None
    baseline_tool = get_tool_fingerprint(observation.fingerprint_id)
    assert baseline_tool is not None
    assert len(get_tool_history(observation.fingerprint_id)) == 1

    drift_event = mcp_registry_drift_event()
    original_insert_alert = storage_module.insert_alert
    calls = {"count": 0}

    def fail_on_second_alert(alert, *, connection=None):
        calls["count"] += 1
        if calls["count"] == 2:
            raise RuntimeError("forced post-registry alert failure")
        return original_insert_alert(alert, connection=connection)

    monkeypatch.setattr(storage_module, "insert_alert", fail_on_second_alert)

    with pytest.raises(RuntimeError, match="forced post-registry alert failure"):
        ingest_event(drift_event)

    events = list_events()
    assert len(events) == 1
    assert events[0].event_id == baseline_event.event_id

    current_tool = get_tool_fingerprint(observation.fingerprint_id)
    assert current_tool is not None
    assert current_tool.latest_event_id == baseline_tool.latest_event_id
    assert current_tool.observation_count == baseline_tool.observation_count
    assert current_tool.drift_count == baseline_tool.drift_count
    assert len(get_tool_history(observation.fingerprint_id)) == 1
    assert list_alerts() == []


def test_ingest_event_persists_event_registry_history_and_alerts_for_mcp_tool(
    monkeypatch,
    tmp_path: Path,
) -> None:
    _configure_test_db(monkeypatch, tmp_path)
    init_db()
    clear_db()

    event = poisoned_mcp_event(
        agent_id="atomic-mcp-client",
        session_id="atomic-poisoned-session",
        server_id="atomic-notes-mcp",
    )

    alerts = ingest_event(event)

    assert [alert.rule_id for alert in alerts] == ["R-MCP-001"]

    events = list_events()
    assert len(events) == 1
    assert events[0].event_id == event.event_id

    tools = list_tools()
    assert len(tools) == 1
    assert tools[0].server_id == "atomic-notes-mcp"
    assert tools[0].tool_name == "list_notes"
    assert tools[0].latest_event_id == event.event_id

    history = get_tool_history(tools[0].fingerprint_id)
    assert len(history) == 1
    assert history[0].event_id == event.event_id

    stored_alerts = list_alerts()
    assert len(stored_alerts) == 1
    assert stored_alerts[0].rule_id == "R-MCP-001"


def test_ingest_event_redacts_tool_call_secrets_before_sqlite_persistence(
    monkeypatch,
    tmp_path: Path,
) -> None:
    db_path = _configure_test_db(monkeypatch, tmp_path)
    init_db()
    clear_db()
    raw_secret = "github_pat_1234567890abcdefABCDEF1234567890abcdef"

    event = AgentEvent(
        source=Source.MCP,
        agent_id="raw-sql-audit",
        session_id="raw-sql-audit-session",
        action_type=ActionType.TOOL_CALL,
        action_params={
            "server_id": "notes-mcp",
            "tool_name": "export_notes",
            "arguments": {"format": "json"},
            "params": {
                "name": "export_notes",
                "arguments": {"access_token": raw_secret},
            },
        },
        raw={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "export_notes",
                "arguments": {"access_token": raw_secret},
            },
        },
    )

    alerts = ingest_event(event)

    assert [alert.rule_id for alert in alerts] == ["R-MCP-005"]

    with sqlite3.connect(db_path) as connection:
        event_row = connection.execute(
            "SELECT action_params_json, raw_json FROM events WHERE event_id = ?",
            (event.event_id,),
        ).fetchone()
        alert_row = connection.execute(
            "SELECT evidence_json FROM alerts WHERE rule_id = 'R-MCP-005'",
        ).fetchone()

    persisted_text = json.dumps(
        {
            "action_params_json": event_row[0],
            "raw_json": event_row[1],
            "evidence_json": alert_row[0],
        }
    )
    assert raw_secret not in persisted_text
    assert "[REDACTED:GITHUB_TOKEN]" in persisted_text

    action_params = json.loads(event_row[0])
    raw_frame = json.loads(event_row[1])
    evidence = json.loads(alert_row[0])

    assert action_params["params"]["arguments"]["access_token"] == "[REDACTED:GITHUB_TOKEN]"
    assert raw_frame["params"]["arguments"]["access_token"] == "[REDACTED:GITHUB_TOKEN]"
    assert evidence["credential_findings"][0] == {
        "param_path": "params.arguments.access_token",
        "secret_type": "github_token_like",
        "redacted_value": "[REDACTED:GITHUB_TOKEN]",
        "value_length": len(raw_secret),
    }
