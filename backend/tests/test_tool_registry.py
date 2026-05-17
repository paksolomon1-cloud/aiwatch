from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.demo_events import (
    benign_mcp_event,
    mcp_registry_baseline_event,
    mcp_registry_drift_event,
    mcp_registry_shadow_event,
)
from app.main import app
from app.storage import clear_db, init_db


def _configure_test_db(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AIWATCH_DB_PATH", str(tmp_path / "aiwatch-tools.db"))
    init_db()
    clear_db()


def _payload(event) -> dict[str, object]:
    return event.model_dump(mode="json", exclude={"event_id", "timestamp"})


def test_tool_fingerprint_creation_and_history(monkeypatch, tmp_path: Path) -> None:
    _configure_test_db(monkeypatch, tmp_path)

    event = benign_mcp_event(agent_id="mcp-client-demo", session_id="tools-001", server_id="notes-mcp")

    with TestClient(app) as client:
        create_response = client.post("/v1/events", json=_payload(event))
        assert create_response.status_code == 200
        assert create_response.json()["alerts_created"] == 0

        tools_response = client.get("/v1/tools")
        assert tools_response.status_code == 200
        tools = tools_response.json()
        assert len(tools) == 1
        assert tools[0]["server_id"] == "notes-mcp"
        assert tools[0]["tool_name"] == "list_files"
        assert tools[0]["name_hash"]
        assert tools[0]["description_hash"]
        assert tools[0]["schema_hash"]
        assert tools[0]["observation_count"] == 1

        fingerprint_id = tools[0]["fingerprint_id"]
        tool_response = client.get(f"/v1/tools/{fingerprint_id}")
        history_response = client.get(f"/v1/tools/{fingerprint_id}/history")

        assert tool_response.status_code == 200
        assert history_response.status_code == 200
        assert tool_response.json()["latest_event_id"] == create_response.json()["event_id"]
        assert len(history_response.json()) == 1
        assert history_response.json()[0]["event_id"] == create_response.json()["event_id"]

    clear_db()


def test_blank_description_still_creates_tool_fingerprint(monkeypatch, tmp_path: Path) -> None:
    _configure_test_db(monkeypatch, tmp_path)

    payload = {
        "source": "mcp",
        "agent_id": "blank-desc-demo",
        "session_id": "blank-desc-session",
        "action_type": "tool_register",
        "action_params": {
            "server_id": "blank-desc-mcp",
            "tool_name": "empty_description_tool",
        },
    }

    with TestClient(app) as client:
        create_response = client.post("/v1/events", json=payload)
        assert create_response.status_code == 200

        tools_response = client.get("/v1/tools")
        assert tools_response.status_code == 200
        tools = tools_response.json()
        assert len(tools) == 1
        assert tools[0]["tool_name"] == "empty_description_tool"
        assert tools[0]["description"] == ""
        assert tools[0]["description_hash"]

        fingerprint_id = tools[0]["fingerprint_id"]
        history_response = client.get(f"/v1/tools/{fingerprint_id}/history")
        assert history_response.status_code == 200
        assert len(history_response.json()) == 1
        assert history_response.json()[0]["description"] == ""

    clear_db()


def test_no_drift_on_repeated_identical_registration(monkeypatch, tmp_path: Path) -> None:
    _configure_test_db(monkeypatch, tmp_path)

    payload = _payload(mcp_registry_baseline_event())

    with TestClient(app) as client:
        first_response = client.post("/v1/events", json=payload)
        second_response = client.post("/v1/events", json=payload)

        assert first_response.status_code == 200
        assert second_response.status_code == 200
        assert "R-MCP-002" not in [alert["rule_id"] for alert in second_response.json()["alerts"]]

        alerts_response = client.get("/v1/alerts")
        rule_ids = [alert["rule_id"] for alert in alerts_response.json()]
        assert "R-MCP-002" not in rule_ids

    clear_db()


def test_missing_and_explicit_empty_schema_do_not_trigger_drift(monkeypatch, tmp_path: Path) -> None:
    _configure_test_db(monkeypatch, tmp_path)

    baseline_payload = {
        "source": "mcp",
        "agent_id": "schema-demo",
        "session_id": "schema-stability-001",
        "action_type": "tool_register",
        "action_params": {
            "server_id": "schema-demo-mcp",
            "tool_name": "schema_stable_tool",
            "description": "Schema stable tool.",
            "input_schema": {"type": "object"},
        },
    }
    repeated_payload = {
        "source": "mcp",
        "agent_id": "schema-demo",
        "session_id": "schema-stability-002",
        "action_type": "tool_register",
        "action_params": {
            "server_id": "schema-demo-mcp",
            "tool_name": "schema_stable_tool",
            "description": "Schema stable tool.",
            "input_schema": {"type": "object"},
            "output_schema": {},
        },
    }

    with TestClient(app) as client:
        first_response = client.post("/v1/events", json=baseline_payload)
        second_response = client.post("/v1/events", json=repeated_payload)

        assert first_response.status_code == 200
        assert second_response.status_code == 200
        assert "R-MCP-002" not in [alert["rule_id"] for alert in second_response.json()["alerts"]]

        alerts_response = client.get("/v1/alerts")
        rule_ids = [alert["rule_id"] for alert in alerts_response.json()]
        assert "R-MCP-002" not in rule_ids

    clear_db()


def test_drift_alert_on_changed_same_server_registration(monkeypatch, tmp_path: Path) -> None:
    _configure_test_db(monkeypatch, tmp_path)

    with TestClient(app) as client:
        baseline_response = client.post("/v1/events", json=_payload(mcp_registry_baseline_event()))
        drift_response = client.post("/v1/events", json=_payload(mcp_registry_drift_event()))

        assert baseline_response.status_code == 200
        assert drift_response.status_code == 200

        rule_ids = [alert["rule_id"] for alert in drift_response.json()["alerts"]]
        assert "R-MCP-002" in rule_ids

    clear_db()


def test_shadowing_alert_on_cross_server_duplicate_name(monkeypatch, tmp_path: Path) -> None:
    _configure_test_db(monkeypatch, tmp_path)

    with TestClient(app) as client:
        baseline_response = client.post("/v1/events", json=_payload(mcp_registry_baseline_event()))
        shadow_response = client.post("/v1/events", json=_payload(mcp_registry_shadow_event()))

        assert baseline_response.status_code == 200
        assert baseline_response.json()["alerts_created"] == 0
        assert shadow_response.status_code == 200

        rule_ids = [alert["rule_id"] for alert in shadow_response.json()["alerts"]]
        assert "R-MCP-004" in rule_ids

    clear_db()


def test_extended_seed_demo_creates_registry_alerts(monkeypatch, tmp_path: Path) -> None:
    _configure_test_db(monkeypatch, tmp_path)
    monkeypatch.setenv("AIWATCH_DEV_MODE", "true")

    with TestClient(app) as client:
        response = client.post("/v1/dev/seed-demo?extended=true")
        assert response.status_code == 200

        payload = response.json()
        assert payload["status"] == "ok"
        assert payload["events_created"] == 8
        assert payload["alerts_created"] == 10
        assert payload["tools_observed"] >= 2

        items = {item["name"]: item for item in payload["items"]}
        assert items["registry baseline MCP tool"]["rule_ids"] == []
        assert items["registry drift MCP tool"]["rule_ids"] == ["R-MCP-001", "R-MCP-002"]
        assert items["registry shadow MCP tool"]["rule_ids"] == ["R-MCP-004"]

        alert_rule_ids = [rule_id for item in payload["items"] for rule_id in item["rule_ids"]]
        assert "R-MCP-001" in alert_rule_ids
        assert "R-MCP-002" in alert_rule_ids
        assert "R-MCP-004" in alert_rule_ids

        tools_response = client.get("/v1/tools")
        assert tools_response.status_code == 200
        assert len(tools_response.json()) >= 2

    clear_db()
