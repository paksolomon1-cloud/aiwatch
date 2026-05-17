from __future__ import annotations

import json

from app.demo_events import benign_coding_event, malicious_coding_event, poisoned_mcp_event
from app.detector import detect_alerts
from app.schemas import ActionType, AgentEvent, Severity, Source


def test_benign_coding_event_has_no_alerts() -> None:
    alerts = detect_alerts(benign_coding_event())
    assert alerts == []


def test_malicious_coding_event_creates_secret_network_and_base64_alerts() -> None:
    alerts = detect_alerts(malicious_coding_event())
    rule_ids = {alert.rule_id for alert in alerts}

    assert len(alerts) >= 3
    assert {"R-CODE-001", "R-CODE-002", "R-CODE-003"}.issubset(rule_ids)
    assert any(alert.severity == Severity.CRITICAL for alert in alerts)


def test_poisoned_mcp_event_creates_mcp_alert() -> None:
    alerts = detect_alerts(poisoned_mcp_event())

    assert any(alert.rule_id == "R-MCP-001" for alert in alerts)
    assert any(alert.severity == Severity.CRITICAL for alert in alerts)


def test_intent_action_mismatch() -> None:
    event = AgentEvent(
        source=Source.CODING_AGENT,
        intent_text="I will summarize the project by reading the README.",
        action_type=ActionType.SHELL_EXEC,
        action_params={"command": "cat .env"},
    )

    alerts = detect_alerts(event)

    assert any(alert.rule_id == "R-INTENT-001" for alert in alerts)


def _mcp_tool_call_event(arguments: object) -> AgentEvent:
    return AgentEvent(
        source=Source.MCP,
        agent_id="mcp-client",
        session_id="credential-test",
        action_type=ActionType.TOOL_CALL,
        action_params={
            "server_id": "notes-mcp",
            "tool_name": "export_notes",
            "arguments": arguments,
        },
    )


def test_openai_like_key_in_tool_call_arguments_triggers_redacted_alert() -> None:
    raw_secret = "sk-proj-1234567890abcdefABCDEF1234567890"
    alerts = detect_alerts(_mcp_tool_call_event({"api_key": raw_secret}))

    assert [alert.rule_id for alert in alerts] == ["R-MCP-005"]
    evidence_text = json.dumps(alerts[0].evidence.model_dump(mode="json"))
    assert alerts[0].severity == Severity.CRITICAL
    assert alerts[0].decision == "block"
    assert "openai_key_like" in evidence_text
    assert "[REDACTED:OPENAI_KEY]" in evidence_text
    assert raw_secret not in evidence_text


def test_github_like_token_triggers_credential_alert() -> None:
    raw_secret = "ghp_1234567890abcdefABCDEF1234567890abcdef"
    alerts = detect_alerts(_mcp_tool_call_event({"access_token": raw_secret}))

    finding = alerts[0].evidence.credential_findings[0]
    assert alerts[0].rule_id == "R-MCP-005"
    assert finding["secret_type"] == "github_token_like"
    assert finding["redacted_value"] == "[REDACTED:GITHUB_TOKEN]"
    assert finding["param_path"] == "params.arguments.access_token"


def test_aws_access_key_triggers_credential_alert() -> None:
    raw_secret = "AKIAIOSFODNN7EXAMPLE"
    alerts = detect_alerts(_mcp_tool_call_event({"aws_key_id": raw_secret}))

    assert alerts[0].rule_id == "R-MCP-005"
    assert alerts[0].evidence.credential_findings[0]["secret_type"] == "aws_access_key_like"


def test_private_key_block_triggers_credential_alert() -> None:
    raw_secret = "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----"
    alerts = detect_alerts(_mcp_tool_call_event({"private_key": raw_secret}))

    assert alerts[0].rule_id == "R-MCP-005"
    assert alerts[0].evidence.credential_findings[0]["secret_type"] == "private_key_like"


def test_nested_secret_path_is_reported() -> None:
    raw_secret = "Bearer abcdefghijklmnopqrstuvwxyz123456"
    alerts = detect_alerts(
        _mcp_tool_call_event(
            {
                "metadata": {
                    "headers": [
                        {
                            "authorization": raw_secret,
                        }
                    ]
                }
            }
        )
    )

    finding = alerts[0].evidence.credential_findings[0]
    assert finding["secret_type"] == "bearer_token_like"
    assert finding["param_path"] == "params.arguments.metadata.headers[0].authorization"


def test_multiple_secrets_are_redacted_without_raw_values() -> None:
    openai_secret = "sk-1234567890abcdefABCDEF1234567890"
    github_secret = "github_pat_1234567890abcdefABCDEF1234567890abcdef"
    alerts = detect_alerts(
        _mcp_tool_call_event(
            {
                "api_key": openai_secret,
                "nested": {"token": github_secret},
            }
        )
    )

    evidence_text = json.dumps(alerts[0].evidence.model_dump(mode="json"))
    assert len(alerts[0].evidence.credential_findings) == 2
    assert "[REDACTED:OPENAI_KEY]" in evidence_text
    assert "[REDACTED:GITHUB_TOKEN]" in evidence_text
    assert openai_secret not in evidence_text
    assert github_secret not in evidence_text


def test_suspicious_key_name_with_high_entropy_value_triggers_generic_secret_alert() -> None:
    raw_secret = "dGhpc19sb29rc19saWtlX2hpZ2hfZW50cm9weV8xMjM0NQ"
    alerts = detect_alerts(_mcp_tool_call_event({"client_secret": raw_secret}))

    evidence_text = json.dumps(alerts[0].evidence.model_dump(mode="json"))
    assert alerts[0].rule_id == "R-MCP-005"
    assert "generic_secret_like" in evidence_text
    assert "[REDACTED:GENERIC_SECRET]" in evidence_text
    assert raw_secret not in evidence_text


def test_benign_tool_call_arguments_do_not_trigger() -> None:
    alerts = detect_alerts(
        _mcp_tool_call_event(
            {
                "query": "password rotation policy",
                "limit": 10,
                "labels": ["public", "demo"],
            }
        )
    )

    assert alerts == []


def test_suspicious_key_name_with_short_value_does_not_trigger() -> None:
    alerts = detect_alerts(_mcp_tool_call_event({"token": "demo"}))

    assert alerts == []


def test_short_secret_named_values_do_not_trigger() -> None:
    alerts = detect_alerts(
        _mcp_tool_call_event(
            {
                "token": "abc",
                "password": "test",
                "api_key": "none",
            }
        )
    )

    assert alerts == []


def test_benign_nested_arguments_do_not_trigger() -> None:
    alerts = detect_alerts(
        _mcp_tool_call_event(
            {
                "filters": [
                    {
                        "field": "password_status",
                        "value": "rotated",
                    }
                ],
                "metadata": {
                    "owner": "demo-user",
                    "purpose": "audit password policy text",
                },
            }
        )
    )

    assert alerts == []


def test_secret_in_nested_params_arguments_is_redacted_even_when_top_level_arguments_exist() -> None:
    raw_secret = "github_pat_1234567890abcdefABCDEF1234567890abcdef"
    event = AgentEvent(
        source=Source.MCP,
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
    )

    alerts = detect_alerts(event)
    evidence_text = json.dumps(alerts[0].evidence.model_dump(mode="json"))

    assert alerts[0].rule_id == "R-MCP-005"
    assert "github_token_like" in evidence_text
    assert "[REDACTED:GITHUB_TOKEN]" in evidence_text
    assert raw_secret not in evidence_text
