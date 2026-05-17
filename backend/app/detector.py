from __future__ import annotations

import re

from app.credential_redaction import redact_mcp_tool_call_action_params
from app.schemas import ActionType, AgentEvent, Alert, AlertEvidence, Severity, Source

SENSITIVE_PATTERNS = [".env", "id_rsa", "credentials", ".pem", "OPENAI_API_KEY", "AWS_SECRET"]
NETWORK_PATTERNS = ["curl ", "wget ", "Invoke-WebRequest", "http://", "https://"]
MCP_INJECTION_PATTERNS = [
    "ignore previous",
    "before returning",
    "you must",
    "read ~/.aws",
    "read .env",
    "include the contents",
]
INTENT_ALLOWED_TERMS = [".env", "environment", "secret", "credential"]
URL_PATTERN = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)


def _get_command(event: AgentEvent) -> str:
    command = event.action_params.get("command", "")
    return command if isinstance(command, str) else ""


def _match_patterns(text: str, patterns: list[str]) -> list[str]:
    lowered = text.lower()
    return [pattern for pattern in patterns if pattern.lower() in lowered]


def _extract_destinations(text: str) -> list[str]:
    return URL_PATTERN.findall(text)


def _extract_file_refs(patterns: list[str]) -> list[str]:
    file_refs: list[str] = []
    for pattern in patterns:
        lowered = pattern.lower()
        if "." in pattern or "/" in pattern or "~" in pattern or lowered == "credentials":
            file_refs.append(pattern)
    return file_refs


def _action_summary(event: AgentEvent) -> str:
    if event.action_type == ActionType.SHELL_EXEC:
        return f"shell_exec: {_get_command(event)}"
    if event.action_type == ActionType.TOOL_REGISTER:
        tool_name = event.action_params.get("tool_name", "unknown")
        return f"tool_register: {tool_name}"
    if event.action_type == ActionType.TOOL_CALL:
        tool_name = event.action_params.get("tool_name")
        if not isinstance(tool_name, str):
            params = event.action_params.get("params")
            tool_name = params.get("name") if isinstance(params, dict) else "unknown"
        return f"tool_call: {tool_name if isinstance(tool_name, str) else 'unknown'}"
    return f"{event.action_type}: {event.action_params}"


def _make_alert(
    event: AgentEvent,
    *,
    rule_id: str,
    severity: Severity,
    summary: str,
    rationale: str,
    matched_patterns: list[str] | None = None,
    files_referenced: list[str] | None = None,
    destinations: list[str] | None = None,
    tool_name: str | None = None,
    server_id: str | None = None,
    decision: str = "log",
) -> Alert:
    return Alert(
        severity=severity,
        rule_id=rule_id,
        source=event.source,
        agent_id=event.agent_id,
        session_id=event.session_id,
        event_ids=[event.event_id],
        summary=summary,
        rationale=rationale,
        evidence=AlertEvidence(
            intent_text=event.intent_text,
            action_summary=_action_summary(event),
            matched_patterns=matched_patterns or [],
            files_referenced=files_referenced or [],
            destinations=destinations or [],
            tool_name=tool_name,
            server_id=server_id,
        ),
        decision=decision,
    )


def detect_alerts(event: AgentEvent) -> list[Alert]:
    alerts: list[Alert] = []

    if event.action_type == ActionType.SHELL_EXEC:
        command = _get_command(event)
        secret_matches = _match_patterns(command, SENSITIVE_PATTERNS)
        if secret_matches:
            alerts.append(
                _make_alert(
                    event,
                    rule_id="R-CODE-001",
                    severity=Severity.CRITICAL,
                    summary="Secret file or credential access detected",
                    rationale=(
                        "The shell command references sensitive files or credential patterns, "
                        "which indicates access to privileged material."
                    ),
                    matched_patterns=secret_matches,
                    files_referenced=_extract_file_refs(secret_matches),
                    destinations=_extract_destinations(command),
                    decision="block",
                )
            )

        network_matches = _match_patterns(command, NETWORK_PATTERNS)
        if network_matches:
            alerts.append(
                _make_alert(
                    event,
                    rule_id="R-CODE-002",
                    severity=Severity.HIGH,
                    summary="Outbound network command detected",
                    rationale=(
                        "The shell command invokes network tooling or references an external URL, "
                        "indicating outbound communication."
                    ),
                    matched_patterns=network_matches,
                    destinations=_extract_destinations(command),
                    decision="log",
                )
            )

        lowered_command = command.lower()
        if "base64" in lowered_command and ("curl" in lowered_command or "wget" in lowered_command):
            matched_patterns = ["base64"]
            if "curl" in lowered_command:
                matched_patterns.append("curl")
            if "wget" in lowered_command:
                matched_patterns.append("wget")

            alerts.append(
                _make_alert(
                    event,
                    rule_id="R-CODE-003",
                    severity=Severity.CRITICAL,
                    summary="Possible encoded data exfiltration",
                    rationale=(
                        "The shell command combines base64 encoding with curl or wget, which is a "
                        "deterministic exfiltration signal."
                    ),
                    matched_patterns=matched_patterns,
                    destinations=_extract_destinations(command),
                    decision="block",
                )
            )

        if event.intent_text and ".env" in lowered_command:
            lowered_intent = event.intent_text.lower()
            if not any(term in lowered_intent for term in INTENT_ALLOWED_TERMS):
                alerts.append(
                    _make_alert(
                        event,
                        rule_id="R-INTENT-001",
                        severity=Severity.HIGH,
                        summary="Intent/action mismatch on sensitive file access",
                        rationale=(
                            "The model's stated intent does not justify reading a sensitive file "
                            "such as .env."
                        ),
                        matched_patterns=[".env"],
                        files_referenced=[".env"],
                        destinations=_extract_destinations(command),
                        decision="log",
                    )
                )

    if event.source == Source.MCP and event.action_type == ActionType.TOOL_REGISTER:
        description = event.action_params.get("description", "")
        if isinstance(description, str):
            injection_matches = _match_patterns(description, MCP_INJECTION_PATTERNS)
            if injection_matches:
                tool_name = event.action_params.get("tool_name")
                server_id = event.action_params.get("server_id")
                alerts.append(
                    _make_alert(
                        event,
                        rule_id="R-MCP-001",
                        severity=Severity.CRITICAL,
                        summary="Poisoned MCP tool description detected",
                        rationale=(
                            "The MCP tool description contains prompt-injection language or direct "
                            "instructions to disclose sensitive contents."
                        ),
                        matched_patterns=injection_matches,
                        files_referenced=_extract_file_refs(injection_matches),
                        tool_name=tool_name if isinstance(tool_name, str) else None,
                        server_id=server_id if isinstance(server_id, str) else None,
                        decision="block",
                    )
                )

    if event.source == Source.MCP and event.action_type == ActionType.TOOL_CALL:
        findings: list[dict[str, object]] = []
        existing_findings = event.action_params.get("credential_findings")
        if isinstance(existing_findings, list):
            findings = [finding for finding in existing_findings if isinstance(finding, dict)]
        else:
            sanitized_params, findings = redact_mcp_tool_call_action_params(event.action_params)
            credential_findings = sanitized_params.get("credential_findings")
            if isinstance(credential_findings, list):
                findings = [finding for finding in credential_findings if isinstance(finding, dict)]

        if findings:
            params = event.action_params.get("params")
            tool_name = event.action_params.get("tool_name")
            if not isinstance(tool_name, str) and isinstance(params, dict):
                tool_name = params.get("name")
            server_id = event.action_params.get("server_id")
            alerts.append(
                Alert(
                    severity=Severity.CRITICAL,
                    rule_id="R-MCP-005",
                    source=event.source,
                    agent_id=event.agent_id,
                    session_id=event.session_id,
                    event_ids=[event.event_id],
                    summary="Credential-shaped value in MCP tool call parameters",
                    rationale=(
                        "The MCP tools/call arguments contain values that match known credential "
                        "formats or suspicious secret-like parameter names."
                    ),
                    evidence=AlertEvidence(
                        intent_text=event.intent_text,
                        action_summary=_action_summary(event),
                        matched_patterns=sorted({str(finding.get("secret_type")) for finding in findings}),
                        tool_name=tool_name if isinstance(tool_name, str) else None,
                        server_id=server_id if isinstance(server_id, str) else None,
                        credential_findings=findings,
                    ),
                    decision="block",
                )
            )

    return alerts
