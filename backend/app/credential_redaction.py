from __future__ import annotations

import re
from copy import deepcopy
from typing import Any

from app.schemas import ActionType, AgentEvent, Source

_OPENAI_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")
_GITHUB_TOKEN_RE = re.compile(r"\b(?:ghp_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_BEARER_TOKEN_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b", re.IGNORECASE)

_SUSPICIOUS_KEY_NAMES = {
    "apikey",
    "api_key",
    "token",
    "access_token",
    "accesstoken",
    "secret",
    "password",
    "private_key",
    "privatekey",
    "client_secret",
    "clientsecret",
    "session_cookie",
    "sessioncookie",
    "authorization",
}

_REDACTED_BY_TYPE = {
    "openai_key_like": "[REDACTED:OPENAI_KEY]",
    "github_token_like": "[REDACTED:GITHUB_TOKEN]",
    "aws_access_key_like": "[REDACTED:AWS_ACCESS_KEY]",
    "private_key_like": "[REDACTED:PRIVATE_KEY]",
    "bearer_token_like": "[REDACTED:BEARER_TOKEN]",
    "generic_secret_like": "[REDACTED:GENERIC_SECRET]",
}


def _normalize_key_name(value: str | None) -> str:
    if not value:
        return ""
    lowered = value.strip().lower()
    collapsed = re.sub(r"[^a-z0-9]+", "_", lowered).strip("_")
    return collapsed


def _looks_high_entropy(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 20 or any(character.isspace() for character in stripped):
        return False

    unique_count = len(set(stripped))
    if unique_count < 10:
        return False

    classes = sum(
        [
            any(character.islower() for character in stripped),
            any(character.isupper() for character in stripped),
            any(character.isdigit() for character in stripped),
            any(character in "_-+/=.:" for character in stripped),
        ]
    )
    return classes >= 2


def _detect_secret_type(value: str, key_name: str | None) -> str | None:
    if value.startswith("[REDACTED:"):
        return None

    if _PRIVATE_KEY_RE.search(value):
        return "private_key_like"
    if _OPENAI_KEY_RE.search(value):
        return "openai_key_like"
    if _GITHUB_TOKEN_RE.search(value):
        return "github_token_like"
    if _AWS_ACCESS_KEY_RE.search(value):
        return "aws_access_key_like"
    if _BEARER_TOKEN_RE.search(value):
        return "bearer_token_like"

    if _normalize_key_name(key_name) in _SUSPICIOUS_KEY_NAMES and _looks_high_entropy(value):
        return "generic_secret_like"

    return None


def _child_path(parent_path: str, key: str | int) -> str:
    if isinstance(key, int):
        return f"{parent_path}[{key}]"
    return f"{parent_path}.{key}"


def _redact_recursive(value: Any, *, path: str, key_name: str | None = None) -> tuple[Any, list[dict[str, Any]]]:
    if isinstance(value, dict):
        redacted_dict: dict[str, Any] = {}
        findings: list[dict[str, Any]] = []
        for child_key, child_value in value.items():
            child_key_text = str(child_key)
            redacted_child, child_findings = _redact_recursive(
                child_value,
                path=_child_path(path, child_key_text),
                key_name=child_key_text,
            )
            redacted_dict[child_key_text] = redacted_child
            findings.extend(child_findings)
        return redacted_dict, findings

    if isinstance(value, list):
        redacted_list: list[Any] = []
        findings: list[dict[str, Any]] = []
        for index, child_value in enumerate(value):
            redacted_child, child_findings = _redact_recursive(
                child_value,
                path=_child_path(path, index),
                key_name=key_name,
            )
            redacted_list.append(redacted_child)
            findings.extend(child_findings)
        return redacted_list, findings

    if isinstance(value, str):
        secret_type = _detect_secret_type(value, key_name)
        if secret_type is None:
            return value, []
        redacted_value = _REDACTED_BY_TYPE[secret_type]
        return redacted_value, [
            {
                "param_path": path,
                "secret_type": secret_type,
                "redacted_value": redacted_value,
                "value_length": len(value),
            }
        ]

    return value, []


def redact_mcp_tool_call_action_params(action_params: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    sanitized = deepcopy(action_params)
    findings: list[dict[str, Any]] = []

    if "arguments" in sanitized:
        redacted_arguments, argument_findings = _redact_recursive(
            sanitized["arguments"],
            path="params.arguments",
        )
        sanitized["arguments"] = redacted_arguments
        findings.extend(argument_findings)

    params = sanitized.get("params")
    if isinstance(params, dict) and "arguments" in params:
        redacted_arguments, params_findings = _redact_recursive(
            params["arguments"],
            path="params.arguments",
        )
        params["arguments"] = redacted_arguments
        findings.extend(params_findings)

    if findings:
        sanitized["credential_findings"] = findings
    else:
        sanitized.pop("credential_findings", None)

    return sanitized, findings


def redact_json_like(value: Any) -> Any:
    redacted_value, _ = _redact_recursive(deepcopy(value), path="raw")
    return redacted_value


def sanitize_event_for_storage(event: AgentEvent) -> AgentEvent:
    if event.source != Source.MCP or event.action_type != ActionType.TOOL_CALL:
        return event

    sanitized_params, _ = redact_mcp_tool_call_action_params(event.action_params)
    sanitized_raw = redact_json_like(event.raw) if event.raw is not None else None
    return event.model_copy(update={"action_params": sanitized_params, "raw": sanitized_raw})
