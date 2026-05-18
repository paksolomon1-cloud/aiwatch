from __future__ import annotations

import os
import hashlib
from dataclasses import dataclass
from typing import Sequence

from app.schemas import ActionType, AgentEvent, Source

ENFORCEMENT_ENV_VAR = "AIWATCH_ENFORCEMENT_MODE"
ENFORCEMENT_MODE_OBSERVE = "observe"
ENFORCEMENT_MODE_DENY = "deny"
SUPPORTED_ENFORCEMENT_MODES = {ENFORCEMENT_MODE_OBSERVE, ENFORCEMENT_MODE_DENY}
DENY_RULE_ID = "R-MCP-005"
DENY_REASON = "Credential-shaped value in MCP tools/call parameters"
QUARANTINE_REASON = "tool_quarantined"


@dataclass(frozen=True)
class EnforcementDecision:
    action: str
    enforcement_mode: str
    rule_id: str | None = None
    reason: str | None = None
    event_id: str | None = None
    tool_name: str | None = None
    tool_fingerprint: str | None = None
    quarantine_reason: str | None = None

    @property
    def should_deny(self) -> bool:
        return self.action == "deny"

    @property
    def should_annotate(self) -> bool:
        return self.event_id is not None and (self.should_deny or self.reason == QUARANTINE_REASON)


def resolve_enforcement_mode(raw_mode: str | None = None) -> str:
    mode = (raw_mode if raw_mode is not None else os.environ.get(ENFORCEMENT_ENV_VAR, "")).strip().lower()
    if not mode:
        return ENFORCEMENT_MODE_OBSERVE
    if mode not in SUPPORTED_ENFORCEMENT_MODES:
        raise ValueError(f"{ENFORCEMENT_ENV_VAR} must be 'observe' or 'deny'")
    return mode


def evaluate_enforcement(events: Sequence[AgentEvent], *, enforcement_mode: str) -> EnforcementDecision:
    resolved_mode = resolve_enforcement_mode(enforcement_mode)

    for event in events:
        if resolved_mode == ENFORCEMENT_MODE_DENY and _is_deniable_credential_tool_call(event):
            return EnforcementDecision(
                action="deny",
                enforcement_mode=resolved_mode,
                rule_id=DENY_RULE_ID,
                reason=DENY_REASON,
                event_id=event.event_id,
            )

        quarantine_match = _quarantine_match(event)
        if quarantine_match is not None:
            action = "deny" if resolved_mode == ENFORCEMENT_MODE_DENY else "observe"
            return EnforcementDecision(
                action=action,
                enforcement_mode=resolved_mode,
                reason=QUARANTINE_REASON,
                event_id=event.event_id,
                tool_name=quarantine_match.tool_name,
                tool_fingerprint=quarantine_match.fingerprint_id,
                quarantine_reason=quarantine_match.quarantine_reason,
            )

    return EnforcementDecision(action="observe", enforcement_mode=resolved_mode)


def annotate_enforcement_decision(event: AgentEvent, decision: EnforcementDecision) -> AgentEvent:
    if not decision.should_annotate or decision.event_id != event.event_id:
        return event

    action_params = dict(event.action_params)
    if decision.reason == QUARANTINE_REASON:
        quarantine: dict[str, object] = {
            "quarantined": True,
            "reason": decision.reason,
            "enforcement_mode": decision.enforcement_mode,
        }
        if decision.tool_name is not None:
            quarantine["tool_name"] = decision.tool_name
        if decision.tool_fingerprint is not None:
            quarantine["tool_fingerprint"] = decision.tool_fingerprint
        if decision.quarantine_reason is not None:
            quarantine["quarantine_reason"] = decision.quarantine_reason
        action_params["quarantine"] = quarantine

    if decision.should_deny:
        enforcement: dict[str, object] = {
            "action": decision.action,
            "enforcement_mode": decision.enforcement_mode,
            "reason": decision.reason,
        }
        if decision.rule_id is not None:
            enforcement["rule_id"] = decision.rule_id
        if decision.tool_name is not None:
            enforcement["tool_name"] = decision.tool_name
        if decision.tool_fingerprint is not None:
            enforcement["tool_fingerprint"] = decision.tool_fingerprint
        if decision.quarantine_reason is not None:
            enforcement["quarantine_reason"] = decision.quarantine_reason
        action_params["enforcement"] = enforcement
    return event.model_copy(update={"action_params": action_params})


def _is_deniable_credential_tool_call(event: AgentEvent) -> bool:
    if event.source != Source.MCP or event.action_type != ActionType.TOOL_CALL:
        return False
    findings = event.action_params.get("credential_findings")
    return isinstance(findings, list) and any(isinstance(finding, dict) for finding in findings)


def _quarantine_match(event: AgentEvent):
    if event.source != Source.MCP or event.action_type != ActionType.TOOL_CALL:
        return None

    tool_name = event.action_params.get("tool_name")
    server_id = event.action_params.get("server_id")
    if not isinstance(tool_name, str) or not tool_name.strip():
        return None

    fingerprint_id = None
    if isinstance(server_id, str) and server_id.strip():
        fingerprint_id = hashlib.sha256(f"{server_id}::{tool_name}".encode("utf-8")).hexdigest()

    try:
        from app.storage import get_quarantined_tool_for_call

        return get_quarantined_tool_for_call(tool_name=tool_name, fingerprint_id=fingerprint_id)
    except Exception:
        return None
