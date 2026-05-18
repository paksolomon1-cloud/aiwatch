from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Sequence

from app.schemas import ActionType, AgentEvent, Source

ENFORCEMENT_ENV_VAR = "AIWATCH_ENFORCEMENT_MODE"
ENFORCEMENT_MODE_OBSERVE = "observe"
ENFORCEMENT_MODE_DENY = "deny"
SUPPORTED_ENFORCEMENT_MODES = {ENFORCEMENT_MODE_OBSERVE, ENFORCEMENT_MODE_DENY}
DENY_RULE_ID = "R-MCP-005"
DENY_REASON = "Credential-shaped value in MCP tools/call parameters"


@dataclass(frozen=True)
class EnforcementDecision:
    action: str
    enforcement_mode: str
    rule_id: str | None = None
    reason: str | None = None
    event_id: str | None = None

    @property
    def should_deny(self) -> bool:
        return self.action == "deny"


def resolve_enforcement_mode(raw_mode: str | None = None) -> str:
    mode = (raw_mode if raw_mode is not None else os.environ.get(ENFORCEMENT_ENV_VAR, "")).strip().lower()
    if not mode:
        return ENFORCEMENT_MODE_OBSERVE
    if mode not in SUPPORTED_ENFORCEMENT_MODES:
        raise ValueError(f"{ENFORCEMENT_ENV_VAR} must be 'observe' or 'deny'")
    return mode


def evaluate_enforcement(events: Sequence[AgentEvent], *, enforcement_mode: str) -> EnforcementDecision:
    resolved_mode = resolve_enforcement_mode(enforcement_mode)
    if resolved_mode != ENFORCEMENT_MODE_DENY:
        return EnforcementDecision(action="observe", enforcement_mode=resolved_mode)

    for event in events:
        if _is_deniable_credential_tool_call(event):
            return EnforcementDecision(
                action="deny",
                enforcement_mode=resolved_mode,
                rule_id=DENY_RULE_ID,
                reason=DENY_REASON,
                event_id=event.event_id,
            )

    return EnforcementDecision(action="observe", enforcement_mode=resolved_mode)


def annotate_enforcement_decision(event: AgentEvent, decision: EnforcementDecision) -> AgentEvent:
    if not decision.should_deny or decision.event_id != event.event_id:
        return event

    action_params = dict(event.action_params)
    action_params["enforcement"] = {
        "action": decision.action,
        "enforcement_mode": decision.enforcement_mode,
        "rule_id": decision.rule_id,
        "reason": decision.reason,
    }
    return event.model_copy(update={"action_params": action_params})


def _is_deniable_credential_tool_call(event: AgentEvent) -> bool:
    if event.source != Source.MCP or event.action_type != ActionType.TOOL_CALL:
        return False
    findings = event.action_params.get("credential_findings")
    return isinstance(findings, list) and any(isinstance(finding, dict) for finding in findings)
