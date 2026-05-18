# Non-Goals

AIWatch v1 is not:

- antivirus or EDR
- a SIEM
- a generic LLM observability platform
- a generic coding-agent monitor
- a prompt firewall
- a full Claude Code security product
- a Cursor runtime integration
- a guarantee against all exfiltration
- a replacement for MCP server sandboxing
- a monitor of all Claude Code or Cursor actions
- a monitor of prompts, shell commands, file edits, hidden reasoning, or arbitrary laptop activity
- a production enterprise gateway in its current state
- full Streamable HTTP support, SSE support, or GET stream handling
- a generic HTTP proxy
- production-ready proxying
- an ML detector
- a tamper-evident HMAC logging system

AIWatch can observe Claude Code-routed MCP traffic when Claude Code launches an MCP server through the AIWatch stdio wrapper. That is narrower than generic Claude Code monitoring.

AIWatch can also observe the local HTTP relay Phase A smoke when MCP POST JSON request/response traffic is routed through the AIWatch local HTTP MCP relay. That path is local-only, experimental, and MCP-specific.

AIWatch has an opt-in deny mode for selected routed MCP tool calls. The current deny MVP is limited to deterministic high-confidence `R-MCP-005` credential-shaped MCP `tools/call` parameters, and only when traffic is routed through the local MCP relay/wrapper with `AIWATCH_ENFORCEMENT_MODE=deny`.

AIWatch can ingest local Lobster Trap JSONL audit logs into its own unified audit timeline. That is local audit interop; it does not make AIWatch a prompt monitor, does not make Lobster Trap an MCP monitor, and does not imply a Veea cloud control plane.

`aiwatch doctor` can inspect local `.mcp.json` and `.cursor/mcp.json` config shape under the current working directory. That is not Cursor runtime support and does not prove any client loaded the config.
