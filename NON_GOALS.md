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
- an HTTP/SSE MCP proxy
- an ML detector
- a tamper-evident HMAC logging system

AIWatch can observe Claude Code-routed MCP traffic when Claude Code launches an MCP server through the AIWatch stdio wrapper. That is narrower than generic Claude Code monitoring.

`aiwatch doctor` can inspect local `.mcp.json` and `.cursor/mcp.json` config shape under the current working directory. That is not Cursor runtime support and does not prove any client loaded the config.
