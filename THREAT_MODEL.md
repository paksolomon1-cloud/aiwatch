# Threat Model

AIWatch v1 is scoped to MCP observability and integrity for traffic routed through the AIWatch wrapper.

## Protected Assets

- MCP tool surface
- MCP tool metadata, descriptions, and schemas
- MCP `tools/call` parameters
- MCP tool registry and history
- operator visibility into MCP behavior

## Trust Boundary

The primary trust boundary is:

```text
MCP client -> AIWatch wrapper/tap -> MCP server
```

AIWatch can observe MCP traffic only when the MCP client is configured to launch or route the MCP server through the AIWatch wrapper/tap path.

Real ingestion paths use the canonical ingest function. Known detected credential-shaped values are redacted before persistence on tested ingest paths, and the event row, MCP registry/history updates, and generated alerts are committed atomically for one ingested event.

## Assumptions

- MCP traffic must be routed through AIWatch to be observed.
- The local operator controls project MCP config.
- The backend is local/dev for now.
- The attacker may control a malicious MCP server.
- The attacker does not control the local AIWatch process or host.
- Local SQLite data and frame logs are local operator artifacts and should be treated as sensitive.

## Covered Threats

- `R-MCP-001`: poisoned MCP tool descriptions
- `R-MCP-002`: fingerprint drift or tool-definition rug-pull
- `R-MCP-004`: MCP tool name shadowing across servers
- `R-MCP-005`: credential-shaped values in MCP `tools/call` parameters
- likely unwrapped MCP servers bypassing AIWatch, detectable by `aiwatch doctor` config checks

## Not Covered

- prompts
- hidden model reasoning
- shell commands
- file edits outside MCP tool calls
- arbitrary local process activity
- generic Claude Code or Cursor monitoring
- Claude Code internals
- Cursor internals
- compromised backend host
- traffic not routed through AIWatch
- production auth or multi-tenant security
- guaranteed prevention or blocking of all exfiltration
- HTTP/SSE MCP proxying
- ML-based detection
- SIEM or enterprise export workflows
