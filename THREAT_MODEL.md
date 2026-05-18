# Threat Model

AIWatch v1 is scoped to MCP observability and integrity for traffic routed through the AIWatch stdio wrapper or local HTTP MCP relay.

## Protected Assets

- MCP tool surface
- MCP tool metadata, descriptions, and schemas
- MCP `tools/call` parameters
- MCP tool registry and history
- operator visibility into MCP behavior
- local unified audit timeline records ingested from Lobster Trap JSONL audit files

## Trust Boundary

The primary trust boundary is:

```text
MCP client -> AIWatch stdio wrapper/tap or local HTTP MCP relay -> MCP server
```

AIWatch can observe MCP traffic only when the MCP client is configured to launch or route the MCP server through the AIWatch stdio wrapper/tap path or local HTTP MCP relay.

The local HTTP MCP relay Phase A path is local-only, experimental, MCP-specific, and limited to a POST JSON request/response subset. It is not full Streamable HTTP support, SSE support, GET stream handling, a generic HTTP proxy, or production-grade proxying.

Real ingestion paths use the canonical ingest function. Known detected credential-shaped values are redacted before persistence on tested ingest paths, and the event row, MCP registry/history updates, and generated alerts are committed atomically for one ingested event.

Optional enforcement is off by default. When `AIWATCH_ENFORCEMENT_MODE=deny` is set for the local MCP relay/wrapper process, AIWatch can deny selected routed MCP `tools/call` requests before forwarding. The MVP deny scope is limited to deterministic high-confidence `R-MCP-005` credential-shaped tool-call parameters.

The Lobster Trap interop path ingests local Lobster Trap JSONL audit records into AIWatch's local audit store after normalization and redaction. It is a local audit timeline bridge, not prompt inspection by AIWatch and not MCP inspection by Lobster Trap.

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
- opt-in deny mode for selected routed MCP tool calls matching deterministic high-confidence rules, currently `R-MCP-005`
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
- Lobster Trap audit records that are not posted to the local AIWatch ingestion endpoint or read by the CLI ingestion command
- production auth or multi-tenant security
- guaranteed prevention or blocking of all exfiltration
- enforcement for traffic not routed through the AIWatch local MCP relay/wrapper
- deny coverage beyond selected deterministic high-confidence MCP tool-call rules
- full Streamable HTTP support, SSE support, GET stream handling, generic HTTP proxying, or production-grade proxying
- ML-based detection
- SIEM or enterprise export workflows
