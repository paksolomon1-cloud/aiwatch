# AIWatch

AIWatch is a local MCP observability and security layer. AIWatch observes MCP traffic routed through the AIWatch stdio wrapper or local HTTP MCP relay. It records MCP tool definitions and tool calls, fingerprints tools, and raises deterministic alerts for tool-surface risks.

AIWatch is MCP-first. It is not generic Claude Code monitoring, Cursor monitoring, laptop monitoring, prompt monitoring, shell monitoring, file-edit monitoring, hidden-reasoning visibility, or arbitrary local process monitoring.

## Veea Positioning

Veea is the broader runtime-security vision for tool-using AI agents. AIWatch is the current working MCP-first implementation, focused on MCP traffic routed through the AIWatch stdio wrapper or local HTTP MCP relay.

Veea Lobster Trap is the baseline prompt/response-layer companion for OpenAI-compatible LLM traffic. AIWatch adds MCP tool-layer visibility alongside Lobster Trap. Together they demonstrate a side-by-side layered runtime-security story; they are not a fused runtime pipeline unless a bridge is implemented and verified.

Phase 0/1 interop is export-only: `py -3.12 scripts\aiwatch.py export-veea-audit --out veea-aiwatch-audit.jsonl` writes stored AIWatch MCP alerts as JSONL, and `--timeline` adds stored MCP observation events for a local Veea-style audit timeline. It does not forward events to Lobster Trap or require Lobster Trap to be running.

Future Veea directions may include additional adapters beyond MCP, richer policy controls, runtime risk scoring, optional blocking, and broader agent/tool compatibility. Those are future product directions, not current AIWatch capabilities.

## Current Detection

- `R-MCP-001`: poisoned MCP tool descriptions
- `R-MCP-002`: MCP tool fingerprint drift
- `R-MCP-004`: MCP tool name shadowing across servers
- `R-MCP-005`: credential-shaped values in MCP `tools/call` parameters, with safe redaction of known detected credential-shaped values on tested backend/API/CLI surfaces

The repo still contains legacy/demo coding-agent rules for seeded demos and eval fixtures, but the product center is MCP observability and integrity.

## Optional Enforcement

AIWatch can optionally deny selected routed MCP tool calls when they match deterministic high-confidence rules, but only when traffic is routed through the AIWatch local MCP relay/wrapper and enforcement mode is explicitly enabled.

Configuration:

```powershell
$env:AIWATCH_ENFORCEMENT_MODE="observe" # default
$env:AIWATCH_ENFORCEMENT_MODE="deny"    # opt-in deny mode
```

The MVP deny rule is limited to `R-MCP-005` for credential-shaped MCP `tools/call` parameters. In `observe` mode, AIWatch preserves the existing behavior: routed events are observed, redacted, stored, and alerted without blocking the upstream MCP call. In `deny` mode, matching `R-MCP-005` routed tool calls are not forwarded to the upstream MCP server; AIWatch returns an MCP-compatible JSON-RPC error and records the deny decision in the local event/alert metadata.

Manual quarantine is also available for registered MCP tools. AIWatch can optionally deny future routed MCP calls to manually quarantined tools when traffic goes through the AIWatch local MCP relay/wrapper and enforcement mode is enabled.

```powershell
py -3.12 scripts\aiwatch.py quarantine-tool --tool-name search_notes --reason "manual demo stop" --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py quarantined-tools --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py unquarantine-tool --tool-name search_notes --backend-url http://127.0.0.1:7330
```

Check the local CLI process setting:

```powershell
py -3.12 scripts\aiwatch.py enforcement-status --backend-url http://127.0.0.1:7330
```

## Current Components

- FastAPI backend
- SQLite persistence
- MCP tool registry and history
- tool fingerprinting
- deterministic alert engine
- CLI wrapper at `backend/scripts/aiwatch.py`
- Veea-style companion audit JSONL export for stored MCP alerts and local MCP audit timelines
- React dashboard
- local stdio MCP wrapper/tap path at `backend/scripts/aiwatch_stdio_tap.py`
- experimental local HTTP MCP relay at `backend/scripts/aiwatch_http_mcp_relay.py`
- `aiwatch doctor` config health check for local `.mcp.json` and `.cursor/mcp.json`
- opt-in deny mode for selected routed MCP tool calls
- manual quarantine state for registered MCP tools
- deterministic local eval harness

Real ingestion paths use the canonical backend ingest function. Known detected credential-shaped values are redacted before persistence on tested ingest paths, and the event row, MCP registry/history updates, and generated alerts are committed atomically for one ingested event.

## Current Proof Points

- Claude Code local stdio MCP wrapper runtime smoke succeeded on Windows.
- AIWatch observed Claude Code-routed MCP traffic when Claude Code launched an MCP server through the AIWatch stdio wrapper.
- Real MCP package smokes passed for `@modelcontextprotocol/server-sequential-thinking@2025.7.1` and `@modelcontextprotocol/server-memory@2026.1.26`.
- Tests recently passed: `175`.
- Eval recently passed: `43/43`.
- Local HTTP POST JSON MCP relay smoke passed for `fixture-http-notes-mcp`.
- Core seed expected count: `5 events / 7 alerts`.
- Extended seed expected count: `8 events / 10 alerts`.

The Claude Code runtime smoke proves local stdio MCP routing through AIWatch worked. The HTTP relay smoke proves the experimental local POST JSON MCP relay can observe a narrow MCP request/response subset when traffic is routed through the AIWatch local HTTP MCP relay. Neither smoke proves generic Claude Code monitoring, generic Cursor monitoring, production proxy coverage, full Streamable HTTP support, SSE support, GET stream handling, prompt visibility, shell command visibility, file edit visibility, hidden reasoning visibility, or client internals visibility.

## Future Veea Direction

The current AIWatch proof gives Veea a concrete MCP-first starting point. Future Veea work may expand toward additional agent/tool adapters, deeper policy controls, richer runtime risk scoring, optional blocking after measured false-positive work, and broader compatibility. These roadmap items should stay clearly future-facing until implemented and validated.

## Quickstart

Start the backend:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
$env:AIWATCH_DEV_MODE="true"
py -3.12 -m uvicorn app.main:app --reload --port 7330
```

Run the CLI from another terminal:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py clear
py -3.12 scripts\aiwatch.py demo-seed
py -3.12 scripts\aiwatch.py alerts
py -3.12 scripts\aiwatch.py tools
```

Run the extended MCP registry demo:

```powershell
py -3.12 scripts\aiwatch.py clear
py -3.12 scripts\aiwatch.py demo-seed --extended
py -3.12 scripts\aiwatch.py alerts
py -3.12 scripts\aiwatch.py tools
```

Run the realistic local stdio MCP smoke:

```powershell
py -3.12 scripts\aiwatch.py clear
py -3.12 scripts\run_realistic_stdio_tap_smoke.py --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Run the real MCP package smoke with a harmless no-token package:

```powershell
py -3.12 scripts\aiwatch.py clear
py -3.12 scripts\run_real_mcp_package_smoke.py --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Run the second real MCP package smoke with another harmless no-token package:

```powershell
py -3.12 scripts\aiwatch.py clear
py -3.12 scripts\run_second_real_mcp_package_smoke.py --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Run the experimental local HTTP POST JSON MCP relay smoke:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py clear
py -3.12 scripts\run_http_mcp_relay_smoke.py --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Expected:

- observed tools: `echo_note`, `list_notes`
- server ID: `fixture-http-notes-mcp`
- alerts: `No alerts found.`

Scope: this is a local-only, experimental, MCP-specific POST JSON request/response subset routed through the AIWatch local HTTP MCP relay. It is not full Streamable HTTP support, SSE support, GET stream handling, a generic HTTP proxy, or production-ready proxying.

Check opt-in routed MCP enforcement mode:

```powershell
py -3.12 scripts\aiwatch.py enforcement-status --backend-url http://127.0.0.1:7330
```

To enable deny mode for a local relay/wrapper process, set `AIWATCH_ENFORCEMENT_MODE=deny` before starting that process. Leave it unset or set it to `observe` for alert-only behavior.

Manual quarantine CLI:

```powershell
py -3.12 scripts\aiwatch.py quarantine-tool --tool-name search_notes --reason "manual demo stop" --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py quarantined-tools --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py unquarantine-tool --tool-name search_notes --backend-url http://127.0.0.1:7330
```

Run live local Lobster Trap audit ingestion for the Unified Audit tab:

Terminal 1:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
$env:AIWATCH_DEV_MODE="true"
py -3.12 -m uvicorn app.main:app --reload --host 127.0.0.1 --port 7330
```

Terminal 2:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py lobstertrap-live-ingest --file C:\Users\pakso\lobstertrap\lobstertrap-audit.jsonl --backend-url http://127.0.0.1:7330 --follow
```

Terminal 3:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\frontend
npm run dev
```

Open `http://localhost:5173/`.

Lobster Trap prompt/response audit records are ingested into AIWatch's local unified audit timeline. LLM/prompt traffic must be routed through Lobster Trap for live prompt/response audit records to appear. MCP traffic must be routed through the AIWatch wrapper/relay for MCP-layer observation and opt-in enforcement. AIWatch correlates ingested Lobster Trap records and routed MCP records when correlation or session metadata lines up.

Run the config health check from the repo root:

```powershell
cd C:\Users\pakso\Desktop\aiwatch
py -3.12 backend\scripts\aiwatch.py doctor
```

Run tests and eval:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 -m pytest
py -3.12 eval\run_eval.py
```

## Limitations

- MCP traffic must be routed through AIWatch to be observed.
- This is a local/dev demo posture, not a production enterprise gateway.
- The local HTTP MCP relay is experimental, MCP-specific, and limited to a local POST JSON request/response subset routed through AIWatch.
- `POST /v1/events` rejects request bodies over 4 MiB before event validation or ingest.
- Missing session replay requests return `404`.
- AIWatch does not observe prompts, shell commands, file edits, hidden reasoning, Claude Code internals, Cursor internals, or arbitrary local process activity.
- AIWatch does not guarantee prevention of all exfiltration.
- Deny mode is opt-in and limited to selected routed MCP tool calls; current deny coverage starts with `R-MCP-005`.
- Manual quarantine only affects future routed MCP calls through the local relay/wrapper when enforcement mode is enabled.
- AIWatch does not implement production auth, HMAC logs, semantic embeddings, full Streamable HTTP, SSE, GET stream handling, a generic HTTP proxy, production-ready proxying, SIEM/exporters, ML detection, or Cursor runtime support.
- `aiwatch doctor` checks config shape only; it cannot prove a client loaded that config or prevent config tampering.

## Documentation

- [Day-of-demo runbook](DEMO_RUNBOOK.md)
- [Reproducible demo checklist](QUICKSTART_DEMO.md)
- [Demo script](DEMO_SCRIPT.md)
- [Real MCP package smoke](REAL_MCP_PACKAGE_SMOKE.md)
- [Realistic local stdio MCP smoke](REALISTIC_MCP_SMOKE.md)
- [Claude Code runtime smoke checklist](docs/CLAUDE_CODE_RUNTIME_SMOKE.md)
- [Claude Code MCP wrapper docs](docs/CLAUDE_CODE_MCP_WRAPPER.md)
- [Cursor MCP smoke exploration](docs/CURSOR_MCP_RUNTIME_SMOKE.md)
- [HTTP MCP relay Phase A](docs/HTTP_MCP_RELAY_PHASE_A.md)
- [Veea Lobster Trap companion demo](docs/LOBSTERTRAP_AIWATCH_COMPANION.md)
- [AIWatch doctor docs](docs/AIWATCH_DOCTOR.md)
- [MCP credential parameter detection](docs/MCP_CREDENTIAL_PARAMETER_DETECTION.md)
- [Threat model](THREAT_MODEL.md)
- [Non-goals](NON_GOALS.md)
