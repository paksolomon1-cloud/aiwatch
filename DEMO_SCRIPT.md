# AIWatch Demo Script

For the single day-of-demo flow, use [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md). This file remains supporting speaker copy.

## One-Sentence Pitch

Veea is the broader runtime-security vision; AIWatch is the working MCP-first proof point. AIWatch observes MCP traffic routed through the AIWatch stdio wrapper or local HTTP MCP relay, fingerprints tool definitions, and flags poisoned, changed, shadowed, or credential-shaped MCP tool-call parameters.

Veea's Lobster Trap covers the model conversation layer; AIWatch adds the MCP tool layer, where agents discover and invoke tools.

## 30-Second Explanation

- MCP gives agents tools.
- Tool descriptions and tool-call parameters can carry security risk.
- Veea is the broader product direction; AIWatch is the implemented MCP-focused demo.
- AIWatch observes MCP traffic routed through its local stdio wrapper/tap path or experimental local HTTP MCP relay.
- It captures `tools/list` and `tools/call` traffic.
- It fingerprints tool definitions and keeps registry history.
- It alerts on poisoned descriptions, drift, shadowing, and credential-shaped tool-call parameters.
- The dashboard and CLI show what AIWatch observed.

## Live Demo Flow

### Terminal 1: Backend

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
$env:AIWATCH_DEV_MODE="true"
py -3.12 -m uvicorn app.main:app --reload --port 7330
```

### Terminal 2: Frontend

```powershell
cd C:\Users\pakso\Desktop\aiwatch\frontend
npm run dev
```

### Dashboard Flow

- Click **Seed Demo**.
- Explain the legacy/demo coding-agent alert briefly.
- Confirm the core seed remains `5 events / 7 alerts`.
- Click **Seed MCP Registry Demo**.
- Confirm the extended seed remains `8 events / 10 alerts`.
- Open **Tools / Registry**.
- Show the clean `search_notes` baseline on `notes-mcp`.
- Show the drifted `search_notes` definition on the same server.
- Show `search_notes` shadowing when `evil-notes-mcp` appears.
- Show `R-MCP-001`, `R-MCP-002`, and `R-MCP-004` at the intended moments.

### Realistic Local Stdio MCP Smoke

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py clear
py -3.12 scripts\run_realistic_stdio_tap_smoke.py --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Expected:

- Tools show `list_notes` and `export_notes_bundle` on `fixture-notes-mcp`.
- Alerts show `R-MCP-001` from captured `tools/list`.
- The benign `tools/call` in the smoke is captured without `R-MCP-005`.
- Protocol stdout is not polluted with AIWatch diagnostics.

### Experimental Local HTTP MCP Relay Smoke

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py clear
py -3.12 scripts\run_http_mcp_relay_smoke.py --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Expected:

- Tools show `echo_note` and `list_notes` on `fixture-http-notes-mcp`.
- Alerts show `No alerts found.`

Key message: this is local-only, experimental, MCP-specific HTTP relay Phase A for a POST JSON request/response subset routed through the AIWatch local HTTP MCP relay. It is not full Streamable HTTP support, SSE support, GET stream handling, a generic HTTP proxy, or production-ready proxying.

### Claude Code Live-Smoke Option

Use this only when Claude Code is installed and available locally.

1. Start the backend with `AIWATCH_DEV_MODE=true`.
2. Clear local AIWatch data.
3. From the repo root, run:

```powershell
cd C:\Users\pakso\Desktop\aiwatch
py -3.12 backend\scripts\aiwatch.py doctor
```

4. Show the project `.mcp.json` wrapper shape: `py -3.12 backend/scripts/aiwatch_stdio_tap.py ... -- py -3.12 backend/scripts/realistic_mcp_fixture_server.py`.
5. Launch Claude Code from the project root.
6. Trigger MCP tool discovery inside Claude Code.
7. Run:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

8. Show `fixture-notes-mcp` tools: `list_notes` and `export_notes_bundle`.
9. Show `R-MCP-001`.
10. Say clearly: this proves Claude Code-routed MCP traffic can be observed when Claude Code launches an MCP server through the AIWatch stdio wrapper. It does not prove generic Claude Code monitoring or visibility into prompts, shell commands, file edits, hidden reasoning, or Claude Code internals.

### R-MCP-005 Credential Parameter Demo

Use the dashboard **Trigger R-MCP-005 Demo** control to post one MCP `tools/call` event with a fake credential-shaped value. This is separate from the seed buttons so the core and extended seed counts stay unchanged.

Key message:

- `R-MCP-005` detects credential-shaped values in MCP `tools/call` parameters.
- Evidence is redacted.
- Raw detected secret values should not be displayed in alert evidence, stored events, or CLI alert output.

## What To Say For Each Screen

### Header / Overview

- "This is a local MCP Tool Security Monitor."
- "It records MCP tool definitions and selected MCP tool-call events that route through AIWatch."
- "The point is not to guess model intent with ML. The point is to make MCP tool trust visible."

### Seed Demo

- "This first seed includes a small legacy coding-agent demo so we can show the alert pipeline end to end."
- "MCP registry monitoring is the real v1 focus."

### Seed MCP Registry Demo

- "AIWatch sees a clean `search_notes` tool definition, then a changed definition on the same server, then the same tool name from another server."
- "That gives us drift and shadowing in a way that is easy to inspect."

### Tools / Registry

- "Each tool gets a stable fingerprint based on server and tool name, plus hashes for description and schema."
- "AIWatch keeps the latest view and the observation history."
- "This makes tool identity visible instead of implicit."

### Alerts

- "`R-MCP-001` means the tool description contains deterministic prompt-injection language."
- "`R-MCP-002` means a known tool definition changed."
- "`R-MCP-004` means the same tool name appears on multiple servers."
- "`R-MCP-005` means a credential-shaped value appeared in MCP `tools/call` parameters, with redacted evidence."

### Wrapper/Tap Path

- "This is an experimental local stdio MCP wrapper/tap path and local HTTP MCP relay path, not a production proxy."
- "It forwards newline-delimited JSON-RPC, captures correlated `tools/list`, captures `tools/call` requests, normalizes events, and reuses the same detection pipeline."
- "The HTTP relay Phase A path covers only local POST JSON MCP request/response traffic routed through the AIWatch local HTTP MCP relay."

### Eval Harness

- "This is a local deterministic fixture eval."
- "It is useful as a regression and demo harness, not as a public benchmark."
- "It tells us whether the known fixtures still trigger exactly the rules we expect."

## Safe Claims

- working FastAPI backend
- SQLite persistence
- MCP tool registry
- hash fingerprinting
- drift detection
- shadowing detection
- poisoned description detection
- credential-shaped tool-call parameter detection
- redaction of known detected credential-shaped values on tested backend/API/CLI surfaces
- `aiwatch doctor` config health check
- local stdio MCP wrapper/tap path
- experimental local HTTP POST JSON MCP relay smoke
- Claude Code local stdio MCP runtime smoke succeeded
- two real no-token MCP package smoke paths
- `/v1/events` 4 MiB request body guard
- missing session replay returns `404`
- React dashboard
- deterministic local eval harness
- 175 pytest passing
- 43/43 eval passing

## Claims Not To Make

- Do not say "AIWatch secures Claude Code."
- Do not say "AIWatch monitors Claude/Cursor."
- Do not say "AIWatch watches your laptop."
- Do not say "AIWatch blocks all exfiltration."
- Do not say "AIWatch observes prompts, shell commands, file edits, hidden reasoning, or Claude/Cursor internals."
- Do not say "production-ready MCP proxy."
- Do not say "Cursor runtime support is implemented."
- Do not say "HTTP/SSE proxy is implemented."
- Do not say "ML detector."
- Do not say "tamper-evident HMAC logs."
- Do not claim generic Claude Code hooks/monitoring.
- Do not claim full Claude Code security integration.
- Do not claim non-MCP Claude Code monitoring.
