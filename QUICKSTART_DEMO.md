# AIWatch Reproducible Demo Checklist

AIWatch observes MCP traffic routed through the AIWatch stdio wrapper or local HTTP MCP relay. This checklist is for a clean local demo path, not a production deployment guide.

For the single day-of-demo flow, use [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md).

Positioning: Veea is the broader runtime-security vision; AIWatch is the current MCP-first implementation used in this demo.

## Prerequisites

- Python 3.12 available as `py -3.12`
- Backend dependencies installed
- Frontend dependencies installed with `npm install` if needed
- For the real MCP package smokes: Node/npm `npx` on PATH

## A. Fast Local Dashboard Demo

### 1. Start Backend

Terminal 1:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
$env:AIWATCH_DEV_MODE="true"
py -3.12 -m uvicorn app.main:app --reload --port 7330
```

### 2. Start Frontend

Terminal 2:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\frontend
npm run dev
```

Open the Vite URL printed by `npm run dev`, usually `http://localhost:5173`.

### 3. Clear Data

Terminal 3:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py clear
```

Expected:

```text
Cleared AIWatch local database.
```

### 4. Seed Core Demo

In the dashboard, click **Seed Demo**.

Expected summary:

```text
Core seed: 5 events / 7 alerts
```

### 5. Show Alerts

Use the dashboard alert view or run:

```powershell
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Expected rules include `R-MCP-001` plus the legacy/demo coding-agent rules used to show the alert pipeline.

### 6. Seed Extended MCP Registry Demo

In the dashboard, click **Seed MCP Registry Demo**.

Expected summary:

```text
Extended seed: 8 events / 10 alerts
```

### 7. Show Tools / Registry

Use the dashboard tools/registry view or run:

```powershell
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
```

Expected registry story:

- `search_notes` baseline on `notes-mcp`
- changed `search_notes` definition on the same server
- `search_notes` shadowing from `evil-notes-mcp`

### 8. Trigger R-MCP-005 Demo

In the dashboard, click **Trigger R-MCP-005 Demo**.

This posts one MCP `tools/call` event with a fake credential-shaped value. It is separate from seed buttons so the seed counts above stay stable.

### 9. Show Redacted Evidence

Run:

```powershell
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Expected:

- an `R-MCP-005` alert
- no raw fake credential in CLI alert output
- redacted evidence visible through backend/API surfaces

Known detected credential-shaped values are redacted on tested backend/API/CLI surfaces.

### 10. Explain Limitations

Use this wording:

- AIWatch observes MCP traffic routed through the AIWatch stdio wrapper or local HTTP MCP relay.
- The wrapper is an experimental local wrapper path for stdio MCP traffic.
- The local HTTP MCP relay is experimental, local-only, MCP-specific, and limited to a POST JSON request/response subset.
- Claude Code-routed MCP traffic can be observed when Claude Code launches an MCP server through the local stdio MCP wrapper.
- AIWatch does not observe prompts, shell commands, file edits, hidden reasoning, Claude internals, Cursor internals, or arbitrary local process activity.
- This is not a production-ready proxy, does not implement full Streamable HTTP, SSE, GET stream handling, or generic HTTP proxying, and does not guarantee all secrets are caught.

## B. CLI-Only Demo

### 1. Start Backend

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
$env:AIWATCH_DEV_MODE="true"
py -3.12 -m uvicorn app.main:app --reload --port 7330
```

### 2. Clear Data

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py clear
```

Expected:

```text
Cleared AIWatch local database.
```

### 3. Run Core Seed

```powershell
py -3.12 scripts\aiwatch.py demo-seed --backend-url http://127.0.0.1:7330
```

Expected output summary:

```text
5 seeded events
7 created alerts
```

The command prints one `[ok] ...` line per seed item.

### 4. Run Tools

```powershell
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
```

Expected: MCP tool fingerprint rows, including seeded demo MCP tools.

### 5. Run Alerts

```powershell
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Expected: 7 alerts after the core seed.

### 6. Run Extended Seed

```powershell
py -3.12 scripts\aiwatch.py demo-seed --extended --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Expected output summary:

```text
8 seeded events
10 created alerts
```

## C. Real MCP Package Smoke

This uses `@modelcontextprotocol/server-sequential-thinking@2025.7.1`.

### 1. Start Backend

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
$env:AIWATCH_DEV_MODE="true"
py -3.12 -m uvicorn app.main:app --reload --port 7330
```

### 2. Clear Data

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py clear
```

### 3. Run Smoke

```powershell
py -3.12 scripts\run_real_mcp_package_smoke.py --backend-url http://127.0.0.1:7330
```

Expected smoke summary:

```text
Observed tools for modelcontextprotocol-sequential-thinking: sequentialthinking
Observed alerts for stdio-real-package-sequential-thinking-001: 0
```

### 4. Show Tools

```powershell
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
```

Expected tool:

```text
sequentialthinking under modelcontextprotocol-sequential-thinking
```

### 5. Show No Alerts

```powershell
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Expected:

```text
No alerts found.
```

### 6. Explain Scope

This proves one real local stdio MCP package can route through AIWatch and populate the MCP registry without false-positive alerts. It does not prove universal production compatibility, HTTP/SSE proxy support, or generic Claude/Cursor monitoring.

## D. Second Real MCP Package Smoke

This uses `@modelcontextprotocol/server-memory@2026.1.26`.

### 1. Start Backend

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
$env:AIWATCH_DEV_MODE="true"
py -3.12 -m uvicorn app.main:app --reload --port 7330
```

### 2. Clear Data

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py clear
```

### 3. Run Smoke

```powershell
py -3.12 scripts\run_second_real_mcp_package_smoke.py --backend-url http://127.0.0.1:7330
```

Expected smoke summary:

```text
Observed tools for modelcontextprotocol-memory: add_observations, create_entities, create_relations, delete_entities, delete_observations, delete_relations, open_nodes, read_graph, search_nodes
Observed alerts for stdio-real-package-memory-001: 0
```

### 4. Show Tools

```powershell
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
```

Expected tools under `modelcontextprotocol-memory`:

```text
add_observations
create_entities
create_relations
delete_entities
delete_observations
delete_relations
open_nodes
read_graph
search_nodes
```

### 5. Show No Alerts

```powershell
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Expected:

```text
No alerts found.
```

### 6. Explain Scope

This proves another real local stdio MCP package can route through AIWatch and populate the MCP registry without false-positive alerts. It does not prove universal production compatibility, HTTP/SSE proxy support, or generic Claude/Cursor monitoring.

## E. Claude Code Smoke Pointer

Use [docs/CLAUDE_CODE_RUNTIME_SMOKE.md](docs/CLAUDE_CODE_RUNTIME_SMOKE.md) for the Claude Code-routed MCP traffic checklist.

Do not restate it as generic Claude Code monitoring. The proven path is Claude Code launching a local stdio MCP server through the AIWatch wrapper.

## F. Experimental Local HTTP MCP Relay Smoke

This exercises the local-only HTTP relay Phase A path. It is an experimental MCP-specific POST JSON request/response subset routed through the AIWatch local HTTP MCP relay.

### 1. Start Backend

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
$env:AIWATCH_DEV_MODE="true"
py -3.12 -m uvicorn app.main:app --reload --port 7330
```

### 2. Run Smoke

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

Scope: this is not full Streamable HTTP support, SSE support, GET stream handling, a generic HTTP proxy, or production-ready proxying.

## Regression Checks

Run:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 -m pytest
py -3.12 eval\run_eval.py
```

Current expected results:

```text
pytest: 141 passed
eval: 39/39 passed
false positives: none
false negatives: none
```

Backend API polish expected in this checkpoint:

- `POST /v1/events` rejects request bodies over 4 MiB with `413`.
- Missing session replay requests return `404`; intentional dashboard clear/reset flows should not show false replay-load errors.
