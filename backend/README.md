# AIWatch Backend

This directory contains the local FastAPI backend, SQLite storage, detector logic, CLI wrapper, stdio MCP wrapper/tap scripts, experimental local HTTP MCP relay scripts, eval harness, and backend tests.

For project positioning, current proof points, limitations, and the main quickstart, see [../README.md](../README.md).

## Local Backend

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
$env:AIWATCH_DEV_MODE="true"
py -3.12 -m uvicorn app.main:app --reload --port 7330
```

## CLI

```powershell
py -3.12 scripts\aiwatch.py clear
py -3.12 scripts\aiwatch.py demo-seed
py -3.12 scripts\aiwatch.py demo-seed --extended
py -3.12 scripts\aiwatch.py tap-demo
py -3.12 scripts\aiwatch.py eval
py -3.12 scripts\aiwatch.py doctor
py -3.12 scripts\aiwatch.py doctor --json
py -3.12 scripts\aiwatch.py tools
py -3.12 scripts\aiwatch.py alerts
```

## Verification

```powershell
py -3.12 -m pytest
py -3.12 eval\run_eval.py
```

Expected current state:

- pytest: `130` passing tests
- eval: `39/39`
- core seed: `5 events / 7 alerts`
- extended seed: `8 events / 10 alerts`
- HTTP relay smoke: observes `echo_note` and `list_notes` under `fixture-http-notes-mcp` with `No alerts found.`

API polish expectations:

- `POST /v1/events` rejects request bodies over 4 MiB with `413` before `AgentEvent` validation or canonical ingest.
- `GET /v1/sessions/{session_id}/replay` returns `404` for missing sessions and still returns valid sessions with events and zero alerts.

## Scope

The backend observes MCP traffic routed through the AIWatch stdio wrapper or local HTTP MCP relay, stores MCP events and registry state locally, and raises deterministic MCP alerts. It does not provide generic Claude Code/Cursor monitoring, prompt visibility, shell-command monitoring, file-edit monitoring, hidden-reasoning visibility, or production enterprise gateway controls.

HTTP relay Phase A is local-only, experimental, MCP-specific, and limited to a POST JSON request/response subset routed through the AIWatch local HTTP MCP relay. It is not full Streamable HTTP support, SSE support, GET stream handling, a generic HTTP proxy, or production-ready proxying.
