# AIWatch Backend

This directory contains the local FastAPI backend, SQLite storage, detector logic, CLI wrapper, stdio MCP wrapper/tap scripts, eval harness, and backend tests.

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

- pytest: `99` passing tests
- eval: `39/39`
- core seed: `5 events / 7 alerts`
- extended seed: `8 events / 10 alerts`

## Scope

The backend observes MCP traffic routed through the AIWatch wrapper, stores MCP events and registry state locally, and raises deterministic MCP alerts. It does not provide generic Claude Code/Cursor monitoring, prompt visibility, shell-command monitoring, file-edit monitoring, hidden-reasoning visibility, or production enterprise gateway controls.
