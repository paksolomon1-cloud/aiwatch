# Realistic MCP Stdio Smoke

This smoke path uses a local **realistic MCP stdio fixture**, not a production MCP compatibility claim and not an external paid service.

It runs:

- `aiwatch_stdio_tap.py`
- a more faithful local stdio fixture server
- `initialize`
- `notifications/initialized`
- `tools/list`
- `tools/call`
- `shutdown` / `exit`

The `tools/list` response includes one benign tool and one intentionally poisoned tool so AIWatch should populate the tool registry and raise `R-MCP-001`.

## Commands

Terminal 1:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
$env:AIWATCH_DEV_MODE="true"
py -3.12 -m uvicorn app.main:app --reload --port 7330
```

Terminal 2:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py clear
py -3.12 scripts\run_realistic_stdio_tap_smoke.py --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py tools
py -3.12 scripts\aiwatch.py alerts
```

Optional raw frame log:

```powershell
py -3.12 scripts\run_realistic_stdio_tap_smoke.py --backend-url http://127.0.0.1:7330 --log-raw-frames
```

## What It Proves

- AIWatch can sit in front of a more realistic MCP-style stdio server than `fake_mcp_server.py`.
- `tools/list` traffic is observed through the tap and normalized into `tool_register` events.
- Registry rows populate from the captured tool definitions.
- Suspicious tool descriptions still trigger deterministic MCP alerts.
- Protocol traffic stays on stdout while diagnostics stay on stderr.

## What It Does Not Prove

- production-grade MCP compatibility
- HTTP/SSE support
- concurrency correctness across many simultaneous MCP clients
- compatibility with Claude Code, Cursor, or a real vendor integration
