# HTTP MCP Relay Phase A

AIWatch observes MCP traffic routed through the AIWatch stdio wrapper or local HTTP MCP relay.

HTTP relay Phase A is local-only, experimental, MCP-specific, and limited to a POST JSON request/response subset routed through the AIWatch local HTTP MCP relay. It is not full Streamable HTTP support, SSE support, GET stream handling, a generic HTTP proxy, or production-grade proxying.

## Smoke

Start the backend first:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
$env:AIWATCH_DEV_MODE="true"
py -3.12 -m uvicorn app.main:app --reload --port 7330
```

Then run:

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
