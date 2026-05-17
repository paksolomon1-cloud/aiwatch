# Real MCP Package Smoke

This smoke path runs a published, no-token MCP stdio package behind the existing AIWatch wrapper:

- wrapper: `backend/scripts/aiwatch_stdio_tap.py`
- package: `@modelcontextprotocol/server-sequential-thinking@2025.7.1`
- transport: local stdio
- client traffic: `initialize`, `notifications/initialized`, `tools/list`

The package is used as a harmless local smoke target. It does not require API keys, tokens, cloud services, or paid accounts. The first run may download the package through `npx`.
Package reference: [@modelcontextprotocol/server-sequential-thinking on npm](https://www.npmjs.com/package/@modelcontextprotocol/server-sequential-thinking).

This is not a production compatibility claim for every MCP server. It only proves that AIWatch can observe MCP traffic routed through its wrapper for this package path.

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
py -3.12 scripts\run_real_mcp_package_smoke.py --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Optional raw frame log:

```powershell
py -3.12 scripts\run_real_mcp_package_smoke.py --backend-url http://127.0.0.1:7330 --log-raw-frames
```

## Expected Output

The smoke script should print protocol responses as `[client] ...` lines, then a summary similar to:

```text
Real MCP package smoke completed with 2 protocol responses.
Observed tools for modelcontextprotocol-sequential-thinking: sequentialthinking
Observed alerts for stdio-real-package-sequential-thinking-001: 0
```

`scripts\aiwatch.py tools` should show at least one registry row for:

```text
SERVER_ID: modelcontextprotocol-sequential-thinking
TOOL_NAME: sequentialthinking
```

`scripts\aiwatch.py alerts` should print:

```text
No alerts found.
```

If other data was already present in the local database, clear it first with `scripts\aiwatch.py clear`.

## What It Proves

- AIWatch can launch a real npm MCP stdio package behind `aiwatch_stdio_tap.py`.
- `tools/list` traffic is forwarded and correlated through the wrapper.
- `tools/list` is normalized into `tool_register` events.
- The MCP registry populates from a benign package tool definition.
- The benign package path does not trigger false-positive alerts in a clean database.
- Protocol traffic remains stdout/stdin only; wrapper diagnostics remain on stderr.

## What It Does Not Prove

- production compatibility with every MCP server
- HTTP/SSE MCP proxy support
- Claude Code or Cursor runtime support
- generic Claude/Cursor monitoring
- prompt, shell command, file edit, hidden reasoning, or client-internal visibility
- prevention of all exfiltration

## Operational Notes

- Requires Node/npm `npx` on PATH.
- The default package is pinned for reproducible smoke behavior.
- Use `--package` only for local experiments with another no-token MCP stdio package.
- Do not use this smoke path with MCP servers that read sensitive local files by default.
