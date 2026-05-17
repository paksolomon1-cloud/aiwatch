# Real MCP Package Smoke

These smoke paths run published, no-token MCP stdio packages behind the existing AIWatch wrapper:

- wrapper: `backend/scripts/aiwatch_stdio_tap.py`
- package: `@modelcontextprotocol/server-sequential-thinking@2025.7.1`
- second package: `@modelcontextprotocol/server-memory@2026.1.26`
- transport: local stdio
- client traffic: `initialize`, `notifications/initialized`, `tools/list`

The packages are used as harmless local smoke targets. They do not require API keys, tokens, cloud services, or paid accounts. The first run may download the package through `npx`.
Package reference: [@modelcontextprotocol/server-sequential-thinking on npm](https://www.npmjs.com/package/@modelcontextprotocol/server-sequential-thinking).
Second package reference: [@modelcontextprotocol/server-memory on npm](https://www.npmjs.com/package/@modelcontextprotocol/server-memory).

This is not a production compatibility claim for every MCP server. It only proves that AIWatch can observe MCP traffic routed through its wrapper for these package paths.

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
py -3.12 scripts\aiwatch.py clear
py -3.12 scripts\run_second_real_mcp_package_smoke.py --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Optional raw frame log:

```powershell
py -3.12 scripts\run_real_mcp_package_smoke.py --backend-url http://127.0.0.1:7330 --log-raw-frames
py -3.12 scripts\run_second_real_mcp_package_smoke.py --backend-url http://127.0.0.1:7330 --log-raw-frames
```

## Expected Output

The smoke script should print protocol responses as `[client] ...` lines, then a summary similar to:

```text
Real MCP package smoke completed with 2 protocol responses.
Observed tools for modelcontextprotocol-sequential-thinking: sequentialthinking
Observed alerts for stdio-real-package-sequential-thinking-001: 0
```

The second package smoke should print protocol responses as `[client] ...` lines, then a summary similar to:

```text
Second real MCP package smoke completed with 2 protocol responses.
Observed tools for modelcontextprotocol-memory: add_observations, create_entities, create_relations, delete_entities, delete_observations, delete_relations, open_nodes, read_graph, search_nodes
Observed alerts for stdio-real-package-memory-001: 0
```

`scripts\aiwatch.py tools` should show at least one registry row for:

```text
SERVER_ID: modelcontextprotocol-sequential-thinking
TOOL_NAME: sequentialthinking
```

For the second package smoke, `scripts\aiwatch.py tools` should show registry rows for:

```text
SERVER_ID: modelcontextprotocol-memory
TOOL_NAME: create_entities
TOOL_NAME: create_relations
TOOL_NAME: add_observations
TOOL_NAME: delete_entities
TOOL_NAME: delete_observations
TOOL_NAME: delete_relations
TOOL_NAME: read_graph
TOOL_NAME: search_nodes
TOOL_NAME: open_nodes
```

`scripts\aiwatch.py alerts` should print:

```text
No alerts found.
```

If other data was already present in the local database, clear it first with `scripts\aiwatch.py clear`.

## What It Proves

- AIWatch can launch real npm MCP stdio packages behind `aiwatch_stdio_tap.py`.
- `tools/list` traffic is forwarded and correlated through the wrapper.
- `tools/list` is normalized into `tool_register` events.
- The MCP registry populates from a benign package tool definition.
- The benign package paths do not trigger false-positive alerts in a clean database.
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
