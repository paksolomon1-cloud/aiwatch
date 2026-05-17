# Cursor MCP Runtime Smoke Exploration

This checklist is exploratory. It is not verified in this repo yet.

AIWatch observes only MCP traffic routed through `aiwatch_stdio_tap.py`. This checklist does not add generic Cursor monitoring, prompt monitoring, shell-command monitoring, file-edit monitoring, or Cursor-internal hooks.

Do not use the spec-approved Cursor success wording unless the runtime smoke actually succeeds locally. Until then, describe this only as a Cursor MCP smoke exploration.

## What This Would Test

Success requires all of these:

- Cursor launches the configured local stdio MCP server through `aiwatch_stdio_tap.py`.
- AIWatch receives `tools/list` traffic.
- `scripts\aiwatch.py tools` shows `list_notes` and `export_notes_bundle` on `fixture-notes-mcp`.
- Any alert is explainable by the fixture, such as `R-MCP-001` for the intentional poisoned tool description.

Failure means documenting the exact blocker, for example Cursor not installed, Cursor not loading `.cursor/mcp.json`, the wrapper not launching, or no `tools/list` reaching AIWatch.

## References

- Cursor MCP docs: <https://docs.cursor.com/context/mcp>
- Cursor Agent MCP CLI docs: <https://docs.cursor.com/cli/mcp>

Cursor documents project-level MCP configuration through `.cursor/mcp.json` and local stdio servers with `command` and `args`. Cursor Agent documents `cursor-agent mcp list` and `cursor-agent mcp list-tools` for inspecting configured servers and tools.

## 1. Start AIWatch Backend

Terminal 1:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
$env:AIWATCH_DEV_MODE="true"
py -3.12 -m uvicorn app.main:app --reload --port 7330
```

If `7330` is occupied, choose another port and update the backend URL in every later command and config value.

## 2. Clear Local AIWatch Data

Terminal 2:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py clear
```

## 3. Prepare Project Cursor MCP Config

From the repo root, inspect the example:

```powershell
cd C:\Users\pakso\Desktop\aiwatch
Get-Content docs\examples\cursor-aiwatch-mcp.example.json
```

Copy or adapt its contents into `.cursor\mcp.json`.

Do not overwrite an existing Cursor MCP config without reviewing it first:

```powershell
cd C:\Users\pakso\Desktop\aiwatch
Test-Path .cursor\mcp.json
```

Create the directory only if needed:

```powershell
New-Item -ItemType Directory -Force .cursor
```

Example config shape:

```json
{
  "mcpServers": {
    "aiwatch-fixture-notes": {
      "type": "stdio",
      "command": "py",
      "args": [
        "-3.12",
        "${workspaceFolder}/backend/scripts/aiwatch_stdio_tap.py",
        "--server-id",
        "fixture-notes-mcp",
        "--backend-url",
        "http://127.0.0.1:7330",
        "--",
        "py",
        "-3.12",
        "${workspaceFolder}/backend/scripts/realistic_mcp_fixture_server.py"
      ]
    }
  }
}
```

If `${workspaceFolder}` does not resolve in your Cursor environment on Windows, replace both script paths with absolute forward-slash paths:

```text
C:/Users/pakso/Desktop/aiwatch/backend/scripts/aiwatch_stdio_tap.py
C:/Users/pakso/Desktop/aiwatch/backend/scripts/realistic_mcp_fixture_server.py
```

## 4. Run AIWatch Doctor

From the repo root:

```powershell
cd C:\Users\pakso\Desktop\aiwatch
py -3.12 backend\scripts\aiwatch.py doctor
py -3.12 backend\scripts\aiwatch.py doctor --json
```

Expected:

```text
[ok] aiwatch-fixture-notes
status: wrapped_by_aiwatch
reason: uses aiwatch_stdio_tap.py with -- upstream separator
```

This only checks local config shape. It does not prove Cursor loaded the config or launched the MCP server.

## 5. Verify Wrapper Mechanics Without Cursor

This does not prove Cursor runtime behavior. It verifies the same wrapper and fixture command path:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\run_realistic_stdio_tap_smoke.py --backend-url http://127.0.0.1:7330
```

Expected:

- `Realistic MCP stdio smoke completed with 4 responses.`
- `captured tools/list: 2 tools`
- `captured tools/call: 1 calls`

## 6. Attempt Cursor Runtime Smoke

Open Cursor on the repo root:

```powershell
cd C:\Users\pakso\Desktop\aiwatch
cursor .
```

If Cursor Agent is installed, inspect MCP server status:

```powershell
cursor-agent mcp list
cursor-agent mcp list-tools aiwatch-fixture-notes
```

If those commands are not available, use Cursor's MCP tools/status UI for your installed version. Trigger tool discovery or list available MCP tools.

## 7. Check AIWatch Results

Terminal 3:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Success output should include:

- `list_notes` on `fixture-notes-mcp`
- `export_notes_bundle` on `fixture-notes-mcp`
- `R-MCP-001` for the fixture's intentionally poisoned tool description
- a generated session id like `stdio-fixture-notes-mcp-YYYYMMDD-HHMMSS-xxxxxxxx`

## Honest Limitations

- This is not verified until Cursor actually launches the wrapper and AIWatch records `tools/list`.
- This does not prove generic Cursor monitoring.
- This does not observe Cursor prompts.
- This does not observe Cursor shell commands.
- This does not observe Cursor file edits.
- This does not hook Cursor internals.
- This does not add HTTP/SSE MCP support.
