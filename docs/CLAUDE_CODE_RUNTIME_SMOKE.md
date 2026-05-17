# Claude Code Runtime Smoke Checklist

This checklist verifies that Claude Code can route local stdio MCP traffic through the AIWatch wrapper.

It does not prove generic Claude Code monitoring. AIWatch only observes MCP traffic routed through `aiwatch_stdio_tap.py`.

## Verified Manual Runtime Result

This smoke was completed successfully on Windows with a real Claude Code runtime.

Observed result:

- Claude Code detected the project `.mcp.json`.
- `aiwatch-fixture-notes` was enabled and reconnected through `/mcp`.
- After clearing the AIWatch database, Claude Code routed MCP traffic through the AIWatch wrapper.
- `scripts\aiwatch.py tools` showed only:
  - `export_notes_bundle` on `fixture-notes-mcp`
  - `list_notes` on `fixture-notes-mcp`
- `scripts\aiwatch.py alerts` showed:
  - `R-MCP-001`
  - summary `Poisoned MCP tool description detected`
  - session id like `stdio-fixture-notes-mcp-...`

Meaning:

- This proves Claude Code-routed MCP traffic can be observed by AIWatch when the MCP server is launched through the stdio wrapper.
- This does not prove generic Claude Code monitoring.
- This does not observe prompts, file edits, shell commands, hidden reasoning, or Claude Code internals.

## Preconditions

- Claude Code is installed and can be launched from PowerShell.
- Python 3.12 is available through `py -3.12`.
- The AIWatch repo is at `C:\Users\pakso\Desktop\aiwatch`.
- No existing project-root `.mcp.json` will be overwritten without review.

## 1. Start AIWatch Backend

Terminal 1:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
$env:AIWATCH_DEV_MODE="true"
py -3.12 -m uvicorn app.main:app --reload --port 7330
```

If `7330` is occupied, choose another port and use that backend URL in every later command and config value.

## 2. Clear Local AIWatch Data

Terminal 2:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py clear
```

## 3. Prepare Project MCP Config

From the repo root, inspect the example:

```powershell
cd C:\Users\pakso\Desktop\aiwatch
Get-Content docs\examples\claude-code-aiwatch-mcp.example.json
```

Copy or adapt its contents into a project-root `.mcp.json`.

Do not overwrite an existing `.mcp.json` without reviewing it first:

```powershell
cd C:\Users\pakso\Desktop\aiwatch
Test-Path .mcp.json
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
        "${CLAUDE_PROJECT_DIR:-.}/backend/scripts/aiwatch_stdio_tap.py",
        "--server-id",
        "fixture-notes-mcp",
        "--backend-url",
        "${AIWATCH_BACKEND_URL:-http://127.0.0.1:7330}",
        "--",
        "py",
        "-3.12",
        "${CLAUDE_PROJECT_DIR:-.}/backend/scripts/realistic_mcp_fixture_server.py"
      ]
    }
  }
}
```

For a non-`7330` backend, set `AIWATCH_BACKEND_URL` before launching Claude Code or replace the URL in `.mcp.json`.

```powershell
$env:AIWATCH_BACKEND_URL="http://127.0.0.1:7330"
```

If Claude Code does not expand `${CLAUDE_PROJECT_DIR:-.}` on your platform, replace those entries with absolute paths:

```text
C:/Users/pakso/Desktop/aiwatch/backend/scripts/aiwatch_stdio_tap.py
C:/Users/pakso/Desktop/aiwatch/backend/scripts/realistic_mcp_fixture_server.py
```

## 4. Launch Claude Code From Project Root

Terminal 2:

```powershell
cd C:\Users\pakso\Desktop\aiwatch
claude
```

If your install uses a different executable name, use that command from the same project root.

## 5. Trigger MCP Tool Discovery

Inside Claude Code, ask for available MCP tools or otherwise trigger the MCP server to load.

Example prompt:

```text
List the available MCP tools for this project.
```

If Claude Code has an MCP status or tools command in your installed version, use it to confirm that `aiwatch-fixture-notes` loaded.

## 6. Check AIWatch Tools

Terminal 3:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
```

Expected tools:

- `list_notes`
- `export_notes_bundle`
- server id `fixture-notes-mcp`

## 7. Check AIWatch Alerts

Terminal 3:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Expected alert:

- `R-MCP-001`
- summary `Poisoned MCP tool description detected`
- session id like `stdio-fixture-notes-mcp-YYYYMMDD-HHMMSS-xxxxxxxx`

## Success Signs

- Claude Code loads the `aiwatch-fixture-notes` MCP server.
- AIWatch wrapper diagnostics show a generated session id if stderr/logs are visible:

```text
[aiwatch] generated session_id=stdio-fixture-notes-mcp-YYYYMMDD-HHMMSS-xxxxxxxx
```

- `scripts\aiwatch.py tools` shows the fixture MCP tools.
- `scripts\aiwatch.py alerts` shows `R-MCP-001`.
- Protocol stdout is not polluted with `[aiwatch]` diagnostics.

## Failure Diagnosis

### Backend Not Running

Symptom:

- No tools or alerts appear.
- Wrapper stderr may show backend unavailable.

Check:

```powershell
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:7330/v1/alerts
```

### Wrong Backend Port

Symptom:

- Backend is running, but wrapper posts to the wrong URL.

Fix:

- Update `AIWATCH_BACKEND_URL`.
- Or replace the URL in `.mcp.json`.
- Re-launch Claude Code so the MCP server process restarts.

### Python Path Issue

Symptom:

- Claude Code cannot start the MCP server.
- Error mentions `py` not found or Python launch failure.

Check:

```powershell
py -3.12 --version
```

Fix:

- Use an absolute Python executable path in `.mcp.json`.

### `.mcp.json` Not In Project Root

Symptom:

- Claude Code launches but does not show `aiwatch-fixture-notes`.

Check:

```powershell
cd C:\Users\pakso\Desktop\aiwatch
Test-Path .mcp.json
```

### Claude Code Did Not Load Project MCP Config

Symptom:

- `.mcp.json` exists, but the MCP server is absent.

Check:

- Restart Claude Code from the project root.
- Check Claude Code's MCP status or server list if available in your installed version.
- Confirm the JSON is valid.

```powershell
Get-Content .mcp.json | ConvertFrom-Json | Out-Null
```

### Windows Path Escaping Issue

Symptom:

- MCP server fails to launch with path parsing errors.

Fix:

- Prefer forward slashes in JSON paths.
- Use absolute paths if environment-variable expansion is unclear.

### Real Server Command Not Found

Symptom:

- The wrapper starts, but the server behind `--` fails.

Check the command after `--` in `.mcp.json`:

```text
py -3.12 C:/Users/pakso/Desktop/aiwatch/backend/scripts/realistic_mcp_fixture_server.py
```

On Windows, do not put the `.py` server script directly after `--`.

Wrong shape:

```text
-- C:/Users/pakso/Desktop/aiwatch/backend/scripts/realistic_mcp_fixture_server.py
```

That can fail with `WinError 193` because Windows tries to execute the `.py` file itself as an application.

Correct shape:

```text
-- py -3.12 C:/Users/pakso/Desktop/aiwatch/backend/scripts/realistic_mcp_fixture_server.py
```

Run it directly if needed:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\realistic_mcp_fixture_server.py
```

## Honest Limitations

- This proves only that Claude Code can route local stdio MCP traffic through AIWatch.
- It does not prove generic Claude Code monitoring.
- It does not observe prompts.
- It does not observe file edits.
- It does not observe shell commands outside MCP traffic.
- It does not observe hidden reasoning.
- It does not observe Claude Code internals.
- It is an experimental local wrapper path.
