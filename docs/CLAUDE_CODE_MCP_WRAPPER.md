# Claude Code MCP Wrapper

This is an experimental local stdio MCP wrapper path.

It does **not** add generic Claude Code monitoring.
It does **not** monitor prompts, shell commands, file edits, or other non-MCP Claude Code actions.
It only shows how AIWatch can observe MCP traffic routed through the AIWatch stdio wrapper.
The manual Claude Code runtime smoke is distinct from the local fixture and real-package smoke scripts: those scripts validate wrapper behavior without proving that Claude Code loaded a project MCP config.

## What This Observes

When Claude Code launches a local stdio MCP server through `aiwatch_stdio_tap.py`, AIWatch can observe:

- MCP JSON-RPC traffic routed through the wrapper
- `tools/list` responses
- `tools/call` requests
- normalized `tool_register` events posted to the AIWatch backend
- MCP tool registry rows
- deterministic MCP alerts such as `R-MCP-001` and `R-MCP-005`

## What This Does Not Observe

This path does not observe:

- Claude prompts
- Claude model output
- non-MCP shell commands
- file edits outside MCP tool calls
- hidden reasoning
- general Claude Code internal behavior
- arbitrary local process activity

## Safety Warnings

- This is experimental.
- This only observes MCP traffic routed through the wrapper.
- It does not monitor non-MCP Claude Code actions.
- Do not route untrusted server commands through the wrapper.
- This is not a production-ready Claude Code integration.

## Why No New Wrapper Script Was Added

The existing tap CLI already supports the required Claude Code wrapper shape:

- `--backend-url`
- `--server-id`
- optional `--session-id`
- `--log-raw-frames`
- `--` as the separator before the real MCP server argv
- arbitrary upstream MCP server command and arguments after `--`

Because of that, no command-launching change was needed for this patch.

If `--session-id` is omitted, AIWatch generates one when the tap process starts. The generated id is readable, process-scoped, and logged to stderr only. Protocol stdout remains JSON-RPC traffic only.

Pass `--session-id` explicitly when you want repeatable demo grouping.

## Sample `.mcp.json`-Style Config

Example file:

- [claude-code-aiwatch-mcp.example.json](examples/claude-code-aiwatch-mcp.example.json)

Example contents:

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

This sample uses the existing no-dependency realistic local fixture server so the wrapper path is testable without Claude Code and without external services.

The sample intentionally omits `--session-id`, so repeated Claude Code launches are grouped into separate AIWatch sessions by default.
If `${CLAUDE_PROJECT_DIR:-.}` is not expanded by your Claude Code environment on Windows, replace those entries with absolute paths such as `C:/Users/pakso/Desktop/aiwatch/backend/scripts/aiwatch_stdio_tap.py`.

On Windows, the real MCP server command after `--` must include the Python launcher before the `.py` script. The sample uses the correct shape:

```text
-- py -3.12 .../realistic_mcp_fixture_server.py
```

Do not put `realistic_mcp_fixture_server.py` directly after `--`; that can fail with `WinError 193`.

## Verified Claude Code Runtime Smoke

A real manual Claude Code runtime smoke was completed successfully on Windows.

Observed:

- Claude Code detected the project `.mcp.json`.
- `aiwatch-fixture-notes` was enabled and reconnected through `/mcp`.
- After clearing the AIWatch database, Claude Code routed MCP traffic through the AIWatch wrapper.
- `scripts\aiwatch.py tools` showed only `export_notes_bundle` and `list_notes` on `fixture-notes-mcp`.
- `scripts\aiwatch.py alerts` showed `R-MCP-001` for the poisoned MCP tool description with a generated session id like `stdio-fixture-notes-mcp-...`.

This proves Claude Code-routed MCP traffic can be observed by AIWatch. It does not prove generic Claude Code monitoring and does not observe prompts, file edits, shell commands, hidden reasoning, or Claude Code internals.

## PowerShell Commands

Start the backend:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
$env:AIWATCH_DEV_MODE="true"
py -3.12 -m uvicorn app.main:app --reload --port 7330
```

If `7330` is occupied, use another port and set `AIWATCH_BACKEND_URL` in the Claude Code environment or replace the backend URL in the sample config.

## How Claude Code Would Use It

1. Put a project-scoped `.mcp.json` in the repo root using the sample shape above.
2. Make sure the backend URL is reachable.
3. Run `py -3.12 backend\scripts\aiwatch.py doctor` from the repo root and confirm `aiwatch-fixture-notes` is `wrapped_by_aiwatch`.
4. Launch Claude Code in the project.
5. When Claude Code connects to the configured MCP server, the real fixture server is launched behind `aiwatch_stdio_tap.py`.
6. AIWatch forwards the stdio traffic and captures `tools/list`.

## How To Verify After Claude Code Launches The Server

From another PowerShell terminal:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Expected:

- `fixture-notes-mcp` tools appear in the registry
- `export_notes_bundle` appears as a tool
- `R-MCP-001` appears for the poisoned tool description

The generated session id appears in the wrapper's stderr diagnostics as:

```text
[aiwatch] generated session_id=stdio-fixture-notes-mcp-YYYYMMDD-HHMMSS-xxxxxxxx
```

It should not appear on protocol stdout.

## No-Claude Local Smoke

The existing realistic smoke helper already exercises the same wrapper command shape without requiring Claude Code:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py clear
py -3.12 scripts\run_realistic_stdio_tap_smoke.py --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

That smoke path proves the wrapper mechanics:

- `aiwatch_stdio_tap.py` launches the real stdio MCP server
- protocol traffic is forwarded
- `tools/list` is captured and normalized
- the registry populates
- `R-MCP-001` appears for the poisoned fixture tool

It does not prove Claude Code internals or full client compatibility beyond the documented local stdio MCP command surface.
