# AIWatch Doctor

`aiwatch doctor` is a local MCP config health check. It reports whether known project MCP config entries appear to route stdio MCP traffic through AIWatch's `aiwatch_stdio_tap.py` wrapper.

It does not modify config files.
It does not monitor Claude Code, Cursor, prompts, file edits, shell commands, or client internals.
It only checks local MCP server command configuration.

## How To Run

From the project root:

```powershell
cd C:\Users\pakso\Desktop\aiwatch
py -3.12 backend\scripts\aiwatch.py doctor
```

From the backend directory:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py doctor
```

JSON output for scripts or reproducibility logs:

```powershell
py -3.12 scripts\aiwatch.py doctor --json
```

The command exits `0` for this first pass, including when unwrapped servers are found.

## Config Files Checked

The first pass only checks config files under the current working directory:

- `.mcp.json`
- `.cursor/mcp.json`

It does not scan the rest of the machine.

## Statuses

- `wrapped_by_aiwatch`: the server references `aiwatch_stdio_tap.py` and includes a `--` separator before the upstream MCP server command.
- `not_wrapped`: the server appears to launch an MCP server directly.
- `invalid_config`: the JSON or server entry is malformed enough that AIWatch cannot classify it.
- `unknown`: the server references `aiwatch_stdio_tap.py`, but the wrapper shape is incomplete or ambiguous.

## What Wrapped Means

A server is classified as wrapped when the command/args reference `aiwatch_stdio_tap.py` and the args contain `--` before the real upstream server command.

Example shape:

```json
{
  "mcpServers": {
    "aiwatch-fixture-notes": {
      "command": "py",
      "args": [
        "-3.12",
        "backend/scripts/aiwatch_stdio_tap.py",
        "--server-id",
        "fixture-notes-mcp",
        "--",
        "py",
        "-3.12",
        "backend/scripts/realistic_mcp_fixture_server.py"
      ]
    }
  }
}
```

## Secret Handling

`aiwatch doctor` does not print config `env` blocks and does not print environment variable values. It prints a command summary and classification reason only.

## How This Fits The Threat Model

`aiwatch doctor` helps identify likely MCP routing gaps before a runtime smoke. It can show that a local project MCP server entry appears to bypass AIWatch or appears to use the AIWatch wrapper shape.

It cannot prove that Claude Code, Cursor, or another MCP client actually loaded the config. It cannot prove the upstream MCP server launched successfully. It cannot prevent config tampering. Use a runtime smoke, such as the Claude Code runtime checklist, for end-to-end verification that MCP traffic is actually routed through AIWatch.

## Limitations

This command does not prove that a client has loaded the config or successfully connected to the MCP server. It only checks the local config shape. Use the Claude Code runtime smoke checklist for an end-to-end manual runtime check.
