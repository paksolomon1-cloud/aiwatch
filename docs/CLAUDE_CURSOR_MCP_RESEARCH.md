# Claude and Cursor MCP Research

## Scope

This is a research spike only.

- No Claude Code integration is implemented here.
- No Cursor integration is implemented here.
- No detection, storage, frontend, or API behavior changes are proposed in this document.
- Current pre-demo scope is MCP-first: the reproducible demo uses the AIWatch wrapper, fixture/real-package stdio smoke paths, and the documented Claude Code-routed MCP smoke evidence. Cursor runtime support is not implemented and is not part of the current demo.

`AIWATCH_SPEC_V2.md` was not present anywhere under `C:\Users\pakso\Desktop\aiwatch` during this spike, so this memo uses the current repository behavior as the practical source of truth.

## Repo Readiness

### Current MCP tap entrypoints

- `backend/scripts/aiwatch_stdio_tap.py`
- `backend/scripts/run_stdio_tap_demo.py`
- `backend/scripts/run_realistic_stdio_tap_smoke.py`

### Current CLI commands

From `backend/app/cli.py`:

- `clear`
- `demo-seed`
- `tap-demo`
- `eval`
- `tools`
- `alerts`

### Current smoke-test scripts

- `backend/scripts/fake_mcp_server.py`
- `backend/scripts/run_stdio_tap_demo.py`
- `backend/scripts/realistic_mcp_fixture_server.py`
- `backend/scripts/run_realistic_stdio_tap_smoke.py`

### Current docs status

- Root demo flow exists in `DEMO_SCRIPT.md`.
- Backend project summary exists in `backend/README.md`.
- Realistic stdio smoke doc exists in `REALISTIC_MCP_SMOKE.md`.

### Readiness result

The realistic MCP smoke path exists and passes.

That means AIWatch now demonstrates MCP `tools/list` observation through the stdio tap against a more realistic local MCP fixture than the original `fake_mcp_server.py`. It still does not prove vendor-client compatibility.

## Official-Doc Findings

### Claude Code

1. `Connect Claude Code to tools via MCP`
   URL: <https://code.claude.com/docs/en/mcp>
   Supported fact: Claude Code officially supports MCP, including local stdio servers, and documents the local stdio install syntax as `claude mcp add [options] <name> -- <command> [args...]`.

2. `Connect Claude Code to tools via MCP`
   URL: <https://code.claude.com/docs/en/mcp>
   Supported fact: Claude Code stores project-scoped MCP server configuration in `.mcp.json` at the project root and shows a standardized config shape with `mcpServers`, `command`, `args`, and `env`.

3. `Connect Claude Code to tools via MCP`
   URL: <https://code.claude.com/docs/en/mcp>
   Supported fact: Claude Code supports `claude mcp add-json` with stdio JSON such as `{"type":"stdio","command":"/path/to/weather-cli","args":[...],"env":{...}}`.

4. `Connect Claude Code to tools via MCP`
   URL: <https://code.claude.com/docs/en/mcp>
   Supported fact: Claude Code can import MCP servers from Claude Desktop with `claude mcp add-from-claude-desktop`, which implies overlapping MCP server configuration concepts across the two clients.

5. `Connect Claude Code to tools via MCP`
   URL: <https://code.claude.com/docs/en/mcp>
   Supported fact: Claude Code itself can be exposed to Claude Desktop through `claude_desktop_config.json` with `type: "stdio"`, `command: "claude"`, and `args: ["mcp", "serve"]`. This is useful only as a config-shape reference, not as an AIWatch integration plan.

6. `Get started with custom connectors using remote MCP`
   URL: <https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp>
   Supported fact: Anthropic distinguishes cloud-brokered remote connectors from local desktop MCP. The page states that local MCP servers configured in Claude Desktop via `claude_desktop_config.json` are a separate mechanism that uses the local network.

### Claude Desktop

1. `Get started with custom connectors using remote MCP`
   URL: <https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp>
   Supported fact: Claude Desktop has a distinct local MCP path via `claude_desktop_config.json`, separate from cloud-brokered remote connectors.

2. `Getting Started with Local MCP Servers on Claude Desktop`
   URL: <https://support.anthropic.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop>
   Supported fact: Anthropic currently documents local MCP on Claude Desktop as a beta feature and emphasizes desktop extensions for managing local MCP servers.

### Cursor

1. `Cursor – Model Context Protocol (MCP)`
   URL: <https://docs.cursor.com/advanced/model-context-protocol>
   Supported fact: Cursor officially supports MCP and documents three transport methods. The official docs snippet states that `stdio` is local, Cursor-managed, single-user, shell-command based, and manually authenticated.

2. `Cursor – Model Context Protocol (MCP)`
   URL: <https://docs.cursor.com/advanced/model-context-protocol>
   Supported fact: Cursor documents `mcp.json`-based configuration with `mcpServers`, `command`, `args`, and `env`, and documents project config at `.cursor/mcp.json` plus global config at `~/.cursor/mcp.json`.

3. `Cursor – Model Context Protocol (MCP)`
   URL: <https://docs.cursor.com/context/model-context-protocol>
   Supported fact: Cursor documents an extension API for programmatic MCP server registration, but that is not needed for an AIWatch stdio wrapper path.

4. `Cursor – Model Context Protocol (MCP) for CLI`
   URL: <https://docs.cursor.com/cli/mcp>
   Supported fact: Cursor CLI officially supports MCP, uses the same MCP configuration as the editor, and documents `cursor-agent mcp list` and `cursor-agent mcp list-tools`.

## Feasibility Table

| Platform | Official MCP support? | Local stdio server support? | Configurable command/args? | Can AIWatch wrap MCP server? | Requires generic agent monitoring? | Confidence | Recommendation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Claude Code | yes | yes | yes | yes | no | yes | yes |
| Claude Desktop | yes | yes | yes | yes | no | unclear | unclear |
| Cursor | yes | yes | yes | yes | no | yes | deferred |

## Interpretation Notes

- `Can AIWatch wrap MCP server?` is an inference from official stdio `command` and `args` configuration support, not a vendor-documented AIWatch feature.
- `Requires generic agent monitoring?` is `no` because the proposed shape only wraps MCP server process launch and observes MCP traffic on stdio.
- `Claude Desktop` is marked `unclear` on recommendation because the current Anthropic docs are steering local MCP toward desktop extensions, while AIWatch currently has a CLI stdio wedge, not a DXT packaging path.

## Spec Consistency Audit

### Claude Code wrapper path

Consistent with repaired AIWatch v1 if:

- AIWatch is described as an MCP stdio wrapper only.
- The wrapper only observes MCP traffic routed through the wrapped server.
- No shell monitoring, file monitoring, prompt monitoring, or model-output monitoring is added.
- No new non-MCP product claims are made.

Would violate the repaired spec if:

- Claude Code support is marketed as full Claude activity monitoring.
- Old coding-agent detection becomes the product center again.
- AIWatch claims to secure Claude Code as a whole rather than observe wrapped MCP traffic.

### Future-only Cursor wrapper path

Cursor runtime support is not implemented. A future Cursor wrapper path would be consistent with repaired AIWatch v1 only if:

- Cursor support stays limited to MCP server command wrapping through Cursor’s MCP config.
- The work is framed as observing MCP tool metadata and traffic, not general Cursor monitoring.
- No shell or filesystem surveillance is added.

Would violate the repaired spec if:

- The implementation starts collecting non-MCP Cursor behavior.
- The project claims a broad Cursor security product without restricting the claim to MCP routing.
- The work grows into generic Composer or agent telemetry.

### Claude Desktop stepping-stone path

Consistent only as a secondary experiment:

- It can help confirm that Anthropic’s local MCP config model is still stdio-command based.
- It should not become a product pivot or a DXT packaging project in AIWatch v1.

## Technical Integration Sketch

These sketches are justified only because the official docs show local stdio MCP server configuration with explicit `command` and `args`.

These are research sketches, not current demo instructions.

### Claude Code

Current normal config shape:

```json
{
  "mcpServers": {
    "github": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN}"
      }
    }
  }
}
```

Proposed AIWatch-wrapper config shape:

```json
{
  "mcpServers": {
    "github": {
      "type": "stdio",
      "command": "py",
      "args": [
        "-3.12",
        "C:/Users/pakso/Desktop/aiwatch/backend/scripts/aiwatch_stdio_tap.py",
        "--server-id",
        "github",
        "--session-id",
        "claude-code-stdio-001",
        "--backend-url",
        "http://127.0.0.1:7330",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-github"
      ],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN}"
      }
    }
  }
}
```

What AIWatch would observe:

- JSON-RPC stdio frames that pass through the wrapper
- `tools/list` normalization into `tool_register` events
- MCP registry population
- poisoned-description, drift, and shadowing signals from wrapped MCP server definitions

What AIWatch would not observe:

- Claude prompts
- Claude model output
- shell commands outside the wrapped MCP process
- file edits outside MCP tool calls
- non-MCP network activity

Tests required before implementation:

- config-shape docs test only if a helper script is introduced
- wrapper launch test with a realistic MCP fixture server
- stdout/stderr separation test
- backend-down forwarding resilience test
- manual smoke against one known local stdio MCP server package

Manual smoke would prove:

- Claude Code can launch a local MCP server through the AIWatch wrapper
- AIWatch can observe wrapped `tools/list` traffic

Manual smoke would not prove:

- complete Claude Code observability
- enforcement or blocking
- compatibility with every MCP server package

### Future-only Cursor sketch

Current normal config shape:

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "${env:GITHUB_TOKEN}"
      }
    }
  }
}
```

Proposed AIWatch-wrapper config shape:

```json
{
  "mcpServers": {
    "github": {
      "type": "stdio",
      "command": "py",
      "args": [
        "-3.12",
        "C:/Users/pakso/Desktop/aiwatch/backend/scripts/aiwatch_stdio_tap.py",
        "--server-id",
        "github",
        "--session-id",
        "cursor-stdio-001",
        "--backend-url",
        "http://127.0.0.1:7330",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-github"
      ],
      "env": {
        "GITHUB_TOKEN": "${env:GITHUB_TOKEN}"
      }
    }
  }
}
```

What AIWatch would observe:

- MCP stdio traffic for the wrapped server
- `tools/list` tool definitions that Cursor loads through that server

What AIWatch would not observe:

- general Cursor editor actions
- Composer planning state
- terminal activity
- non-MCP tool usage

Tests required before implementation:

- wrapper launch against realistic fixture server
- docs-driven config sample validation
- manual editor smoke
- manual `cursor-agent` smoke, because the CLI uses the same MCP config

Manual smoke would prove:

- Cursor can launch a local stdio MCP server through the AIWatch wrapper
- AIWatch can ingest wrapped tool definitions and surface deterministic MCP alerts

Manual smoke would not prove:

- coverage of all Cursor MCP transports
- complete parity between editor and CLI behavior

## Marketing Claims

### Overclaims to avoid

- `AIWatch is a whole-product security layer for Claude Code`
- `AIWatch provides broad Cursor security coverage`
- `AIWatch monitors everything the agent does`
- `AIWatch blocks exfiltration from Claude or Cursor`
- `AIWatch is a full MCP proxy for all clients`

### Claims that are technically true

- `AIWatch can observe MCP traffic when a local stdio MCP server is launched through the AIWatch wrapper.`
- `Claude Code and Cursor both document local stdio MCP server configuration with command and args fields.`
- `That documented stdio surface appears sufficient for an experimental AIWatch wrapper integration without generic shell or file monitoring.`

## Current Pre-Demo Recommendation

Do not implement Cursor for the current demo. Keep the demo centered on AIWatch observing MCP traffic routed through the AIWatch wrapper, the fixture and real-package stdio smoke paths, and the completed Claude Code-routed MCP smoke evidence.

Do not:

- add generic agent monitoring
- add non-MCP telemetry
- revive demo coding-agent rules as product-center behavior
- market this as full Claude or Cursor security coverage

## Deferred Future Note

A later MCP-only wrapper experiment should be handled one platform at a time and should not be part of the current demo hardening pass. Do not add generic agent monitoring. Add only:

- a documentation-backed sample config using `aiwatch_stdio_tap.py` as the stdio wrapper
- one manual smoke path against a real local stdio MCP server package
- any minimal test coverage needed for wrapper launch/config helpers

Do not change detection rules, storage, frontend, or product claims.
