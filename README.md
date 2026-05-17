# AIWatch

AIWatch is a local MCP observability and security layer. It observes MCP traffic routed through the AIWatch stdio wrapper, records MCP tool definitions and tool calls, fingerprints tools, and raises deterministic alerts for tool-surface risks.

AIWatch is MCP-first. It is not generic Claude Code monitoring, Cursor monitoring, laptop monitoring, prompt monitoring, shell monitoring, file-edit monitoring, hidden-reasoning visibility, or arbitrary local process monitoring.

## Current Detection

- `R-MCP-001`: poisoned MCP tool descriptions
- `R-MCP-002`: MCP tool fingerprint drift
- `R-MCP-004`: MCP tool name shadowing across servers
- `R-MCP-005`: credential-shaped values in MCP `tools/call` parameters, with safe redaction before storage/output for detected credential values

The repo still contains legacy/demo coding-agent rules for seeded demos and eval fixtures, but the product center is MCP observability and integrity.

## Current Components

- FastAPI backend
- SQLite persistence
- MCP tool registry and history
- tool fingerprinting
- deterministic alert engine
- CLI wrapper at `backend/scripts/aiwatch.py`
- React dashboard
- local stdio MCP wrapper/tap path at `backend/scripts/aiwatch_stdio_tap.py`
- `aiwatch doctor` config health check for local `.mcp.json` and `.cursor/mcp.json`
- deterministic local eval harness

Real ingestion paths use the canonical backend ingest function. Known detected credential-shaped values are redacted before persistence on tested ingest paths, and the event row, MCP registry/history updates, and generated alerts are committed atomically for one ingested event.

## Current Proof Points

- Claude Code local stdio MCP wrapper runtime smoke succeeded on Windows.
- AIWatch observed Claude Code-routed MCP traffic when Claude Code launched an MCP server through the AIWatch stdio wrapper.
- Tests recently passed: `99`.
- Eval recently passed: `39/39`.
- Core seed expected count: `5 events / 7 alerts`.
- Extended seed expected count: `8 events / 10 alerts`.

The Claude Code runtime smoke proves local stdio MCP routing through AIWatch worked. It does not prove generic Claude Code monitoring, production proxy coverage, or visibility into prompts, shell commands, file edits, hidden reasoning, or Claude Code internals.

## Quickstart

Start the backend:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
$env:AIWATCH_DEV_MODE="true"
py -3.12 -m uvicorn app.main:app --reload --port 7330
```

Run the CLI from another terminal:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py clear
py -3.12 scripts\aiwatch.py demo-seed
py -3.12 scripts\aiwatch.py alerts
py -3.12 scripts\aiwatch.py tools
```

Run the extended MCP registry demo:

```powershell
py -3.12 scripts\aiwatch.py clear
py -3.12 scripts\aiwatch.py demo-seed --extended
py -3.12 scripts\aiwatch.py alerts
py -3.12 scripts\aiwatch.py tools
```

Run the realistic local stdio MCP smoke:

```powershell
py -3.12 scripts\aiwatch.py clear
py -3.12 scripts\run_realistic_stdio_tap_smoke.py --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Run the real MCP package smoke with a harmless no-token package:

```powershell
py -3.12 scripts\aiwatch.py clear
py -3.12 scripts\run_real_mcp_package_smoke.py --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Run the second real MCP package smoke with another harmless no-token package:

```powershell
py -3.12 scripts\aiwatch.py clear
py -3.12 scripts\run_second_real_mcp_package_smoke.py --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Run the config health check from the repo root:

```powershell
cd C:\Users\pakso\Desktop\aiwatch
py -3.12 backend\scripts\aiwatch.py doctor
```

Run tests and eval:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 -m pytest
py -3.12 eval\run_eval.py
```

## Limitations

- MCP traffic must be routed through AIWatch to be observed.
- This is a local/dev demo posture, not a production enterprise gateway.
- AIWatch does not observe prompts, shell commands, file edits, hidden reasoning, Claude Code internals, Cursor internals, or arbitrary local process activity.
- AIWatch does not guarantee prevention of all exfiltration.
- AIWatch does not implement production auth, HMAC logs, semantic embeddings, HTTP/SSE MCP proxying, SIEM/exporters, ML detection, or Cursor runtime support.
- `aiwatch doctor` checks config shape only; it cannot prove a client loaded that config or prevent config tampering.

## Documentation

- [Reproducible demo checklist](QUICKSTART_DEMO.md)
- [Demo script](DEMO_SCRIPT.md)
- [Real MCP package smoke](REAL_MCP_PACKAGE_SMOKE.md)
- [Claude Code runtime smoke checklist](docs/CLAUDE_CODE_RUNTIME_SMOKE.md)
- [Claude Code MCP wrapper docs](docs/CLAUDE_CODE_MCP_WRAPPER.md)
- [AIWatch doctor docs](docs/AIWATCH_DOCTOR.md)
- [MCP credential parameter detection](docs/MCP_CREDENTIAL_PARAMETER_DETECTION.md)
- [Threat model](THREAT_MODEL.md)
- [Non-goals](NON_GOALS.md)
