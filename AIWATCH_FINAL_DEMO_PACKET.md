# AIWatch Final Demo Packet

Use [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md) as the single day-of-demo source. This packet remains supporting reference material.

## 1. One-line thesis

Veea is the broader runtime-security vision for tool-using AI agents. AIWatch is the working MCP-first proof point: a local observability and integrity layer for MCP traffic routed through the AIWatch stdio wrapper or local HTTP MCP relay.

## 2. 20-second pitch

MCP gives agents tools, and tool definitions plus tool calls create a real trust boundary. AIWatch makes that boundary visible by observing MCP traffic routed through its stdio wrapper or local HTTP MCP relay, fingerprinting tools, and flagging poisoned descriptions, drift, shadowing, and credential-shaped tool-call parameters.

The demo shows current AIWatch proof, not the full future Veea product. Future Veea direction may include additional adapters, richer policy controls, runtime risk scoring, optional blocking, and broader agent/tool compatibility.

Optional companion framing: Veea Lobster Trap can be shown separately as the prompt/response-layer policy proxy for OpenAI-compatible LLM traffic, while AIWatch remains the MCP tool-layer proof point. Treat this as side-by-side layered runtime security unless a real bridge between the projects is implemented and verified.

## 3. 5-minute demo script

### Open dashboard

1. Start the backend and frontend.
2. Open the dashboard in the browser.
3. Say this limitation line before clicking anything:

`AIWatch observes only MCP traffic routed through the AIWatch stdio wrapper or local HTTP MCP relay. It does not observe prompts, shell commands, file edits, hidden reasoning, or generic Claude/Cursor internals.`

### Seed core demo

1. Click `Seed Demo`.
2. Say:

`This first pass shows the alert pipeline with a small legacy demo set, but the product center is MCP observability and integrity.`

3. Confirm:

`Core seed expected state: 5 events / 7 alerts.`

### Show alerts

1. Open the alerts view.
2. Point out that the alert table shows deterministic outcomes, not model-inferred speculation.
3. Mention that the core seed includes `R-MCP-001` and a small legacy coding-agent demo set.

### Seed extended MCP registry demo

1. Click `Seed MCP Registry Demo`.
2. Confirm:

`Extended seed expected state: 8 events / 10 alerts.`

### Show tool registry and fingerprints

1. Open the registry/tools view.
2. Explain that AIWatch stores current tool fingerprints and observation history.
3. Show the clean `search_notes` baseline on `notes-mcp`.

### Show drift and shadowing

1. Show that `search_notes` later changes on the same server.
2. Explain that this is `R-MCP-002`, tool fingerprint drift.
3. Show the same tool name appearing from `evil-notes-mcp`.
4. Explain that this is `R-MCP-004`, tool name shadowing across servers.

### Trigger R-MCP-005 demo

1. Click `Trigger R-MCP-005 Demo`.
2. Say this clearly:

`This is a synthetic local MCP tools/call fixture posted to the backend so the dashboard can show redacted evidence. It is not itself a live client capture proof.`

### Show redacted evidence

1. Open the new `R-MCP-005` alert.
2. Show that the evidence contains redacted values, not the raw fake credential.
3. Say:

`Known detected credential-shaped values are redacted on tested backend, API, and CLI surfaces.`

### Close with proof points

1. Mention fixture stdio smoke.
2. Mention Claude Code stdio MCP smoke.
3. Mention the two real MCP package smokes with `@modelcontextprotocol/server-sequential-thinking@2025.7.1` and `@modelcontextprotocol/server-memory@2026.1.26`.
4. Say:

`This is a narrow, local proof that AIWatch can observe MCP traffic routed through its stdio wrapper or local HTTP MCP relay, not a universal client or proxy claim.`

## 4. CLI-only fallback demo

### Start backend

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
$env:AIWATCH_DEV_MODE="true"
py -3.12 -m uvicorn app.main:app --reload --port 7330
```

### Clear

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py clear
```

### Core seed

```powershell
py -3.12 scripts\aiwatch.py demo-seed --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Expected:

- core seed: `5 events / 7 alerts`

### Extended seed

```powershell
py -3.12 scripts\aiwatch.py demo-seed --extended --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Expected:

- extended seed: `8 events / 10 alerts`

### Run eval

```powershell
py -3.12 eval\run_eval.py
```

Expected:

- eval: `39/39`
- false positives: none
- false negatives: none

### Run real MCP package smoke

```powershell
py -3.12 scripts\aiwatch.py clear
py -3.12 scripts\run_real_mcp_package_smoke.py --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Expected:

- tests: `130 passed`
- real MCP package smoke tool: `sequentialthinking` under `modelcontextprotocol-sequential-thinking`
- second real MCP package smoke tools: memory tools under `modelcontextprotocol-memory`
- real MCP package smoke alerts: `No alerts found.`

### Run experimental local HTTP MCP relay smoke

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

Scope: this is local-only, experimental, MCP-specific HTTP relay Phase A for a POST JSON request/response subset routed through the AIWatch local HTTP MCP relay. It is not full Streamable HTTP support, SSE support, GET stream handling, a generic HTTP proxy, or production-ready proxying.

## 5. Architecture explanation

The MCP client launches or routes an MCP server through the AIWatch stdio wrapper/tap or local HTTP MCP relay. Those observation paths capture relevant MCP `tools/list` and `tools/call` activity and post normalized events into the FastAPI backend. The backend writes sanitized events into SQLite, updates the MCP tool registry and history, runs deterministic rules, and exposes results to the CLI and dashboard.

In plain English:

- MCP client: the thing using tools
- AIWatch stdio wrapper/tap: the local observation point on stdio MCP traffic
- AIWatch local HTTP MCP relay: the experimental local-only POST JSON MCP relay Phase A observation point
- MCP server: the tool provider behind the AIWatch observation path
- FastAPI backend: the ingest and query surface
- SQLite store: the local event, alert, and registry database
- registry/history: current tool fingerprints plus observation trail
- deterministic rule engine: fixed rule checks, not an LLM judge
- CLI/dashboard: operator views into what AIWatch observed

## 6. Rule explanation

### R-MCP-001

Catches poisoned MCP tool descriptions with deterministic prompt-injection style language inside tool metadata.

Does not catch:

- every malicious tool description
- non-MCP behavior
- prompt content outside routed MCP traffic

### R-MCP-002

Catches tool fingerprint drift when the same MCP server re-registers the same tool name with a changed description or schema.

Does not catch:

- every semantic risk in a tool that never changes
- changes on traffic AIWatch did not observe

### R-MCP-004

Catches tool name shadowing when the same tool name appears across different server IDs.

Does not catch:

- every spoofing scenario
- trust problems that do not manifest as cross-server name collision

### R-MCP-005

Catches credential-shaped MCP tool-call parameters using deterministic pattern detection and stores redacted evidence on tested backend, API, and CLI surfaces.

Does not catch:

- every possible secret format
- proof that a detected value is active or valid
- proof that all possible secrets are detected

## 7. Proof points

- `pytest`: `130 passed`
- `eval`: `39/39`
- fixture stdio smoke
- Claude Code stdio MCP smoke
- two real MCP package smokes
- local HTTP POST JSON MCP relay smoke
- canonical ingest audit
- rollback tests
- redaction regressions
- doctor secrecy tests
- `/v1/events` request body size guard
- replay missing-session `404`
- seed count tests

## 7.1 Future Veea Roadmap

- additional adapters beyond MCP
- richer policy controls
- runtime risk scoring
- optional blocking after measured false-positive work
- broader agent/tool compatibility

These are future Veea directions, not implemented AIWatch claims.

## 8. Hard Q&A

### Does AIWatch monitor Claude Code?

No. It can observe Claude Code-routed MCP traffic when Claude Code launches an MCP server through the AIWatch wrapper.

### Does AIWatch monitor Cursor?

No. Cursor runtime support is not implemented.

### Does it read prompts?

No. Prompt content is out of scope.

### Does it watch shell commands or file edits?

No. It does not observe shell commands or file edits outside routed MCP traffic.

### Is it production-ready?

No. It is a local demo-ready MCP wrapper, experimental local HTTP MCP relay, and backend, not a universal production MCP proxy.

### Does it block attacks?

Not today. The current product center is observability, integrity checks, and deterministic alerting.

### Does it catch all secrets?

No. `R-MCP-005` is deterministic pattern detection with tested redaction coverage, not proof of complete secret coverage.

### Why MCP?

Because MCP tool definitions and tool calls create a concrete, inspectable trust boundary for agent tool use.

### Why not just use model guardrails?

Model guardrails do not give you a local registry, fingerprint history, deterministic drift/shadowing checks, or storage-backed evidence for wrapped MCP traffic.

### What is novel?

The combination of MCP observation through the stdio wrapper or local HTTP MCP relay, fingerprinted tool registry/history, deterministic MCP integrity rules, and tested redaction-before-persistence on canonical ingest paths.

### What happens if traffic bypasses AIWatch?

AIWatch does not see it. That is why wrapper routing and `aiwatch doctor` matter.

### What does doctor prove?

It proves local config shape only. It can show whether a project MCP config appears wrapped, but it does not prove a client actually loaded it.

### Why is the R-MCP-005 dashboard demo synthetic?

Because it is there to show redacted evidence cleanly in the dashboard without changing the seed counts or pretending a live client capture happened when it did not.

### What does the real MCP package smoke prove?

It proves that the pinned real local stdio MCP package paths can run through the AIWatch wrapper, populate the registry, and avoid false-positive alerts in a clean run.

### What are the biggest limitations?

AIWatch only sees routed MCP traffic, the package smoke depends on Node/npm/npx, the HTTP relay Phase A path is only a local POST JSON MCP request/response subset, the frontend R-MCP-005 demo is synthetic, and `R-MCP-005` does not prove total secret coverage.

## 9. Caveats / non-goals

- no generic Claude/Cursor monitoring
- no prompt monitoring
- no shell or file monitoring
- no hidden reasoning visibility
- no arbitrary laptop monitoring
- no guaranteed all-secret detection
- no universal production MCP proxy claim
- no full Streamable HTTP, SSE, GET stream handling, generic HTTP proxy, or production-ready proxying claim
- real package smoke requires Node/npm/npx on PATH and may download the pinned package on first run
- backend must already be running before seed and smoke commands
- frontend `Trigger R-MCP-005 Demo` is synthetic

## 10. Future work

- broader MCP server compatibility testing
- full Streamable HTTP/SSE MCP support
- richer eval corpus
- optional blocking policy after a measured false-positive rate
- packaging and install polish
- possible Cursor documentation later, not current implementation
- optional tamper-evident logs later
