# AIWatch Final Demo Packet

Use [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md) as the single day-of-demo source. This packet remains supporting reference material.

## 1. One-line thesis

Veea is the broader runtime-security vision for tool-using AI agents. AIWatch is the working MCP-first proof point: a local observability and integrity layer for MCP traffic routed through the AIWatch stdio wrapper or local HTTP MCP relay.

## 2. 20-second pitch

MCP gives agents tools, and tool definitions plus tool calls create a real trust boundary. AIWatch makes that boundary visible by observing MCP traffic routed through its stdio wrapper or local HTTP MCP relay, fingerprinting tools, and flagging poisoned descriptions, drift, shadowing, and credential-shaped tool-call parameters.

The demo shows current AIWatch proof, not the full future Veea product. Future Veea direction may include additional adapters, richer policy controls, runtime risk scoring, optional blocking, and broader agent/tool compatibility.

Optional companion framing: we use Veea Lobster Trap as the prompt/response-layer baseline and AIWatch as the MCP tool-layer extension. The immediate value is layered runtime visibility across model conversations and routed MCP tools. AIWatch now has a local audit bridge for ingesting Lobster Trap JSONL audit logs into its own unified timeline; unified policy remains future work.

Phase 0/1 technical bridge: AIWatch can export MCP-layer alerts and an MCP observation-plus-alert timeline into Veea-style audit JSONL envelopes as first interop primitives. This is export-only, not live Lobster Trap forwarding or a shared runtime pipeline.

Phase 2 local merge artifact: AIWatch can merge its local MCP audit timeline JSONL file with a Lobster Trap prompt/response audit JSONL file into a unified Veea-style audit timeline. This is local export/merge interop, not a shared event bus and not TerraFabric deployment.

Phase 3 local ingestion: AIWatch can ingest Lobster Trap JSONL audit logs into a local SQLite-backed unified audit timeline and show those records in the AIWatch dashboard beside AIWatch MCP-layer records. The Unified Audit tab includes local risk counts and cross-layer grouping when shared session/request metadata is present. This is local integration, not a Veea cloud control plane, and AIWatch still does not inspect prompts directly.

## 3. 3-minute hackathon demo script

Use this as the polished live path. It is intentionally shorter than the fallback proof commands.

### What to say first

```text
AIWatch is the agent/tool runtime layer. Lobster Trap is the prompt/response policy layer. Unified Audit correlates both layers locally. Enforcement is opt-in and only applies to routed MCP traffic through the AIWatch wrapper or local relay.
```

### Start backend in demo mode

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
$env:AIWATCH_DEV_MODE="true"
py -3.12 -m uvicorn app.main:app --reload --host 127.0.0.1 --port 7330
```

### Start frontend

```powershell
cd C:\Users\pakso\Desktop\aiwatch\frontend
npm run dev
```

Open:

```text
http://localhost:5173/
```

### Seed unified demo

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py demo-seed-unified --extended --backend-url http://127.0.0.1:7330
```

### What to click

- `Overview`
- `Coverage / Controls`
- `Unified Audit`
- `Tools / Registry`

### What to say while clicking

```text
The Coverage / Controls panel is the product map: AIWatch covers routed MCP tool traffic, Lobster Trap covers prompt/response audit records, and Unified Audit shows both local layers together.
```

In `Unified Audit`, point out:

- AIWatch MCP records
- Lobster Trap records
- cross-layer grouped incidents when metadata lines up
- elevated local risk context when related risk signals appear in both layers

```text
AIWatch ingests Lobster Trap prompt/response audit records locally and correlates them with routed MCP records when session or correlation metadata lines up.
```

### Manual quarantine control loop

Use `search_notes` for the bundled extended registry demo, or choose a visible tool name from `Tools / Registry`.

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py quarantined-tools --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py quarantine-tool --tool-name search_notes --reason "Demo quarantine after suspicious routed MCP behavior" --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py quarantined-tools --backend-url http://127.0.0.1:7330
```

```text
This is the control loop: detect a suspicious routed MCP tool, manually quarantine it in the local registry, then use opt-in deny mode for future routed calls to that selected tool.
```

### Explain deny mode

```text
In observe mode, quarantined tools are marked but still forwarded. In opt-in deny mode, future routed calls to quarantined tools are stopped before forwarding through the AIWatch wrapper or relay.
```

Optional status/config commands:

```powershell
py -3.12 scripts\aiwatch.py enforcement-status --backend-url http://127.0.0.1:7330
$env:AIWATCH_ENFORCEMENT_MODE="deny"
```

### Two attack examples

MCP blocked attack:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py demo-blocked-mcp-attack --backend-url http://127.0.0.1:7330
```

Expected result: JSON output shows `action=deny`, `enforcement_mode=deny`, `rule_id=R-MCP-005`, and `upstream_contacted=false`. In deny mode, AIWatch stops selected high-risk routed MCP calls before forwarding.

Prompt-layer correlated attack:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py demo-seed-unified --extended --backend-url http://127.0.0.1:7330
```

Expected result in `Unified Audit`: the bundled Lobster Trap `DENY` record with `correlation_id=demo-poisoned-mcp` groups with related AIWatch MCP activity and appears as elevated cross-layer risk. Lobster Trap provides the prompt/response decision; AIWatch ingests it locally and correlates it with routed MCP activity.

### Optional live Lobster Trap prompt-layer ingest

```powershell
py -3.12 scripts\aiwatch.py lobstertrap-live-ingest --file C:\Users\pakso\lobstertrap\lobstertrap-audit.jsonl --backend-url http://127.0.0.1:7330 --follow
```

```text
LLM traffic must be routed through Lobster Trap for live prompt/response audit records. AIWatch ingests the Lobster Trap JSONL audit log and correlates those records with routed MCP activity when correlation or session metadata lines up.
```

### Closing statement

```text
AIWatch provides a local trust layer for routed MCP agents: it observes tool traffic, detects risky MCP behavior, ingests Lobster Trap prompt/response audit records, correlates both layers in Unified Audit, and can optionally deny selected high-risk or quarantined routed tool calls before forwarding.
```

### Troubleshooting

- Backend not running: start the backend command above from `C:\Users\pakso\Desktop\aiwatch\backend`.
- Dev endpoints disabled: set `$env:AIWATCH_DEV_MODE="true"` before starting the backend.
- Frontend URL: use the localhost URL printed by Vite.
- Unified Audit shows zero records: run `demo-seed-unified --extended`.
- Lobster Trap shows no records: ingest demo records or run `lobstertrap-live-ingest --follow`.
- DB modified after demo: do not commit `backend/data/aiwatch.db`.

## 4. 5-minute demo script

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

### Show local unified audit

1. In the backend directory, seed the full unified audit demo with the safe helper:

`py -3.12 scripts\aiwatch.py demo-seed-unified --extended --backend-url http://127.0.0.1:7330`

2. Open the `Unified Audit` tab.
3. Point to the local risk summary and cross-layer grouping.
4. Say:

`AIWatch MCP records + Lobster Trap prompt/response audit records are grouped locally when they share session/request metadata. This is local integration, not TerraFabric deployment.`

### Close with proof points

1. Mention fixture stdio smoke.
2. Mention Claude Code stdio MCP smoke.
3. Mention the two real MCP package smokes with `@modelcontextprotocol/server-sequential-thinking@2025.7.1` and `@modelcontextprotocol/server-memory@2026.1.26`.
4. Say:

`This is a narrow, local proof that AIWatch can observe MCP traffic routed through its stdio wrapper or local HTTP MCP relay, not a universal client or proxy claim.`

## 5. CLI-only fallback demo

### Start backend

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
$env:AIWATCH_DEV_MODE="true"
py -3.12 -m uvicorn app.main:app --reload --port 7330
```

### Unified seed

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py demo-seed-unified --extended --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py tools --backend-url http://127.0.0.1:7330
py -3.12 scripts\aiwatch.py alerts --backend-url http://127.0.0.1:7330
```

Expected:

- unified helper sequence: clear local AIWatch database, seed extended AIWatch demo data, ingest the bundled Lobster Trap audit fixture
- output includes `Lobster Trap records ingested: N`

### Run eval

```powershell
py -3.12 eval\run_eval.py
```

Expected:

- eval: `43/43`
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

- tests: `175 passed`
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

Scope: this is local-only, experimental, MCP-specific HTTP relay Phase A for a POST JSON request/response subset routed through the AIWatch local HTTP MCP relay. It is not full Streamable HTTP support, SSE support, GET stream handling, a generic HTTP proxy, or production-grade proxying.

## 6. Architecture explanation

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

## 7. Rule explanation

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

## 8. Proof points

- `pytest`: `175 passed`
- `eval`: `43/43`
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

## 8.1 Future Veea Roadmap

- additional adapters beyond MCP
- richer policy controls
- runtime risk scoring
- optional blocking after measured false-positive work
- broader agent/tool compatibility

These are future Veea directions, not implemented AIWatch claims.

## 9. Hard Q&A

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

## 10. Caveats / non-goals

- no generic Claude/Cursor monitoring
- no prompt monitoring
- no shell or file monitoring
- no hidden reasoning visibility
- no arbitrary laptop monitoring
- no guaranteed all-secret detection
- no universal production MCP proxy claim
- no full Streamable HTTP, SSE, GET stream handling, generic HTTP proxy, or production-grade proxying claim
- real package smoke requires Node/npm/npx on PATH and may download the pinned package on first run
- backend must already be running before seed and smoke commands
- frontend `Trigger R-MCP-005 Demo` is synthetic

## 11. Future work

- broader MCP server compatibility testing
- full Streamable HTTP/SSE MCP support
- richer eval corpus
- optional blocking policy after a measured false-positive rate
- packaging and install polish
- possible Cursor documentation later, not current implementation
- optional tamper-evident logs later
