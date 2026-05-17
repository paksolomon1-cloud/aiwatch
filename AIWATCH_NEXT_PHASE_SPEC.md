# AIWatch Next-Phase Authority Spec

This file is the source of truth for AIWatch work after the current demo-ready checkpoint. It preserves the narrow MCP-first product boundary while defining how to proceed into riskier work such as stdio tap hardening, additional real MCP package smoke tests, Claude Code smoke refinement, and possible Cursor MCP runtime smoke.

No future task should broaden AIWatch's claim without first updating this spec.

## 1. Status Snapshot

### Current verified state

- AIWatch is demo-ready.
- Git/GitHub checkpoint exists.
- Current branch is clean after commits:
  - initial demo-ready checkpoint
  - generated artifact ignore cleanup
  - UI/layout/R-MCP-005 collapse/root wording fixes
- `pytest`: `113 passed`
- `eval`: `39/39`
- Frontend build passes.
- Fixture stdio smoke works.
- Claude Code stdio MCP smoke works.
- Real MCP package smoke works using `@modelcontextprotocol/server-sequential-thinking@2025.7.1`.
- Second real MCP package smoke works using `@modelcontextprotocol/server-memory@2026.1.26`.
- Real package smoke expected tool: `sequentialthinking` under `modelcontextprotocol-sequential-thinking`.
- Second real package smoke expected tools: `add_observations`, `create_entities`, `create_relations`, `delete_entities`, `delete_observations`, `delete_relations`, `open_nodes`, `read_graph`, and `search_nodes` under `modelcontextprotocol-memory`.
- Real package smoke expected alerts: `No alerts found.`
- Canonical ingest is `backend/app/storage.py::ingest_event()`.
- Real ingestion paths route through canonical ingest.
- Redaction-before-persistence and rollback behavior are tested.
- `R-MCP-005` redaction regressions cover tested backend/API/CLI surfaces.
- `aiwatch doctor` and `aiwatch doctor --json` exist.
- Root API message now uses canonical MCP-first wording.
- Dashboard proof points show `113`, `39/39`, `5/7`, `8/10`.
- `R-MCP-005` action params are collapsed by default in session replay.
- Nonexistent session replay now returns `404`.
- `POST /v1/events` rejects request bodies over 4 MiB with `413` before `AgentEvent` validation or canonical ingest.

### Demo seed counts

| Seed | Expected state |
| --- | --- |
| Core seed | `5 events / 7 alerts` |
| Extended seed | `8 events / 10 alerts` |

### Currently closed findings

| Finding | Status | Notes |
| --- | --- | --- |
| Finding 1: stale dashboard proof numbers | Closed | Dashboard now reflects current proof points. |
| Finding 12: root endpoint positioning drift | Closed | Root endpoint now uses MCP-first positioning. |
| Finding 2: unbounded readline in stdio tap | Closed | Stdio tap has a max frame size and oversized-frame tests. |
| Finding 3: non-UTF-8 upstream output can crash tap | Closed | Stdio tap decodes invalid upstream bytes safely. |
| Finding 4: hung upstream process cleanup | Closed | Stdio tap terminates then kills on cleanup timeout. |
| Finding 6: `request_methods` no eviction | Closed | Pending request-method correlation map is capped. |
| Finding 7: no `/v1/events` request body size limit | Closed | `/v1/events` has a 4 MiB raw body guard and 413 tests. |
| Finding 8: replay returns `200` for nonexistent sessions | Closed | Missing replay sessions return 404; frontend intentional reset flows avoid false errors. |

### Currently open findings

| Finding | Status | Priority area |
| --- | --- | --- |
| Finding 9: duplicate frame method logic | Open | Cleanup/refactor |

### Skipped or noise findings

| Finding | Status | Notes |
| --- | --- | --- |
| Finding 5: unlocked bool duplicate log race | Skipped/noise | Low practical impact for current local demo. |
| Finding 10: join timeout race/noise | Skipped/noise | Related cleanup can be revisited during tap hardening if needed. |
| Finding 11: double redaction currently harmless | Skipped/noise | Current behavior is safe and tested. |

## 2. Product Boundary

AIWatch observes MCP traffic routed through the AIWatch wrapper.

The core product claim is:

> AIWatch is a local observability and integrity layer for MCP traffic routed through the AIWatch wrapper.

Runtime smoke with Claude Code means Claude Code-routed MCP traffic can be observed when configured through the wrapper. It does not mean AIWatch monitors Claude Code generally.

Future Cursor work must be framed the same way: Cursor-routed MCP traffic through the wrapper, not Cursor monitoring.

### Hard non-goals

AIWatch does not monitor:

- prompts
- shell commands
- file edits
- hidden reasoning
- Claude Code internals
- Cursor internals
- arbitrary local process activity

AIWatch does not currently claim:

- generic Claude Code monitoring
- generic Cursor monitoring
- production-ready universal MCP proxying
- all-secret detection
- all-exfiltration blocking
- enterprise auth
- SIEM/export platform
- ML detection
- public fingerprint registry
- block-on-critical enforcement

### Forbidden phrasing

Do not use these phrases as product claims:

- "AIWatch secures Claude Code"
- "AIWatch monitors Claude"
- "AIWatch monitors Cursor"
- "AIWatch watches your laptop"
- "AIWatch blocks all exfiltration"
- "AIWatch catches all secrets"
- "production-ready proxy"

These phrases may appear only as explicit negative examples or caveats.

### Safe phrasing

Use these phrases:

- "MCP traffic routed through the AIWatch wrapper"
- "Claude Code-routed MCP traffic"
- "Cursor-routed MCP traffic, if configured through the wrapper"
- "local stdio MCP wrapper"
- "experimental local wrapper path"
- "deterministic MCP security checks"
- "known detected credential-shaped values are redacted on tested backend/API/CLI surfaces"

## 3. Existing Architecture

AIWatch is a local MCP observation and integrity system built around a stdio wrapper/tap and a backend ingest path.

| Component | Role |
| --- | --- |
| MCP client | Launches or talks to an MCP server. Examples include local demo clients and Claude Code when configured through the wrapper. |
| AIWatch stdio wrapper/tap | Sits between the MCP client and upstream MCP server, forwards stdio traffic, and captures relevant MCP frames. |
| Upstream MCP server | Provides MCP tools. The server is not modified by AIWatch. |
| FastAPI backend | Receives normalized events, serves events/alerts/tools, and exposes dev/demo endpoints. |
| SQLite local store | Stores events, alerts, tool fingerprints, and tool observation history. |
| `AgentEvent` normalization | Converts observed MCP frames into structured events for ingest. |
| Canonical ingest path | `backend/app/storage.py::ingest_event()` is the write path for real event ingestion. |
| Registry/current fingerprints | Stores latest known tool identity and hashes. |
| Registry history | Stores observed tool definitions over time. |
| Deterministic detector | Produces fixed-rule alerts from normalized events and registry state. |
| Alerts | Store rule results, rationale, and evidence. |
| CLI | Runs local demo, eval, doctor, tools, and alerts commands. |
| Frontend dashboard | Presents demo state, alerts, sessions, tools, registry details, and redacted evidence. |

### Load-bearing invariant

Every real event ingestion path must use `ingest_event()`, which sanitizes before persistence and commits the event row, registry/history updates, and generated alerts atomically for one event.

Do not write new API, tap, demo, smoke, or script ingestion paths that call lower-level storage helpers directly.

## 4. Detection Rules

### Rule summary

| Rule | Name | Current focus |
| --- | --- | --- |
| `R-MCP-001` | Poisoned MCP tool description | Tool metadata poisoning |
| `R-MCP-002` | MCP tool fingerprint drift | Tool definition change over time |
| `R-MCP-004` | MCP tool name shadowing | Same tool name across server IDs |
| `R-MCP-005` | Credential-shaped MCP tool-call parameter | Credential-like values in `tools/call` arguments |

### R-MCP-001: poisoned MCP tool description

Detects:

- MCP tool descriptions containing deterministic prompt-injection style language.
- Tool metadata that appears to instruct the model to read, reveal, ignore, override, or exfiltrate sensitive information.

Operates on:

- MCP `tool_register` events, usually normalized from `tools/list` responses.
- Tool description text.

Does not detect:

- every possible malicious or misleading description.
- prompt content outside routed MCP traffic.
- shell commands, file edits, or non-MCP client internals.

Demo evidence:

- Core seed includes a poisoned MCP tool alert.
- Realistic stdio fixture smoke includes an intentionally poisoned tool description.

Eval coverage notes:

- Eval includes malicious poisoned-description cases and benign documentation/password-policy style descriptions to guard against obvious false positives.

### R-MCP-002: MCP tool fingerprint drift

Detects:

- The same MCP server re-registering an existing tool name with a changed description hash or schema hash.

Operates on:

- MCP `tool_register` events.
- Current fingerprint row and registry history for the tool.

Does not detect:

- semantic risk in a tool that never changes.
- drift for traffic not routed through AIWatch.
- every possible tool identity spoofing pattern.

Demo evidence:

- Extended seed shows `search_notes` changing on `notes-mcp`.

Eval coverage notes:

- Eval includes description drift and schema drift fixtures.

### R-MCP-004: MCP tool name shadowing

Detects:

- The same MCP tool name appearing on multiple server IDs.

Operates on:

- MCP `tool_register` events.
- Registry lookup by tool name across server IDs.

Does not detect:

- every spoofing scenario.
- trust problems that do not create a cross-server name collision.
- traffic not routed through AIWatch.

Demo evidence:

- Extended seed shows `search_notes` on `evil-notes-mcp` shadowing `search_notes` on `notes-mcp`.

Eval coverage notes:

- Eval includes malicious shadowing cases and benign similar-name cases.

### R-MCP-005: credential-shaped MCP tool-call parameter

Detects:

- Credential-shaped values in MCP `tools/call` parameters using deterministic patterns.
- Known shapes such as OpenAI-style keys, GitHub tokens, AWS access key IDs, private key blocks, bearer-token-shaped values, and long high-entropy-looking values under sensitive field names.

Operates on:

- MCP `tool_call` events.
- `params.arguments` and normalized action params.

Does not detect:

- every possible secret format.
- whether a detected value is active or valid.
- credential leakage outside routed MCP traffic.
- complete secret coverage.

Demo evidence:

- Frontend `Trigger R-MCP-005 Demo` posts a synthetic local MCP `tools/call` fixture so the dashboard can show redacted evidence.
- This demo is not a live client capture proof.

Eval coverage notes:

- Eval includes multiple credential-shaped tool-call fixtures and benign short/non-entropy values.

Required redaction statement:

- `R-MCP-005` is deterministic pattern detection only.
- It is not proof that every possible secret is caught.
- Redaction guarantees apply to known detected values on tested backend/API/CLI surfaces.
- Raw values should not be shown in demo UI by default.

## 5. Current Proof Points

| Proof point | Current result |
| --- | --- |
| Backend tests | `113 passed` |
| Eval | `39/39` |
| Fixture stdio smoke | Works |
| Claude Code stdio MCP smoke | Works |
| Real MCP package smoke | Works with `@modelcontextprotocol/server-sequential-thinking@2025.7.1` |
| Second real MCP package smoke | Works with `@modelcontextprotocol/server-memory@2026.1.26` |
| Canonical ingest audit | Complete |
| Rollback tests | Present |
| Redaction regression tests | Present |
| Doctor secrecy tests | Present |
| Replay missing-session behavior | `404` |
| `/v1/events` raw body guard | 4 MiB, returns `413` before validation/ingest |
| Demo seed count tests | Present |
| Frontend build | Passing |
| Phrase scan | Clean |

Demo seed counts:

- Core seed: `5 events / 7 alerts`
- Extended seed: `8 events / 10 alerts`

## 6. Open Risks and Priorities

### Priority 1: stdio tap robustness before any broader runtime integration

Address:

- oversized frames
- non-UTF-8 upstream output
- hung upstream cleanup
- `request_methods` map eviction

Reason:

- The wrapper is the observation point. It should be hardened before connecting more clients or expanding runtime smoke claims.

### Priority 2: runtime smoke expansion

Address:

- second real MCP package smoke
- improved Claude Code MCP runtime smoke docs/tests
- Cursor MCP runtime smoke attempt

Reason:

- Compatibility evidence should grow through narrow MCP-routed smoke tests, not through broad client monitoring claims.

### Priority 3: API/demo polish

Address:

- replay nonexistent session `404`
- `/v1/events` request body size limit
- frame method deduplication
- docs sweep

Reason:

- These improve correctness and operator clarity without changing product scope.

### Priority 4: future but not now

Defer:

- HTTP/SSE MCP support
- broader compatibility matrix
- optional blocking policy
- tamper-evident logs
- packaging/install polish

Reason:

- These expand surface area and should come after wrapper robustness and smoke expansion.

## 7. Required Next Implementation Order

1. Stdio tap robustness hardening.
2. Second real MCP package smoke.
3. Claude Code smoke refinement.
4. Cursor MCP runtime smoke exploration.
5. Replay endpoint `404` plus frontend silent clear coupling fix.
6. Request body size guard.
7. Docs sweep.
8. Only then consider HTTP/SSE MCP support.

Why this order:

- Wrapper hardening reduces risk before connecting more clients.
- A second real package strengthens compatibility evidence while staying narrow.
- Claude Code and Cursor must remain MCP-routed smoke tests, not generic monitoring claims.
- HTTP/SSE expands scope and should come later.

## 8. Stdio Tap Robustness Spec

### Oversized frames

Implementation requirements:

- Add a max frame/line size constant.
- Do not parse or post an oversized frame.
- Log a concise warning to stderr.
- Do not pollute protocol stdout.
- Preserve valid forwarding behavior as safely as possible.
- Add a test.

Acceptance notes:

- Oversized input must not create an `AgentEvent`.
- Valid subsequent frames should still work when practical.
- Diagnostics must stay on stderr.

### Non-UTF-8 upstream output

Implementation requirements:

- Invalid bytes must not crash the tap.
- Prefer bytes-mode reading with `decode(errors="replace")` or equivalent.
- Preserve valid JSON-RPC forwarding.
- Add a test.

Acceptance notes:

- A malformed byte sequence should not terminate the wrapper.
- Valid UTF-8 JSON-RPC frames should continue to forward and normalize.

### Hung upstream cleanup

Implementation requirements:

- On `wait` timeout, terminate.
- Wait briefly.
- Kill if still alive.
- Avoid flaky test if not practical.
- Add a test if reliable.

Acceptance notes:

- Cleanup should not leave obvious orphan processes in normal failure cases.
- Tests should not rely on long real sleeps.

### `request_methods` cap/eviction

Implementation requirements:

- Add a cap or TTL.
- Numeric ID `1` and string ID `"1"` must remain distinct.
- Notifications/no-ID frames must not poison the map.
- Add a test for many unmatched requests.

Acceptance notes:

- The request-method correlation map should not grow unbounded.
- Correlation should still work for normal request/response pairs.

## 9. Runtime Smoke Expansion Spec

### Second real MCP package smoke

Requirements:

- no token
- no cloud
- harmless local behavior
- stdio-based
- no sensitive local file access by default
- routed through `aiwatch_stdio_tap.py`
- captures `tools/list`
- registry populates
- benign package should not create false-positive alerts
- document exact package/version and commands

Selection guidance:

- Prefer a small published MCP package with a stable version.
- Avoid packages that require accounts, credentials, network APIs, or local filesystem crawling by default.
- Treat first-run package download as an operational caveat.

### Claude Code smoke refinement

Requirements:

- Preserve current claim:

> Claude Code-routed MCP traffic can be observed when routed through the wrapper.

- No prompt, shell, file, hidden-reasoning, or internal monitoring claims.
- Update docs only if command drift exists.
- Keep examples Windows-safe.

Success criterion:

- Claude Code launches the configured local stdio MCP server through the wrapper.
- `tools/list` reaches AIWatch and registry populates.

### Cursor MCP runtime smoke

Requirements:

- Exploration only.
- Do not claim implementation until verified.
- Inspect `.cursor/mcp.json` shape.
- Run `aiwatch doctor`.
- Attempt local stdio MCP wrapper routing.
- Success criterion: `tools/list` reaches AIWatch and registry populates.
- Failure criterion: document exact blocker honestly.
- No Cursor internals.
- No prompt/file/shell monitoring.
- No browser automation claim.

Approved wording after success:

- "Cursor-routed MCP traffic can be observed if configured through the wrapper."

Forbidden wording after success:

- "AIWatch monitors Cursor."

## 10. Replay 404 Coupling Warning

Resolved coupling:

- The replay endpoint now returns `404` for nonexistent sessions.
- The frontend uses explicit clear-state handling and silent stale replay refreshes for intentional clear, seed, and credential demo actions.
- Intentional reset flows should not show a false replay-load error banner.

The accepted fix used both patterns where appropriate:

- `loadSessionReplay(..., { silent: true })`
- clear `selectedSessionId` and `sessionReplay` before reloading

Normal user-triggered replay load errors should still be visible.

## 11. Demo and UI Guardrails

Current frontend status:

- frontend is demo-ready
- do not redesign
- no new pages unless required
- no animations
- no production SaaS framing

Preserve:

- `2x2` proof grid
- limitation line
- `R-MCP-005` collapse
- demo controls ordering
- alert table compact summaries
- detail pane rationale
- redacted evidence block

Any future UI work must:

- improve demo clarity
- not alter backend claims
- not expose raw fake credential values by default

## 12. Docs Sweep Scope

The prior audit missed:

- `backend/scripts/fake_mcp_server.py`
- `backend/scripts/realistic_mcp_fixture_server.py`
- `backend/scripts/run_real_mcp_package_smoke.py`
- `backend/tests/test_eval_harness.py`
- `backend/tests/test_mcp_normalizer.py`
- `NON_GOALS.md`
- `DEMO_SCRIPT.md`
- `QUICKSTART_DEMO.md`
- `docs/`

Next docs/code sweep should be read-only and scoped to those files.

## 13. Validation Requirements

Every implementation task must run the relevant validation.

### Default backend validation

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 -m pytest
py -3.12 eval\run_eval.py
```

### Frontend validation

```powershell
cd C:\Users\pakso\Desktop\aiwatch\frontend
npm run build
```

### Smoke validation where relevant

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py clear
py -3.12 scripts\run_realistic_stdio_tap_smoke.py --backend-url http://127.0.0.1:7330
py -3.12 scripts\run_real_mcp_package_smoke.py --backend-url http://127.0.0.1:7330
py -3.12 scripts\run_second_real_mcp_package_smoke.py --backend-url http://127.0.0.1:7330
```

Note:

- `aiwatch.py clear` clears the local SQLite database directly and does not take `--backend-url`.
- Smoke scripts require a running backend.
- Real package smoke requires Node/npm/`npx` on PATH and may download the pinned package on first run.

### Phrase scan

```powershell
cd C:\Users\pakso\Desktop\aiwatch
Select-String -Path README.md,QUICKSTART_DEMO.md,DEMO_SCRIPT.md,THREAT_MODEL.md,NON_GOALS.md,docs\*.md,frontend\src\*.tsx,frontend\src\*.ts -Pattern "secures Claude Code","monitors Claude","monitors Cursor","watches your laptop","blocks all exfiltration","all secrets are caught","production-ready proxy"
```

Any remaining matches must be explicit negative/non-goal wording.

## 14. Git Workflow

Before risky work, commit clean state. After each successful risky task, commit again. Do not pile multiple risky changes into one uncommitted working tree.

Use branches if possible:

- `robustness/stdio-tap`
- `smoke/second-real-mcp`
- `smoke/cursor-mcp`
- `api/replay-404`

Useful commands:

```powershell
git status
git log --oneline
git checkout -b robustness/stdio-tap
git add -A
git commit -m "..."
git restore .
git reset --hard <commit>
```

Safety rule:

- Do not run `git restore .` or `git reset --hard <commit>` unless the intent is explicit and the target state is understood.
- Prefer small commits after each validated risky task.

## 15. Future Work Not Yet Authorized

These are intentionally not next:

- generic Claude monitoring
- generic Cursor monitoring
- HTTP/SSE MCP proxy
- ML detector
- enterprise auth
- hosted dashboard
- SIEM exporter
- blocking policy
- public fingerprint registry
- tamper-evident logs
- large frontend redesign

These can be reconsidered only after wrapper robustness and runtime smoke expansion are complete.

## 16. Final Operating Rule

When in doubt, preserve the narrow claim: AIWatch observes MCP traffic routed through the AIWatch wrapper. Do not expand the claim just because a client like Claude Code or Cursor is involved.
