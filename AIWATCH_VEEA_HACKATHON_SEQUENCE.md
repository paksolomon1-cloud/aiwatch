# AIWatch/Veea Hackathon Sequence Spec

## Purpose

This file defines the safest sequence from the current hackathon-ready AIWatch state into Veea-facing positioning without broadening current technical claims.

Use it to decide what work should happen next, what must remain out of scope, and when to stop. This is a planning/spec document, not an implementation request.

## Current Relationship

- Veea is the broader runtime-security product vision for tool-using AI agents.
- AIWatch is the current working MCP-first implementation/proof point.
- AIWatch currently observes MCP traffic routed through the AIWatch stdio wrapper or local HTTP MCP relay.
- Veea can guide narrative, roadmap, UI framing, and future expansion, but not current technical claims.

## Non-Negotiable Product Boundary

AIWatch does not currently claim:

- generic Claude monitoring
- generic Cursor monitoring
- prompt monitoring
- shell command monitoring
- file-edit monitoring
- hidden reasoning visibility
- arbitrary laptop/network monitoring
- production-grade proxying
- catching all secrets
- blocking all exfiltration

## Current Validated Proof State

- Backend tests: `175 passed`
- Eval: `43/43`
- Frontend build passes
- Stdio wrapper smoke works
- Two real MCP package smokes work
- Local HTTP MCP relay Phase A POST JSON subset smoke works
- HTTP relay observes `echo_note` and `list_notes` on `fixture-http-notes-mcp`
- HTTP relay alerts: `No alerts found.`

## Recommended Sequence

### Step 0: Confirm Current Repo State

Purpose:

- Ensure latest docs/runbook commits are pushed.
- Ensure working tree is clean.
- Confirm no generated DB/cache files are modified.

What to inspect:

- `git status`
- `git log --oneline -5`
- tracked generated artifacts such as `backend/data/aiwatch.db`, `backend/eval/aiwatch-eval.db`, `__pycache__/`, and `*.pyc`

Allowed changes:

- None by default.
- Tiny cleanup only if generated/cache files are dirty and can be safely restored.

Explicit non-goals:

- Do not modify backend behavior.
- Do not modify relay behavior.
- Do not add Veea positioning yet.
- Do not touch frontend copy unless it is already stale or unsafe.

Validation commands:

```powershell
cd C:\Users\pakso\Desktop\aiwatch
git status
git log --oneline -5
git status --short
git ls-files -m | Select-String -Pattern "aiwatch.db","aiwatch-eval.db","__pycache__",".pyc"
```

Commit recommendation:

- Commit only if a generated-file cleanup or missing planning document was intentionally fixed.

Stop/continue criteria:

- Continue if `git status` is clean and no generated DB/cache files are modified.
- Stop if the working tree is dirty with unexplained code, database, or cache changes.

Exit criteria:

- Clean git status.
- Recent commits pushed.
- No generated DB/cache modifications.

### Step 1: Final Phrase/Proof/Repo Hygiene Audit

Purpose:

- Run phrase scan.
- Run stale proof-count scan.
- Check generated files.
- Check proof consistency.
- Perform validation sanity check only if needed.

What to inspect:

- `README.md`
- `QUICKSTART_DEMO.md`
- `DEMO_SCRIPT.md`
- `DEMO_RUNBOOK.md`
- `AIWATCH_FINAL_DEMO_PACKET.md`
- `AIWATCH_NEXT_PHASE_SPEC.md`
- `AIWATCH_VEEA_HACKATHON_SEQUENCE.md`
- `THREAT_MODEL.md`
- `NON_GOALS.md`
- `backend/README.md`
- `docs/*.md`
- `frontend/src/*.ts`
- `frontend/src/*.tsx`

Allowed changes:

- Tiny docs-only fixes for stale proof counts.
- Tiny docs-only fixes for unsafe positive claims.
- Tiny docs-only fixes for broken links.
- Tiny text-only frontend proof literal fixes if existing dashboard copy is stale.

Explicit non-goals:

- Do not add Veea positioning yet.
- Do not implement backend behavior.
- Do not implement relay behavior.
- Do not add frontend features.
- Do not redesign the frontend.
- Do not add tests unless an existing literal assertion fails and a minimal docs/proof update is required.

Validation commands:

```powershell
cd C:\Users\pakso\Desktop\aiwatch
git status
git status --short
git ls-files -m | Select-String -Pattern "aiwatch.db","aiwatch-eval.db","__pycache__",".pyc"
Select-String -Path README.md,QUICKSTART_DEMO.md,DEMO_SCRIPT.md,DEMO_RUNBOOK.md,AIWATCH_FINAL_DEMO_PACKET.md,AIWATCH_NEXT_PHASE_SPEC.md,AIWATCH_VEEA_HACKATHON_SEQUENCE.md,THREAT_MODEL.md,NON_GOALS.md,backend\README.md,docs\*.md,frontend\src\*.tsx,frontend\src\*.ts -Pattern "secures Claude Code","provides broad Claude monitoring","provides broad Cursor monitoring","has device-wide laptop visibility","guarantees complete exfiltration blocking","every secret is detected","production-grade proxy"
$oldCount = "11" + "3"
Select-String -Path README.md,QUICKSTART_DEMO.md,DEMO_SCRIPT.md,DEMO_RUNBOOK.md,AIWATCH_FINAL_DEMO_PACKET.md,AIWATCH_NEXT_PHASE_SPEC.md,AIWATCH_VEEA_HACKATHON_SEQUENCE.md,THREAT_MODEL.md,NON_GOALS.md,backend\README.md,docs\*.md,frontend\src\*.tsx,frontend\src\*.ts -Pattern "$oldCount passed","$oldCount tests","pytest: $oldCount","Backend tests.*$oldCount","proof points show ``$oldCount"
```

Commit recommendation:

- Commit after fixing any real hygiene issue and rerunning the relevant scans.

Stop/continue criteria:

- Continue if scans show only explicit caveats, non-goals, hard Q&A corrections, or forbidden-phrase examples.
- Stop if any positive product claim says AIWatch monitors non-MCP client activity or broader laptop/network activity.

Exit criteria:

- No stale `113` counts.
- No unsafe positive claims.
- No generated files dirty.
- Repo clean.

### Step 2: Veea Positioning Pass

Purpose:

- Add lightweight Veea narrative to README/demo/runbook/final packet.
- Keep AIWatch as current MCP-first implementation.
- Do not imply future Veea capabilities already exist.

What to inspect:

- `README.md`
- `DEMO_RUNBOOK.md`
- `DEMO_SCRIPT.md`
- `AIWATCH_FINAL_DEMO_PACKET.md`
- `QUICKSTART_DEMO.md`
- `NON_GOALS.md`
- `THREAT_MODEL.md`

Allowed changes:

- Lightweight docs copy that improves narrative and product framing.
- Future-looking Veea roadmap language clearly labeled as future direction.
- Cross-links that make the day-of-demo path easier to follow.

Explicit non-goals:

- Do not rebrand AIWatch as if it already implements the full Veea vision.
- Do not claim new adapters, risk scoring, blocking, or broader compatibility are implemented.
- Do not broaden AIWatch into generic Claude or Cursor monitoring.
- Do not claim prompt, shell command, file-edit, hidden reasoning, laptop, or arbitrary network monitoring.

Validation commands:

```powershell
cd C:\Users\pakso\Desktop\aiwatch
Select-String -Path README.md,QUICKSTART_DEMO.md,DEMO_SCRIPT.md,DEMO_RUNBOOK.md,AIWATCH_FINAL_DEMO_PACKET.md,AIWATCH_NEXT_PHASE_SPEC.md,AIWATCH_VEEA_HACKATHON_SEQUENCE.md,THREAT_MODEL.md,NON_GOALS.md,backend\README.md,docs\*.md,frontend\src\*.tsx,frontend\src\*.ts -Pattern "secures Claude Code","provides broad Claude monitoring","provides broad Cursor monitoring","has device-wide laptop visibility","guarantees complete exfiltration blocking","every secret is detected","production-grade proxy"
$oldCount = "11" + "3"
Select-String -Path README.md,QUICKSTART_DEMO.md,DEMO_SCRIPT.md,DEMO_RUNBOOK.md,AIWATCH_FINAL_DEMO_PACKET.md,AIWATCH_NEXT_PHASE_SPEC.md,AIWATCH_VEEA_HACKATHON_SEQUENCE.md,THREAT_MODEL.md,NON_GOALS.md,backend\README.md,docs\*.md,frontend\src\*.tsx,frontend\src\*.ts -Pattern "$oldCount passed","$oldCount tests","pytest: $oldCount","Backend tests.*$oldCount","proof points show ``$oldCount"
```

Commit recommendation:

- Commit if the Veea language improves narrative while preserving the AIWatch proof boundary.

Stop/continue criteria:

- Continue if Veea is framed as broader vision and AIWatch remains the current routed-MCP implementation.
- Stop if any copy implies a future Veea capability is already implemented in AIWatch.

Exit criteria:

- Veea language improves narrative without changing current AIWatch scope.

### Step 3: Optional Dashboard/UI Framing Pass

Purpose:

- Update existing dashboard copy/subtitle/proof wording only if useful.
- No new frontend features.
- No redesign.

What to inspect:

- `frontend/src/App.tsx`
- `frontend/src/*.ts`
- `frontend/src/*.tsx`
- current dashboard proof grid and limitation line
- `DEMO_RUNBOOK.md` for exact demo wording

Allowed changes:

- Minimal text-only copy edits to existing labels, subtitles, proof literals, or limitation copy.
- Updates that reinforce Veea vision plus AIWatch proof without overclaiming.

Explicit non-goals:

- Do not add new controls.
- Do not add new views.
- Do not redesign layout.
- Do not change backend/API behavior.
- Do not add runtime features.

Validation commands:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\frontend
npm run build

cd C:\Users\pakso\Desktop\aiwatch
Select-String -Path README.md,QUICKSTART_DEMO.md,DEMO_SCRIPT.md,DEMO_RUNBOOK.md,AIWATCH_FINAL_DEMO_PACKET.md,AIWATCH_NEXT_PHASE_SPEC.md,AIWATCH_VEEA_HACKATHON_SEQUENCE.md,THREAT_MODEL.md,NON_GOALS.md,backend\README.md,docs\*.md,frontend\src\*.tsx,frontend\src\*.ts -Pattern "secures Claude Code","provides broad Claude monitoring","provides broad Cursor monitoring","has device-wide laptop visibility","guarantees complete exfiltration blocking","every secret is detected","production-grade proxy"
```

Commit recommendation:

- Commit only after frontend build passes and generated/cache artifacts are clean or restored.

Stop/continue criteria:

- Continue if edits are text-only and existing UI still says AIWatch observes routed MCP traffic only.
- Stop if the desired change requires new frontend features or backend behavior.

Exit criteria:

- Dashboard reinforces Veea vision plus AIWatch proof without overclaiming.

### Step 4: Final Rehearsal/Readiness Pass

Purpose:

- Use `DEMO_RUNBOOK.md`.
- Verify commands.
- Rehearse the 3-5 minute flow.
- Capture final screenshot/GIF needs only if already supported by existing tools.

What to inspect:

- `DEMO_RUNBOOK.md`
- `README.md`
- `QUICKSTART_DEMO.md`
- `DEMO_SCRIPT.md`
- `AIWATCH_FINAL_DEMO_PACKET.md`
- backend/frontend startup commands
- smoke commands and expected outputs

Allowed changes:

- Typo fixes.
- Broken-link fixes.
- Final proof corrections if rehearsal reveals stale wording.
- Screenshot/GIF references only if they do not require new product behavior.

Explicit non-goals:

- Do not start risky engineering.
- Do not add new demo controls.
- Do not add new backend routes.
- Do not change smoke behavior.
- Do not add production packaging.

Validation commands:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 -m pytest
py -3.12 eval\run_eval.py

cd C:\Users\pakso\Desktop\aiwatch\frontend
npm run build
```

Optional smoke rehearsal, with backend running:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 scripts\aiwatch.py clear
py -3.12 scripts\run_realistic_stdio_tap_smoke.py --backend-url http://127.0.0.1:7330
py -3.12 scripts\run_real_mcp_package_smoke.py --backend-url http://127.0.0.1:7330
py -3.12 scripts\run_second_real_mcp_package_smoke.py --backend-url http://127.0.0.1:7330
py -3.12 scripts\run_http_mcp_relay_smoke.py --backend-url http://127.0.0.1:7330
```

Commit recommendation:

- Commit only typo/proof/link fixes that are validated and low risk.

Stop/continue criteria:

- Continue if the demo flow is repeatable and all proof wording remains honest.
- Stop if rehearsal reveals a command/output mismatch that needs more than a narrow docs correction.

Exit criteria:

- Demo flow is coherent, repeatable, and honest.

### Step 5: Freeze Before Submission

Purpose:

- Stop risky engineering.
- Allow only typo fixes, broken-link fixes, or final proof corrections.
- Run final validation and push.

What to inspect:

- `git status`
- final docs
- generated/cache file status
- final validation output

Allowed changes:

- Typos.
- Broken links.
- Final proof corrections.
- Generated/cache restoration.

Explicit non-goals:

- Do not add behavior.
- Do not add frontend features.
- Do not add backend routes.
- Do not alter database schema.
- Do not add auth, blocking policy, or production packaging.

Validation commands:

```powershell
cd C:\Users\pakso\Desktop\aiwatch\backend
py -3.12 -m pytest
py -3.12 eval\run_eval.py

cd C:\Users\pakso\Desktop\aiwatch\frontend
npm run build

cd C:\Users\pakso\Desktop\aiwatch
git status
git ls-files -m | Select-String -Pattern "aiwatch.db","aiwatch-eval.db","__pycache__",".pyc"
```

Commit recommendation:

- Make one final low-risk commit only if changes were made.
- Push only after final status is clean and validation is complete.

Stop/continue criteria:

- Continue to submission only when the repo is clean and the demo runbook remains the source of truth.
- Stop if any risky uncommitted change remains.

Exit criteria:

- Final repo clean.
- Final validation complete.
- No risky uncommitted changes.

## Safe Veea Language

Approved phrases:

- "Veea is a runtime security layer for tool-using AI agents."
- "AIWatch is the first working implementation, focused on MCP tool traffic."
- "AIWatch observes MCP traffic routed through the AIWatch stdio wrapper or local HTTP MCP relay."
- "Future Veea directions include additional adapters, richer policy controls, runtime risk scoring, optional blocking, and broader agent/tool compatibility."

## Unsafe Language / Do Not Claim

Forbidden current claims:

- "AIWatch provides broad Claude monitoring"
- "AIWatch provides broad Cursor monitoring"
- "AIWatch has prompt visibility"
- "AIWatch watches shell commands"
- "AIWatch watches file edits"
- "AIWatch sees hidden reasoning"
- "AIWatch has device-wide laptop visibility"
- "AIWatch is a production-grade proxy"
- "AIWatch catches all secrets"
- "AIWatch guarantees complete exfiltration blocking"

These phrases may appear only as explicit negative examples, non-goals, caveats, or hard Q&A corrections.

## HTTP Relay Phase A Boundary

HTTP relay Phase A is:

- local-only
- experimental
- MCP-specific
- a POST JSON request/response subset

HTTP relay Phase A is not:

- SSE
- GET stream handling
- full Streamable HTTP
- a generic HTTP proxy
- production-grade proxying

## Decision Rule

- If a change improves clarity without expanding technical scope, it is probably safe.
- If a change implies AIWatch sees activity outside routed MCP traffic, reject it.
- If a change implements new runtime behavior, defer it until after hackathon readiness.

## Prompt Sequence

Next Codex prompts, in order:

1. Final hygiene audit prompt.
2. Veea positioning pass prompt.
3. Optional dashboard copy pass prompt.
4. Final rehearsal/readiness prompt.

## Final Operating Rule

When in doubt, preserve the narrow claim:
AIWatch observes MCP traffic routed through the AIWatch stdio wrapper or local HTTP MCP relay.
