# AIWatch Frontend

This Vite + React + TypeScript app is the local dashboard for AIWatch. It presents the repaired v1 story: `mitmproxy for MCP` with tool fingerprints, drift history, shadowing warnings, deterministic alerts, and a small local registry UI.

## Implemented

- overview dashboard
- alerts table with detail panel
- session replay
- MCP tool registry view
- local dev controls for clear, core seed, and extended MCP registry seed

## Local Development

Terminal 1:

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
py -3.12 -m uvicorn app.main:app --reload --port 7330
```

Terminal 2:

```powershell
cd backend
py -3.12 scripts\clear_data.py
```

Terminal 3:

```powershell
cd frontend
npm install
npm run dev
```

With the dashboard open:

- Click **Seed Demo** for the stable five-event walkthrough.
- Click **Seed MCP Registry Demo** for MCP fingerprint, drift, and shadowing scenarios.

CLI fallback:

```powershell
cd backend
py -3.12 scripts\seed_demo.py
py -3.12 scripts\seed_demo.py --extended
```

## Development-Only Endpoints

- `DELETE http://127.0.0.1:7330/v1/dev/clear`
- `POST http://127.0.0.1:7330/v1/dev/seed-demo`

These endpoints exist for local demos only and must not be exposed in production without authentication.

## Dashboard Views

- Overview: backend health, event and alert counts, recent sessions, and registry summary.
- Alerts: a scannable alert table with linked event context and MCP evidence detail.
- Tools / Registry: current MCP tool fingerprints, shadowing warnings, and hash history.
- Session replay: chronological event playback with linked alerts and intent/action mismatch highlighting.
