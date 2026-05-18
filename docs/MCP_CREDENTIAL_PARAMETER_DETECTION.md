# MCP Credential Parameter Detection

`R-MCP-005` detects credential-shaped values in MCP `tools/call` arguments.

This is MCP-only detection. It does not monitor prompts, shell commands, file edits, Claude Code internals, Cursor internals, or non-MCP process activity.

## What It Detects

AIWatch recursively scans `tools/call` `params.arguments` values for deterministic credential signals:

- OpenAI-style API keys such as `sk-...`
- GitHub tokens such as `ghp_...` and `github_pat_...`
- AWS access key IDs such as `AKIA...`
- private key blocks such as `-----BEGIN PRIVATE KEY-----`
- bearer-token-shaped values
- common secret field names with long, high-entropy-looking values, such as `api_key`, `token`, `access_token`, `secret`, `password`, `private_key`, `client_secret`, `session_cookie`, and `authorization`

## Rule

- Rule ID: `R-MCP-005`
- Severity: `critical`
- Decision: `block`
- Summary: `Credential-shaped value in MCP tool call parameters`

## Redaction Guarantee

Raw detected secret values are not stored in alert evidence. For backend-ingested MCP `tool_call` events, tool-call arguments and raw JSON-like payloads are sanitized before the event row is written.

Real ingestion paths use the canonical ingest function. Known detected credential-shaped values are redacted before persistence on tested ingest paths. Event, registry/history updates, and generated alerts are committed atomically for one ingested event.

Evidence stores redacted findings in this shape:

```json
{
  "param_path": "params.arguments.api_key",
  "secret_type": "openai_key_like",
  "redacted_value": "[REDACTED:OPENAI_KEY]",
  "value_length": 39
}
```

Multiple findings are stored as multiple redacted entries. The CLI alert table prints alert summaries, not raw evidence values.

Known detected credential-shaped values are redacted on tested backend, API, CLI, and opt-in frame-log surfaces. Current regression coverage checks persisted event action params, persisted raw JSON-like payloads, persisted alert evidence, `POST /v1/events` responses, `GET /v1/events` output, `GET /v1/alerts` output, CLI alert output, and validation error responses.

That does not mean every possible future integration path is safe by default, and it does not mean every possible secret format is detected.

## False-Positive Limits

AIWatch does not alert just because a benign word like `password` appears in a query or description string. Suspicious field names require a long, high-entropy-looking value unless the value matches a strong known credential pattern.

Examples that should not alert:

```json
{"token": "demo"}
```

```json
{"query": "password rotation policy"}
```

## Limitations

This is deterministic pattern detection, not full secret validation. It does not call external APIs, does not verify whether a credential is active, does not guarantee every secret is detected, and does not inspect non-MCP traffic.
