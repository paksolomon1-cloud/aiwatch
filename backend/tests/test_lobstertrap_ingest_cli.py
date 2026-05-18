from __future__ import annotations

import json
from pathlib import Path

from app.cli import main as cli_main


def _secret(*parts: str) -> str:
    return "".join(parts)


def test_ingest_lobstertrap_audit_cli_posts_jsonl_and_continues_after_bad_line(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    audit_path = tmp_path / "lobstertrap-audit.jsonl"
    raw_secret = _secret("Bearer ", "LOBSTERTRAPCLI", "1234567890", "ABCDEF")
    audit_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": "2026-05-18T12:00:00Z",
                        "request_id": "req-cli-1",
                        "direction": "ingress",
                        "action": "DENY",
                        "rule_name": "block_prompt_injection",
                        "prompt": raw_secret,
                    },
                    sort_keys=True,
                ),
                "{not-json",
                json.dumps(
                    {
                        "timestamp": "2026-05-18T12:01:00Z",
                        "request_id": "req-cli-2",
                        "direction": "egress",
                        "action": "ALLOW",
                    },
                    sort_keys=True,
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    posted_records: list[dict[str, object]] = []

    def fake_request_json(path, *, backend_url, method="GET", body=None):
        posted_records.append(
            {
                "path": path,
                "backend_url": backend_url,
                "method": method,
                "body": body,
            }
        )
        return {"accepted": 1, "rejected": 0, "stored_record_ids": [len(posted_records)]}

    monkeypatch.setattr("app.cli.request_json", fake_request_json)

    assert cli_main(
        [
            "ingest-lobstertrap-audit",
            "--file",
            str(audit_path),
            "--backend-url",
            "http://127.0.0.1:7330",
        ]
    ) == 0

    captured = capsys.readouterr()
    rendered_cli_output = captured.out + captured.err

    assert len(posted_records) == 2
    assert all(record["path"] == "/v1/integrations/lobstertrap/audit" for record in posted_records)
    assert all(record["method"] == "POST" for record in posted_records)
    assert [record["body"]["request_id"] for record in posted_records] == ["req-cli-1", "req-cli-2"]
    assert "Skipping malformed JSONL line 2" in captured.err
    assert "Ingested 2 Lobster Trap audit records; rejected 0; malformed lines 1; stored IDs [1, 2]." in captured.out
    assert raw_secret not in rendered_cli_output


def test_ingest_lobstertrap_audit_cli_rejects_nonlocal_backend_url(tmp_path: Path, capsys) -> None:
    audit_path = tmp_path / "lobstertrap-audit.jsonl"
    audit_path.write_text('{"request_id":"req-cli-local","action":"ALLOW"}\n', encoding="utf-8")

    assert cli_main(
        [
            "ingest-lobstertrap-audit",
            "--file",
            str(audit_path),
            "--backend-url",
            "https://example.com",
        ]
    ) == 2

    captured = capsys.readouterr()
    assert "only posts to a local AIWatch backend URL" in captured.err


def test_ingest_demo_lobstertrap_audit_cli_posts_bundled_fixture(monkeypatch, capsys) -> None:
    posted_records: list[dict[str, object]] = []

    def fake_request_json(path, *, backend_url, method="GET", body=None):
        posted_records.append(
            {
                "path": path,
                "backend_url": backend_url,
                "method": method,
                "body": body,
            }
        )
        return {"accepted": 1, "rejected": 0, "stored_record_ids": [len(posted_records)]}

    monkeypatch.setattr("app.cli.request_json", fake_request_json)

    assert cli_main(
        [
            "ingest-demo-lobstertrap-audit",
            "--backend-url",
            "http://127.0.0.1:7330",
        ]
    ) == 0

    captured = capsys.readouterr()
    assert len(posted_records) == 3
    assert all(record["path"] == "/v1/integrations/lobstertrap/audit" for record in posted_records)
    assert all(record["method"] == "POST" for record in posted_records)
    assert [record["body"]["request_id"] for record in posted_records] == [
        "lt-demo-req-deny-001",
        "lt-demo-req-allow-001",
        "lt-demo-req-review-001",
    ]
    assert "Ingested 3 Lobster Trap audit records; rejected 0; malformed lines 0; stored IDs [1, 2, 3]." in captured.out


def test_lobstertrap_status_cli_prints_backend_status(monkeypatch, capsys) -> None:
    requested: list[dict[str, object]] = []

    def fake_request_json(path, *, backend_url, method="GET", body=None):
        requested.append(
            {
                "path": path,
                "backend_url": backend_url,
                "method": method,
                "body": body,
            }
        )
        return {
            "source": "lobstertrap",
            "configured": True,
            "status": "active",
            "total_records": 1,
            "deny_count": 1,
            "human_review_count": 0,
            "quarantine_count": 0,
            "allow_count": 0,
            "redacted_count": 1,
            "last_record_at": "2026-05-18T12:00:00Z",
            "seconds_since_last_record": 1,
            "last_decision": "DENY",
            "last_rule_id": "block_prompt_injection",
            "last_summary": "Lobster Trap prompt/response inspection",
            "suggested_ingest_command": (
                "py -3.12 scripts\\aiwatch.py ingest-lobstertrap-audit --file <jsonl> "
                "--backend-url http://127.0.0.1:7330"
            ),
            "demo_ingest_command": (
                "py -3.12 scripts\\aiwatch.py ingest-demo-lobstertrap-audit "
                "--backend-url http://127.0.0.1:7330"
            ),
        }

    monkeypatch.setattr("app.cli.request_json", fake_request_json)

    assert cli_main(["lobstertrap-status", "--backend-url", "http://127.0.0.1:7330"]) == 0

    captured = capsys.readouterr()
    assert requested == [
        {
            "path": "/v1/integrations/lobstertrap/status",
            "backend_url": "http://127.0.0.1:7330",
            "method": "GET",
            "body": None,
        }
    ]
    assert '"status": "active"' in captured.out
    assert '"last_decision": "DENY"' in captured.out
