from __future__ import annotations

import json
from pathlib import Path

from app.cli import build_parser, main as cli_main


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


def test_lobstertrap_live_ingest_posts_existing_records_before_follow_waits(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    audit_path = tmp_path / "lobstertrap-audit.jsonl"
    audit_path.write_text(
        "\n".join(
            [
                json.dumps({"request_id": "req-live-1", "action": "DENY", "rule_name": "block_prompt_injection"}),
                json.dumps({"request_id": "req-live-2", "action": "ALLOW"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    posted_records: list[dict[str, object]] = []

    def fake_request_json(path, *, backend_url, method="GET", body=None):
        posted_records.append({"path": path, "backend_url": backend_url, "method": method, "body": body})
        return {"accepted": 1, "rejected": 0, "stored_record_ids": [len(posted_records)]}

    monkeypatch.setattr("app.cli.request_json", fake_request_json)

    assert cli_main(
        [
            "lobstertrap-live-ingest",
            "--file",
            str(audit_path),
            "--backend-url",
            "http://127.0.0.1:7330",
            "--follow",
            "--max-records",
            "2",
            "--poll-interval-seconds",
            "0.01",
        ]
    ) == 0

    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert [record["body"]["request_id"] for record in posted_records] == ["req-live-1", "req-live-2"]
    assert "Lobster Trap prompt/response audit records are being ingested" in captured.out
    assert "Records ingested: 2" in captured.out
    assert "Malformed/skipped records: 0" in captured.out
    assert "Last decision/rule: ALLOW" in captured.out
    assert "AIWatch monitors prompts" not in output
    assert "blocks all exfiltration" not in output


def test_lobstertrap_live_ingest_from_end_skips_existing_and_posts_appended(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    audit_path = tmp_path / "lobstertrap-audit.jsonl"
    audit_path.write_text(
        json.dumps({"request_id": "req-existing", "action": "DENY", "rule_name": "existing_rule"}) + "\n",
        encoding="utf-8",
    )
    posted_records: list[dict[str, object]] = []
    appended = False

    def fake_request_json(path, *, backend_url, method="GET", body=None):
        posted_records.append({"path": path, "backend_url": backend_url, "method": method, "body": body})
        return {"accepted": 1, "rejected": 0, "stored_record_ids": [len(posted_records)]}

    def fake_sleep(_seconds: float) -> None:
        nonlocal appended
        if not appended:
            with audit_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({"request_id": "req-appended", "action": "HUMAN_REVIEW"}) + "\n")
            appended = True

    monkeypatch.setattr("app.cli.request_json", fake_request_json)
    monkeypatch.setattr("app.cli.time.sleep", fake_sleep)

    assert cli_main(
        [
            "lobstertrap-live-ingest",
            "--file",
            str(audit_path),
            "--backend-url",
            "http://127.0.0.1:7330",
            "--follow",
            "--from-end",
            "--max-records",
            "1",
            "--poll-interval-seconds",
            "0.01",
        ]
    ) == 0

    captured = capsys.readouterr()
    assert [record["body"]["request_id"] for record in posted_records] == ["req-appended"]
    assert "From end: enabled" in captured.out
    assert "Records ingested: 1" in captured.out


def test_lobstertrap_live_ingest_missing_file_errors_by_default(tmp_path: Path, capsys) -> None:
    missing_path = tmp_path / "missing-lobstertrap-audit.jsonl"

    assert cli_main(
        [
            "lobstertrap-live-ingest",
            "--file",
            str(missing_path),
            "--backend-url",
            "http://127.0.0.1:7330",
        ]
    ) == 2

    captured = capsys.readouterr()
    assert "Lobster Trap live audit ingestion step failed" in captured.err
    assert "Lobster Trap fixture/audit file not found" in captured.err


def test_lobstertrap_live_ingest_wait_for_file_reports_timeout(tmp_path: Path, capsys) -> None:
    missing_path = tmp_path / "missing-lobstertrap-audit.jsonl"

    assert cli_main(
        [
            "lobstertrap-live-ingest",
            "--file",
            str(missing_path),
            "--backend-url",
            "http://127.0.0.1:7330",
            "--wait-for-file",
            "--wait-timeout-seconds",
            "0.001",
            "--poll-interval-seconds",
            "0.001",
        ]
    ) == 2

    captured = capsys.readouterr()
    assert "timed out waiting for Lobster Trap audit file" in captured.err


def test_lobstertrap_live_ingest_skips_malformed_lines_without_crashing(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    audit_path = tmp_path / "lobstertrap-audit.jsonl"
    audit_path.write_text(
        "{not-json\n"
        + json.dumps({"request_id": "req-live-good", "action": "DENY", "rule_name": "block_prompt_injection"})
        + "\n",
        encoding="utf-8",
    )
    posted_records: list[dict[str, object]] = []

    def fake_request_json(path, *, backend_url, method="GET", body=None):
        posted_records.append({"path": path, "backend_url": backend_url, "method": method, "body": body})
        return {"accepted": 1, "rejected": 0, "stored_record_ids": [len(posted_records)]}

    monkeypatch.setattr("app.cli.request_json", fake_request_json)

    assert cli_main(
        [
            "lobstertrap-live-ingest",
            "--file",
            str(audit_path),
            "--backend-url",
            "http://127.0.0.1:7330",
        ]
    ) == 0

    captured = capsys.readouterr()
    assert [record["body"]["request_id"] for record in posted_records] == ["req-live-good"]
    assert "Skipping malformed JSONL line 1" in captured.err
    assert "Records ingested: 1" in captured.out
    assert "Malformed/skipped records: 1 (malformed: 1; backend rejected: 0)" in captured.out
    assert "Last decision/rule: DENY / block_prompt_injection" in captured.out


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


def test_demo_seed_unified_clears_seeds_before_lobstertrap_ingest(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    audit_path = tmp_path / "lobstertrap-audit-sample.jsonl"
    audit_path.write_text('{"request_id":"req-unified-1","action":"DENY"}\n', encoding="utf-8")
    order: list[str] = []

    def fake_clear_db():
        order.append("clear")

    def fake_request_json(path, *, backend_url, method="GET", body=None):
        if path.startswith("/v1/dev/seed-demo"):
            order.append("seed")
            return {
                "status": "ok",
                "events_created": 8,
                "alerts_created": 10,
                "tools_observed": 4,
                "items": [],
            }
        if path == "/v1/integrations/lobstertrap/audit":
            order.append("ingest")
            return {"accepted": 1, "rejected": 0, "stored_record_ids": [101]}
        if path == "/v1/audit/summary":
            order.append("summary")
            return {
                "aiwatch_mcp_records": 8,
                "lobstertrap_records": 1,
                "total_records": 9,
            }
        raise AssertionError(f"unexpected path: {path}")

    monkeypatch.setattr("app.cli.DEMO_LOBSTERTRAP_AUDIT_PATH", audit_path)
    monkeypatch.setattr("app.cli.clear_db", fake_clear_db)
    monkeypatch.setattr("app.cli.request_json", fake_request_json)

    assert cli_main(["demo-seed-unified", "--extended", "--backend-url", "http://127.0.0.1:7330"]) == 0

    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert order == ["clear", "seed", "ingest", "summary"]
    assert "AIWatch seed result: 8 events; 10 alerts; 4 tools observed." in captured.out
    assert "Lobster Trap records ingested: 1" in captured.out
    assert "aiwatch_mcp_records=8; lobstertrap_records=1; total_records=9" in captured.out
    assert "deployed Veea infrastructure" not in output
    assert "actual TerraFabric control plane" not in output


def test_demo_seed_unified_reports_malformed_lobstertrap_fixture(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    audit_path = tmp_path / "bad-lobstertrap-audit.jsonl"
    audit_path.write_text("{not-json\n", encoding="utf-8")

    def fake_request_json(path, *, backend_url, method="GET", body=None):
        if path.startswith("/v1/dev/seed-demo"):
            return {
                "status": "ok",
                "events_created": 5,
                "alerts_created": 7,
                "tools_observed": 2,
                "items": [],
            }
        raise AssertionError(f"unexpected path after malformed fixture: {path}")

    monkeypatch.setattr("app.cli.DEMO_LOBSTERTRAP_AUDIT_PATH", audit_path)
    monkeypatch.setattr("app.cli.clear_db", lambda: None)
    monkeypatch.setattr("app.cli.request_json", fake_request_json)

    assert cli_main(["demo-seed-unified", "--backend-url", "http://127.0.0.1:7330"]) == 1

    captured = capsys.readouterr()
    assert "Lobster Trap fixture ingestion step failed" in captured.err
    assert "malformed Lobster Trap fixture JSONL line 1" in captured.err


def test_demo_seed_unified_reports_missing_lobstertrap_fixture(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    missing_path = tmp_path / "missing-lobstertrap-audit.jsonl"

    def fake_request_json(path, *, backend_url, method="GET", body=None):
        if path.startswith("/v1/dev/seed-demo"):
            return {
                "status": "ok",
                "events_created": 5,
                "alerts_created": 7,
                "tools_observed": 2,
                "items": [],
            }
        raise AssertionError(f"unexpected path after missing fixture: {path}")

    monkeypatch.setattr("app.cli.DEMO_LOBSTERTRAP_AUDIT_PATH", missing_path)
    monkeypatch.setattr("app.cli.clear_db", lambda: None)
    monkeypatch.setattr("app.cli.request_json", fake_request_json)

    assert cli_main(["demo-seed-unified", "--backend-url", "http://127.0.0.1:7330"]) == 1

    captured = capsys.readouterr()
    assert "Lobster Trap fixture ingestion step failed" in captured.err
    assert "Lobster Trap fixture/audit file not found" in captured.err


def test_demo_seed_unified_help_and_touched_docs_avoid_live_deployment_claims() -> None:
    root_dir = Path(__file__).resolve().parents[2]
    checked_text = "\n".join(
        [
            build_parser().format_help(),
            (root_dir / "DEMO_RUNBOOK.md").read_text(encoding="utf-8"),
            (root_dir / "AIWATCH_FINAL_DEMO_PACKET.md").read_text(encoding="utf-8"),
            (root_dir / "docs" / "LOBSTERTRAP_AIWATCH_COMPANION.md").read_text(encoding="utf-8"),
        ]
    )

    forbidden_live_deployment_claims = [
        "live Veea platform integration",
        "deployed Veea infrastructure",
        "actual TerraFabric control plane",
    ]
    for phrase in forbidden_live_deployment_claims:
        assert phrase not in checked_text


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
