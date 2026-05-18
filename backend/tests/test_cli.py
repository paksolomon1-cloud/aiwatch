from __future__ import annotations

import json
import urllib.error
from pathlib import Path

from app.cli import (
    build_eval_command,
    build_parser,
    build_tap_demo_command,
    format_doctor_results,
    format_doctor_results_json,
    format_table,
    handle_demo_seed,
    inspect_mcp_config_file,
    inspect_mcp_configs,
    main as cli_main,
)


def test_parser_recognizes_demo_seed_and_extended_flag() -> None:
    parser = build_parser()

    args = parser.parse_args(["demo-seed", "--extended", "--backend-url", "http://localhost:9000"])

    assert args.command == "demo-seed"
    assert args.extended is True
    assert args.backend_url == "http://localhost:9000"


def test_parser_recognizes_demo_seed_unified_and_extended_flag() -> None:
    parser = build_parser()

    args = parser.parse_args(["demo-seed-unified", "--extended", "--backend-url", "http://localhost:9000"])

    assert args.command == "demo-seed-unified"
    assert args.extended is True
    assert args.backend_url == "http://localhost:9000"


def test_parser_recognizes_other_commands() -> None:
    parser = build_parser()

    assert parser.parse_args(["clear"]).command == "clear"
    assert parser.parse_args(["tap-demo"]).command == "tap-demo"
    assert parser.parse_args(["eval"]).command == "eval"
    assert parser.parse_args(["doctor"]).command == "doctor"
    assert parser.parse_args(["doctor", "--json"]).json is True
    assert parser.parse_args(["tools"]).command == "tools"
    assert parser.parse_args(["alerts"]).command == "alerts"
    assert parser.parse_args(["enforcement-status"]).command == "enforcement-status"
    assert parser.parse_args(["export-veea-audit"]).command == "export-veea-audit"
    assert parser.parse_args(["export-veea-audit", "--out", "audit.jsonl"]).out == Path("audit.jsonl")
    assert parser.parse_args(["export-veea-audit", "--timeline"]).timeline is True


def test_help_text_lists_supported_commands() -> None:
    help_text = build_parser().format_help()

    assert "demo-seed" in help_text
    assert "demo-seed-unified" in help_text
    assert "clear" in help_text
    assert "tap-demo" in help_text
    assert "eval" in help_text
    assert "doctor" in help_text
    assert "tools" in help_text
    assert "alerts" in help_text
    assert "enforcement-status" in help_text
    assert "export-veea-audit" in help_text


def test_format_table_renders_headers_and_rows() -> None:
    rendered = format_table(
        ["COL_A", "COL_B"],
        [["alpha", "1"], ["beta", "22"]],
    )

    assert "COL_A" in rendered
    assert "COL_B" in rendered
    assert "alpha" in rendered
    assert "beta" in rendered


def test_build_tap_demo_command_points_to_stdio_demo_script() -> None:
    command = build_tap_demo_command("python-test")

    assert command[0] == "python-test"
    assert Path(command[1]).name == "run_stdio_tap_demo.py"


def test_build_eval_command_points_to_eval_runner() -> None:
    command = build_eval_command("python-test")

    assert command[0] == "python-test"
    assert Path(command[1]).name == "run_eval.py"


def _write_mcp_config(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_doctor_reports_no_config_files_found(tmp_path: Path) -> None:
    results = inspect_mcp_configs(tmp_path)
    rendered = format_doctor_results(results, cwd=tmp_path)

    assert results == []
    assert "No MCP config files found." in rendered
    assert ".mcp.json" in rendered
    assert ".cursor" in rendered


def test_doctor_detects_wrapped_mcp_server(tmp_path: Path) -> None:
    _write_mcp_config(
        tmp_path / ".mcp.json",
        {
            "mcpServers": {
                "aiwatch-fixture-notes": {
                    "command": "py",
                    "args": [
                        "-3.12",
                        "backend/scripts/aiwatch_stdio_tap.py",
                        "--server-id",
                        "fixture-notes-mcp",
                        "--",
                        "py",
                        "-3.12",
                        "backend/scripts/realistic_mcp_fixture_server.py",
                    ],
                }
            }
        },
    )

    [result] = inspect_mcp_configs(tmp_path)

    assert result.server_name == "aiwatch-fixture-notes"
    assert result.status == "wrapped_by_aiwatch"
    assert result.reason == "uses aiwatch_stdio_tap.py with -- upstream separator"


def test_doctor_detects_claude_code_example_as_wrapped() -> None:
    example_path = Path(__file__).resolve().parents[2] / "docs" / "examples" / "claude-code-aiwatch-mcp.example.json"

    [result] = inspect_mcp_config_file(example_path)

    assert result.config_path == example_path
    assert result.server_name == "aiwatch-fixture-notes"
    assert result.status == "wrapped_by_aiwatch"
    assert result.reason == "uses aiwatch_stdio_tap.py with -- upstream separator"


def test_doctor_json_serializes_results_without_env_values(tmp_path: Path) -> None:
    _write_mcp_config(
        tmp_path / ".mcp.json",
        {
            "mcpServers": {
                "aiwatch-fixture-notes": {
                    "command": "py",
                    "args": [
                        "-3.12",
                        "backend/scripts/aiwatch_stdio_tap.py",
                        "--server-id",
                        "fixture-notes-mcp",
                        "--",
                        "py",
                        "-3.12",
                        "backend/scripts/realistic_mcp_fixture_server.py",
                    ],
                    "env": {"API_TOKEN": "super-secret-token"},
                }
            }
        },
    )

    rendered = format_doctor_results_json(inspect_mcp_configs(tmp_path), cwd=tmp_path)
    payload = json.loads(rendered)

    assert payload["checked"] == [
        str(tmp_path / ".mcp.json"),
        str(tmp_path / ".cursor" / "mcp.json"),
    ]
    assert payload["results"][0]["server_name"] == "aiwatch-fixture-notes"
    assert payload["results"][0]["status"] == "wrapped_by_aiwatch"
    assert "super-secret-token" not in rendered
    assert "API_TOKEN" not in rendered


def test_doctor_detects_direct_unwrapped_mcp_server(tmp_path: Path) -> None:
    _write_mcp_config(
        tmp_path / ".mcp.json",
        {
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                }
            }
        },
    )

    [result] = inspect_mcp_configs(tmp_path)

    assert result.server_name == "github"
    assert result.status == "not_wrapped"
    assert result.reason == "launches MCP server directly"


def test_doctor_reports_invalid_json_without_crashing(tmp_path: Path) -> None:
    config_path = tmp_path / ".mcp.json"
    config_path.write_text("{not-json", encoding="utf-8")

    [result] = inspect_mcp_configs(tmp_path)

    assert result.config_path == config_path
    assert result.server_name == "<file>"
    assert result.status == "invalid_config"
    assert "invalid JSON" in result.reason


def test_doctor_accepts_windows_utf8_bom_json(tmp_path: Path) -> None:
    config_path = tmp_path / ".mcp.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "aiwatch-fixture-notes": {
                        "command": "py",
                        "args": ["-3.12", "aiwatch_stdio_tap.py", "--", "py", "server.py"],
                    }
                }
            }
        ),
        encoding="utf-8-sig",
    )

    [result] = inspect_mcp_configs(tmp_path)

    assert result.server_name == "aiwatch-fixture-notes"
    assert result.status == "wrapped_by_aiwatch"


def test_doctor_reports_server_missing_command_or_args(tmp_path: Path) -> None:
    _write_mcp_config(
        tmp_path / ".mcp.json",
        {
            "mcpServers": {
                "missing-command": {"args": ["server.py"]},
                "missing-args": {"command": "py"},
            }
        },
    )

    results = {result.server_name: result for result in inspect_mcp_configs(tmp_path)}

    assert results["missing-command"].status == "invalid_config"
    assert results["missing-command"].reason == "missing command"
    assert results["missing-args"].status == "invalid_config"
    assert results["missing-args"].reason == "missing args"


def test_doctor_does_not_print_env_secret_values(tmp_path: Path) -> None:
    _write_mcp_config(
        tmp_path / ".mcp.json",
        {
            "mcpServers": {
                "secret-server": {
                    "command": "py",
                    "args": ["server.py"],
                    "env": {"API_TOKEN": "super-secret-token"},
                }
            }
        },
    )

    rendered = format_doctor_results(inspect_mcp_configs(tmp_path), cwd=tmp_path)

    assert "secret-server" in rendered
    assert "super-secret-token" not in rendered
    assert "API_TOKEN" not in rendered


def test_doctor_detects_cursor_mcp_config_if_present(tmp_path: Path) -> None:
    _write_mcp_config(
        tmp_path / ".cursor" / "mcp.json",
        {
            "mcpServers": {
                "cursor-fixture": {
                    "command": "py",
                    "args": [
                        "-3.12",
                        "backend/scripts/aiwatch_stdio_tap.py",
                        "--",
                        "py",
                        "-3.12",
                        "server.py",
                    ],
                }
            }
        },
    )

    [result] = inspect_mcp_configs(tmp_path)

    assert result.config_path == tmp_path / ".cursor" / "mcp.json"
    assert result.server_name == "cursor-fixture"
    assert result.status == "wrapped_by_aiwatch"


def test_doctor_detects_cursor_example_as_wrapped() -> None:
    example_path = Path(__file__).resolve().parents[2] / "docs" / "examples" / "cursor-aiwatch-mcp.example.json"

    [result] = inspect_mcp_config_file(example_path)

    assert result.config_path == example_path
    assert result.server_name == "aiwatch-fixture-notes"
    assert result.status == "wrapped_by_aiwatch"
    assert result.reason == "uses aiwatch_stdio_tap.py with -- upstream separator"


def test_doctor_warns_when_aiwatch_tap_is_missing_upstream_separator(tmp_path: Path) -> None:
    _write_mcp_config(
        tmp_path / ".mcp.json",
        {
            "mcpServers": {
                "broken-wrapper": {
                    "command": "py",
                    "args": ["-3.12", "backend/scripts/aiwatch_stdio_tap.py", "py", "server.py"],
                }
            }
        },
    )

    [result] = inspect_mcp_configs(tmp_path)

    assert result.status == "unknown"
    assert result.reason == "references aiwatch_stdio_tap.py but is missing -- upstream separator"
    assert result.advice == "add -- before the real upstream MCP server command"


def test_doctor_warns_when_separator_appears_before_aiwatch_tap(tmp_path: Path) -> None:
    _write_mcp_config(
        tmp_path / ".mcp.json",
        {
            "mcpServers": {
                "misordered-wrapper": {
                    "command": "py",
                    "args": ["--", "-3.12", "backend/scripts/aiwatch_stdio_tap.py", "py", "server.py"],
                }
            }
        },
    )

    [result] = inspect_mcp_configs(tmp_path)

    assert result.status == "unknown"
    assert result.reason == "references aiwatch_stdio_tap.py but is missing -- upstream separator"


def test_demo_seed_reports_disabled_dev_endpoints(monkeypatch, capsys) -> None:
    parser = build_parser()
    args = parser.parse_args(["demo-seed"])

    def _raise_404(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            url="http://127.0.0.1:7330/v1/dev/seed-demo",
            code=404,
            msg="Not Found",
            hdrs=None,
            fp=None,
        )

    monkeypatch.setattr("app.cli.request_json", _raise_404)

    result = handle_demo_seed(args)
    output = capsys.readouterr().out

    assert result == 1
    assert "AIWatch dev endpoints are disabled." in output


def test_enforcement_status_defaults_to_observe(monkeypatch, capsys) -> None:
    monkeypatch.delenv("AIWATCH_ENFORCEMENT_MODE", raising=False)

    assert cli_main(["enforcement-status", "--backend-url", "http://127.0.0.1:7330"]) == 0

    output = capsys.readouterr().out
    assert "AIWatch enforcement mode: observe" in output
    assert "AIWATCH_ENFORCEMENT_MODE=observe|deny" in output
    assert "local MCP relay/wrapper traffic only" in output


def test_enforcement_docs_do_not_add_forbidden_product_claims() -> None:
    root_dir = Path(__file__).resolve().parents[2]
    docs = [
        root_dir / "README.md",
        root_dir / "THREAT_MODEL.md",
        root_dir / "NON_GOALS.md",
        root_dir / "DEMO_RUNBOOK.md",
    ]
    enforcement_lines = "\n".join(
        line
        for path in docs
        for line in path.read_text(encoding="utf-8").splitlines()
        if "enforcement" in line.lower() or "deny mode" in line.lower() or "R-MCP-005" in line
    )
    forbidden_phrases = [
        "live Veea platform integration",
        "TerraFabric API",
        "TerraFabric SDK",
        "deployed Veea infrastructure",
        "actual TerraFabric control plane",
        "AIWatch monitors prompts",
        "AIWatch watches prompts",
        "Lobster Trap monitors MCP",
        "monitors Claude",
        "monitors Cursor",
        "watches your laptop",
        "blocks all exfiltration",
        "all secrets are caught",
        "production-ready proxy",
        "production shared dashboard",
    ]

    for phrase in forbidden_phrases:
        assert phrase not in enforcement_lines
