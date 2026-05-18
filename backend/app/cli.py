from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Sequence

from app.enforcement import ENFORCEMENT_ENV_VAR, resolve_enforcement_mode
from app.storage import clear_db, init_db, list_alerts as list_local_alerts, list_events as list_local_events
from app.veea_audit import (
    build_unified_veea_audit_timeline,
    build_veea_audit_envelopes,
    build_veea_audit_timeline,
    read_jsonl_objects,
    render_veea_audit_jsonl,
    write_veea_audit_jsonl,
)

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_BACKEND_URL = "http://127.0.0.1:7330"
BACKEND_DOWN_MESSAGE = (
    "AIWatch backend is not running. Start it with: "
    "py -3.12 -m uvicorn app.main:app --reload --port 7330"
)
DEV_ENDPOINTS_DISABLED_MESSAGE = (
    "AIWatch dev endpoints are disabled. Start the backend with "
    "AIWATCH_DEV_MODE=true for local demos."
)
MCP_CONFIG_CANDIDATES = (Path(".mcp.json"), Path(".cursor") / "mcp.json")
DEMO_LOBSTERTRAP_AUDIT_PATH = ROOT_DIR / "demo" / "lobstertrap-audit-sample.jsonl"


@dataclass(frozen=True)
class DoctorServerResult:
    config_path: Path
    server_name: str
    status: str
    reason: str
    command_summary: str
    advice: str


@dataclass(frozen=True)
class LobsterTrapIngestResult:
    accepted: int
    rejected: int
    malformed: int
    stored_record_ids: list[int]


class CliStepError(Exception):
    """Raised when a multi-step CLI command fails at a named step."""


def request_json(
    path: str,
    *,
    backend_url: str = DEFAULT_BACKEND_URL,
    method: str = "GET",
    body: dict[str, Any] | None = None,
) -> Any:
    request = urllib.request.Request(
        f"{backend_url}{path}",
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def short_hash(value: str, *, limit: int = 12) -> str:
    return value if len(value) <= limit else f"{value[:limit]}..."


def format_table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def _render_row(row: list[str]) -> str:
        return "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row))

    lines = [_render_row(headers), _render_row(["-" * width for width in widths])]
    lines.extend(_render_row(row) for row in rows)
    return "\n".join(lines)


def build_tap_demo_command(python_executable: str | None = None) -> list[str]:
    executable = python_executable or sys.executable
    return [executable, str(ROOT_DIR / "scripts" / "run_stdio_tap_demo.py")]


def build_eval_command(python_executable: str | None = None) -> list[str]:
    executable = python_executable or sys.executable
    return [executable, str(ROOT_DIR / "eval" / "run_eval.py")]


def _command_summary(command: object, args: object) -> str:
    command_text = command if isinstance(command, str) and command else "<missing>"
    if isinstance(args, list):
        return " ".join([command_text, *("<arg>" for _ in args)])
    return f"{command_text} <invalid-args>"


def _contains_aiwatch_tap(value: object) -> bool:
    return isinstance(value, str) and "aiwatch_stdio_tap.py" in value.replace("\\", "/")


def _has_upstream_separator_after_tap(command_has_tap: bool, args: list[str]) -> bool:
    if command_has_tap:
        return "--" in args

    tap_indexes = [index for index, arg in enumerate(args) if _contains_aiwatch_tap(arg)]
    if not tap_indexes:
        return False

    last_tap_index = max(tap_indexes)
    return any(index > last_tap_index and arg == "--" for index, arg in enumerate(args))


def _is_python_command(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    executable = Path(value.replace("\\", "/")).name.lower()
    return executable in {"py", "python", "python.exe", "python3", "python3.exe"} or executable.startswith("python3.")


def _classify_mcp_server(config_path: Path, server_name: str, server_config: object) -> DoctorServerResult:
    if not isinstance(server_config, dict):
        return DoctorServerResult(
            config_path=config_path,
            server_name=server_name,
            status="invalid_config",
            reason="server entry is not an object",
            command_summary="<invalid>",
            advice="use an object with command and args fields",
        )

    command = server_config.get("command")
    args = server_config.get("args")
    command_summary = _command_summary(command, args)

    if not isinstance(command, str) or not command:
        return DoctorServerResult(
            config_path=config_path,
            server_name=server_name,
            status="invalid_config",
            reason="missing command",
            command_summary=command_summary,
            advice="add a command field for the MCP server",
        )

    if args is None:
        return DoctorServerResult(
            config_path=config_path,
            server_name=server_name,
            status="invalid_config",
            reason="missing args",
            command_summary=command_summary,
            advice="add an args array for the MCP server",
        )

    if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        return DoctorServerResult(
            config_path=config_path,
            server_name=server_name,
            status="invalid_config",
            reason="args must be a list of strings",
            command_summary=command_summary,
            advice="use an args array and keep env values out of command arguments",
        )

    command_has_tap = _contains_aiwatch_tap(command)
    args_have_tap = any(_contains_aiwatch_tap(arg) for arg in args)
    has_separator = _has_upstream_separator_after_tap(command_has_tap, args)

    if (command_has_tap or (_is_python_command(command) and args_have_tap) or args_have_tap) and has_separator:
        return DoctorServerResult(
            config_path=config_path,
            server_name=server_name,
            status="wrapped_by_aiwatch",
            reason="uses aiwatch_stdio_tap.py with -- upstream separator",
            command_summary=command_summary,
            advice="no action needed",
        )

    if command_has_tap or args_have_tap:
        return DoctorServerResult(
            config_path=config_path,
            server_name=server_name,
            status="unknown",
            reason="references aiwatch_stdio_tap.py but is missing -- upstream separator",
            command_summary=command_summary,
            advice="add -- before the real upstream MCP server command",
        )

    return DoctorServerResult(
        config_path=config_path,
        server_name=server_name,
        status="not_wrapped",
        reason="launches MCP server directly",
        command_summary=command_summary,
        advice="route this server through aiwatch_stdio_tap.py to observe MCP traffic",
    )


def inspect_mcp_config_file(config_path: Path) -> list[DoctorServerResult]:
    try:
        parsed = json.loads(config_path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as error:
        return [
            DoctorServerResult(
                config_path=config_path,
                server_name="<file>",
                status="invalid_config",
                reason=f"invalid JSON: {error.msg}",
                command_summary="<invalid-json>",
                advice="fix JSON syntax before AIWatch can inspect MCP servers",
            )
        ]

    if not isinstance(parsed, dict):
        return [
            DoctorServerResult(
                config_path=config_path,
                server_name="<file>",
                status="invalid_config",
                reason="config root is not an object",
                command_summary="<invalid-root>",
                advice="use a JSON object with a top-level mcpServers object",
            )
        ]

    mcp_servers = parsed.get("mcpServers")
    if not isinstance(mcp_servers, dict):
        return [
            DoctorServerResult(
                config_path=config_path,
                server_name="<file>",
                status="invalid_config",
                reason="missing top-level mcpServers object",
                command_summary="<missing-mcpServers>",
                advice="add a top-level mcpServers object",
            )
        ]

    return [
        _classify_mcp_server(config_path, str(server_name), server_config)
        for server_name, server_config in mcp_servers.items()
    ]


def inspect_mcp_configs(cwd: Path) -> list[DoctorServerResult]:
    results: list[DoctorServerResult] = []
    for relative_path in MCP_CONFIG_CANDIDATES:
        config_path = cwd / relative_path
        if config_path.exists():
            results.extend(inspect_mcp_config_file(config_path))
    return results


def _status_marker(status: str) -> str:
    if status == "wrapped_by_aiwatch":
        return "[ok]"
    if status == "not_wrapped":
        return "[warn]"
    if status == "invalid_config":
        return "[invalid]"
    return "[unknown]"


def format_doctor_results(results: list[DoctorServerResult], *, cwd: Path) -> str:
    if not results:
        checked = ", ".join(str(cwd / path) for path in MCP_CONFIG_CANDIDATES)
        return f"No MCP config files found. Checked: {checked}"

    lines: list[str] = []
    current_config: Path | None = None
    for result in results:
        if current_config != result.config_path:
            if lines:
                lines.append("")
            lines.append(f"CONFIG: {result.config_path}")
            current_config = result.config_path

        lines.extend(
            [
                f"  {_status_marker(result.status)} {result.server_name}",
                f"     status: {result.status}",
                f"     reason: {result.reason}",
                f"     command: {result.command_summary}",
                f"     advice: {result.advice}",
            ]
        )

    return "\n".join(lines)


def format_doctor_results_json(results: list[DoctorServerResult], *, cwd: Path) -> str:
    payload: dict[str, object] = {
        "checked": [str(cwd / path) for path in MCP_CONFIG_CANDIDATES],
        "results": [
            {
                "config_path": str(result.config_path),
                "server_name": result.server_name,
                "status": result.status,
                "reason": result.reason,
                "command_summary": result.command_summary,
                "advice": result.advice,
            }
            for result in results
        ],
    }
    return json.dumps(payload, indent=2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aiwatch", description="Local AIWatch development CLI.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    clear_parser = subparsers.add_parser("clear", help="Clear the local AIWatch SQLite database.")
    clear_parser.set_defaults(handler=handle_clear)

    demo_seed_parser = subparsers.add_parser("demo-seed", help="Seed the local backend demo data.")
    demo_seed_parser.add_argument("--extended", action="store_true", help="Seed the extended MCP registry demo.")
    demo_seed_parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL)
    demo_seed_parser.set_defaults(handler=handle_demo_seed)

    demo_seed_unified_parser = subparsers.add_parser(
        "demo-seed-unified",
        help="Clear, seed AIWatch demo data, and ingest the bundled Lobster Trap audit fixture.",
    )
    demo_seed_unified_parser.add_argument("--extended", action="store_true", help="Seed the extended MCP registry demo.")
    demo_seed_unified_parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL)
    demo_seed_unified_parser.set_defaults(handler=handle_demo_seed_unified)

    tap_demo_parser = subparsers.add_parser("tap-demo", help="Run the stdio tap demo.")
    tap_demo_parser.set_defaults(handler=handle_tap_demo)

    eval_parser = subparsers.add_parser("eval", help="Run the local deterministic fixture eval harness.")
    eval_parser.set_defaults(handler=handle_eval)

    doctor_parser = subparsers.add_parser("doctor", help="Check local MCP configs for AIWatch stdio wrapping.")
    doctor_parser.add_argument("--json", action="store_true", help="Print doctor results as JSON.")
    doctor_parser.set_defaults(handler=handle_doctor)

    tools_parser = subparsers.add_parser("tools", help="List current MCP tool fingerprints.")
    tools_parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL)
    tools_parser.set_defaults(handler=handle_tools)

    alerts_parser = subparsers.add_parser("alerts", help="List stored alerts.")
    alerts_parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL)
    alerts_parser.set_defaults(handler=handle_alerts)

    export_parser = subparsers.add_parser(
        "export-veea-audit",
        help="Export stored MCP alerts or a Veea companion audit timeline as JSONL.",
    )
    export_parser.add_argument("--out", type=Path, help="Write JSONL to this file instead of stdout.")
    export_parser.add_argument(
        "--timeline",
        action="store_true",
        help="Include stored MCP observation events with MCP alerts in timestamp order.",
    )
    export_parser.set_defaults(handler=handle_export_veea_audit)

    merge_parser = subparsers.add_parser(
        "merge-veea-audit",
        help="Merge AIWatch and Lobster Trap JSONL audit artifacts into one local Veea-style timeline.",
    )
    merge_parser.add_argument("--aiwatch", type=Path, help="Existing AIWatch Veea timeline JSONL file.")
    merge_parser.add_argument("--lobstertrap", type=Path, help="Lobster Trap JSONL audit file.")
    merge_parser.add_argument("--out", type=Path, help="Write merged JSONL to this file instead of stdout.")
    merge_parser.set_defaults(handler=handle_merge_veea_audit)

    ingest_lobstertrap_parser = subparsers.add_parser(
        "ingest-lobstertrap-audit",
        help="Ingest a local Lobster Trap JSONL audit file into the AIWatch backend.",
    )
    ingest_lobstertrap_parser.add_argument("--file", type=Path, required=True, help="Lobster Trap JSONL audit file.")
    ingest_lobstertrap_parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL)
    ingest_lobstertrap_parser.add_argument(
        "--follow",
        action="store_true",
        help="Continue tailing the file for appended Lobster Trap audit records.",
    )
    ingest_lobstertrap_parser.set_defaults(handler=handle_ingest_lobstertrap_audit)

    ingest_demo_lobstertrap_parser = subparsers.add_parser(
        "ingest-demo-lobstertrap-audit",
        help="Ingest the bundled Lobster Trap demo audit fixture into the AIWatch backend.",
    )
    ingest_demo_lobstertrap_parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL)
    ingest_demo_lobstertrap_parser.set_defaults(handler=handle_ingest_demo_lobstertrap_audit)

    lobstertrap_status_parser = subparsers.add_parser(
        "lobstertrap-status",
        help="Print local Lobster Trap integration status from the AIWatch backend.",
    )
    lobstertrap_status_parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL)
    lobstertrap_status_parser.set_defaults(handler=handle_lobstertrap_status)

    enforcement_status_parser = subparsers.add_parser(
        "enforcement-status",
        help="Show the local AIWatch routed MCP enforcement mode.",
    )
    enforcement_status_parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL)
    enforcement_status_parser.set_defaults(handler=handle_enforcement_status)

    return parser


def handle_clear(_: argparse.Namespace) -> int:
    clear_db()
    print("Cleared AIWatch local database.")
    return 0


def _format_seed_result(item: dict[str, object]) -> str:
    name = str(item.get("name", "unknown"))
    event_id = str(item.get("event_id", "unknown"))
    alerts_created = int(item.get("alerts_created", 0))
    rule_ids = ", ".join(str(rule_id) for rule_id in item.get("rule_ids", []))
    alert_label = "alert" if alerts_created == 1 else "alerts"
    suffix = f" -> {rule_ids}" if rule_ids else " -> none"
    return f"[ok] {name}: event_id={event_id}, {alerts_created} {alert_label}{suffix}"


def seed_demo_backend(*, backend_url: str, extended: bool) -> dict[str, object]:
    response_data = request_json(
        f"/v1/dev/seed-demo?clear=true&extended={'true' if extended else 'false'}",
        backend_url=backend_url,
        method="POST",
        body={},
    )
    if not isinstance(response_data, dict):
        raise CliStepError("AIWatch demo seed step failed: backend returned a non-object response.")
    return response_data


def handle_demo_seed(args: argparse.Namespace) -> int:
    try:
        response_data = seed_demo_backend(backend_url=args.backend_url, extended=args.extended)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            print(DEV_ENDPOINTS_DISABLED_MESSAGE)
            return 1
        raise
    except urllib.error.URLError:
        print(BACKEND_DOWN_MESSAGE)
        return 1
    except CliStepError as error:
        print(str(error))
        return 1

    for item in response_data.get("items", []):
        if isinstance(item, dict):
            print(_format_seed_result(item))

    return 0


def _seed_result_summary(response_data: dict[str, object]) -> str:
    events_created = int(response_data.get("events_created", 0))
    alerts_created = int(response_data.get("alerts_created", 0))
    tools_observed = int(response_data.get("tools_observed", 0))
    return f"{events_created} events; {alerts_created} alerts; {tools_observed} tools observed"


def _fetch_audit_summary(*, backend_url: str) -> dict[str, object] | None:
    try:
        summary = request_json("/v1/audit/summary", backend_url=backend_url)
    except (urllib.error.HTTPError, urllib.error.URLError):
        return None
    return summary if isinstance(summary, dict) else None


def handle_demo_seed_unified(args: argparse.Namespace) -> int:
    try:
        clear_db()
    except Exception as error:
        print(f"Clear step failed: {error}", file=sys.stderr)
        return 1

    try:
        seed_response = seed_demo_backend(backend_url=args.backend_url, extended=args.extended)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            print(f"AIWatch demo seed step failed: {DEV_ENDPOINTS_DISABLED_MESSAGE}", file=sys.stderr)
            return 1
        print(f"AIWatch demo seed step failed: HTTP {error.code}", file=sys.stderr)
        return 1
    except urllib.error.URLError:
        print(f"AIWatch demo seed step failed: {BACKEND_DOWN_MESSAGE}", file=sys.stderr)
        return 1
    except CliStepError as error:
        print(str(error), file=sys.stderr)
        return 1

    try:
        ingest_result = ingest_lobstertrap_audit_file(
            DEMO_LOBSTERTRAP_AUDIT_PATH,
            backend_url=args.backend_url,
            follow=False,
            strict_jsonl=True,
            step_name="Lobster Trap fixture ingestion step",
        )
    except CliStepError as error:
        print(str(error), file=sys.stderr)
        return 1

    summary = _fetch_audit_summary(backend_url=args.backend_url)

    print("Unified demo seed complete.")
    print(f"AIWatch seed result: {_seed_result_summary(seed_response)}.")
    print(f"Lobster Trap records ingested: {ingest_result.accepted}")
    if summary is not None:
        print(
            "Final audit summary: "
            f"aiwatch_mcp_records={summary.get('aiwatch_mcp_records', 'unknown')}; "
            f"lobstertrap_records={summary.get('lobstertrap_records', 'unknown')}; "
            f"total_records={summary.get('total_records', 'unknown')}."
        )
    else:
        print("Final audit summary: unavailable.")
    return 0


def handle_tap_demo(_: argparse.Namespace) -> int:
    process = subprocess.run(build_tap_demo_command(), cwd=ROOT_DIR, check=False)
    return process.returncode


def handle_eval(_: argparse.Namespace) -> int:
    process = subprocess.run(build_eval_command(), cwd=ROOT_DIR, check=False)
    return process.returncode


def handle_doctor(args: argparse.Namespace) -> int:
    cwd = Path.cwd()
    results = inspect_mcp_configs(cwd)
    if args.json:
        print(format_doctor_results_json(results, cwd=cwd))
    else:
        print(format_doctor_results(results, cwd=cwd))
    return 0


def handle_tools(args: argparse.Namespace) -> int:
    try:
        tools = request_json("/v1/tools", backend_url=args.backend_url)
    except urllib.error.URLError:
        print(BACKEND_DOWN_MESSAGE)
        return 1

    if not isinstance(tools, list) or not tools:
        print("No tools found.")
        return 0

    rows = [
        [
            str(tool.get("tool_name", "")),
            str(tool.get("server_id", "")),
            str(tool.get("observation_count", "")),
            short_hash(str(tool.get("description_hash", ""))),
        ]
        for tool in tools
        if isinstance(tool, dict)
    ]
    print(format_table(["TOOL_NAME", "SERVER_ID", "OBS", "DESC_HASH"], rows))
    return 0


def handle_alerts(args: argparse.Namespace) -> int:
    try:
        alerts = request_json("/v1/alerts", backend_url=args.backend_url)
    except urllib.error.URLError:
        print(BACKEND_DOWN_MESSAGE)
        return 1

    if not isinstance(alerts, list) or not alerts:
        print("No alerts found.")
        return 0

    rows = []
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        event_ids = alert.get("event_ids")
        primary_event_id = event_ids[0] if isinstance(event_ids, list) and event_ids else "n/a"
        rows.append(
            [
                str(alert.get("severity", "")),
                str(alert.get("rule_id", "")),
                str(alert.get("decision", "")),
                str(alert.get("session_id", "")),
                str(primary_event_id),
                str(alert.get("summary", "")),
            ]
        )

    print(format_table(["SEVERITY", "RULE_ID", "DECISION", "SESSION_ID", "EVENT_ID", "SUMMARY"], rows))
    return 0


def handle_export_veea_audit(args: argparse.Namespace) -> int:
    init_db()
    if args.timeline:
        envelopes = build_veea_audit_timeline(list_local_events(), list_local_alerts())
        record_label = "AIWatch MCP audit timeline records"
    else:
        envelopes = build_veea_audit_envelopes(list_local_alerts())
        record_label = "AIWatch MCP alert audit envelopes"

    if args.out:
        output_path = Path(args.out)
        write_veea_audit_jsonl(envelopes, output_path)
        print(f"Exported {len(envelopes)} {record_label} to {output_path}.")
        return 0

    sys.stdout.write(render_veea_audit_jsonl(envelopes))
    print(f"Exported {len(envelopes)} {record_label} to stdout.", file=sys.stderr)
    return 0


def handle_merge_veea_audit(args: argparse.Namespace) -> int:
    if args.aiwatch is None and args.lobstertrap is None:
        print("Provide --aiwatch, --lobstertrap, or both.", file=sys.stderr)
        return 2

    aiwatch_envelopes = read_jsonl_objects(args.aiwatch) if args.aiwatch is not None else []
    lobstertrap_records = read_jsonl_objects(args.lobstertrap) if args.lobstertrap is not None else []
    envelopes = build_unified_veea_audit_timeline(aiwatch_envelopes, lobstertrap_records)

    if args.out:
        output_path = Path(args.out)
        write_veea_audit_jsonl(envelopes, output_path)
        print(f"Merged {len(envelopes)} Veea audit timeline records to {output_path}.")
        return 0

    sys.stdout.write(render_veea_audit_jsonl(envelopes))
    print(f"Merged {len(envelopes)} Veea audit timeline records to stdout.", file=sys.stderr)
    return 0


def _is_local_backend_url(backend_url: str) -> bool:
    parsed = urllib.parse.urlparse(backend_url)
    return parsed.scheme in {"http", "https"} and parsed.hostname in {"localhost", "127.0.0.1", "::1"}


def _iter_jsonl_lines(input_path: Path, *, follow: bool) -> Iterator[tuple[int, str]]:
    line_number = 0
    with input_path.open("r", encoding="utf-8-sig") as handle:
        while True:
            raw_line = handle.readline()
            if raw_line:
                line_number += 1
                yield line_number, raw_line
                continue

            if not follow:
                return

            time.sleep(0.25)


def ingest_lobstertrap_audit_file(
    input_path: Path,
    *,
    backend_url: str,
    follow: bool,
    strict_jsonl: bool = False,
    step_name: str = "Lobster Trap audit ingestion step",
) -> LobsterTrapIngestResult:
    if not _is_local_backend_url(backend_url):
        raise CliStepError(
            f"{step_name} failed: ingest-lobstertrap-audit only posts to a local AIWatch backend URL."
        )

    if not input_path.exists():
        raise CliStepError(f"{step_name} failed: Lobster Trap fixture/audit file not found: {input_path}")

    accepted = 0
    rejected = 0
    malformed = 0
    stored_record_ids: list[int] = []

    try:
        for line_number, raw_line in _iter_jsonl_lines(input_path, follow=follow):
            line = raw_line.strip()
            if not line:
                continue

            try:
                payload = json.loads(line)
            except json.JSONDecodeError as error:
                malformed += 1
                if strict_jsonl:
                    raise CliStepError(
                        f"{step_name} failed: malformed Lobster Trap fixture JSONL line "
                        f"{line_number}: {error.msg}"
                    ) from None
                print(f"Skipping malformed JSONL line {line_number}: {error.msg}", file=sys.stderr)
                continue

            if not isinstance(payload, dict):
                malformed += 1
                if strict_jsonl:
                    raise CliStepError(
                        f"{step_name} failed: malformed Lobster Trap fixture JSONL line "
                        f"{line_number}: expected JSON object"
                    )
                print(f"Skipping JSONL line {line_number}: expected JSON object", file=sys.stderr)
                continue

            try:
                response_data = request_json(
                    "/v1/integrations/lobstertrap/audit",
                    backend_url=backend_url,
                    method="POST",
                    body=payload,
                )
            except urllib.error.HTTPError as error:
                raise CliStepError(
                    f"{step_name} failed: AIWatch backend rejected Lobster Trap audit line "
                    f"{line_number}: HTTP {error.code}"
                ) from None
            except urllib.error.URLError:
                raise CliStepError(f"{step_name} failed: {BACKEND_DOWN_MESSAGE}") from None

            if isinstance(response_data, dict):
                accepted += int(response_data.get("accepted", 0))
                rejected += int(response_data.get("rejected", 0))
                ids = response_data.get("stored_record_ids", [])
                if isinstance(ids, list):
                    stored_record_ids.extend(record_id for record_id in ids if isinstance(record_id, int))
    except KeyboardInterrupt:
        print("Stopped following Lobster Trap audit file.", file=sys.stderr)

    return LobsterTrapIngestResult(
        accepted=accepted,
        rejected=rejected,
        malformed=malformed,
        stored_record_ids=stored_record_ids,
    )


def handle_ingest_lobstertrap_audit(args: argparse.Namespace) -> int:
    try:
        ingest_result = ingest_lobstertrap_audit_file(
            Path(args.file),
            backend_url=args.backend_url,
            follow=args.follow,
        )
    except CliStepError as error:
        print(str(error), file=sys.stderr)
        return 2 if "only posts to a local AIWatch backend URL" in str(error) or "not found" in str(error) else 1

    print(
        "Ingested "
        f"{ingest_result.accepted} Lobster Trap audit records; "
        f"rejected {ingest_result.rejected}; malformed lines {ingest_result.malformed}; "
        f"stored IDs {ingest_result.stored_record_ids}."
    )
    return 0


def handle_ingest_demo_lobstertrap_audit(args: argparse.Namespace) -> int:
    demo_args = argparse.Namespace(
        file=DEMO_LOBSTERTRAP_AUDIT_PATH,
        backend_url=args.backend_url,
        follow=False,
    )
    return handle_ingest_lobstertrap_audit(demo_args)


def handle_lobstertrap_status(args: argparse.Namespace) -> int:
    try:
        status = request_json("/v1/integrations/lobstertrap/status", backend_url=args.backend_url)
    except urllib.error.URLError:
        print(BACKEND_DOWN_MESSAGE)
        return 1

    print(json.dumps(status, indent=2, sort_keys=True))
    return 0


def handle_enforcement_status(args: argparse.Namespace) -> int:
    try:
        mode = resolve_enforcement_mode()
    except ValueError as error:
        print(f"Invalid enforcement configuration: {error}", file=sys.stderr)
        return 2

    print(f"AIWatch enforcement mode: {mode}")
    print(f"Config: {ENFORCEMENT_ENV_VAR}=observe|deny")
    print("Scope: local MCP relay/wrapper traffic only.")
    print(f"Backend URL: {args.backend_url}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
