from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from fastapi.testclient import TestClient

from app.main import app
from app.storage import clear_db, init_db

FIXTURES_PATH = Path(__file__).with_name("fixtures.jsonl")
EVAL_DB_PATH = Path(__file__).with_name("aiwatch-eval.db")


@dataclass(frozen=True)
class EvalFixture:
    name: str
    category: str
    description: str
    events: list[dict[str, Any]]
    expected_rule_ids: list[str]


@dataclass(frozen=True)
class RuleComparison:
    expected_rule_ids: set[str]
    actual_rule_ids: set[str]
    false_positives: set[str]
    false_negatives: set[str]
    passed: bool


@dataclass(frozen=True)
class EvalCaseResult:
    fixture: EvalFixture
    comparison: RuleComparison


@dataclass(frozen=True)
class EvalRunSummary:
    total_cases: int
    passed_cases: int
    failed_cases: int
    false_positives_by_rule: dict[str, int]
    false_negatives_by_rule: dict[str, int]
    case_results: list[EvalCaseResult]


def load_fixtures(fixtures_path: Path = FIXTURES_PATH) -> list[EvalFixture]:
    fixtures: list[EvalFixture] = []
    for raw_line in fixtures_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        payload = json.loads(line)
        if "event" in payload:
            events = [payload["event"]]
        elif "events" in payload:
            events = payload["events"]
        else:
            raise ValueError(f"Fixture {payload.get('name', 'unknown')} is missing event/events")

        fixtures.append(
            EvalFixture(
                name=str(payload["name"]),
                category=str(payload["category"]),
                description=str(payload["description"]),
                events=[dict(event) for event in events],
                expected_rule_ids=[str(rule_id) for rule_id in payload.get("expected_rule_ids", [])],
            )
        )

    return fixtures


def compare_rule_ids(expected_rule_ids: Iterable[str], actual_rule_ids: Iterable[str]) -> RuleComparison:
    expected = {rule_id for rule_id in expected_rule_ids if rule_id}
    actual = {rule_id for rule_id in actual_rule_ids if rule_id}
    false_positives = actual - expected
    false_negatives = expected - actual
    return RuleComparison(
        expected_rule_ids=expected,
        actual_rule_ids=actual,
        false_positives=false_positives,
        false_negatives=false_negatives,
        passed=not false_positives and not false_negatives,
    )


def _format_rule_set(rule_ids: set[str]) -> str:
    return ", ".join(sorted(rule_ids)) if rule_ids else "-"


def _format_table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def _render_row(row: list[str]) -> str:
        return "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row))

    output = [_render_row(headers), _render_row(["-" * width for width in widths])]
    output.extend(_render_row(row) for row in rows)
    return "\n".join(output)


def _collect_actual_rule_ids(client: TestClient, fixture: EvalFixture) -> set[str]:
    clear_db()
    for event in fixture.events:
        response = client.post("/v1/events", json=event)
        if response.status_code != 200:
            raise RuntimeError(
                f"Fixture '{fixture.name}' failed to ingest with status {response.status_code}: "
                f"{response.text}"
            )

    alerts_response = client.get("/v1/alerts")
    alerts_response.raise_for_status()
    alerts = alerts_response.json()
    return {
        str(alert["rule_id"])
        for alert in alerts
        if isinstance(alert, dict) and isinstance(alert.get("rule_id"), str)
    }


def run_eval_fixtures(
    fixtures: Sequence[EvalFixture],
    *,
    db_path: Path = EVAL_DB_PATH,
) -> EvalRunSummary:
    false_positives_by_rule: Counter[str] = Counter()
    false_negatives_by_rule: Counter[str] = Counter()
    case_results: list[EvalCaseResult] = []

    previous_db_path = os.environ.get("AIWATCH_DB_PATH")
    os.environ["AIWATCH_DB_PATH"] = str(db_path)
    init_db()

    try:
        with TestClient(app) as client:
            for fixture in fixtures:
                actual_rule_ids = _collect_actual_rule_ids(client, fixture)
                comparison = compare_rule_ids(fixture.expected_rule_ids, actual_rule_ids)
                case_results.append(EvalCaseResult(fixture=fixture, comparison=comparison))

                for rule_id in comparison.false_positives:
                    false_positives_by_rule[rule_id] += 1
                for rule_id in comparison.false_negatives:
                    false_negatives_by_rule[rule_id] += 1
    finally:
        clear_db()
        if previous_db_path is None:
            os.environ.pop("AIWATCH_DB_PATH", None)
        else:
            os.environ["AIWATCH_DB_PATH"] = previous_db_path

    passed_cases = sum(1 for result in case_results if result.comparison.passed)
    return EvalRunSummary(
        total_cases=len(case_results),
        passed_cases=passed_cases,
        failed_cases=len(case_results) - passed_cases,
        false_positives_by_rule=dict(sorted(false_positives_by_rule.items())),
        false_negatives_by_rule=dict(sorted(false_negatives_by_rule.items())),
        case_results=case_results,
    )


def format_eval_report(summary: EvalRunSummary) -> str:
    rows = [
        [
            result.fixture.name,
            result.fixture.category,
            _format_rule_set(result.comparison.expected_rule_ids),
            _format_rule_set(result.comparison.actual_rule_ids),
            "PASS" if result.comparison.passed else "FAIL",
        ]
        for result in summary.case_results
    ]

    false_positive_lines = (
        "\n".join(f"- {rule_id}: {count}" for rule_id, count in summary.false_positives_by_rule.items())
        if summary.false_positives_by_rule
        else "- none"
    )
    false_negative_lines = (
        "\n".join(f"- {rule_id}: {count}" for rule_id, count in summary.false_negatives_by_rule.items())
        if summary.false_negatives_by_rule
        else "- none"
    )

    return (
        "AIWatch local deterministic fixture eval\n"
        f"Total cases: {summary.total_cases}\n"
        f"Passed cases: {summary.passed_cases}\n"
        f"Failed cases: {summary.failed_cases}\n\n"
        "False positives by rule\n"
        f"{false_positive_lines}\n\n"
        "False negatives by rule\n"
        f"{false_negative_lines}\n\n"
        "Per-case results\n"
        f"{_format_table(['CASE', 'CATEGORY', 'EXPECTED', 'ACTUAL', 'STATUS'], rows)}"
    )


def run_and_print_eval(
    *,
    fixtures_path: Path = FIXTURES_PATH,
    db_path: Path = EVAL_DB_PATH,
) -> int:
    fixtures = load_fixtures(fixtures_path)
    summary = run_eval_fixtures(fixtures, db_path=db_path)
    print(format_eval_report(summary))
    return 0 if summary.failed_cases == 0 else 1
