from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Iterator

from app.credential_redaction import redact_json_like
from app.schemas import AgentEvent, Alert, ToolFingerprint, ToolObservation

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / "data" / "aiwatch.db"


class DuplicateEventIdError(Exception):
    """Raised when an event insert collides with an existing event_id."""


def _db_path() -> Path:
    raw_path = os.environ.get("AIWATCH_DB_PATH")
    if not raw_path:
        return DEFAULT_DB_PATH

    candidate = Path(raw_path)
    if candidate.is_absolute():
        return candidate
    return BASE_DIR / candidate


def _connect() -> sqlite3.Connection:
    db_path = _db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    return connection


@contextmanager
def _connection_scope(connection: sqlite3.Connection | None = None) -> Iterator[sqlite3.Connection]:
    if connection is not None:
        yield connection
        return

    with _connect() as managed_connection:
        yield managed_connection


def _event_to_row(event: AgentEvent) -> dict[str, object]:
    payload = event.model_dump(mode="json")
    return {
        "event_id": payload["event_id"],
        "timestamp": payload["timestamp"],
        "agent_id": payload["agent_id"],
        "session_id": payload["session_id"],
        "source": payload["source"],
        "intent_text": payload["intent_text"],
        "action_type": payload["action_type"],
        "action_params_json": json.dumps(payload["action_params"]),
        "raw_json": json.dumps(payload["raw"]) if payload["raw"] is not None else None,
        "parent_event_id": payload["parent_event_id"],
    }


def _alert_to_row(alert: Alert) -> dict[str, object]:
    payload = alert.model_dump(mode="json")
    return {
        "alert_id": payload["alert_id"],
        "created_at": payload["created_at"],
        "severity": payload["severity"],
        "rule_id": payload["rule_id"],
        "source": payload["source"],
        "agent_id": payload["agent_id"],
        "session_id": payload["session_id"],
        "event_ids_json": json.dumps(payload["event_ids"]),
        "summary": payload["summary"],
        "rationale": payload["rationale"],
        "evidence_json": json.dumps(payload["evidence"]),
        "decision": payload["decision"],
    }


def _tool_fingerprint_to_row(tool: ToolFingerprint) -> dict[str, object]:
    payload = tool.model_dump(mode="json")
    return {
        "fingerprint_id": payload["fingerprint_id"],
        "server_id": payload["server_id"],
        "tool_name": payload["tool_name"],
        "description": payload["description"],
        "name_hash": payload["name_hash"],
        "description_hash": payload["description_hash"],
        "schema_hash": payload["schema_hash"],
        "first_seen": payload["first_seen"],
        "last_seen": payload["last_seen"],
        "observation_count": payload["observation_count"],
        "drift_count": payload["drift_count"],
        "latest_event_id": payload["latest_event_id"],
    }


def _tool_observation_to_row(observation: ToolObservation) -> dict[str, object]:
    payload = observation.model_dump(mode="json")
    return {
        "event_id": payload["event_id"],
        "fingerprint_id": payload["fingerprint_id"],
        "observed_at": payload["observed_at"],
        "agent_id": payload["agent_id"],
        "session_id": payload["session_id"],
        "server_id": payload["server_id"],
        "tool_name": payload["tool_name"],
        "description": payload["description"],
        "name_hash": payload["name_hash"],
        "description_hash": payload["description_hash"],
        "schema_hash": payload["schema_hash"],
        "input_schema_json": json.dumps(payload["input_schema"]),
        "output_schema_json": json.dumps(payload["output_schema"]),
    }


def _utc_now_text() -> str:
    return datetime.now(timezone.utc).isoformat()


def _optional_text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _audit_record_to_row(envelope: dict[str, Any]) -> dict[str, object]:
    sanitized = redact_json_like(envelope)
    if not isinstance(sanitized, dict):
        sanitized = {}

    return {
        "source": _optional_text(sanitized.get("source")) or "unknown",
        "layer": _optional_text(sanitized.get("layer")) or "unknown",
        "event_type": _optional_text(sanitized.get("event_type")) or "unknown",
        "timestamp": _optional_text(sanitized.get("timestamp")),
        "decision": _optional_text(sanitized.get("decision")),
        "action": _optional_text(sanitized.get("action")),
        "rule_id": _optional_text(sanitized.get("rule_id")),
        "severity": _optional_text(sanitized.get("severity")),
        "summary": _optional_text(sanitized.get("summary")) or "External audit record",
        "redacted": 1 if sanitized.get("redacted", True) else 0,
        "record_json_sanitized": json.dumps(sanitized, sort_keys=True),
        "created_at": _utc_now_text(),
    }


def _event_from_row(row: sqlite3.Row) -> AgentEvent:
    return AgentEvent(
        event_id=row["event_id"],
        timestamp=row["timestamp"],
        agent_id=row["agent_id"],
        session_id=row["session_id"],
        source=row["source"],
        intent_text=row["intent_text"],
        action_type=row["action_type"],
        action_params=json.loads(row["action_params_json"]),
        raw=json.loads(row["raw_json"]) if row["raw_json"] is not None else None,
        parent_event_id=row["parent_event_id"],
    )


def _alert_from_row(row: sqlite3.Row) -> Alert:
    return Alert(
        alert_id=row["alert_id"],
        created_at=row["created_at"],
        severity=row["severity"],
        rule_id=row["rule_id"],
        source=row["source"],
        agent_id=row["agent_id"],
        session_id=row["session_id"],
        event_ids=json.loads(row["event_ids_json"]),
        summary=row["summary"],
        rationale=row["rationale"],
        evidence=json.loads(row["evidence_json"]),
        decision=row["decision"],
    )


def _tool_fingerprint_from_row(row: sqlite3.Row) -> ToolFingerprint:
    return ToolFingerprint(
        fingerprint_id=row["fingerprint_id"],
        server_id=row["server_id"],
        tool_name=row["tool_name"],
        description=row["description"],
        name_hash=row["name_hash"],
        description_hash=row["description_hash"],
        schema_hash=row["schema_hash"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        observation_count=row["observation_count"],
        drift_count=row["drift_count"],
        latest_event_id=row["latest_event_id"],
    )


def _tool_observation_from_row(row: sqlite3.Row) -> ToolObservation:
    return ToolObservation(
        event_id=row["event_id"],
        fingerprint_id=row["fingerprint_id"],
        observed_at=row["observed_at"],
        agent_id=row["agent_id"],
        session_id=row["session_id"],
        server_id=row["server_id"],
        tool_name=row["tool_name"],
        description=row["description"],
        name_hash=row["name_hash"],
        description_hash=row["description_hash"],
        schema_hash=row["schema_hash"],
        input_schema=json.loads(row["input_schema_json"]),
        output_schema=json.loads(row["output_schema_json"]),
    )


def _audit_record_from_row(row: sqlite3.Row) -> dict[str, Any]:
    record = json.loads(row["record_json_sanitized"])
    if not isinstance(record, dict):
        record = {}

    record["id"] = row["audit_record_id"]
    record.setdefault("source", row["source"])
    record.setdefault("layer", row["layer"])
    record.setdefault("event_type", row["event_type"])
    record.setdefault("timestamp", row["timestamp"])
    record.setdefault("decision", row["decision"])
    record.setdefault("action", row["action"])
    record.setdefault("rule_id", row["rule_id"])
    record.setdefault("severity", row["severity"])
    record.setdefault("summary", row["summary"])
    record.setdefault("redacted", bool(row["redacted"]))
    record["created_at"] = row["created_at"]
    return record


def init_db() -> None:
    with _connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                source TEXT NOT NULL,
                intent_text TEXT,
                action_type TEXT NOT NULL,
                action_params_json TEXT NOT NULL,
                raw_json TEXT,
                parent_event_id TEXT
            );

            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                severity TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                source TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                event_ids_json TEXT NOT NULL,
                summary TEXT NOT NULL,
                rationale TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                decision TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tool_fingerprints (
                fingerprint_id TEXT PRIMARY KEY,
                server_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                description TEXT NOT NULL,
                name_hash TEXT NOT NULL,
                description_hash TEXT NOT NULL,
                schema_hash TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                observation_count INTEGER NOT NULL,
                drift_count INTEGER NOT NULL DEFAULT 0,
                latest_event_id TEXT
            );

            CREATE TABLE IF NOT EXISTS tool_observations (
                observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                fingerprint_id TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                server_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                description TEXT NOT NULL,
                name_hash TEXT NOT NULL,
                description_hash TEXT NOT NULL,
                schema_hash TEXT NOT NULL,
                input_schema_json TEXT NOT NULL,
                output_schema_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_records (
                audit_record_id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                layer TEXT NOT NULL,
                event_type TEXT NOT NULL,
                timestamp TEXT,
                decision TEXT,
                action TEXT,
                rule_id TEXT,
                severity TEXT,
                summary TEXT NOT NULL,
                redacted INTEGER NOT NULL,
                record_json_sanitized TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )


def insert_event(event: AgentEvent, *, connection: sqlite3.Connection | None = None) -> None:
    """Internal write helper for one event row.

    Do not call this from API/tap/demo paths; use ingest_event() so redaction,
    registry updates, alert generation, and transaction boundaries are
    preserved. Direct calls are still useful in focused storage tests.
    """
    row = _event_to_row(event)
    try:
        with _connection_scope(connection) as active_connection:
            active_connection.execute(
                """
                INSERT INTO events (
                    event_id,
                    timestamp,
                    agent_id,
                    session_id,
                    source,
                    intent_text,
                    action_type,
                    action_params_json,
                    raw_json,
                    parent_event_id
                )
                VALUES (
                    :event_id,
                    :timestamp,
                    :agent_id,
                    :session_id,
                    :source,
                    :intent_text,
                    :action_type,
                    :action_params_json,
                    :raw_json,
                    :parent_event_id
                )
                """,
                row,
            )
    except sqlite3.IntegrityError as error:
        if "events.event_id" in str(error):
            raise DuplicateEventIdError(event.event_id) from error
        raise


def insert_alert(alert: Alert, *, connection: sqlite3.Connection | None = None) -> None:
    """Internal write helper for one alert row.

    Do not call this from API/tap/demo paths; use ingest_event() so redaction,
    registry updates, alert generation, and transaction boundaries are
    preserved. Direct calls are still useful in focused storage tests.
    """
    row = _alert_to_row(alert)
    with _connection_scope(connection) as active_connection:
        active_connection.execute(
            """
            INSERT INTO alerts (
                alert_id,
                created_at,
                severity,
                rule_id,
                source,
                agent_id,
                session_id,
                event_ids_json,
                summary,
                rationale,
                evidence_json,
                decision
            )
            VALUES (
                :alert_id,
                :created_at,
                :severity,
                :rule_id,
                :source,
                :agent_id,
                :session_id,
                :event_ids_json,
                :summary,
                :rationale,
                :evidence_json,
                :decision
            )
            """,
            row,
        )


def upsert_tool_fingerprint(
    tool: ToolFingerprint,
    *,
    connection: sqlite3.Connection | None = None,
) -> None:
    """Internal registry current-row write helper.

    Do not call this from API/tap/demo paths; use ingest_event() so redaction,
    registry updates, alert generation, and transaction boundaries are
    preserved.
    """
    row = _tool_fingerprint_to_row(tool)
    with _connection_scope(connection) as active_connection:
        active_connection.execute(
            """
            INSERT INTO tool_fingerprints (
                fingerprint_id,
                server_id,
                tool_name,
                description,
                name_hash,
                description_hash,
                schema_hash,
                first_seen,
                last_seen,
                observation_count,
                drift_count,
                latest_event_id
            )
            VALUES (
                :fingerprint_id,
                :server_id,
                :tool_name,
                :description,
                :name_hash,
                :description_hash,
                :schema_hash,
                :first_seen,
                :last_seen,
                :observation_count,
                :drift_count,
                :latest_event_id
            )
            ON CONFLICT(fingerprint_id) DO UPDATE SET
                server_id = excluded.server_id,
                tool_name = excluded.tool_name,
                description = excluded.description,
                name_hash = excluded.name_hash,
                description_hash = excluded.description_hash,
                schema_hash = excluded.schema_hash,
                first_seen = excluded.first_seen,
                last_seen = excluded.last_seen,
                observation_count = excluded.observation_count,
                drift_count = excluded.drift_count,
                latest_event_id = excluded.latest_event_id
            """,
            row,
        )


def insert_tool_observation(
    observation: ToolObservation,
    *,
    connection: sqlite3.Connection | None = None,
) -> None:
    """Internal registry history write helper.

    Do not call this from API/tap/demo paths; use ingest_event() so redaction,
    registry updates, alert generation, and transaction boundaries are
    preserved.
    """
    row = _tool_observation_to_row(observation)
    with _connection_scope(connection) as active_connection:
        active_connection.execute(
            """
            INSERT INTO tool_observations (
                event_id,
                fingerprint_id,
                observed_at,
                agent_id,
                session_id,
                server_id,
                tool_name,
                description,
                name_hash,
                description_hash,
                schema_hash,
                input_schema_json,
                output_schema_json
            )
            VALUES (
                :event_id,
                :fingerprint_id,
                :observed_at,
                :agent_id,
                :session_id,
                :server_id,
                :tool_name,
                :description,
                :name_hash,
                :description_hash,
                :schema_hash,
                :input_schema_json,
                :output_schema_json
            )
            """,
            row,
        )


def insert_audit_record(
    envelope: dict[str, Any],
    *,
    connection: sqlite3.Connection | None = None,
) -> int:
    row = _audit_record_to_row(envelope)
    with _connection_scope(connection) as active_connection:
        cursor = active_connection.execute(
            """
            INSERT INTO audit_records (
                source,
                layer,
                event_type,
                timestamp,
                decision,
                action,
                rule_id,
                severity,
                summary,
                redacted,
                record_json_sanitized,
                created_at
            )
            VALUES (
                :source,
                :layer,
                :event_type,
                :timestamp,
                :decision,
                :action,
                :rule_id,
                :severity,
                :summary,
                :redacted,
                :record_json_sanitized,
                :created_at
            )
            """,
            row,
        )
        return int(cursor.lastrowid)


def list_events() -> list[AgentEvent]:
    with _connect() as connection:
        rows = connection.execute("SELECT * FROM events ORDER BY timestamp ASC").fetchall()
    return [_event_from_row(row) for row in rows]


def list_alerts() -> list[Alert]:
    with _connect() as connection:
        rows = connection.execute("SELECT * FROM alerts ORDER BY created_at ASC").fetchall()
    return [_alert_from_row(row) for row in rows]


def list_tools() -> list[ToolFingerprint]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT * FROM tool_fingerprints ORDER BY last_seen DESC, tool_name ASC"
        ).fetchall()
    return [_tool_fingerprint_from_row(row) for row in rows]


def list_audit_records(limit: int = 100) -> list[dict[str, Any]]:
    safe_limit = min(max(limit, 1), 1000)
    with _connect() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM audit_records
            ORDER BY COALESCE(timestamp, created_at) DESC,
                     created_at DESC,
                     audit_record_id DESC,
                     source ASC,
                     layer ASC,
                     event_type ASC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()
    return [_audit_record_from_row(row) for row in rows]


def get_tool_fingerprint(
    fingerprint_id: str,
    *,
    connection: sqlite3.Connection | None = None,
) -> ToolFingerprint | None:
    with _connection_scope(connection) as active_connection:
        row = active_connection.execute(
            "SELECT * FROM tool_fingerprints WHERE fingerprint_id = ?",
            (fingerprint_id,),
        ).fetchone()
    return _tool_fingerprint_from_row(row) if row is not None else None


def get_tool_history(fingerprint_id: str) -> list[ToolObservation]:
    with _connect() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM tool_observations
            WHERE fingerprint_id = ?
            ORDER BY observed_at ASC, observation_id ASC
            """,
            (fingerprint_id,),
        ).fetchall()
    return [_tool_observation_from_row(row) for row in rows]


def count_events() -> int:
    with _connect() as connection:
        row = connection.execute("SELECT COUNT(*) AS count FROM events").fetchone()
    return int(row["count"])


def count_alerts() -> int:
    with _connect() as connection:
        row = connection.execute("SELECT COUNT(*) AS count FROM alerts").fetchone()
    return int(row["count"])


def count_tools() -> int:
    with _connect() as connection:
        row = connection.execute("SELECT COUNT(*) AS count FROM tool_fingerprints").fetchone()
    return int(row["count"])


def get_session_events(session_id: str) -> list[AgentEvent]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT * FROM events WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,),
        ).fetchall()
    return [_event_from_row(row) for row in rows]


def get_session_alerts(session_id: str) -> list[Alert]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT * FROM alerts WHERE session_id = ? ORDER BY created_at ASC",
            (session_id,),
        ).fetchall()
    return [_alert_from_row(row) for row in rows]


def find_tools_by_name(
    tool_name: str,
    exclude_server_id: str | None = None,
    *,
    connection: sqlite3.Connection | None = None,
) -> list[ToolFingerprint]:
    query = "SELECT * FROM tool_fingerprints WHERE tool_name = ?"
    params: tuple[object, ...] = (tool_name,)

    if exclude_server_id is not None:
        query += " AND server_id != ?"
        params = (tool_name, exclude_server_id)

    query += " ORDER BY server_id ASC, first_seen ASC"

    with _connection_scope(connection) as active_connection:
        rows = active_connection.execute(query, params).fetchall()
    return [_tool_fingerprint_from_row(row) for row in rows]


def ingest_event(event: AgentEvent) -> list[Alert]:
    """Canonical write path for ingesting exactly one runtime event.

    This function is the backend entrypoint for event ingestion. It keeps the
    event row, MCP registry reads/writes, history rows, and alert inserts on one
    SQLite connection so the whole ingest commits or rolls back together.
    """
    from app.credential_redaction import sanitize_event_for_storage
    from app.detector import detect_alerts
    from app.tool_registry import observe_tool_registration

    stored_event = sanitize_event_for_storage(event)
    with _connect() as connection:
        insert_event(stored_event, connection=connection)
        alerts = detect_alerts(stored_event)
        alerts.extend(observe_tool_registration(stored_event, connection=connection))
        for alert in alerts:
            insert_alert(alert, connection=connection)
        return alerts


def clear_db() -> None:
    init_db()
    with _connect() as connection:
        connection.execute("DELETE FROM audit_records")
        connection.execute("DELETE FROM tool_observations")
        connection.execute("DELETE FROM tool_fingerprints")
        connection.execute("DELETE FROM alerts")
        connection.execute("DELETE FROM events")
