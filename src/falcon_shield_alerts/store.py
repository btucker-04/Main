"""SQLite state. A failed poll does not commit check rows."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from falcon_shield_alerts.diff import StoredCheck, TransitionEvent

SCHEMA = """
CREATE TABLE IF NOT EXISTS checks (
    check_id TEXT PRIMARY KEY,
    base_check_id TEXT,
    integration_id TEXT,
    integration_alias TEXT,
    name TEXT,
    saas_name TEXT,
    status TEXT,
    impact TEXT,
    affected NUMERIC,
    security_domain TEXT,
    status_last_changed_date TEXT,
    status_reason TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    check_id TEXT,
    kind TEXT NOT NULL,
    dedupe_key TEXT NOT NULL UNIQUE,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    slack_channel TEXT,
    slack_ts TEXT
);

CREATE TABLE IF NOT EXISTS poll_runs (
    id INTEGER PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    ok INTEGER NOT NULL,
    error TEXT,
    checks_seen INTEGER
);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


class StoredEvent:
    def __init__(
        self,
        *,
        id: int,
        check_id: str,
        kind: str,
        dedupe_key: str,
        payload: dict[str, Any],
        created_at: str,
        slack_channel: str | None,
        slack_ts: str | None,
    ) -> None:
        self.id = id
        self.check_id = check_id
        self.kind = kind
        self.dedupe_key = dedupe_key
        self.payload = payload
        self.created_at = created_at
        self.slack_channel = slack_channel
        self.slack_ts = slack_ts


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


def is_seeded(conn: sqlite3.Connection) -> bool:
    return get_meta(conn, "seeded") == "1"


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    if row is None:
        return None
    value = row["value"]
    return None if value is None else str(value)


def load_checks(conn: sqlite3.Connection) -> dict[str, StoredCheck]:
    rows = conn.execute(
        """
        SELECT check_id, status, base_check_id, integration_id, integration_alias,
               name, saas_name, impact, affected, security_domain,
               status_last_changed_date, status_reason, first_seen_at, last_seen_at
        FROM checks
        """
    ).fetchall()
    loaded: dict[str, StoredCheck] = {}
    for row in rows:
        check = StoredCheck(
            check_id=row["check_id"],
            status=row["status"] or "",
            base_check_id=row["base_check_id"] or "",
            integration_id=row["integration_id"] or "",
            integration_alias=row["integration_alias"] or "",
            name=row["name"] or "",
            saas_name=row["saas_name"] or "",
            impact=row["impact"] or "",
            affected=row["affected"],
            security_domain=row["security_domain"] or "",
            status_last_changed_date=row["status_last_changed_date"],
            status_reason=row["status_reason"] or "",
            first_seen_at=row["first_seen_at"],
            last_seen_at=row["last_seen_at"],
        )
        loaded[check.check_id] = check
    return loaded


def list_unsent(conn: sqlite3.Connection) -> list[StoredEvent]:
    rows = conn.execute(
        """
        SELECT id, check_id, kind, dedupe_key, payload_json, created_at,
               slack_channel, slack_ts
        FROM events
        WHERE slack_ts IS NULL
        ORDER BY id ASC
        """
    ).fetchall()
    return [_event_from_row(row) for row in rows]


def commit_success(
    conn: sqlite3.Connection,
    *,
    upserts: list[StoredCheck],
    delete_ids: list[str],
    events: list[TransitionEvent],
    seeded: bool,
    last_digest_date: str | None,
    started_at: str,
    finished_at: str,
    checks_seen: int,
) -> int:
    """Commit statuses and new events together. Slack delivery is a later step."""

    conn.execute("BEGIN")
    try:
        for check_id in delete_ids:
            conn.execute("DELETE FROM checks WHERE check_id = ?", (check_id,))
        for row in upserts:
            _upsert_check(conn, row)
        for event in events:
            _insert_event(conn, event, created_at=finished_at)
        _set_meta(conn, "seeded", "1" if seeded else "0")
        if last_digest_date is not None:
            _set_meta(conn, "last_digest_date", last_digest_date)
        cursor = conn.execute(
            """
            INSERT INTO poll_runs (started_at, finished_at, ok, error, checks_seen)
            VALUES (?, ?, 1, NULL, ?)
            """,
            (started_at, finished_at, checks_seen),
        )
        run_id = int(cursor.lastrowid)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return run_id


def record_failure(
    conn: sqlite3.Connection,
    *,
    event: TransitionEvent,
    started_at: str,
    finished_at: str,
    error: str,
) -> None:
    """Record an operator notice without changing check rows."""

    conn.execute("BEGIN")
    try:
        _insert_event(conn, event, created_at=finished_at)
        conn.execute(
            """
            INSERT INTO poll_runs (started_at, finished_at, ok, error, checks_seen)
            VALUES (?, ?, 0, ?, NULL)
            """,
            (started_at, finished_at, error),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def mark_sent(
    conn: sqlite3.Connection,
    event_id: int,
    *,
    channel: str,
    ts: str,
    payload: dict[str, Any],
) -> None:
    conn.execute(
        """
        UPDATE events
        SET slack_channel = ?, slack_ts = ?, payload_json = ?
        WHERE id = ?
        """,
        (channel, ts, json.dumps(payload, ensure_ascii=False), event_id),
    )


def mark_poll_failed(conn: sqlite3.Connection, run_id: int, error: str) -> None:
    conn.execute(
        "UPDATE poll_runs SET ok = 0, error = ? WHERE id = ?",
        (error, run_id),
    )


def _upsert_check(conn: sqlite3.Connection, row: StoredCheck) -> None:
    conn.execute(
        """
        INSERT INTO checks (
            check_id, base_check_id, integration_id, integration_alias, name,
            saas_name, status, impact, affected, security_domain,
            status_last_changed_date, status_reason, first_seen_at, last_seen_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(check_id) DO UPDATE SET
            base_check_id = excluded.base_check_id,
            integration_id = excluded.integration_id,
            integration_alias = excluded.integration_alias,
            name = excluded.name,
            saas_name = excluded.saas_name,
            status = excluded.status,
            impact = excluded.impact,
            affected = excluded.affected,
            security_domain = excluded.security_domain,
            status_last_changed_date = excluded.status_last_changed_date,
            status_reason = excluded.status_reason,
            first_seen_at = excluded.first_seen_at,
            last_seen_at = excluded.last_seen_at
        """,
        (
            row.check_id,
            row.base_check_id,
            row.integration_id,
            row.integration_alias,
            row.name,
            row.saas_name,
            row.status,
            row.impact,
            row.affected,
            row.security_domain,
            row.status_last_changed_date,
            row.status_reason,
            row.first_seen_at,
            row.last_seen_at,
        ),
    )


def _insert_event(
    conn: sqlite3.Connection,
    event: TransitionEvent,
    *,
    created_at: str,
) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO events (
            check_id, kind, dedupe_key, payload_json, created_at
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (
            event.check_id or None,
            event.kind,
            event.dedupe_key,
            json.dumps(event.payload, ensure_ascii=False),
            created_at,
        ),
    )


def _set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        """
        INSERT INTO meta (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (key, value),
    )


def _event_from_row(row: sqlite3.Row) -> StoredEvent:
    payload = json.loads(row["payload_json"])
    if not isinstance(payload, dict):
        payload = {}
    return StoredEvent(
        id=int(row["id"]),
        check_id=row["check_id"] or "",
        kind=str(row["kind"]),
        dedupe_key=str(row["dedupe_key"]),
        payload=payload,
        created_at=str(row["created_at"]),
        slack_channel=row["slack_channel"],
        slack_ts=row["slack_ts"],
    )
