import sqlite3

import pytest

from falcon_shield_alerts.diff import TransitionEvent
from falcon_shield_alerts.store import (
    commit_success,
    connect,
    init_db,
    is_seeded,
    load_checks,
)
from tests.support import remembered


def _event(key: str = "chk-1:failed:2026-10-01") -> TransitionEvent:
    return TransitionEvent(
        check_id="chk-1",
        kind="newly_failed",
        dedupe_key=key,
        payload={"name": "MFA disabled"},
    )


def test_schema_rejects_a_duplicate_dedupe_key(tmp_path) -> None:
    conn = connect(str(tmp_path / "state.sqlite"))
    init_db(conn)
    commit_success(
        conn,
        upserts=[remembered(status="Failed")],
        delete_ids=[],
        events=[_event()],
        seeded=True,
        last_digest_date=None,
        started_at="2026-10-15T17:47:00Z",
        finished_at="2026-10-15T17:47:00Z",
        checks_seen=1,
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """
            INSERT INTO events (check_id, kind, dedupe_key, payload_json, created_at)
            VALUES ('chk-1', 'newly_failed', 'chk-1:failed:2026-10-01', '{}', 't')
            """
        )
    count = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
    assert count == 1
    again = commit_success(
        conn,
        upserts=[remembered(status="Failed", affected=4)],
        delete_ids=[],
        events=[_event()],
        seeded=True,
        last_digest_date="2026-10-15",
        started_at="2026-10-15T18:00:00Z",
        finished_at="2026-10-15T18:00:00Z",
        checks_seen=1,
    )
    assert again
    assert conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"] == 1
    assert load_checks(conn)["chk-1"].affected == 4
    assert is_seeded(conn)
    conn.close()


def test_failed_write_rolls_back_check_rows(tmp_path) -> None:
    conn = connect(str(tmp_path / "state.sqlite"))
    init_db(conn)
    commit_success(
        conn,
        upserts=[remembered(status="Passed", affected=1)],
        delete_ids=[],
        events=[],
        seeded=True,
        last_digest_date=None,
        started_at="t0",
        finished_at="t0",
        checks_seen=1,
    )
    bad = TransitionEvent(
        check_id="chk-2",
        kind="newly_failed",
        dedupe_key="chk-2:failed:t",
        payload={"bad": {1}},
    )
    with pytest.raises(TypeError):
        commit_success(
            conn,
            upserts=[remembered("chk-2", status="Failed")],
            delete_ids=["chk-1"],
            events=[bad],
            seeded=True,
            last_digest_date="2026-10-15",
            started_at="t1",
            finished_at="t1",
            checks_seen=2,
        )
    rows = load_checks(conn)
    assert list(rows) == ["chk-1"]
    assert rows["chk-1"].status == "Passed"
    assert rows["chk-1"].affected == 1
    assert conn.execute("SELECT value FROM meta WHERE key = 'last_digest_date'").fetchone() is None
    conn.close()
