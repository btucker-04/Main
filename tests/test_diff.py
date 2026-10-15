from datetime import datetime, timezone

import pytest

from falcon_shield_alerts.diff import (
    CANNOT_RUN,
    DuplicateSnapshotId,
    build_digest,
    build_operator_event,
    diff_snapshot,
    not_returned_event,
)
from tests.support import remembered, snapshot

NOW = datetime(2026, 10, 15, 17, 47, tzinfo=timezone.utc)
CLOCK = "2026-10-15T17:47:00Z"


def _diff(stored: dict, checks: list, *, seeded: bool, announce: bool = False):
    return diff_snapshot(
        stored,
        checks,
        seeded=seeded,
        announce_existing=announce,
        now=NOW,
    )


def test_unseeded_snapshot_is_silent() -> None:
    result = _diff({}, [snapshot(status="Failed"), snapshot("chk-2", "Passed")], seeded=False)
    assert result.events == []
    assert result.performed_seed is True
    assert {row.check_id for row in result.upserts} == {"chk-1", "chk-2"}
    assert result.delete_ids == []
    assert result.missing_failed_ids == []


def test_announce_existing_emits_only_current_failures() -> None:
    result = _diff(
        {},
        [snapshot(status="Failed"), snapshot("chk-2", "Passed")],
        seeded=False,
        announce=True,
    )
    assert [event.kind for event in result.events] == ["newly_failed"]
    assert result.events[0].check_id == "chk-1"
    assert result.events[0].dedupe_key == "chk-1:failed:2026-10-01"
    assert result.performed_seed is True


def test_new_failed_check_after_seed_posts_once() -> None:
    result = _diff({}, [snapshot(status="Failed")], seeded=True)
    assert [event.kind for event in result.events] == ["newly_failed"]
    assert result.upserts[0].first_seen_at == CLOCK


def test_new_non_failed_check_after_seed_is_stored_quietly() -> None:
    result = _diff({}, [snapshot(status="Pending")], seeded=True)
    assert result.events == []
    assert result.upserts[0].status == "Pending"


def test_transition_into_failed() -> None:
    stored = {"chk-1": remembered(status="Passed", first_seen_at="2026-10-01T00:00:00Z")}
    result = _diff(stored, [snapshot(status="Failed")], seeded=True)
    assert [event.kind for event in result.events] == ["newly_failed"]
    assert result.upserts[0].first_seen_at == CLOCK


def test_still_failed_does_not_post_even_if_affected_changes() -> None:
    stored = {
        "chk-1": remembered(
            status="Failed",
            affected=1,
            first_seen_at="2026-10-12T00:00:00Z",
        )
    }
    result = _diff(stored, [snapshot(status="Failed", affected=9)], seeded=True)
    assert result.events == []
    assert result.upserts[0].affected == 9
    assert result.upserts[0].first_seen_at == "2026-10-12T00:00:00Z"
    assert result.upserts[0].last_seen_at == CLOCK


@pytest.mark.parametrize(
    ("status", "kind", "key"),
    [
        ("Passed", "recovered", "chk-1:recovered:2026-10-01"),
        ("Dismissed", "dismissed", "chk-1:dismissed:2026-10-01"),
        ("Pending", "left_failed", "chk-1:left:Pending:2026-10-01"),
        ("Stale", "left_failed", "chk-1:left:Stale:2026-10-01"),
        ("NA", "left_failed", "chk-1:left:NA:2026-10-01"),
        ("Not Available", "left_failed", "chk-1:left:Not Available:2026-10-01"),
        (CANNOT_RUN, "left_failed", f"chk-1:left:{CANNOT_RUN}:2026-10-01"),
        ("Weird", "left_failed", "chk-1:left:Weird:2026-10-01"),
    ],
)
def test_leaving_failed(status: str, kind: str, key: str) -> None:
    stored = {"chk-1": remembered(status="Failed")}
    result = _diff(stored, [snapshot(status=status)], seeded=True)
    assert [event.kind for event in result.events] == [kind]
    assert result.events[0].dedupe_key == key
    assert result.events[0].payload["status"] == status


def test_same_status_is_quiet() -> None:
    stored = {"chk-1": remembered(status="Stale")}
    result = _diff(stored, [snapshot(status="Stale")], seeded=True)
    assert result.events == []


def test_non_failed_status_change_has_no_event() -> None:
    stored = {"chk-1": remembered(status="Passed")}
    result = _diff(stored, [snapshot(status="Pending")], seeded=True)
    assert result.events == []
    assert result.upserts[0].status == "Pending"


def test_missing_changed_date_uses_the_cycle_clock() -> None:
    first = snapshot("chk-1", status_last_changed_date=None)
    second = snapshot("chk-2", status_last_changed_date="")
    result = _diff({}, [first, second], seeded=True)
    assert result.events[0].dedupe_key == f"chk-1:failed:{CLOCK}"
    assert result.events[1].dedupe_key == f"chk-2:failed:{CLOCK}"
    assert result.events[0].dedupe_key != result.events[1].dedupe_key


def test_missing_failed_check_is_looked_up_and_passed_check_is_deleted() -> None:
    stored = {
        "failed": remembered("failed", status="Failed"),
        "passed": remembered("passed", status="Passed"),
    }
    result = _diff(stored, [], seeded=True)
    assert result.missing_failed_ids == ["failed"]
    assert result.delete_ids == ["passed"]
    assert result.events == []


def test_duplicate_id_in_snapshot_aborts() -> None:
    with pytest.raises(DuplicateSnapshotId):
        _diff({}, [snapshot("chk-1"), snapshot("chk-1")], seeded=True)


def test_not_returned_is_left_failed_and_not_a_pass() -> None:
    event = not_returned_event(remembered(status="Failed"), NOW)
    assert event.kind == "left_failed"
    assert event.payload["status"] == "not returned"
    assert event.dedupe_key == f"chk-1:left:not returned:{CLOCK}"


def test_digest_lists_open_failures_and_is_once_per_day() -> None:
    rows = [
        remembered("b", status="Failed", name="Beta", first_seen_at="2026-10-12T00:00:00Z"),
        remembered("a", status="Failed", name="Alpha", first_seen_at="2026-10-15T00:00:00Z"),
        remembered("c", status="Passed", name="Gone"),
    ]
    event = build_digest(rows, now=NOW)
    assert event is not None
    assert event.dedupe_key == "digest:2026-10-15"
    assert event.payload["count"] == 2
    assert [item["name"] for item in event.payload["checks"]] == ["Alpha", "Beta"]
    assert event.payload["checks"][1]["days_open"] == 3
    assert build_digest([remembered(status="Passed")], now=NOW) is None


def test_operator_dedupe_key() -> None:
    event = build_operator_event(
        status="403",
        messages=["not authorized"],
        trace_id="trace-9",
        now=NOW,
    )
    assert event.dedupe_key == "operator:403:2026-10-15"
    assert event.payload["trace_id"] == "trace-9"


def test_cannot_run_uses_the_unicode_apostrophe() -> None:
    assert CANNOT_RUN == "Can\u2019t Run"
    assert "'" not in CANNOT_RUN
