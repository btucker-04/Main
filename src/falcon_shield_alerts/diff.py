"""Transition table from the last stored status to a completed snapshot."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Never

EventKind = Literal[
    "newly_failed",
    "recovered",
    "dismissed",
    "left_failed",
    "digest",
    "operator",
]

# Printed by the API with U+2019, not ASCII apostrophe. Compared only when
# that exact status arrives on a check. The poller does not send it as a filter.
CANNOT_RUN = "Can\u2019t Run"


@dataclass(frozen=True)
class CheckSnapshot:
    id: str
    status: str
    base_check_id: str = ""
    integration_id: str = ""
    integration_alias: str = ""
    name: str = ""
    saas_name: str = ""
    impact: str = ""
    affected: int | float | None = None
    security_domain: str = ""
    status_last_changed_date: str | None = None
    status_reason: str = ""
    remediation_plan: str = ""
    dismiss_reason: str = ""
    user_who_dismissed: str = ""


@dataclass(frozen=True)
class StoredCheck:
    check_id: str
    status: str
    base_check_id: str
    integration_id: str
    integration_alias: str
    name: str
    saas_name: str
    impact: str
    affected: int | float | None
    security_domain: str
    status_last_changed_date: str | None
    status_reason: str
    first_seen_at: str
    last_seen_at: str


@dataclass(frozen=True)
class TransitionEvent:
    check_id: str
    kind: EventKind
    dedupe_key: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class DiffResult:
    events: list[TransitionEvent]
    upserts: list[StoredCheck]
    delete_ids: list[str]
    missing_failed_ids: list[str]
    performed_seed: bool


class DuplicateSnapshotId(Exception):
    def __init__(self, check_id: str) -> None:
        self.check_id = check_id
        super().__init__(f"duplicate check id: {check_id}")


def format_utc(value: datetime) -> str:
    moment = value.astimezone(timezone.utc).replace(microsecond=0)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_day(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d")


def days_open(first_seen_at: str, now: datetime) -> int:
    opened = datetime.strptime(first_seen_at, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    elapsed = now.astimezone(timezone.utc) - opened
    return max(0, elapsed.days)


def snapshot_from_api(data: Mapping[str, Any]) -> CheckSnapshot:
    changed = data.get("status_last_changed_date")
    if changed == "":
        changed = None
    return CheckSnapshot(
        id=str(data["id"]),
        status=str(data["status"]),
        base_check_id=_text(data, "base_check_id"),
        integration_id=_text(data, "integration_id"),
        integration_alias=_text(data, "integration_alias"),
        name=_text(data, "name"),
        saas_name=_text(data, "saas_name"),
        impact=_text(data, "impact"),
        affected=_affected_value(data.get("affected")),
        security_domain=_text(data, "security_domain"),
        status_last_changed_date=changed if isinstance(changed, str) else None,
        status_reason=_text(data, "status_reason"),
        remediation_plan=_text(data, "remediation_plan"),
        dismiss_reason=_text(data, "dismiss_reason"),
        user_who_dismissed=_text(data, "user_who_dismissed"),
    )


def diff_snapshot(
    stored: Mapping[str, StoredCheck],
    snapshot: list[CheckSnapshot],
    *,
    seeded: bool,
    announce_existing: bool,
    now: datetime,
) -> DiffResult:
    """Apply the transition table. The initial seed posts nothing unless asked."""

    cycle_clock = format_utc(now)
    seen: set[str] = set()
    events: list[TransitionEvent] = []
    upserts: list[StoredCheck] = []
    for check in snapshot:
        if check.id in seen:
            raise DuplicateSnapshotId(check.id)
        seen.add(check.id)
        previous = stored.get(check.id)
        if not seeded:
            if announce_existing and check.status == "Failed":
                events.append(_event("newly_failed", check, cycle_clock))
            first_seen = cycle_clock
        else:
            kind = _kind(None if previous is None else previous.status, check.status)
            if kind is not None:
                events.append(_event(kind, check, cycle_clock))
            first_seen = _first_seen(previous, check.status, cycle_clock)
        upserts.append(_stored_from_snapshot(check, first_seen, cycle_clock))

    delete_ids: list[str] = []
    missing_failed_ids: list[str] = []
    if seeded:
        for check_id, row in stored.items():
            if check_id in seen:
                continue
            if row.status == "Failed":
                missing_failed_ids.append(check_id)
            else:
                delete_ids.append(check_id)
    return DiffResult(
        events=events,
        upserts=upserts,
        delete_ids=delete_ids,
        missing_failed_ids=missing_failed_ids,
        performed_seed=not seeded,
    )


def transition_for_status(
    previous: StoredCheck,
    check: CheckSnapshot,
    *,
    now: datetime,
) -> tuple[TransitionEvent | None, StoredCheck]:
    """Apply the table to one stored row and a follow-up check body."""

    cycle_clock = format_utc(now)
    kind = _kind(previous.status, check.status)
    event = None if kind is None else _event(kind, check, cycle_clock)
    first_seen = _first_seen(previous, check.status, cycle_clock)
    return event, _stored_from_snapshot(check, first_seen, cycle_clock)


def not_returned_event(row: StoredCheck, now: datetime) -> TransitionEvent:
    when = format_utc(now)
    status = "not returned"
    return TransitionEvent(
        check_id=row.check_id,
        kind="left_failed",
        dedupe_key=dedupe_key("left_failed", check_id=row.check_id, when=when, status=status),
        payload={
            "name": row.name,
            "saas_name": row.saas_name,
            "integration_alias": row.integration_alias,
            "integration_id": row.integration_id,
            "impact": row.impact,
            "affected": row.affected,
            "security_domain": row.security_domain,
            "status_since": when,
            "check_id": row.check_id,
            "status_reason": row.status_reason,
            "remediation_plan": "",
            "dismiss_reason": "",
            "user_who_dismissed": "",
            "status": status,
        },
    )


def build_digest(rows: list[StoredCheck], *, now: datetime) -> TransitionEvent | None:
    failing = [row for row in rows if row.status == "Failed"]
    if not failing:
        return None
    failing.sort(key=lambda row: (row.name, row.check_id))
    today = utc_day(now)
    checks = [
        {
            "impact": row.impact,
            "name": row.name,
            "saas_name": row.saas_name,
            "affected": row.affected,
            "days_open": days_open(row.first_seen_at, now),
            "check_id": row.check_id,
        }
        for row in failing
    ]
    return TransitionEvent(
        check_id="",
        kind="digest",
        dedupe_key=dedupe_key("digest", check_id="", when=today),
        payload={"count": len(failing), "checks": checks},
    )


def build_operator_event(
    *,
    status: str,
    messages: list[str],
    trace_id: str | None,
    now: datetime,
) -> TransitionEvent:
    today = utc_day(now)
    return TransitionEvent(
        check_id="",
        kind="operator",
        dedupe_key=dedupe_key("operator", check_id="", when=today, status=status),
        payload={
            "http_status": status,
            "messages": list(messages),
            "trace_id": trace_id,
        },
    )


def dedupe_key(
    kind: EventKind,
    *,
    check_id: str,
    when: str,
    status: str = "",
) -> str:
    if kind == "newly_failed":
        return f"{check_id}:failed:{when}"
    elif kind == "recovered":
        return f"{check_id}:recovered:{when}"
    elif kind == "dismissed":
        return f"{check_id}:dismissed:{when}"
    elif kind == "left_failed":
        return f"{check_id}:left:{status}:{when}"
    elif kind == "digest":
        return f"digest:{when}"
    elif kind == "operator":
        return f"operator:{status}:{when}"
    else:
        _exhaustive: Never = kind
        raise RuntimeError(_exhaustive)


def rows_after_apply(
    stored: Mapping[str, StoredCheck],
    upserts: list[StoredCheck],
    delete_ids: list[str],
) -> list[StoredCheck]:
    rows = dict(stored)
    for check_id in delete_ids:
        rows.pop(check_id, None)
    for row in upserts:
        rows[row.check_id] = row
    return list(rows.values())


def _kind(old: str | None, new: str) -> EventKind | None:
    if old is None:
        if new == "Failed":
            return "newly_failed"
        return None
    if old == new:
        return None
    if new == "Failed":
        return "newly_failed"
    if old != "Failed":
        return None
    if new == "Passed":
        return "recovered"
    if new == "Dismissed":
        return "dismissed"
    if new:
        return "left_failed"
    return None


def _event(kind: EventKind, check: CheckSnapshot, cycle_clock: str) -> TransitionEvent:
    when = _status_since(check, cycle_clock)
    return TransitionEvent(
        check_id=check.id,
        kind=kind,
        dedupe_key=dedupe_key(kind, check_id=check.id, when=when, status=check.status),
        payload=_payload(check, status_since=when),
    )


def _status_since(check: CheckSnapshot, cycle_clock: str) -> str:
    raw = check.status_last_changed_date
    if raw is None or raw == "":
        return cycle_clock
    return raw


def _first_seen(previous: StoredCheck | None, new_status: str, cycle_clock: str) -> str:
    if previous is None:
        return cycle_clock
    if new_status == "Failed" and previous.status != "Failed":
        return cycle_clock
    return previous.first_seen_at


def _stored_from_snapshot(
    check: CheckSnapshot,
    first_seen_at: str,
    last_seen_at: str,
) -> StoredCheck:
    return StoredCheck(
        check_id=check.id,
        status=check.status,
        base_check_id=check.base_check_id,
        integration_id=check.integration_id,
        integration_alias=check.integration_alias,
        name=check.name,
        saas_name=check.saas_name,
        impact=check.impact,
        affected=check.affected,
        security_domain=check.security_domain,
        status_last_changed_date=check.status_last_changed_date,
        status_reason=check.status_reason,
        first_seen_at=first_seen_at,
        last_seen_at=last_seen_at,
    )


def _payload(check: CheckSnapshot, *, status_since: str) -> dict[str, Any]:
    return {
        "name": check.name,
        "saas_name": check.saas_name,
        "integration_alias": check.integration_alias,
        "integration_id": check.integration_id,
        "impact": check.impact,
        "affected": check.affected,
        "security_domain": check.security_domain,
        "status_since": status_since,
        "check_id": check.id,
        "status_reason": check.status_reason,
        "remediation_plan": check.remediation_plan,
        "dismiss_reason": check.dismiss_reason,
        "user_who_dismissed": check.user_who_dismissed,
        "status": check.status,
    }


def _affected_value(value: object) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def _text(data: Mapping[str, Any], key: str) -> str:
    value = data.get(key)
    if isinstance(value, str):
        return value
    return ""
