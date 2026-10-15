"""One poll: lock, read, diff, commit, then post unsent Slack messages."""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone

from falcon_shield_alerts.config import Config
from falcon_shield_alerts.diff import (
    DuplicateSnapshotId,
    EventKind,
    build_digest,
    build_operator_event,
    diff_snapshot,
    format_utc,
    not_returned_event,
    rows_after_apply,
    snapshot_from_api,
    transition_for_status,
    utc_day,
)
from falcon_shield_alerts.falcon import FalconClient, FalconError
from falcon_shield_alerts.lock import file_lock
from falcon_shield_alerts.slack import (
    TRANSITION_KINDS,
    MAX_TRANSITION_POSTS,
    SlackClient,
    SlackError,
    render_message,
    render_overflow,
)
from falcon_shield_alerts.store import (
    StoredEvent,
    commit_success,
    connect,
    init_db,
    is_seeded,
    list_unsent,
    load_checks,
    mark_poll_failed,
    mark_sent,
    get_meta,
    record_failure,
)

logger = logging.getLogger("falcon_shield_alerts")


def run_poll(
    config: Config,
    *,
    announce_existing: bool = False,
    client: FalconClient,
    slack: SlackClient,
    now: datetime | None = None,
) -> int:
    run_at = now if now is not None else datetime.now(timezone.utc)
    if run_at.tzinfo is None:
        run_at = run_at.replace(tzinfo=timezone.utc)
    started = format_utc(run_at)
    with file_lock(config.state_path):
        conn = connect(config.state_path)
        try:
            init_db(conn)
            try:
                return _poll_locked(
                    config,
                    conn,
                    client=client,
                    slack=slack,
                    announce_existing=announce_existing,
                    run_at=run_at,
                    started=started,
                )
            except (FalconError, DuplicateSnapshotId) as exc:
                _fail(config, conn, exc, run_at=run_at, started=started)
                _deliver(conn, slack, config.slack_channel_id, config)
                return 1
        finally:
            conn.close()


def _poll_locked(
    config: Config,
    conn: sqlite3.Connection,
    *,
    client: FalconClient,
    slack: SlackClient,
    announce_existing: bool,
    run_at: datetime,
    started: str,
) -> int:
    prior_unsent = list_unsent(conn)
    seeded = is_seeded(conn)
    checks = client.fetch_all_checks()
    snapshot = [snapshot_from_api(item) for item in checks]
    stored = load_checks(conn)
    result = diff_snapshot(
        stored,
        snapshot,
        seeded=seeded,
        announce_existing=announce_existing,
        now=run_at,
    )
    events = list(result.events)
    upserts = list(result.upserts)
    delete_ids = list(result.delete_ids)

    for check_id in result.missing_failed_ids:
        found = client.fetch_one(check_id)
        previous = stored[check_id]
        if len(found) == 0:
            events.append(not_returned_event(previous, run_at))
            delete_ids.append(check_id)
            continue
        if len(found) != 1:
            raise FalconError("truncated", [f"lookup for {check_id} returned {len(found)} checks"])
        event, row = transition_for_status(
            previous,
            snapshot_from_api(found[0]),
            now=run_at,
        )
        if event is not None:
            events.append(event)
        upserts.append(row)

    for event in events:
        if event.kind != "newly_failed":
            continue
        names, unavailable = client.fetch_affected_names(event.check_id)
        if unavailable:
            event.payload["entity_sample_unavailable"] = True
        else:
            event.payload["entity_names"] = names
            event.payload["entity_sample_unavailable"] = False

    last_digest_date: str | None = None
    today = utc_day(run_at)
    if seeded and not prior_unsent and get_meta(conn, "last_digest_date") != today:
        final_rows = rows_after_apply(stored, upserts, delete_ids)
        digest = build_digest(final_rows, now=run_at)
        if digest is not None:
            events.append(digest)
            last_digest_date = today

    run_id = commit_success(
        conn,
        upserts=upserts,
        delete_ids=delete_ids,
        events=events,
        seeded=True,
        last_digest_date=last_digest_date,
        started_at=started,
        finished_at=started,
        checks_seen=len(snapshot),
    )
    delivered = _deliver(conn, slack, config.slack_channel_id, config)
    if not delivered:
        mark_poll_failed(conn, run_id, "slack delivery failed")
        return 1
    return 0


def _fail(
    config: Config,
    conn: sqlite3.Connection,
    exc: FalconError | DuplicateSnapshotId,
    *,
    run_at: datetime,
    started: str,
) -> None:
    if isinstance(exc, DuplicateSnapshotId):
        status = "duplicate"
        messages = [str(exc)]
        trace_id = None
    else:
        status = exc.status
        messages = [_scrub(message, config) for message in exc.messages]
        trace_id = _scrub(exc.trace_id, config) if exc.trace_id else None
    logger.error("falcon poll failed http_status=%s trace_id=%s", status, trace_id or "")
    event = build_operator_event(
        status=status,
        messages=messages,
        trace_id=trace_id,
        now=run_at,
    )
    record_failure(
        conn,
        event=event,
        started_at=started,
        finished_at=format_utc(run_at),
        error=_scrub(f"{status}: {'; '.join(messages)}", config)[:500],
    )


def _deliver(
    conn: sqlite3.Connection,
    slack: SlackClient,
    channel: str,
    config: Config,
) -> bool:
    pending = list_unsent(conn)
    transitions = [event for event in pending if event.kind in TRANSITION_KINDS]
    others = [event for event in pending if event.kind not in TRANSITION_KINDS]
    ok = True
    for event in transitions[:MAX_TRANSITION_POSTS]:
        if not _post_one(conn, slack, channel, event, config):
            ok = False
    overflow = transitions[MAX_TRANSITION_POSTS:]
    if overflow:
        pairs = [(event.check_id, event.payload) for event in overflow]
        try:
            ts = slack.post_message(channel, render_overflow(pairs))
        except SlackError as exc:
            logger.error("slack rejected kind=overflow error=%s", _scrub(exc.error, config))
            ok = False
        else:
            for event in overflow:
                payload = dict(event.payload)
                payload["delivered_by"] = "overflow"
                payload["overflow_count"] = len(overflow)
                mark_sent(conn, event.id, channel=channel, ts=ts, payload=payload)
            logger.info("slack posted kind=overflow count=%s", len(overflow))
    for event in others:
        if not _post_one(conn, slack, channel, event, config):
            ok = False
    return ok


def _post_one(
    conn: sqlite3.Connection,
    slack: SlackClient,
    channel: str,
    event: StoredEvent,
    config: Config,
) -> bool:
    kind = _event_kind(event.kind)
    try:
        ts = slack.post_message(channel, render_message(kind, event.payload))
    except SlackError as exc:
        logger.error(
            "slack rejected check_id=%s kind=%s error=%s",
            event.check_id,
            event.kind,
            _scrub(exc.error, config),
        )
        return False
    mark_sent(conn, event.id, channel=channel, ts=ts, payload=event.payload)
    logger.info("slack posted check_id=%s kind=%s", event.check_id, event.kind)
    return True


def _event_kind(value: str) -> EventKind:
    if value == "newly_failed":
        return "newly_failed"
    elif value == "recovered":
        return "recovered"
    elif value == "dismissed":
        return "dismissed"
    elif value == "left_failed":
        return "left_failed"
    elif value == "digest":
        return "digest"
    elif value == "operator":
        return "operator"
    else:
        raise RuntimeError(f"unknown event kind: {value}")


def _scrub(text: str, config: Config) -> str:
    redacted = text
    for secret in (
        config.falcon_client_secret,
        config.falcon_client_id,
        config.slack_bot_token,
    ):
        if secret:
            redacted = redacted.replace(secret, "[redacted]")
    return redacted
