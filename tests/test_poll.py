import json
from datetime import datetime, timedelta, timezone

from falcon_shield_alerts.poll import run_poll
from falcon_shield_alerts.store import connect, load_checks
from tests.support import (
    FalconAPI,
    SlackAPI,
    api_check,
    config_for,
    falcon_client,
    slack_client,
)

NOW = datetime(2026, 10, 15, 17, 47, tzinfo=timezone.utc)
LATER = NOW + timedelta(hours=1)


def _events(path: str) -> list[dict]:
    conn = connect(path)
    try:
        rows = conn.execute(
            """
            SELECT kind, dedupe_key, payload_json, slack_ts
            FROM events
            ORDER BY id
            """
        ).fetchall()
    finally:
        conn.close()
    return [
        {
            "kind": row["kind"],
            "dedupe_key": row["dedupe_key"],
            "payload": json.loads(row["payload_json"]),
            "slack_ts": row["slack_ts"],
        }
        for row in rows
    ]


def _checks(path: str):
    conn = connect(path)
    try:
        return load_checks(conn)
    finally:
        conn.close()


def _run(path, api, slack_api, *, announce=False, now=NOW, sleeps=None):
    http, client = falcon_client(api, sleep=lambda seconds: None if sleeps is None else sleeps.append(seconds))
    slack_http, slack = slack_client(slack_api)
    try:
        return run_poll(
            config_for(path),
            announce_existing=announce,
            client=client,
            slack=slack,
            now=now,
        )
    finally:
        http.close()
        slack_http.close()


def test_first_seed_is_silent_and_stores_attributes(tmp_path) -> None:
    path = str(tmp_path / "state.sqlite")
    api = FalconAPI(
        [api_check("chk-1", "Failed", affected=4), api_check("chk-2", "Passed")]
    )
    slack = SlackAPI()
    code = _run(path, api, slack)
    assert code == 0
    assert slack.posts == []
    assert _events(path) == []
    rows = _checks(path)
    assert rows["chk-1"].status == "Failed"
    assert rows["chk-1"].affected == 4
    assert rows["chk-1"].base_check_id == "base-1"
    assert rows["chk-1"].integration_id == "int-1"
    assert rows["chk-2"].status == "Passed"
    assert all("status" not in request.url.params for request in api.calls)


def test_announce_existing_posts_failed_checks_with_entity_sample(tmp_path) -> None:
    path = str(tmp_path / "state.sqlite")
    api = FalconAPI([api_check("chk-1", "Failed", name="MFA disabled")])
    api.affected["chk-1"] = (200, [{"entity_name": "alice"}, {"entity_name": "bob"}])
    slack = SlackAPI()
    code = _run(path, api, slack, announce=True)
    assert code == 0
    assert slack.posts[0]["channel"] == "C0123"
    assert "Falcon Shield failed: MFA disabled" in slack.posts[0]["text"]
    assert "Entity sample: alice, bob" in slack.posts[0]["text"]
    assert _events(path)[0]["slack_ts"]
    assert any(request.url.path.endswith("/check-affected/v3") for request in api.calls)


def test_still_failed_updates_affected_without_its_own_message(tmp_path) -> None:
    path = str(tmp_path / "state.sqlite")
    api = FalconAPI([api_check("chk-1", "Failed", name="MFA disabled", affected=1)])
    slack = SlackAPI()
    assert _run(path, api, slack, now=NOW) == 0
    first_seen = _checks(path)["chk-1"].first_seen_at
    api.calls.clear()
    api.checks = [api_check("chk-1", "Failed", name="MFA disabled", affected=8)]
    slack.posts.clear()
    assert _run(path, api, slack, now=LATER) == 0
    row = _checks(path)["chk-1"]
    assert row.affected == 8
    assert row.first_seen_at == first_seen
    assert row.last_seen_at != first_seen
    kinds = [event["kind"] for event in _events(path)]
    assert kinds == ["digest"]
    assert "Falcon Shield still failing (1)" in slack.posts[0]["text"]
    assert "affected 8" in slack.posts[0]["text"]
    assert not any(request.url.path.endswith("/check-affected/v3") for request in api.calls)


def test_429_abort_leaves_state_unchanged(tmp_path) -> None:
    path = str(tmp_path / "state.sqlite")
    api = FalconAPI([api_check("chk-1", "Passed", affected=2)])
    slack = SlackAPI()
    assert _run(path, api, slack, now=NOW) == 0
    before = _checks(path)["chk-1"]
    api.force_checks_status = 429
    api.error_body = {"errors": [{"message": "slow down"}], "meta": {"trace_id": "tr-429"}}
    sleeps: list[float] = []
    code = _run(path, api, slack, now=LATER, sleeps=sleeps)
    assert code == 1
    assert sleeps == [1, 2, 4]
    assert _checks(path)["chk-1"] == before
    assert [event["dedupe_key"] for event in _events(path)] == ["operator:429:2026-10-15"]
    assert "slow down" in slack.posts[-1]["text"]
    assert "trace_id: tr-429" in slack.posts[-1]["text"]


def test_duplicate_id_does_not_write_state(tmp_path) -> None:
    path = str(tmp_path / "state.sqlite")
    api = FalconAPI([api_check("chk-1", "Passed")])
    slack = SlackAPI()
    assert _run(path, api, slack, now=NOW) == 0
    before = _checks(path)
    api.checks = [api_check("dup", "Failed"), api_check("dup", "Failed")]
    assert _run(path, api, slack, now=LATER) == 1
    assert _checks(path) == before
    assert _events(path)[0]["dedupe_key"] == "operator:duplicate:2026-10-15"


def test_403_does_not_change_checks_and_posts_one_operator_per_day(tmp_path) -> None:
    path = str(tmp_path / "state.sqlite")
    api = FalconAPI([api_check("chk-1", "Failed")])
    slack = SlackAPI()
    assert _run(path, api, slack, now=NOW) == 0
    before = _checks(path)
    api.force_checks_status = 403
    api.error_body = {
        "errors": [{"code": 403, "message": "denied client-secret"}],
        "meta": {"trace_id": "trace-9"},
    }
    assert _run(path, api, slack, now=LATER) == 1
    assert _run(path, api, slack, now=LATER) == 1
    assert _checks(path) == before
    operators = [event for event in _events(path) if event["kind"] == "operator"]
    assert len(operators) == 1
    assert operators[0]["dedupe_key"] == "operator:403:2026-10-15"
    rendered = json.dumps(operators[0]["payload"])
    assert "client-secret" not in rendered
    assert "[redacted]" in rendered
    assert "xoxb-test-token" not in slack.posts[-1]["text"]


def test_network_error_does_not_write_checks(tmp_path) -> None:
    path = str(tmp_path / "state.sqlite")
    api = FalconAPI([api_check("chk-1", "Passed")])
    slack = SlackAPI()
    assert _run(path, api, slack, now=NOW) == 0
    before = _checks(path)
    api.network_error = True
    assert _run(path, api, slack, now=LATER) == 1
    assert _checks(path) == before
    assert _events(path)[0]["dedupe_key"] == "operator:network:2026-10-15"


def test_missing_failed_check_lookup_posts_not_returned_and_deletes_passed(tmp_path) -> None:
    path = str(tmp_path / "state.sqlite")
    api = FalconAPI(
        [
            api_check("gone", "Failed", name="Gone check"),
            api_check("ok", "Passed", name="Still fine"),
        ]
    )
    slack = SlackAPI()
    assert _run(path, api, slack, now=NOW) == 0
    api.calls.clear()
    api.checks = []
    api.lookups["gone"] = (200, [])
    assert _run(path, api, slack, now=LATER) == 0
    assert _checks(path) == {}
    assert len(slack.posts) == 1
    text = slack.posts[0]["text"]
    assert "Falcon Shield no longer failed: Gone check" in text
    assert "Now: not returned" in text
    assert "Passed" not in text
    looked_up = [
        request.url.params.get("id")
        for request in api.calls
        if request.url.path.endswith("/checks/v3") and "id" in request.url.params
    ]
    assert looked_up == ["gone"]


def test_lookup_error_leaves_old_rows(tmp_path) -> None:
    path = str(tmp_path / "state.sqlite")
    api = FalconAPI(
        [api_check("gone", "Failed"), api_check("ok", "Passed")]
    )
    slack = SlackAPI()
    assert _run(path, api, slack, now=NOW) == 0
    before = _checks(path)
    api.checks = []
    api.lookups["gone"] = (500, {"errors": [{"message": "later"}], "meta": {"trace_id": "tr-lookup"}})
    assert _run(path, api, slack, now=LATER) == 1
    assert _checks(path) == before
    assert _events(path)[0]["kind"] == "operator"
    assert "later" in slack.posts[-1]["text"]


def test_lookup_body_applies_the_transition_table(tmp_path) -> None:
    path = str(tmp_path / "state.sqlite")
    api = FalconAPI([api_check("chk-1", "Failed", name="MFA disabled")])
    slack = SlackAPI()
    assert _run(path, api, slack, now=NOW) == 0
    api.checks = []
    api.lookups["chk-1"] = (
        200,
        [api_check("chk-1", "Passed", name="MFA disabled", changed="2026-10-03")],
    )
    slack.posts.clear()
    assert _run(path, api, slack, now=LATER) == 0
    assert _checks(path)["chk-1"].status == "Passed"
    assert "Was Failed, now Passed" in slack.posts[0]["text"]


def test_slack_rejection_leaves_that_message_unsent_and_continues(tmp_path) -> None:
    path = str(tmp_path / "state.sqlite")
    api = FalconAPI(
        [
            api_check("first", "Failed", name="first"),
            api_check("second", "Failed", name="second"),
        ]
    )
    slack = SlackAPI()
    slack.fail_prefixes = ("Falcon Shield failed: first",)
    assert _run(path, api, slack, announce=True) == 1
    posted = [body["text"].splitlines()[0] for body in slack.posts]
    assert posted == [
        "Falcon Shield failed: first",
        "Falcon Shield failed: second",
    ]
    events = _events(path)
    by_name = {event["payload"]["name"]: event for event in events}
    assert by_name["first"]["slack_ts"] is None
    assert by_name["second"]["slack_ts"]


def test_overflow_marks_the_remainder_sent(tmp_path) -> None:
    path = str(tmp_path / "state.sqlite")
    api = FalconAPI(
        [api_check(f"id-{index}", "Failed", name=f"check-{index}") for index in range(21)]
    )
    slack = SlackAPI()
    assert _run(path, api, slack, announce=True) == 0
    texts = [body["text"] for body in slack.posts]
    assert sum(text.startswith("Falcon Shield failed:") for text in texts) == 20
    assert texts[-1].startswith("Falcon Shield poller: 1 more updates not sent individually:")
    assert "check-20" in texts[-1]
    assert not any(text.startswith("Falcon Shield failed: check-20") for text in texts)
    events = _events(path)
    assert all(event["slack_ts"] for event in events)
    overflow = events[-1]
    assert overflow["payload"]["delivered_by"] == "overflow"
    assert overflow["payload"]["name"] == "check-20"


def test_unsent_events_are_retried_before_a_new_digest(tmp_path) -> None:
    path = str(tmp_path / "state.sqlite")
    api = FalconAPI([api_check("chk-1", "Failed", name="MFA disabled")])
    slack = SlackAPI()
    slack.fail_prefixes = ("Falcon Shield failed:",)
    assert _run(path, api, slack, announce=True, now=NOW) == 1
    assert [event["kind"] for event in _events(path)] == ["newly_failed"]
    assert _events(path)[0]["slack_ts"] is None

    slack.fail_prefixes = ()
    slack.posts.clear()
    assert _run(path, api, slack, now=LATER) == 0
    assert [event["kind"] for event in _events(path)] == ["newly_failed"]
    assert _events(path)[0]["slack_ts"]
    assert slack.posts[0]["text"].startswith("Falcon Shield failed: MFA disabled")

    slack.posts.clear()
    assert _run(path, api, slack, now=LATER) == 0
    assert [event["kind"] for event in _events(path)] == ["newly_failed", "digest"]
    assert _run(path, api, slack, now=LATER) == 0
    assert [event["kind"] for event in _events(path)] == ["newly_failed", "digest"]


def test_failed_overflow_post_leaves_the_remainder_unsent(tmp_path) -> None:
    path = str(tmp_path / "state.sqlite")
    api = FalconAPI(
        [api_check(f"id-{index}", "Failed", name=f"check-{index}") for index in range(21)]
    )
    slack = SlackAPI()
    slack.fail_prefixes = ("Falcon Shield poller:",)
    assert _run(path, api, slack, announce=True) == 1
    events = _events(path)
    assert sum(event["slack_ts"] is not None for event in events) == 20
    assert events[-1]["slack_ts"] is None
    assert "delivered_by" not in events[-1]["payload"]
