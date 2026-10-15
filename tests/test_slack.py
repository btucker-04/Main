import json

import httpx

from falcon_shield_alerts.slack import (
    MAX_MESSAGE_CHARS,
    SlackClient,
    render_message,
    render_overflow,
)


def _payload(**overrides: object) -> dict:
    payload: dict = {
        "name": "MFA disabled",
        "saas_name": "GitHub",
        "integration_alias": "Prod",
        "integration_id": "int-1",
        "impact": "High",
        "affected": 3,
        "security_domain": "Identity",
        "status_since": "2026-10-01T00:00:00Z",
        "check_id": "chk-1",
        "status_reason": "no mfa",
        "remediation_plan": "Turn on MFA",
        "dismiss_reason": "",
        "user_who_dismissed": "",
        "status": "Failed",
        "entity_names": ["alice", "bob"],
        "entity_sample_unavailable": False,
    }
    payload.update(overrides)
    return payload


def test_newly_failed_message() -> None:
    text = render_message("newly_failed", _payload())
    assert text == "\n".join(
        [
            "Falcon Shield failed: MFA disabled",
            "SaaS: GitHub",
            "Integration: Prod",
            "Impact: High",
            "Affected: 3",
            "Domain: Identity",
            "Status since: 2026-10-01T00:00:00Z",
            "Check id: chk-1",
            "Reason: no mfa",
            "Remediation: Turn on MFA",
            "Entity sample: alice, bob",
        ]
    )


def test_integration_id_is_used_when_alias_is_empty() -> None:
    text = render_message(
        "newly_failed",
        _payload(integration_alias="", integration_id="int-9", status_reason="", remediation_plan=""),
    )
    assert "Integration: int-9" in text
    assert "Reason:" not in text
    assert "Remediation:" not in text


def test_remediation_cuts_at_500_characters() -> None:
    exact = render_message("newly_failed", _payload(remediation_plan="a" * 500, entity_names=None))
    assert "Remediation: " + ("a" * 500) in exact
    assert "truncated" not in exact.split("Remediation: ", 1)[1]
    longer = render_message(
        "newly_failed",
        _payload(remediation_plan=("a" * 500) + "Z", entity_names=None),
    )
    remediation = longer.split("Remediation: ", 1)[1].split("\n", 1)[0]
    assert remediation == ("a" * 500) + " truncated"
    assert "Z" not in remediation


def test_entity_sample_unavailable_is_stated() -> None:
    text = render_message(
        "newly_failed",
        _payload(entity_sample_unavailable=True, entity_names=None),
    )
    assert "Entity sample was unavailable." in text


def test_recovered_dismissed_and_left_failed_messages() -> None:
    recovered = render_message("recovered", _payload(status="Passed"))
    assert recovered == "\n".join(
        [
            "Falcon Shield recovered: MFA disabled",
            "SaaS: GitHub",
            "Integration: Prod",
            "Impact: High",
            "Check id: chk-1",
            "Was Failed, now Passed",
            "Status since: 2026-10-01T00:00:00Z",
        ]
    )
    dismissed = render_message(
        "dismissed",
        _payload(
            status="Dismissed",
            dismiss_reason="accepted risk",
            user_who_dismissed="ada@example.com",
        ),
    )
    assert dismissed == "\n".join(
        [
            "Falcon Shield dismissed: MFA disabled",
            "SaaS: GitHub",
            "Integration: Prod",
            "Check id: chk-1",
            "dismiss_reason: accepted risk",
            "user_who_dismissed: ada@example.com",
            "This check was dismissed. It is not a pass.",
        ]
    )
    left = render_message("left_failed", _payload(status="Can\u2019t Run"))
    assert left == "\n".join(
        [
            "Falcon Shield no longer failed: MFA disabled",
            "Now: Can\u2019t Run",
            "SaaS: GitHub",
            "Integration: Prod",
            "Check id: chk-1",
        ]
    )


def test_digest_caps_at_30_lines() -> None:
    checks = [
        {
            "impact": "High",
            "name": f"n{index}",
            "saas_name": "Box",
            "affected": index,
            "days_open": index,
        }
        for index in range(31)
    ]
    text = render_message("digest", {"count": 31, "checks": checks})
    lines = text.splitlines()
    assert lines[0] == "Falcon Shield still failing (31)"
    assert lines[1] == "High  n0  Box  affected 0  0 days open"
    assert lines[30] == "High  n29  Box  affected 29  29 days open"
    assert lines[31] == "and 1 more"
    assert "n30" not in text
    assert "Remediation" not in text
    exact = render_message("digest", {"count": 30, "checks": checks[:30]})
    assert "and " not in exact
    assert len(exact.splitlines()) == 31


def test_operator_message_has_status_message_and_trace() -> None:
    text = render_message(
        "operator",
        {"http_status": "403", "messages": ["not authorized"], "trace_id": "trace-9"},
    )
    assert text == "\n".join(
        [
            "Falcon Shield poller error",
            "HTTP 403",
            "not authorized",
            "trace_id: trace-9",
        ]
    )
    assert "client-secret" not in text
    assert "xoxb" not in text


def test_messages_stay_under_3000_characters() -> None:
    text = render_message("newly_failed", _payload(name="n" * 4000))
    assert len(text) <= MAX_MESSAGE_CHARS
    assert text.endswith("\ntruncated")


def test_overflow_names_the_remainder() -> None:
    text = render_overflow([("c1", {"name": "Alpha"}), ("c2", {"name": "Beta"})])
    assert text == "Falcon Shield poller: 2 more updates not sent individually: Alpha, Beta"


def test_chat_post_message_sends_plain_text() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"ok": True, "ts": "1.2", "channel": "C0123"})

    http = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        client = SlackClient(token="xoxb-test-token", http=http)
        ts = client.post_message("C0123", "Falcon Shield failed: MFA disabled")
    finally:
        http.close()
    assert ts == "1.2"
    request = captured[0]
    assert str(request.url) == "https://slack.com/api/chat.postMessage"
    assert request.headers["authorization"] == "Bearer xoxb-test-token"
    body = json.loads(request.content.decode())
    assert body == {"channel": "C0123", "text": "Falcon Shield failed: MFA disabled"}
    assert "blocks" not in body
    assert "xoxb-test-token" not in json.dumps({key: value for key, value in body.items()})
