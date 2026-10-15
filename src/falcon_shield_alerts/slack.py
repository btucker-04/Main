"""Slack text for each event kind, and chat.postMessage."""

from __future__ import annotations

import json
from typing import Any, Never

import httpx

from falcon_shield_alerts.diff import EventKind

SLACK_POST_URL = "https://slack.com/api/chat.postMessage"
MAX_MESSAGE_CHARS = 3000
REMEDIATION_LIMIT = 500
DIGEST_LINE_LIMIT = 30
MAX_TRANSITION_POSTS = 20
TRANSITION_KINDS = frozenset({"newly_failed", "recovered", "dismissed", "left_failed"})


class SlackError(Exception):
    def __init__(self, error: str) -> None:
        self.error = error
        super().__init__(error)


class SlackClient:
    def __init__(self, *, token: str, http: httpx.Client) -> None:
        self._token = token
        self._http = http

    def __repr__(self) -> str:
        return "SlackClient()"

    def post_message(self, channel: str, text: str) -> str:
        text = clamp_message(text)
        try:
            response = self._http.post(
                SLACK_POST_URL,
                headers={"Authorization": f"Bearer {self._token}"},
                json={"channel": channel, "text": text},
            )
        except httpx.RequestError as exc:
            raise SlackError("network") from exc
        try:
            body = response.json()
        except json.JSONDecodeError as exc:
            raise SlackError("not_json") from exc
        if response.status_code != 200 or not isinstance(body, dict) or body.get("ok") is not True:
            error = "http_error"
            if isinstance(body, dict) and isinstance(body.get("error"), str):
                error = body["error"]
            raise SlackError(error)
        ts = body.get("ts")
        if not isinstance(ts, str) or ts == "":
            raise SlackError("missing_ts")
        return ts


def render_message(kind: EventKind, payload: dict[str, Any]) -> str:
    if kind == "newly_failed":
        text = _newly_failed(payload)
    elif kind == "recovered":
        text = _recovered(payload)
    elif kind == "dismissed":
        text = _dismissed(payload)
    elif kind == "left_failed":
        text = _left_failed(payload)
    elif kind == "digest":
        text = _digest(payload)
    elif kind == "operator":
        text = _operator(payload)
    else:
        _exhaustive: Never = kind
        raise RuntimeError(_exhaustive)
    return clamp_message(text)


def render_overflow(events: list[tuple[str, dict[str, Any]]]) -> str:
    names = [_name(payload, check_id) for check_id, payload in events]
    count = len(events)
    text = (
        "Falcon Shield poller: "
        f"{count} more updates not sent individually: "
        + ", ".join(names)
    )
    return clamp_message(text)


def clamp_message(text: str) -> str:
    if len(text) <= MAX_MESSAGE_CHARS:
        return text
    suffix = "\ntruncated"
    return text[: MAX_MESSAGE_CHARS - len(suffix)] + suffix


def _newly_failed(payload: dict[str, Any]) -> str:
    lines = [
        f"Falcon Shield failed: {_text(payload, 'name')}",
        f"SaaS: {_text(payload, 'saas_name')}",
        f"Integration: {_integration(payload)}",
        f"Impact: {_text(payload, 'impact')}",
        f"Affected: {_affected(payload.get('affected'))}",
        f"Domain: {_text(payload, 'security_domain')}",
        f"Status since: {_text(payload, 'status_since')}",
        f"Check id: {_text(payload, 'check_id')}",
    ]
    reason = _text(payload, "status_reason")
    if reason:
        lines.append(f"Reason: {reason}")
    remediation = _remediation(_text(payload, "remediation_plan"))
    if remediation:
        lines.append(f"Remediation: {remediation}")
    sample = _entity_sample(payload)
    if sample is not None:
        lines.append(sample)
    return "\n".join(lines)


def _recovered(payload: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"Falcon Shield recovered: {_text(payload, 'name')}",
            f"SaaS: {_text(payload, 'saas_name')}",
            f"Integration: {_integration(payload)}",
            f"Impact: {_text(payload, 'impact')}",
            f"Check id: {_text(payload, 'check_id')}",
            "Was Failed, now Passed",
            f"Status since: {_text(payload, 'status_since')}",
        ]
    )


def _dismissed(payload: dict[str, Any]) -> str:
    lines = [
        f"Falcon Shield dismissed: {_text(payload, 'name')}",
        f"SaaS: {_text(payload, 'saas_name')}",
        f"Integration: {_integration(payload)}",
        f"Check id: {_text(payload, 'check_id')}",
    ]
    reason = _text(payload, "dismiss_reason")
    if reason:
        lines.append(f"dismiss_reason: {reason}")
    user = _text(payload, "user_who_dismissed")
    if user:
        lines.append(f"user_who_dismissed: {user}")
    lines.append("This check was dismissed. It is not a pass.")
    return "\n".join(lines)


def _left_failed(payload: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"Falcon Shield no longer failed: {_text(payload, 'name')}",
            f"Now: {_text(payload, 'status')}",
            f"SaaS: {_text(payload, 'saas_name')}",
            f"Integration: {_integration(payload)}",
            f"Check id: {_text(payload, 'check_id')}",
        ]
    )


def _digest(payload: dict[str, Any]) -> str:
    checks = payload.get("checks")
    rows = checks if isinstance(checks, list) else []
    count = payload.get("count")
    total = count if isinstance(count, int) else len(rows)
    lines = [f"Falcon Shield still failing ({total})"]
    shown = rows[:DIGEST_LINE_LIMIT]
    for item in shown:
        if not isinstance(item, dict):
            continue
        lines.append(
            f"{_text(item, 'impact')}  {_text(item, 'name')}  {_text(item, 'saas_name')}  "
            f"affected {_affected(item.get('affected'))}  {item.get('days_open', 0)} days open"
        )
    extra = total - len(shown)
    if extra > 0:
        lines.append(f"and {extra} more")
    return "\n".join(lines)


def _operator(payload: dict[str, Any]) -> str:
    lines = [
        "Falcon Shield poller error",
        f"HTTP {_text(payload, 'http_status')}",
    ]
    messages = payload.get("messages")
    if isinstance(messages, list):
        for message in messages:
            if isinstance(message, str) and message:
                lines.append(message)
    trace_id = payload.get("trace_id")
    if isinstance(trace_id, str) and trace_id:
        lines.append(f"trace_id: {trace_id}")
    return "\n".join(lines)


def _remediation(plan: str) -> str:
    if not plan:
        return ""
    if len(plan) > REMEDIATION_LIMIT:
        return plan[:REMEDIATION_LIMIT] + " truncated"
    return plan


def _entity_sample(payload: dict[str, Any]) -> str | None:
    if payload.get("entity_sample_unavailable") is True:
        return "Entity sample was unavailable."
    names = payload.get("entity_names")
    if names is None:
        return None
    if not isinstance(names, list) or not names:
        return "Entity sample: none"
    shown = [name for name in names if isinstance(name, str) and name][:5]
    if not shown:
        return "Entity sample: none"
    return "Entity sample: " + ", ".join(shown)


def _integration(payload: dict[str, Any]) -> str:
    alias = _text(payload, "integration_alias")
    if alias:
        return alias
    return _text(payload, "integration_id")


def _affected(value: object) -> str:
    if value is None or isinstance(value, bool):
        return ""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    if isinstance(value, (int, float)):
        return str(value)
    return ""


def _text(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if isinstance(value, str):
        return value
    return ""


def _name(payload: dict[str, Any], check_id: str) -> str:
    name = _text(payload, "name")
    return name or check_id
