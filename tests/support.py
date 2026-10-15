"""Shared fixtures for poller tests. No live Falcon or Slack calls."""

from __future__ import annotations

import json
from typing import Any

import httpx

from falcon_shield_alerts.config import Config
from falcon_shield_alerts.diff import CheckSnapshot, StoredCheck
from falcon_shield_alerts.falcon import FalconClient
from falcon_shield_alerts.slack import SlackClient

NOW_CLOCK = 1_700_000_000.0


def config_for(path: str) -> Config:
    return Config(
        falcon_base_url="https://api.crowdstrike.com",
        falcon_client_id="client-id",
        falcon_client_secret="client-secret",
        slack_bot_token="xoxb-test-token",
        slack_channel_id="C0123",
        state_path=path,
    )


def api_check(
    check_id: str,
    status: str = "Failed",
    *,
    name: str | None = None,
    affected: int = 3,
    changed: str | None = "2026-10-01",
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "id": check_id,
        "status": status,
        "name": name or check_id,
        "saas_name": "GitHub",
        "integration_alias": "Prod",
        "integration_id": "int-1",
        "impact": "High",
        "affected": affected,
        "security_domain": "Identity",
        "base_check_id": "base-1",
        "status_reason": "because",
        "remediation_plan": "Fix it",
    }
    if changed is not None:
        body["status_last_changed_date"] = changed
    return body


def snapshot(
    check_id: str = "chk-1",
    status: str = "Failed",
    **overrides: Any,
) -> CheckSnapshot:
    values: dict[str, Any] = {
        "id": check_id,
        "status": status,
        "name": "MFA disabled",
        "saas_name": "GitHub",
        "integration_alias": "Prod",
        "integration_id": "int-1",
        "impact": "High",
        "affected": 3,
        "security_domain": "Identity",
        "status_last_changed_date": "2026-10-01",
        "status_reason": "no mfa",
        "remediation_plan": "Turn on MFA",
        "base_check_id": "base-1",
    }
    values.update(overrides)
    return CheckSnapshot(**values)


def remembered(
    check_id: str = "chk-1",
    status: str = "Passed",
    **overrides: Any,
) -> StoredCheck:
    values: dict[str, Any] = {
        "check_id": check_id,
        "status": status,
        "base_check_id": "base-1",
        "integration_id": "int-1",
        "integration_alias": "Prod",
        "name": "MFA disabled",
        "saas_name": "GitHub",
        "impact": "High",
        "affected": 1,
        "security_domain": "Identity",
        "status_last_changed_date": "2026-09-01",
        "status_reason": "",
        "first_seen_at": "2026-10-01T00:00:00Z",
        "last_seen_at": "2026-10-01T00:00:00Z",
    }
    values.update(overrides)
    return StoredCheck(**values)


class FalconAPI:
    """Fake CrowdStrike transport. Records calls and serves fixture pages."""

    def __init__(self, checks: list[dict[str, Any]] | None = None) -> None:
        self.checks = list(checks or [])
        self.calls: list[httpx.Request] = []
        self.force_checks_status: int | None = None
        self.error_body: dict[str, Any] = {
            "errors": [{"code": 403, "id": "e1", "message": "not authorized"}],
            "meta": {"trace_id": "trace-9", "pagination": {"limit": 0, "offset": 0, "total": 0}},
        }
        self.lookups: dict[str, tuple[int, Any]] = {}
        self.affected: dict[str, tuple[int, Any]] = {}
        self.token_expires_in: int | float = 1800
        self.token_status: int = 201
        self.checks_script: list[httpx.Response | None] = []
        self.network_error = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        path = request.url.path
        if path == "/oauth2/token":
            if self.token_status != 201:
                return httpx.Response(self.token_status, json=self.error_body)
            return httpx.Response(
                201,
                json={
                    "access_token": "token-abc",
                    "expires_in": self.token_expires_in,
                    "token_type": "bearer",
                },
            )
        if path == "/saas-security/entities/checks/v3":
            if self.network_error:
                raise httpx.ConnectError("network down")
            return self._checks(request)
        if path == "/saas-security/entities/check-affected/v3":
            check_id = request.url.params["id"]
            status, body = self.affected.get(check_id, (200, []))
            return httpx.Response(status, json=body)
        return httpx.Response(404, json={"errors": [{"message": "unexpected path"}]})

    def _checks(self, request: httpx.Request) -> httpx.Response:
        if self.checks_script:
            scripted = self.checks_script.pop(0)
            if scripted is not None:
                return scripted
        if self.force_checks_status is not None:
            return httpx.Response(self.force_checks_status, json=self.error_body)
        if "id" in request.url.params:
            check_id = request.url.params["id"]
            if check_id in self.lookups:
                status, body = self.lookups[check_id]
                return httpx.Response(status, json=body)
            matched = [item for item in self.checks if item.get("id") == check_id]
            return httpx.Response(200, json=matched)
        offset = int(request.url.params.get("offset", "0"))
        limit = int(request.url.params.get("limit", "100"))
        return httpx.Response(200, json=self.checks[offset : offset + limit])

    def paths(self) -> list[str]:
        return [request.url.path for request in self.calls]


class SlackAPI:
    def __init__(self) -> None:
        self.posts: list[dict[str, Any]] = []
        self.fail_prefixes: tuple[str, ...] = ()
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        body = json.loads(request.content.decode())
        self.posts.append(body)
        text = body.get("text", "")
        if any(text.startswith(prefix) for prefix in self.fail_prefixes):
            return httpx.Response(200, json={"ok": False, "error": "channel_not_found"})
        return httpx.Response(200, json={"ok": True, "ts": f"{len(self.posts)}.000", "channel": body.get("channel")})


def falcon_client(api: FalconAPI, *, sleep: Any = None, clock: Any = None) -> tuple[httpx.Client, FalconClient]:
    http = httpx.Client(transport=httpx.MockTransport(api))
    client = FalconClient(
        base_url="https://api.crowdstrike.com",
        client_id="client-id",
        client_secret="client-secret",
        http=http,
        sleep=sleep or (lambda _seconds: None),
        clock=clock or (lambda: NOW_CLOCK),
    )
    return http, client


def slack_client(api: SlackAPI) -> tuple[httpx.Client, SlackClient]:
    http = httpx.Client(transport=httpx.MockTransport(api))
    return http, SlackClient(token="xoxb-test-token", http=http)
