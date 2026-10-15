"""Falcon Shield token, paged checks, one-id lookup, and affected sample."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from typing import Any

import httpx

logger = logging.getLogger("falcon_shield_alerts")

PAGE_LIMIT = 100
TOKEN_RENEW_SECONDS = 120
# Retry a 429 up to 3 times: wait 1s, then 2s, then 4s.
MAX_429_RETRIES = 3
BACKOFF_SECONDS = (1, 2, 4)
AFFECTED_SAMPLE_LIMIT = 5

_UNSET = object()


class FalconError(Exception):
    def __init__(
        self,
        status: str,
        messages: list[str] | None = None,
        trace_id: str | None = None,
    ) -> None:
        self.status = status
        self.messages = list(messages or [])
        self.trace_id = trace_id
        super().__init__(status)


class FalconClient:
    """Thin client. Tests pass an httpx client with a fake transport."""

    def __init__(
        self,
        *,
        base_url: str,
        client_id: str,
        client_secret: str,
        member_cid: str | None = None,
        http: httpx.Client,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._member_cid = member_cid
        self._http = http
        self._sleep = sleep
        self._clock = clock
        self._access_token: str | None = None
        self._expires_at: float | None = None
        self.envelope_property: str | None = None
        self._envelope: str | None | object = _UNSET

    def __repr__(self) -> str:
        return f"FalconClient(base_url={self._base_url!r})"

    def fetch_all_checks(self) -> list[dict[str, Any]]:
        """Page limit=100, offset by the page length, until a short or empty page."""

        offset = 0
        collected: list[dict[str, Any]] = []
        seen: set[str] = set()
        while True:
            self._ensure_token()
            page, envelope = self._checks_page(limit=PAGE_LIMIT, offset=offset)
            self._note_envelope(envelope)
            for item in page:
                check_id = str(item["id"])
                if check_id in seen:
                    raise FalconError("duplicate", [f"duplicate check id: {check_id}"])
                seen.add(check_id)
                collected.append(item)
            if len(page) < PAGE_LIMIT:
                return collected
            offset += len(page)

    def fetch_one(self, check_id: str) -> list[dict[str, Any]]:
        self._ensure_token()
        body = self._get_json(
            "/saas-security/entities/checks/v3",
            params={"id": check_id},
        )
        checks, _envelope = parse_checks_document(body)
        return checks

    def fetch_affected_names(self, check_id: str) -> tuple[list[str] | None, bool]:
        """Return (names, unavailable). A failed sample does not fail the poll."""

        try:
            self._ensure_token()
            body = self._get_json(
                "/saas-security/entities/check-affected/v3",
                params={"id": check_id, "limit": AFFECTED_SAMPLE_LIMIT, "offset": 0},
            )
            names = parse_entity_names(body)[:AFFECTED_SAMPLE_LIMIT]
        except FalconError:
            logger.info("falcon affected sample unavailable check_id=%s", check_id)
            return None, True
        return names, False

    def _ensure_token(self) -> None:
        if self._access_token is None or self._remaining() < TOKEN_RENEW_SECONDS:
            self._fetch_token()

    def _remaining(self) -> float:
        if self._expires_at is None:
            return 0
        return self._expires_at - self._clock()

    def _fetch_token(self) -> None:
        form = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        if self._member_cid:
            form["member_cid"] = self._member_cid
        response = self._send(
            "POST",
            f"{self._base_url}/oauth2/token",
            data=form,
        )
        logger.info("falcon token http_status=%s", response.status_code)
        if response.status_code not in (200, 201):
            raise _error_from_response(response)
        try:
            body = response.json()
        except json.JSONDecodeError as exc:
            raise FalconError("truncated", ["token body is not JSON"]) from exc
        if not isinstance(body, dict):
            raise FalconError("truncated", ["token body is not an object"])
        token = body.get("access_token")
        expires_in = body.get("expires_in")
        if not isinstance(token, str) or token == "":
            raise FalconError("token", ["access_token missing"])
        if isinstance(expires_in, bool) or not isinstance(expires_in, (int, float)):
            raise FalconError("token", ["expires_in missing"])
        self._access_token = token
        self._expires_at = self._clock() + float(expires_in)

    def _checks_page(
        self,
        *,
        limit: int,
        offset: int,
    ) -> tuple[list[dict[str, Any]], str | None]:
        body = self._get_json(
            "/saas-security/entities/checks/v3",
            params={"limit": limit, "offset": offset},
        )
        checks, envelope = parse_checks_document(body)
        logger.info(
            "falcon checks page http_status=200 offset=%s count=%s",
            offset,
            len(checks),
        )
        return checks, envelope

    def _get_json(self, path: str, *, params: dict[str, Any]) -> Any:
        if self._access_token is None:
            raise FalconError("token", ["access_token missing"])
        response = self._send(
            "GET",
            f"{self._base_url}{path}",
            params=params,
            headers={"Authorization": f"Bearer {self._access_token}"},
        )
        if response.status_code != 200:
            error = _error_from_response(response)
            logger.error(
                "falcon request failed http_status=%s trace_id=%s",
                error.status,
                error.trace_id or "",
            )
            raise error
        try:
            return response.json()
        except json.JSONDecodeError as exc:
            raise FalconError("truncated", ["response body is not JSON"]) from exc

    def _send(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        for attempt in range(MAX_429_RETRIES + 1):
            try:
                response = self._http.request(method, url, **kwargs)
            except httpx.RequestError as exc:
                raise FalconError("network", ["network error"]) from exc
            if response.status_code != 429:
                return response
            if attempt == MAX_429_RETRIES:
                error = _error_from_response(response)
                logger.error(
                    "falcon request failed http_status=%s trace_id=%s",
                    error.status,
                    error.trace_id or "",
                )
                raise error
            self._sleep(BACKOFF_SECONDS[attempt])
        raise FalconError("429", ["rate limited"])

    def _note_envelope(self, envelope: str | None) -> None:
        if self._envelope is _UNSET:
            self._envelope = envelope
            self.envelope_property = envelope
            label = "bare-array" if envelope is None else envelope
            logger.info("falcon checks list envelope_property=%s", label)
            return
        if envelope != self._envelope:
            raise FalconError("truncated", ["check list envelope changed"])


def parse_checks_document(body: object) -> tuple[list[dict[str, Any]], str | None]:
    """Accept a bare array, or an object with exactly one array of checks."""

    items, envelope = _extract_array(body)
    return [_parse_check(item) for item in items], envelope


def parse_entity_names(body: object) -> list[str]:
    items, _envelope = _extract_array(body)
    names: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            raise FalconError("truncated", ["affected entity is not an object"])
        name = item.get("entity_name")
        if isinstance(name, str) and name:
            names.append(name)
    return names


def _extract_array(body: object) -> tuple[list[object], str | None]:
    if isinstance(body, list):
        return body, None
    if isinstance(body, dict):
        array_keys = [key for key, value in body.items() if isinstance(value, list)]
        if len(array_keys) != 1:
            raise FalconError(
                "truncated",
                ["check list body is not a single array"],
            )
        key = array_keys[0]
        items = body[key]
        if not isinstance(items, list):
            raise FalconError("truncated", ["check list body is not a single array"])
        return items, key
    raise FalconError("truncated", ["check list body is not a JSON array"])


def _parse_check(item: object) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise FalconError("truncated", ["check is not an object"])
    check_id = item.get("id")
    status = item.get("status")
    if not isinstance(check_id, str) or check_id == "":
        raise FalconError("truncated", ["check id is missing"])
    if not isinstance(status, str) or status == "":
        raise FalconError("truncated", ["check status is missing"])
    parsed: dict[str, Any] = {"id": check_id, "status": status}
    for key in (
        "base_check_id",
        "integration_id",
        "integration_alias",
        "name",
        "saas_name",
        "impact",
        "security_domain",
        "status_reason",
        "remediation_plan",
        "dismiss_reason",
        "user_who_dismissed",
        "status_last_changed_date",
    ):
        if key not in item:
            continue
        value = item[key]
        if value is None:
            continue
        if not isinstance(value, str):
            raise FalconError("truncated", [f"{key} is not a string"])
        parsed[key] = value
    if "affected" in item and item["affected"] is not None:
        affected = item["affected"]
        if isinstance(affected, bool) or not isinstance(affected, (int, float)):
            raise FalconError("truncated", ["affected is not a number"])
        parsed["affected"] = affected
    return parsed


def _error_from_response(response: httpx.Response) -> FalconError:
    messages: list[str] = []
    trace_id: str | None = None
    try:
        body = response.json()
    except json.JSONDecodeError:
        body = None
    if isinstance(body, dict):
        errors = body.get("errors")
        if isinstance(errors, list):
            for item in errors:
                if isinstance(item, dict):
                    message = item.get("message")
                    if isinstance(message, str):
                        messages.append(message)
        meta = body.get("meta")
        if isinstance(meta, dict):
            trace = meta.get("trace_id")
            if isinstance(trace, str):
                trace_id = trace
    return FalconError(str(response.status_code), messages, trace_id)
