import json
import logging
from pathlib import Path

import httpx
import pytest

from falcon_shield_alerts.falcon import (
    PAGE_LIMIT,
    FalconClient,
    FalconError,
    parse_checks_document,
)
from tests.support import NOW_CLOCK, FalconAPI, api_check

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "checks.json"
DOCUMENTED_KEYS = {
    "account_id",
    "affected",
    "affected_impact_percentage",
    "affected_impact_total",
    "affected_impact_type",
    "base_check_id",
    "business_owners",
    "check_tags",
    "compliance_data",
    "created_by",
    "creation_date",
    "details",
    "dismiss_expiration_date",
    "dismiss_reason",
    "id",
    "impact",
    "integration_alias",
    "integration_id",
    "is_global",
    "name",
    "org_domains",
    "remediation_plan",
    "saas_name",
    "security_check_type",
    "security_domain",
    "status",
    "status_last_changed_date",
    "status_reason",
    "user_who_dismissed",
}


def _client(api: FalconAPI, sleeps: list[float] | None = None, clock: list[float] | None = None):
    http = httpx.Client(transport=httpx.MockTransport(api))
    ticks = clock if clock is not None else [NOW_CLOCK]

    def current() -> float:
        return ticks[0]

    def sleep(seconds: float) -> None:
        if sleeps is not None:
            sleeps.append(seconds)
        ticks[0] += seconds

    client = FalconClient(
        base_url="https://api.crowdstrike.com/",
        client_id="client-id",
        client_secret="client-secret",
        member_cid="member-1",
        http=http,
        sleep=sleep,
        clock=current,
    )
    return http, client


def test_parser_accepts_fixture_and_ignores_unknown_key() -> None:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert DOCUMENTED_KEYS <= set(document[0])
    assert "legacy_score" in document[0]
    checks, envelope = parse_checks_document(document)
    assert envelope is None
    assert checks[0]["id"] == "chk-failed"
    assert checks[0]["name"] == "MFA disabled"
    assert checks[0]["affected"] == 3
    assert checks[0]["remediation_plan"] == "Turn on MFA"
    assert "legacy_score" not in checks[0]
    assert "business_owners" not in checks[0]
    assert "is_global" not in checks[0]


def test_parser_accepts_one_array_property_and_rejects_other_objects() -> None:
    check = api_check("chk-1")
    checks, envelope = parse_checks_document({"resources": [check], "meta": {"trace_id": "t"}})
    assert envelope == "resources"
    assert checks[0]["id"] == "chk-1"
    with pytest.raises(FalconError) as two_arrays:
        parse_checks_document({"resources": [check], "errors": []})
    assert two_arrays.value.status == "truncated"
    with pytest.raises(FalconError):
        parse_checks_document({"meta": {"trace_id": "t"}})
    with pytest.raises(FalconError):
        parse_checks_document("nope")
    with pytest.raises(FalconError):
        parse_checks_document([{"status": "Failed"}])


def test_full_pages_then_short_page_advances_offset() -> None:
    checks = [api_check(f"id-{index}", "Passed") for index in range(PAGE_LIMIT * 2 + 1)]
    api = FalconAPI(checks)
    http, client = _client(api)
    try:
        loaded = client.fetch_all_checks()
    finally:
        http.close()
    assert [item["id"] for item in loaded] == [item["id"] for item in checks]
    check_calls = [
        request
        for request in api.calls
        if request.url.path.endswith("/checks/v3")
    ]
    assert [int(request.url.params["offset"]) for request in check_calls] == [0, 100, 200]
    assert [int(request.url.params["limit"]) for request in check_calls] == [100, 100, 100]
    for request in check_calls:
        assert "status" not in request.url.params


def test_empty_page_stops_the_walk() -> None:
    checks = [api_check(f"id-{index}", "Passed") for index in range(PAGE_LIMIT)]
    api = FalconAPI(checks)
    http, client = _client(api)
    try:
        loaded = client.fetch_all_checks()
    finally:
        http.close()
    assert len(loaded) == PAGE_LIMIT
    offsets = [
        int(request.url.params["offset"])
        for request in api.calls
        if request.url.path.endswith("/checks/v3")
    ]
    assert offsets == [0, 100]


def test_duplicate_id_aborts_the_cycle() -> None:
    api = FalconAPI([api_check("same"), api_check("same")])
    http, client = _client(api)
    try:
        with pytest.raises(FalconError) as caught:
            client.fetch_all_checks()
    finally:
        http.close()
    assert caught.value.status == "duplicate"
    assert "same" in caught.value.messages[0]


def test_429_then_success_uses_backoff() -> None:
    sleeps: list[float] = []
    api = FalconAPI([api_check("chk-1", "Passed")])
    api.checks_script = [
        httpx.Response(429, json={"errors": [{"message": "slow down"}], "meta": {"trace_id": "tr"}})
    ]
    http, client = _client(api, sleeps)
    try:
        loaded = client.fetch_all_checks()
    finally:
        http.close()
    assert [item["id"] for item in loaded] == ["chk-1"]
    assert sleeps == [1]


def test_429_retries_then_aborts() -> None:
    sleeps: list[float] = []
    api = FalconAPI([api_check("chk-1")])
    api.force_checks_status = 429
    api.error_body = {"errors": [{"message": "slow down"}], "meta": {"trace_id": "tr-429"}}
    http, client = _client(api, sleeps)
    try:
        with pytest.raises(FalconError) as caught:
            client.fetch_all_checks()
    finally:
        http.close()
    assert caught.value.status == "429"
    assert caught.value.trace_id == "tr-429"
    assert sleeps == [1, 2, 4]
    check_calls = [request for request in api.calls if request.url.path.endswith("/checks/v3")]
    assert len(check_calls) == 4


def test_token_is_form_encoded_and_refreshed_inside_the_window() -> None:
    sleeps: list[float] = []
    checks = [api_check(f"id-{index}", "Passed") for index in range(PAGE_LIMIT + 1)]
    api = FalconAPI(checks)
    api.token_expires_in = 119
    http, client = _client(api, sleeps)
    try:
        client.fetch_all_checks()
    finally:
        http.close()
    token_calls = [request for request in api.calls if request.url.path == "/oauth2/token"]
    assert len(token_calls) == 2
    body = token_calls[0].content.decode()
    assert "client_id=client-id" in body
    assert "client_secret=client-secret" in body
    assert "member_cid=member-1" in body
    assert token_calls[0].headers["content-type"].startswith("application/x-www-form-urlencoded")
    assert "client-secret" not in str(token_calls[0].url)


def test_token_at_the_renew_floor_is_reused(caplog: pytest.LogCaptureFixture) -> None:
    checks = [api_check(f"id-{index}", "Passed") for index in range(PAGE_LIMIT + 1)]
    api = FalconAPI(checks)
    api.token_expires_in = 120
    http, client = _client(api)
    with caplog.at_level(logging.DEBUG):
        try:
            client.fetch_all_checks()
        finally:
            http.close()
    token_calls = [request for request in api.calls if request.url.path == "/oauth2/token"]
    assert len(token_calls) == 1
    assert "client-secret" not in caplog.text
    assert "token-abc" not in caplog.text
    assert client.envelope_property is None


def test_envelope_property_is_recorded() -> None:
    api = FalconAPI()
    api.checks_script = [
        httpx.Response(200, json={"resources": [api_check("chk-1", "Passed")], "meta": {}})
    ]
    http, client = _client(api)
    try:
        loaded = client.fetch_all_checks()
    finally:
        http.close()
    assert [item["id"] for item in loaded] == ["chk-1"]
    assert client.envelope_property == "resources"


def test_affected_sample_caps_names_and_failure_is_unavailable() -> None:
    api = FalconAPI()
    names = [{"entity_name": f"user-{index}"} for index in range(6)]
    api.affected["chk-1"] = (200, names)
    api.affected["chk-2"] = (500, {"errors": [{"message": "boom"}], "meta": {"trace_id": "tr"}})
    http, client = _client(api)
    try:
        client.fetch_all_checks()
        sample, unavailable = client.fetch_affected_names("chk-1")
        failed, failed_flag = client.fetch_affected_names("chk-2")
    finally:
        http.close()
    assert sample == ["user-0", "user-1", "user-2", "user-3", "user-4"]
    assert unavailable is False
    assert failed is None
    assert failed_flag is True
    affected_call = next(
        request for request in api.calls if request.url.path.endswith("/check-affected/v3")
    )
    assert affected_call.url.params["limit"] == "5"
    assert affected_call.url.params["id"] == "chk-1"
