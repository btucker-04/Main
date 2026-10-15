import pytest

from falcon_shield_alerts.config import REQUIRED_ENV, load_config


def test_missing_env_names_every_absent_variable() -> None:
    with pytest.raises(SystemExit) as caught:
        load_config({})
    message = str(caught.value)
    assert message.startswith("Missing required environment:")
    for name in REQUIRED_ENV:
        assert name in message


def test_missing_env_names_only_the_blank_ones() -> None:
    env = {name: "set" for name in REQUIRED_ENV}
    env["SLACK_BOT_TOKEN"] = "  "
    env["STATE_PATH"] = ""
    with pytest.raises(SystemExit) as caught:
        load_config(env)
    message = str(caught.value)
    assert "SLACK_BOT_TOKEN" in message
    assert "STATE_PATH" in message
    assert "FALCON_CLIENT_ID" not in message.split(": ", 1)[1]


def test_load_config_reads_required_values_and_optional_member() -> None:
    env = {name: f" {name.lower()} " for name in REQUIRED_ENV}
    env["FALCON_MEMBER_CID"] = " cid "
    config = load_config(env)
    assert config.falcon_base_url == "falcon_base_url"
    assert config.falcon_client_secret == "falcon_client_secret"
    assert config.member_cid == "cid"
    assert "falcon_client_secret" not in repr(config)
    assert "slack_bot_token" not in repr(config)
