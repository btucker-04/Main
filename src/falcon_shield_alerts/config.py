"""Environment configuration for a live poll."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

REQUIRED_ENV: tuple[str, ...] = (
    "FALCON_BASE_URL",
    "FALCON_CLIENT_ID",
    "FALCON_CLIENT_SECRET",
    "SLACK_BOT_TOKEN",
    "SLACK_CHANNEL_ID",
    "STATE_PATH",
)


@dataclass(frozen=True, repr=False)
class Config:
    falcon_base_url: str
    falcon_client_id: str
    falcon_client_secret: str
    slack_bot_token: str
    slack_channel_id: str
    state_path: str
    member_cid: str | None = None

    def __repr__(self) -> str:
        return (
            "Config("
            f"falcon_base_url={self.falcon_base_url!r}, "
            f"slack_channel_id={self.slack_channel_id!r}, "
            f"state_path={self.state_path!r})"
        )


def load_config(env: Mapping[str, str] | None = None) -> Config:
    """Load a live-poll config. Name every missing required variable."""

    source = os.environ if env is None else env
    missing = [name for name in REQUIRED_ENV if _blank(source.get(name))]
    if missing:
        names = ", ".join(missing)
        raise SystemExit(f"Missing required environment: {names}")
    member = source.get("FALCON_MEMBER_CID")
    return Config(
        falcon_base_url=_required(source, "FALCON_BASE_URL"),
        falcon_client_id=_required(source, "FALCON_CLIENT_ID"),
        falcon_client_secret=_required(source, "FALCON_CLIENT_SECRET"),
        slack_bot_token=_required(source, "SLACK_BOT_TOKEN"),
        slack_channel_id=_required(source, "SLACK_CHANNEL_ID"),
        state_path=_required(source, "STATE_PATH"),
        member_cid=None if _blank(member) else str(member).strip(),
    )


def _required(source: Mapping[str, str], name: str) -> str:
    value = source.get(name)
    if value is None:
        raise SystemExit(f"Missing required environment: {name}")
    return value.strip()


def _blank(value: str | None) -> bool:
    return value is None or value.strip() == ""
