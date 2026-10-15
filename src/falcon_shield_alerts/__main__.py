"""One-shot Falcon Shield poll, or a fixture dry-run that does not post."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx

from falcon_shield_alerts.config import load_config
from falcon_shield_alerts.diff import diff_snapshot, snapshot_from_api
from falcon_shield_alerts.falcon import FalconClient, FalconError, parse_checks_document
from falcon_shield_alerts.poll import run_poll
from falcon_shield_alerts.slack import SlackClient, render_message


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    parser = argparse.ArgumentParser(prog="falcon_shield_alerts")
    parser.add_argument(
        "--dry-run",
        metavar="FIXTURE",
        help="Read a check-list fixture, print messages, and do not post to Slack",
    )
    parser.add_argument(
        "--announce-existing",
        action="store_true",
        help="During the initial seed, emit one newly_failed event per Failed check",
    )
    args = parser.parse_args(argv)
    if args.dry_run:
        return dry_run(args.dry_run, announce_existing=args.announce_existing)
    config = load_config()
    with httpx.Client(timeout=30.0) as http:
        client = FalconClient(
            base_url=config.falcon_base_url,
            client_id=config.falcon_client_id,
            client_secret=config.falcon_client_secret,
            member_cid=config.member_cid,
            http=http,
        )
        slack = SlackClient(token=config.slack_bot_token, http=http)
        return run_poll(
            config,
            announce_existing=args.announce_existing,
            client=client,
            slack=slack,
        )


def dry_run(path: str, *, announce_existing: bool) -> int:
    """Print transition messages for a fixture. Write nothing to Slack or SQLite."""

    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        checks, _envelope = parse_checks_document(document)
        snapshots = [snapshot_from_api(item) for item in checks]
    except (OSError, json.JSONDecodeError, FalconError) as exc:
        print(f"fixture rejected: {exc}", file=sys.stderr)
        return 2
    result = diff_snapshot(
        {},
        snapshots,
        seeded=False,
        announce_existing=announce_existing,
        now=datetime.now(timezone.utc),
    )
    for event in result.events:
        sys.stdout.write(render_message(event.kind, event.payload))
        sys.stdout.write("\n\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
