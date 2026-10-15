# Falcon Shield alerts

Poll CrowdStrike Falcon Shield (`GET /saas-security/entities/checks/v3`), remember the last status of each check in SQLite, and post to one Slack channel when a check newly fails or leaves the failed state.

The first successful snapshot seeds the store and posts nothing. Pass `--announce-existing` to emit one message per check that is already `Failed` during that seed.

Live posting needs Falcon credentials and a Slack bot token. Until those exist, dry-run a fixture:

```bash
python -m falcon_shield_alerts --dry-run tests/fixtures/checks.json --announce-existing
```

Required environment for a live poll:

- `FALCON_BASE_URL`
- `FALCON_CLIENT_ID`
- `FALCON_CLIENT_SECRET`
- `SLACK_BOT_TOKEN`
- `SLACK_CHANNEL_ID`
- `STATE_PATH`

Optional: `FALCON_MEMBER_CID` (MSSP member lock).

`deploy/falcon-shield-alerts.timer` runs the one-shot poll every 15 minutes. Do not commit the SQLite file or secrets.

```bash
python -m pytest
```
