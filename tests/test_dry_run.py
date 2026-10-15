from pathlib import Path

import httpx

from falcon_shield_alerts.__main__ import main

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "checks.json"


def test_dry_run_is_silent_without_announce(capsys) -> None:
    code = main(["--dry-run", str(FIXTURE)])
    captured = capsys.readouterr()
    assert code == 0
    assert captured.out == ""
    assert "Falcon Shield failed:" not in captured.out


def test_dry_run_prints_failed_checks_and_does_not_post(capsys, monkeypatch, tmp_path) -> None:
    def explode(*_args, **_kwargs):
        raise AssertionError("HTTP client should not be created")

    monkeypatch.setattr(httpx, "Client", explode)
    monkeypatch.setenv("STATE_PATH", str(tmp_path / "should-not-exist.sqlite"))
    code = main(["--dry-run", str(FIXTURE), "--announce-existing"])
    captured = capsys.readouterr()
    assert code == 0
    assert "Falcon Shield failed: MFA disabled" in captured.out
    assert "SSO enabled" not in captured.out
    assert "Was Failed, now Passed" not in captured.out
    assert not (tmp_path / "should-not-exist.sqlite").exists()


def test_startup_names_missing_environment(capsys, monkeypatch) -> None:
    for name in (
        "FALCON_BASE_URL",
        "FALCON_CLIENT_ID",
        "FALCON_CLIENT_SECRET",
        "SLACK_BOT_TOKEN",
        "SLACK_CHANNEL_ID",
        "STATE_PATH",
    ):
        monkeypatch.delenv(name, raising=False)
    try:
        main([])
        raised = False
    except SystemExit as exc:
        raised = True
        assert "FALCON_BASE_URL" in str(exc)
        assert "SLACK_BOT_TOKEN" in str(exc)
    assert raised
