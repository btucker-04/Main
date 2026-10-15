from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_timer_runs_every_15_minutes() -> None:
    timer = (ROOT / "deploy" / "falcon-shield-alerts.timer").read_text(encoding="utf-8")
    service = (ROOT / "deploy" / "falcon-shield-alerts.service").read_text(encoding="utf-8")
    assert "OnUnitActiveSec=15min" in timer
    assert "falcon_shield_alerts" in service
    assert "xoxb-" not in service
    assert "client_secret" not in service
