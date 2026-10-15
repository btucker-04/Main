import os
import subprocess
import sys
from pathlib import Path

from falcon_shield_alerts.lock import file_lock

SRC = str(Path(__file__).resolve().parents[1] / "src")
CHILD = (
    "import sys\n"
    "from falcon_shield_alerts.lock import lock_is_held\n"
    "sys.exit(0 if lock_is_held(sys.argv[1]) else 1)\n"
)


def _child(path: Path) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC
    return subprocess.run(
        [sys.executable, "-c", CHILD, str(path)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def test_second_opener_sees_the_lock(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite"
    with file_lock(str(path)):
        held = _child(path)
    assert held.returncode == 0, held.stderr
    free = _child(path)
    assert free.returncode == 1, free.stderr
