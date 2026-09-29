"""Backup fallback when the sqlite3 executable is unavailable."""

import os
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest

BACKUP_SH = Path(__file__).resolve().parent.parent / "scripts" / "capauth-backup.sh"


def _make_keystore(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE enrolled_keys(fpr TEXT PRIMARY KEY, pubkey TEXT)")
        db.executemany(
            "INSERT INTO enrolled_keys VALUES(?, ?)", [("AAA", "pub-aaa"), ("BBB", "pub-bbb")]
        )


@pytest.mark.skipif(shutil.which("bash") is None, reason="requires bash")
def test_backup_uses_python_online_sqlite_backup_without_cli(tmp_path: Path):
    home = tmp_path / "home"
    db = home / "service" / "keys.db"
    _make_keystore(db)
    env = dict(os.environ)
    env.update(
        {"CAPAUTH_HOME": str(home), "CAPAUTH_DATA_VOLUME": "__capauth_test_no_such_volume__"}
    )
    for key in (
        "CAPAUTH_AUTHENTIK_PG_HOST",
        "CAPAUTH_AUTHENTIK_PG_DB",
        "CAPAUTH_AUTHENTIK_PG_USER",
        "CAPAUTH_BACKUP_REMOTE",
    ):
        env.pop(key, None)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for command in (
        "bash",
        "python3",
        "mkdir",
        "chmod",
        "date",
        "hostname",
        "stat",
        "sha256sum",
        "awk",
        "grep",
        "cp",
        "find",
        "docker",
    ):
        executable = shutil.which(command)
        if executable:
            (bin_dir / command).symlink_to(executable)
    env["PATH"] = str(bin_dir)
    result = subprocess.run(["bash", str(BACKUP_SH)], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "Python SQLite online backup" in result.stdout
    saved = next((home / "backups").glob("capauth-backup-*/keys.db"))
    with sqlite3.connect(saved) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("SELECT count(*) FROM enrolled_keys").fetchone()[0] == 2
