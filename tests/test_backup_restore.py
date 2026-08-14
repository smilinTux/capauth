"""Tests for the capauth identity-state backup + restore tooling.

Exercises scripts/capauth-backup.sh and scripts/capauth-restore.sh end to end
against a SCRATCH capauth home (never live identity state). Covers:

- a full backup -> wipe -> restore round-trip for the keystore (keys.db) and the
  bunker pairing store (bunker_sessions.json), asserting data survives;
- the MANIFEST (sha256 + sizes, no secrets) the restore verifies against;
- argument handling (--dry-run touches nothing, --latest, bad/missing args);
- the confirm gate (refuses to overwrite without --yes when non-interactive);
- fail-closed integrity: a tampered artifact aborts the restore before writing.

These drive the shell scripts via subprocess; no live docker volume / Postgres is
touched (the keystore host-path leg and the file-copy bunker leg are fully
exercisable offline; the pg leg is config-gated and left inert here).
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKUP_SH = REPO_ROOT / "scripts" / "capauth-backup.sh"
RESTORE_SH = REPO_ROOT / "scripts" / "capauth-restore.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("sqlite3") is None or shutil.which("bash") is None,
    reason="requires bash + sqlite3 on PATH",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _make_keystore(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("CREATE TABLE enrolled_keys(fpr TEXT PRIMARY KEY, pubkey TEXT)")
        conn.executemany(
            "INSERT INTO enrolled_keys VALUES(?, ?)",
            [("AAA", "pub-aaa"), ("BBB", "pub-bbb")],
        )
        conn.commit()
    finally:
        conn.close()


BUNKER_JSON = (
    '{"version":1,"sessions":[{"session_id":"s1","pairing_secret":"tok1",'
    '"ttl_seconds":600,"created_at":1.0,"seen_ids":["a","b"]}]}'
)


@pytest.fixture
def scratch(tmp_path: Path):
    """A throwaway capauth home + backup root, wired via env for the scripts."""
    home = tmp_path / "home"
    (home / "service").mkdir(parents=True)
    backups = tmp_path / "backups"
    backups.mkdir()

    keystore = home / "service" / "keys.db"
    bunker = home / "service" / "bunker_sessions.json"
    _make_keystore(keystore)
    bunker.write_text(BUNKER_JSON)

    env = dict(os.environ)
    env.update(
        {
            "CAPAUTH_HOME": str(home),
            "CAPAUTH_BACKUP_DIR": str(backups),
            # A name that cannot match a real docker volume, so the host-path leg
            # is the only keystore source and tests never touch docker.
            "CAPAUTH_DATA_VOLUME": "__capauth_test_no_such_volume__",
        }
    )
    # Ensure the pg leg stays inert.
    for k in (
        "CAPAUTH_AUTHENTIK_PG_HOST",
        "CAPAUTH_AUTHENTIK_PG_DB",
        "CAPAUTH_AUTHENTIK_PG_USER",
        "CAPAUTH_BACKUP_REMOTE",
    ):
        env.pop(k, None)

    return {
        "dir": tmp_path,
        "home": home,
        "backups": backups,
        "keystore": keystore,
        "bunker": bunker,
        "env": env,
    }


def _run(script: Path, args, env, input_text=None):
    return subprocess.run(
        ["bash", str(script), *args],
        env=env,
        input=input_text,
        capture_output=True,
        text=True,
    )


def _latest_backup(backups: Path) -> Path:
    dirs = sorted(backups.glob("capauth-backup-*"))
    assert dirs, "no backup dir was produced"
    return dirs[-1]


# ── backup ────────────────────────────────────────────────────────────────────


def test_backup_produces_manifest_and_artifacts(scratch):
    r = _run(BACKUP_SH, [], scratch["env"])
    assert r.returncode == 0, r.stderr
    dest = _latest_backup(scratch["backups"])

    assert (dest / "keys.db").is_file()
    assert (dest / "bunker_sessions.json").is_file()

    manifest = (dest / "MANIFEST.txt").read_text()
    assert "keys.db:" in manifest and "sha256=" in manifest
    assert "bunker_sessions.json:" in manifest
    # Manifest records the real sha256 of the copied bunker store.
    assert _sha256(dest / "bunker_sessions.json") in manifest
    # Never leaks secret-looking material: no pairing token value in the manifest.
    assert "tok1" not in manifest


def test_backup_dry_run_writes_nothing(scratch):
    r = _run(BACKUP_SH, ["--dry-run"], scratch["env"])
    assert r.returncode == 0, r.stderr
    assert list(scratch["backups"].glob("capauth-backup-*")) == []


def test_backup_bunker_disabled_skips_leg(scratch):
    env = dict(scratch["env"])
    env["CAPAUTH_BUNKER_STORE"] = ""  # explicit disable
    r = _run(BACKUP_SH, [], env)
    assert r.returncode == 0, r.stderr
    dest = _latest_backup(scratch["backups"])
    assert (dest / "keys.db").is_file()
    assert not (dest / "bunker_sessions.json").exists()


def test_backup_empty_source_exits_3(scratch):
    # No keystore, no bunker, no pg -> nothing to back up -> guard exit 3.
    scratch["keystore"].unlink()
    scratch["bunker"].unlink()
    r = _run(BACKUP_SH, [], scratch["env"])
    assert r.returncode == 3, (r.stdout, r.stderr)


# ── restore round-trip ────────────────────────────────────────────────────────


def test_full_round_trip_yes(scratch):
    ks_rows_before = ("AAA=pub-aaa", "BBB=pub-bbb")
    bunker_sha_before = _sha256(scratch["bunker"])

    assert _run(BACKUP_SH, [], scratch["env"]).returncode == 0
    dest = _latest_backup(scratch["backups"])

    # Wipe live state.
    scratch["keystore"].unlink()
    scratch["bunker"].unlink()

    r = _run(RESTORE_SH, [str(dest), "--yes"], scratch["env"])
    assert r.returncode == 0, r.stderr

    # Bunker store came back byte-identical.
    assert scratch["bunker"].is_file()
    assert _sha256(scratch["bunker"]) == bunker_sha_before

    # Keystore data survived.
    conn = sqlite3.connect(str(scratch["keystore"]))
    try:
        rows = tuple(
            f"{f}={p}"
            for f, p in conn.execute("SELECT fpr, pubkey FROM enrolled_keys ORDER BY fpr")
        )
    finally:
        conn.close()
    assert rows == ks_rows_before


def test_restore_preserves_existing_before_overwrite(scratch):
    assert _run(BACKUP_SH, [], scratch["env"]).returncode == 0
    dest = _latest_backup(scratch["backups"])
    # Live bunker differs from the backup; restore must set it aside first.
    scratch["bunker"].write_text('{"version":1,"sessions":[]}')

    r = _run(RESTORE_SH, [str(dest), "--yes"], scratch["env"])
    assert r.returncode == 0, r.stderr

    aside = list(scratch["bunker"].parent.glob("bunker_sessions.json.pre-restore-*"))
    assert aside, "existing store should be preserved before overwrite"
    assert _sha256(scratch["bunker"]) == _sha256(dest / "bunker_sessions.json")


def test_restore_latest(scratch):
    assert _run(BACKUP_SH, [], scratch["env"]).returncode == 0
    scratch["bunker"].unlink()
    r = _run(RESTORE_SH, ["--latest", "--yes"], scratch["env"])
    assert r.returncode == 0, r.stderr
    assert scratch["bunker"].is_file()


# ── restore gating / arg handling ─────────────────────────────────────────────


def test_restore_dry_run_touches_nothing(scratch):
    assert _run(BACKUP_SH, [], scratch["env"]).returncode == 0
    dest = _latest_backup(scratch["backups"])
    sha_before = _sha256(scratch["bunker"])
    # Corrupt live state so we can prove dry-run does not restore it.
    scratch["bunker"].write_text("LIVE-UNCHANGED")

    r = _run(RESTORE_SH, [str(dest), "--dry-run"], scratch["env"])
    assert r.returncode == 0, r.stderr
    assert scratch["bunker"].read_text() == "LIVE-UNCHANGED"
    assert _sha256(scratch["bunker"]) != sha_before  # unchanged from our edit


def test_restore_refuses_without_confirmation(scratch):
    # Non-interactive (empty stdin), no --yes -> must refuse, non-zero, no write.
    assert _run(BACKUP_SH, [], scratch["env"]).returncode == 0
    dest = _latest_backup(scratch["backups"])
    scratch["bunker"].write_text("LIVE")

    r = _run(RESTORE_SH, [str(dest)], scratch["env"], input_text="")
    assert r.returncode != 0
    assert "confirmation" in (r.stdout + r.stderr).lower()
    assert scratch["bunker"].read_text() == "LIVE"  # untouched


def test_restore_missing_dir_errors(scratch):
    r = _run(RESTORE_SH, [str(scratch["dir"] / "nope"), "--yes"], scratch["env"])
    assert r.returncode != 0
    assert "not a directory" in (r.stdout + r.stderr).lower()


def test_restore_no_manifest_errors(scratch):
    bogus = scratch["dir"] / "bogus"
    bogus.mkdir()
    r = _run(RESTORE_SH, [str(bogus), "--yes"], scratch["env"])
    assert r.returncode != 0
    assert "manifest" in (r.stdout + r.stderr).lower()


def test_restore_unknown_flag_errors(scratch):
    r = _run(RESTORE_SH, ["--bogus"], scratch["env"])
    assert r.returncode != 0
    assert "unknown option" in (r.stdout + r.stderr).lower()


def test_restore_fail_closed_on_tamper(scratch):
    # A tampered artifact must abort BEFORE any live state is written.
    assert _run(BACKUP_SH, [], scratch["env"]).returncode == 0
    dest = _latest_backup(scratch["backups"])
    scratch["bunker"].write_text("LIVE-INTACT")
    # Corrupt the backed-up artifact so its sha no longer matches the manifest.
    (dest / "bunker_sessions.json").write_text('{"tampered":true}')

    r = _run(RESTORE_SH, [str(dest), "--yes"], scratch["env"])
    assert r.returncode != 0
    assert "mismatch" in (r.stdout + r.stderr).lower()
    # Live state was NOT overwritten (fail-closed before apply).
    assert scratch["bunker"].read_text() == "LIVE-INTACT"


def test_restore_include_pg_without_config_errors(scratch):
    # Craft an artifact that contains an authentik dump but no PG config set.
    assert _run(BACKUP_SH, [], scratch["env"]).returncode == 0
    dest = _latest_backup(scratch["backups"])
    dump = dest / "authentik-testdb.sql.gz"
    import gzip

    payload = b"-- fake dump\n"
    dump.write_bytes(gzip.compress(payload))
    # Record its sha in the manifest so integrity verify passes and we reach the
    # config check (which must fail, since no PG host/db/user is configured).
    sha = hashlib.sha256(dump.read_bytes()).hexdigest()
    with (dest / "MANIFEST.txt").open("a") as fh:
        fh.write(
            f"authentik-testdb.sql.gz: source=pg://x bytes={dump.stat().st_size} sha256={sha}\n"
        )

    r = _run(RESTORE_SH, [str(dest), "--include-pg", "--yes"], scratch["env"])
    assert r.returncode != 0
    assert (
        "pg_host" in (r.stdout + r.stderr).lower() or "configured" in (r.stdout + r.stderr).lower()
    )


# ── home resolution + public-key coverage (noroc2027, 2026-08-14) ─────────────
#
# Two gaps found by running this script for real on a live node:
#
# 1. It defaulted CAPAUTH_HOME_DIR to the LEGACY ~/.capauth while the live home
#    is ~/.skcapstone/capauth (which is what capauth.resolve_capauth_home()
#    prefers). The run "succeeded" with rc=0 and backed up NOTHING, warning
#    about a keystore that was simply somewhere else. A backup that silently
#    covers nothing is worse than no backup: doctor's backups_configured check
#    would have gone green on an empty directory.
#
# 2. `capauth doctor` asks for identity/public.asc inside the backup set so
#    restorability can actually be proven (backup_restorable). The script never
#    copied it. Public key material is safe to back up; the script's refusal to
#    copy PRIVATE material is the invariant that matters and is untouched here.


def _run_backup(env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(BACKUP_SH)], env=env, capture_output=True, text=True, timeout=120
    )


def test_default_home_prefers_the_skcapstone_home_over_legacy(tmp_path, monkeypatch):
    """With both present, the modern home wins, matching resolve_capauth_home()."""
    fake_home = tmp_path / "user"
    modern = fake_home / ".skcapstone" / "capauth"
    legacy = fake_home / ".capauth"
    _make_keystore(modern / "service" / "keys.db")
    (legacy / "service").mkdir(parents=True)  # exists but has no keystore

    env = dict(os.environ)
    env["HOME"] = str(fake_home)
    env.pop("CAPAUTH_HOME", None)
    env.pop("CAPAUTH_DB_PATH", None)
    env.pop("CAPAUTH_BACKUP_DIR", None)

    res = _run_backup(env)
    assert res.returncode == 0, res.stderr
    dirs = sorted((modern / "backups").glob("capauth-backup-*"))
    assert dirs, f"nothing backed up under the modern home:\n{res.stdout}"
    assert (dirs[-1] / "keys.db").exists()


def test_legacy_home_is_still_used_when_it_is_the_only_one(tmp_path):
    fake_home = tmp_path / "user"
    legacy = fake_home / ".capauth"
    _make_keystore(legacy / "service" / "keys.db")

    env = dict(os.environ)
    env["HOME"] = str(fake_home)
    for k in ("CAPAUTH_HOME", "CAPAUTH_DB_PATH", "CAPAUTH_BACKUP_DIR"):
        env.pop(k, None)

    res = _run_backup(env)
    assert res.returncode == 0, res.stderr
    assert sorted((legacy / "backups").glob("capauth-backup-*")), res.stdout


def test_the_identity_public_key_is_included_so_restore_is_provable(scratch):
    """doctor's backup_restorable compares live public.asc against the backup."""
    env, home, backups = scratch["env"], scratch["home"], scratch["backups"]
    ident = home / "identity"
    ident.mkdir(parents=True, exist_ok=True)
    armor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\npub\n-----END PGP PUBLIC KEY BLOCK-----\n"
    (ident / "public.asc").write_text(armor, encoding="utf-8")

    res = _run_backup(env)
    assert res.returncode == 0, res.stderr
    latest = sorted(backups.glob("capauth-backup-*"))[-1]
    assert (latest / "public.asc").read_text(encoding="utf-8") == armor


def test_private_key_material_is_never_backed_up(scratch):
    """The invariant that must survive every change here."""
    env, home, backups = scratch["env"], scratch["home"], scratch["backups"]
    ident = home / "identity"
    ident.mkdir(parents=True, exist_ok=True)
    (ident / "public.asc").write_text("pub", encoding="utf-8")
    (ident / "private.asc").write_text("SECRET-KEY-MATERIAL", encoding="utf-8")

    res = _run_backup(env)
    assert res.returncode == 0, res.stderr
    latest = sorted(backups.glob("capauth-backup-*"))[-1]
    assert not (latest / "private.asc").exists()
    for f in latest.rglob("*"):
        if f.is_file():
            assert b"SECRET-KEY-MATERIAL" not in f.read_bytes(), (
                f"private material leaked into {f}"
            )
