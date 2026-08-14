"""Tests for the key-custody doctor checks (capauth doctor custody).

Covers coord card 2b3af4b7. Each check is exercised against a *good* synthetic
fixture (passes) and a *bad* one (fails/warns): e.g. a 0644 private key -> FAIL,
a missing revocation cert -> FAIL, a stale backup -> WARN, a corrupt keystore ->
FAIL, a mismatched backup public key -> FAIL. Also asserts no secret material
leaks into any check output.
"""

from __future__ import annotations

import os
import sqlite3
import time
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pgpy
import pytest
from pgpy.constants import (
    CompressionAlgorithm,
    EllipticCurveOID,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SignatureType,
    SymmetricKeyAlgorithm,
)

from capauth import custody
from capauth.custody import (
    CheckResult,
    CustodyPaths,
    Status,
    check_backup_restorable,
    check_backups_configured,
    check_identity_present,
    check_key_status,
    check_keypair_match,
    check_keystore_integrity,
    check_nextcloud_signing_key,
    check_private_key_permissions,
    check_revocation_cert,
    exit_code,
    format_report,
    overall_status,
    report_to_dict,
    run_custody_checks,
)

PASSPHRASE = "test-custody-passphrase-2026"


# ── key builders (mirror tests/test_key_revocation_expiry.py) ─────────────────


def _new_ed25519_key(
    name: str,
    email: str,
    created: datetime | None = None,
    key_expiration: timedelta | None = None,
) -> pgpy.PGPKey:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        key = pgpy.PGPKey.new(PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519, created=created)
        uid = pgpy.PGPUID.new(name, email=email)
        kwargs = {}
        if key_expiration is not None:
            kwargs["key_expiration"] = key_expiration
        key.add_uid(
            uid,
            usage={KeyFlags.Sign, KeyFlags.Certify},
            hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA512],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.Uncompressed],
            **kwargs,
        )
    return key


def _revoked_public_armor(key: pgpy.PGPKey) -> str:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        rev_sig = key.revoke(key, sigtype=SignatureType.KeyRevocation)
        pub = key.pubkey
        pub |= rev_sig
        return str(pub)


# ── good-home fixture ──────────────────────────────────────────────────────────


def _write(path: Path, text: str, mode: int | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)
    return path


def _make_good_keystore(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE keys (fpr TEXT PRIMARY KEY)")
    conn.execute("INSERT INTO keys VALUES ('DEADBEEF')")
    conn.commit()
    conn.close()


@pytest.fixture
def good_key() -> pgpy.PGPKey:
    return _new_ed25519_key("Custody Carol", "carol@test.io")


@pytest.fixture
def good_paths(tmp_path: Path, good_key: pgpy.PGPKey) -> CustodyPaths:
    """A fully-healthy custody layout under tmp_path."""
    home = tmp_path / "capauth"
    identity = home / "identity"
    public_armor = str(good_key.pubkey)

    pub = _write(identity / "public.asc", public_armor)
    priv = _write(identity / "private.asc", str(good_key), mode=0o600)
    profile = _write(identity / "profile.json", '{"entity": "carol"}')
    rev = _write(
        identity / "root-revocation.asc",
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\nrevocation\n-----END PGP PUBLIC KEY BLOCK-----\n",
    )

    keystore = home / "service" / "keys.db"
    _make_good_keystore(keystore)

    backup_root = home / "backups"
    backup_dir = backup_root / "capauth-backup-20260724T000000Z"
    _write(backup_dir / "public.asc", public_armor)  # matches live -> restorable
    (backup_dir / "MANIFEST.txt").write_text("manifest", encoding="utf-8")

    nc_key = home / "nextcloud" / "capauth.key"
    _write(nc_key, "PRIVATE-KEY-MATERIAL-NEVER-PRINTED", mode=0o600)

    return CustodyPaths(
        home=home,
        identity_dir=identity,
        private_key=priv,
        public_key=pub,
        profile=profile,
        revocation_cert=rev,
        keystore=keystore,
        backup_root=backup_root,
        nextcloud_key=nc_key,
    )


# ── whole-suite: good home passes, exits 0 ────────────────────────────────────


class TestHealthyHome:
    def test_all_checks_ok(self, good_paths):
        results = run_custody_checks(paths=good_paths)
        bad = [(r.name, r.status.value, r.detail) for r in results if r.status is not Status.OK]
        assert bad == [], f"expected all-OK, got: {bad}"

    def test_overall_ok_and_exit_zero(self, good_paths):
        results = run_custody_checks(paths=good_paths)
        assert overall_status(results) is Status.OK
        assert exit_code(results) == 0

    def test_json_report_shape(self, good_paths):
        report = report_to_dict(run_custody_checks(paths=good_paths))
        assert report["overall"] == "OK"
        assert report["exit_code"] == 0
        assert {c["name"] for c in report["checks"]} == {
            "identity_present",
            "keypair_match",
            "private_key_perms",
            "key_status",
            "revocation_cert",
            "keystore_integrity",
            "backups_configured",
            "backup_restorable",
            "nextcloud_signing_key",
        }


# ── identity presence ─────────────────────────────────────────────────────────


class TestIdentityPresent:
    def test_present_ok(self, good_paths):
        r = check_identity_present(
            good_paths.private_key, good_paths.public_key, good_paths.profile
        )
        assert r.status is Status.OK

    def test_missing_private_key_fails(self, good_paths):
        good_paths.private_key.unlink()
        r = check_identity_present(
            good_paths.private_key, good_paths.public_key, good_paths.profile
        )
        assert r.status is Status.FAIL

    def test_missing_public_key_warns(self, good_paths):
        good_paths.public_key.unlink()
        r = check_identity_present(
            good_paths.private_key, good_paths.public_key, good_paths.profile
        )
        assert r.status is Status.WARN


# ── private-key permissions ───────────────────────────────────────────────────


class TestPrivateKeyPermissions:
    def test_owner_only_ok(self, good_paths):
        r = check_private_key_permissions(good_paths.private_key)
        assert r.status is Status.OK

    def test_group_world_readable_fails(self, good_paths):
        good_paths.private_key.chmod(0o644)
        r = check_private_key_permissions(good_paths.private_key)
        assert r.status is Status.FAIL
        assert "600" in r.remediation

    def test_group_readable_only_fails(self, good_paths):
        good_paths.private_key.chmod(0o640)
        r = check_private_key_permissions(good_paths.private_key)
        assert r.status is Status.FAIL

    def test_missing_fails(self, good_paths):
        good_paths.private_key.unlink()
        r = check_private_key_permissions(good_paths.private_key)
        assert r.status is Status.FAIL


# ── revocation / expiry ───────────────────────────────────────────────────────


class TestKeyStatus:
    def test_healthy_key_ok(self, good_paths):
        r = check_key_status(good_paths.public_key)
        assert r.status is Status.OK

    def test_revoked_key_fails(self, good_paths, good_key):
        good_paths.public_key.write_text(_revoked_public_armor(good_key), encoding="utf-8")
        r = check_key_status(good_paths.public_key)
        assert r.status is Status.FAIL
        assert "REVOKED" in r.detail

    def test_expired_key_fails(self, tmp_path):
        created = datetime.now(timezone.utc) - timedelta(days=10)
        key = _new_ed25519_key(
            "Expired Ed", "ed@test.io", created=created, key_expiration=timedelta(days=1)
        )
        pub = tmp_path / "public.asc"
        pub.write_text(str(key.pubkey), encoding="utf-8")
        r = check_key_status(pub)
        assert r.status is Status.FAIL
        assert "EXPIRED" in r.detail

    def test_expiring_soon_warns(self, tmp_path):
        key = _new_ed25519_key("Soon Sue", "sue@test.io", key_expiration=timedelta(days=5))
        pub = tmp_path / "public.asc"
        pub.write_text(str(key.pubkey), encoding="utf-8")
        r = check_key_status(pub)
        assert r.status is Status.WARN


# ── revocation certificate presence ───────────────────────────────────────────


class TestRevocationCert:
    def test_present_ok(self, good_paths):
        r = check_revocation_cert(good_paths.revocation_cert)
        assert r.status is Status.OK

    def test_missing_fails(self, good_paths):
        good_paths.revocation_cert.unlink()
        r = check_revocation_cert(good_paths.revocation_cert)
        assert r.status is Status.FAIL

    def test_not_armored_warns(self, good_paths):
        good_paths.revocation_cert.write_text("not a pgp block", encoding="utf-8")
        r = check_revocation_cert(good_paths.revocation_cert)
        assert r.status is Status.WARN


# ── keystore integrity ────────────────────────────────────────────────────────


class TestKeystoreIntegrity:
    def test_valid_db_ok(self, good_paths):
        r = check_keystore_integrity(good_paths.keystore)
        assert r.status is Status.OK

    def test_absent_warns(self, good_paths):
        good_paths.keystore.unlink()
        r = check_keystore_integrity(good_paths.keystore)
        assert r.status is Status.WARN

    def test_corrupt_db_fails(self, good_paths):
        good_paths.keystore.write_bytes(b"this is not a sqlite database at all" * 8)
        r = check_keystore_integrity(good_paths.keystore)
        assert r.status is Status.FAIL


# ── backup freshness ──────────────────────────────────────────────────────────


class TestBackupsConfigured:
    def test_recent_backup_ok(self, good_paths):
        r = check_backups_configured(good_paths.backup_root)
        assert r.status is Status.OK

    def test_no_backup_fails(self, good_paths):
        for child in good_paths.backup_root.glob("capauth-backup-*"):
            for f in child.rglob("*"):
                if f.is_file():
                    f.unlink()
            child.rmdir()
        r = check_backups_configured(good_paths.backup_root)
        assert r.status is Status.FAIL

    def test_stale_backup_warns(self, good_paths):
        old = time.time() - 40 * 86400
        for child in good_paths.backup_root.glob("capauth-backup-*"):
            os.utime(child, (old, old))
        r = check_backups_configured(good_paths.backup_root, max_age_days=14)
        assert r.status is Status.WARN


# ── backup restorability (temp-dir restore, fingerprint match) ────────────────


class TestBackupRestorable:
    def test_matching_backup_ok(self, good_paths):
        r = check_backup_restorable(good_paths.public_key, good_paths.backup_root)
        assert r.status is Status.OK
        assert "matches live fingerprint" in r.detail

    def test_no_live_key_leftuntouched(self, good_paths):
        """Restorability must never touch/create live state."""
        live_before = good_paths.public_key.read_text()
        check_backup_restorable(good_paths.public_key, good_paths.backup_root)
        assert good_paths.public_key.read_text() == live_before

    def test_mismatched_backup_fails(self, good_paths):
        other = _new_ed25519_key("Other Otto", "otto@test.io")
        backup_dir = good_paths.backup_root / "capauth-backup-20260724T000000Z"
        (backup_dir / "public.asc").write_text(str(other.pubkey), encoding="utf-8")
        r = check_backup_restorable(good_paths.public_key, good_paths.backup_root)
        assert r.status is Status.FAIL

    def test_no_backup_key_warns(self, good_paths):
        for f in good_paths.backup_root.rglob("public.asc"):
            f.unlink()
        r = check_backup_restorable(good_paths.public_key, good_paths.backup_root)
        assert r.status is Status.WARN


# ── nextcloud signing key ─────────────────────────────────────────────────────


class TestNextcloudSigningKey:
    def test_present_owner_only_ok(self, good_paths):
        r = check_nextcloud_signing_key(good_paths.nextcloud_key)
        assert r.status is Status.OK

    def test_absent_fails(self, good_paths):
        good_paths.nextcloud_key.unlink()
        r = check_nextcloud_signing_key(good_paths.nextcloud_key)
        assert r.status is Status.FAIL
        assert "456cb3a" in r.remediation

    def test_group_world_readable_fails(self, good_paths):
        good_paths.nextcloud_key.chmod(0o644)
        r = check_nextcloud_signing_key(good_paths.nextcloud_key)
        assert r.status is Status.FAIL


# ── no-secret-leak guarantee ──────────────────────────────────────────────────


class TestNoSecretLeak:
    def test_private_key_body_never_in_output(self, good_paths):
        """Neither the private key nor the nextcloud key material appears in any
        check detail/remediation, nor in the rendered/JSON reports."""
        priv_body = good_paths.private_key.read_text()
        nc_body = good_paths.nextcloud_key.read_text()
        # A distinctive secret substring from the armored private key body.
        priv_secret_line = [
            ln for ln in priv_body.splitlines() if ln and "BEGIN" not in ln and "END" not in ln
        ][0]

        results = run_custody_checks(paths=good_paths)
        blob = format_report(results) + repr(report_to_dict(results))
        for r in results:
            blob += r.detail + r.remediation

        assert nc_body not in blob
        assert priv_secret_line not in blob
        # The private key file is stat-ed, never read: its body must be absent.
        assert priv_body not in blob


# ── result serialization ──────────────────────────────────────────────────────


class TestSerialization:
    def test_check_result_to_dict(self):
        r = CheckResult("x", Status.FAIL, "detail", "fix it")
        assert r.to_dict() == {
            "name": "x",
            "status": "FAIL",
            "detail": "detail",
            "remediation": "fix it",
        }

    def test_exit_code_nonzero_on_fail(self):
        results = [CheckResult("a", Status.OK, "ok"), CheckResult("b", Status.FAIL, "bad")]
        assert exit_code(results) == 1
        assert overall_status(results) is Status.FAIL


# ── keypair correspondence (lumina incident, 2026-08-14) ──────────────────────
#
# On Chef's primary node the identity held private.asc for
# "test-agent <test-agent@skcapstone.local>" alongside public.asc for
# "dounoit <dounoit@gmail.com>": two unrelated keys in one identity dir. Every
# signature it produced was unverifiable by anyone holding its published key,
# and `capauth doctor` reported identity_present OK because it only ever read
# public.asc. Same shape as the Jarvis incident, where a profile advertised a
# fingerprint the home did not hold.
#
# A key that cannot verify what it signs is not an identity, so this is FAIL.


def test_keypair_match_ok_on_a_real_pair(good_paths):
    result = check_keypair_match(good_paths.private_key, good_paths.public_key)
    assert result.status is Status.OK
    assert result.name == "keypair_match"


def test_keypair_match_fails_when_the_halves_are_different_keys(good_paths, tmp_path):
    """The lumina incident, reproduced."""
    stranger = _new_ed25519_key("Someone Else", "else@test.io")
    good_paths.public_key.write_text(str(stranger.pubkey), encoding="utf-8")

    result = check_keypair_match(good_paths.private_key, good_paths.public_key)
    assert result.status is Status.FAIL
    assert "do not match" in result.detail.lower()
    # Both fingerprints must be NAMED, or the operator cannot tell which half
    # is the wrong one and which key to go find.
    assert str(stranger.fingerprint).replace(" ", "") in result.detail


def test_keypair_match_reports_the_uids_so_the_stray_key_is_identifiable(good_paths):
    """The uid is what made the lumina case diagnosable: 'test-agent' vs a
    real address said immediately which half was the accident."""
    stranger = _new_ed25519_key("test-agent", "test-agent@skcapstone.local")
    good_paths.public_key.write_text(str(stranger.pubkey), encoding="utf-8")

    result = check_keypair_match(good_paths.private_key, good_paths.public_key)
    assert "test-agent" in result.detail


def test_keypair_match_warns_when_a_half_is_missing(good_paths):
    good_paths.public_key.unlink()
    result = check_keypair_match(good_paths.private_key, good_paths.public_key)
    assert result.status is Status.WARN  # identity_present already FAILs on this


def test_keypair_match_runs_as_part_of_the_custody_suite(good_paths):
    names = [r.name for r in run_custody_checks(paths=good_paths)]
    assert "keypair_match" in names


def test_a_mismatched_keypair_fails_the_whole_suite(good_paths):
    stranger = _new_ed25519_key("Someone Else", "else@test.io")
    good_paths.public_key.write_text(str(stranger.pubkey), encoding="utf-8")
    results = run_custody_checks(paths=good_paths)
    assert overall_status(results) is Status.FAIL
    assert exit_code(results) == 1
