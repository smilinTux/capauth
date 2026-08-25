"""Identity-estate lifecycle, alternate-home, and Syncthing policy tests."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path
from unittest.mock import Mock, patch

import pgpy
from click.testing import CliRunner
from pgpy.constants import (
    CompressionAlgorithm,
    EllipticCurveOID,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SymmetricKeyAlgorithm,
)

from capauth.cli import main
from capauth.estate import (
    EstateManifest,
    EstateStatus,
    SyncthingFolder,
    audit_estate,
    check_syncthing_policy,
    classify_artifacts,
    discover_roots,
    scan_gpg_keyring,
    scan_identity_roots,
    QuarantineEvidence,
    quarantine_archive_metadata,
)


def _key(name: str = "Estate Test") -> pgpy.PGPKey:
    key = pgpy.PGPKey.new(PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519)
    uid = pgpy.PGPUID.new(name, email="estate@example.test")
    key.add_uid(
        uid,
        usage={KeyFlags.Sign, KeyFlags.Certify},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.Uncompressed],
    )
    return key


def _fingerprint(key: pgpy.PGPKey) -> str:
    return str(key.fingerprint).replace(" ", "")


def _write_manifest(
    path: Path,
    *,
    active_key: pgpy.PGPKey,
    allowed_root: Path,
    retired_fingerprint: str | None = None,
    archive: Path | None = None,
) -> Path:
    identities = [
        {
            "fingerprint": _fingerprint(active_key),
            "status": "active",
            "identity_type": "human",
            "label": "active operator",
            "allowed_secret_roots": [str(allowed_root)],
        }
    ]
    if retired_fingerprint is not None:
        assert archive is not None
        identities.append(
            {
                "fingerprint": retired_fingerprint,
                "status": "retired",
                "identity_type": "service",
                "label": "retired service",
                "quarantine": {
                    "archive": str(archive),
                    "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                    "verified_at": "2026-08-21T00:00:00Z",
                    "verified_by": "test-operator",
                },
            }
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"version": 1, "identities": identities}),
        encoding="utf-8",
    )
    return path


def _write_identity(root: Path, key: pgpy.PGPKey) -> None:
    identity = root / "identity"
    identity.mkdir(parents=True)
    (identity / "public.asc").write_text(str(key.pubkey), encoding="utf-8")
    (identity / "private.asc").write_text(str(key), encoding="utf-8")
    (identity / "private.asc").chmod(0o600)


def _write_syncthing_config(home: Path, folder: Path) -> Path:
    config = home / ".config" / "syncthing" / "config.xml"
    config.parent.mkdir(parents=True)
    config.write_text(
        f'<configuration><folder id="skcapstone" path="{folder}" /></configuration>',
        encoding="utf-8",
    )
    return config


def test_manifest_rejects_duplicate_fingerprint(tmp_path: Path) -> None:
    key = _key()
    record = {
        "fingerprint": _fingerprint(key),
        "status": "active",
        "identity_type": "human",
    }
    path = tmp_path / "estate.json"
    path.write_text(
        json.dumps({"version": 1, "identities": [record, record]}),
        encoding="utf-8",
    )
    try:
        EstateManifest.load(path)
    except ValueError as exc:
        assert "duplicate fingerprint" in str(exc)
    else:
        raise AssertionError("duplicate fingerprint must fail closed")


def test_discovers_chiwk12_style_alternate_home(tmp_path: Path) -> None:
    alternate_home = tmp_path / "home" / "mrarch"
    root = alternate_home / ".skcapstone" / "agents" / "jarvis" / "capauth"
    root.mkdir(parents=True)

    roots, findings = discover_roots([alternate_home])

    assert root.resolve() in roots
    assert not any(f.status is EstateStatus.FAIL for f in findings)


def test_distinct_legacy_tree_fails_but_symlink_alias_passes(tmp_path: Path) -> None:
    home = tmp_path / "operator"
    legacy = home / ".capauth"
    canonical = home / ".skcapstone" / "capauth"
    legacy.mkdir(parents=True)
    canonical.mkdir(parents=True)

    _, findings = discover_roots([home])
    assert any(f.code == "split_identity_root" and f.status is EstateStatus.FAIL for f in findings)

    legacy.rmdir()
    legacy.symlink_to(canonical, target_is_directory=True)
    _, findings = discover_roots([home])
    assert any(f.code == "legacy_alias" and f.status is EstateStatus.OK for f in findings)


def test_syncthing_policy_is_checked_at_folder_root(tmp_path: Path) -> None:
    sync_root = tmp_path / "shared"
    identity_root = sync_root / "agents" / "jarvis" / "capauth"
    identity_root.mkdir(parents=True)
    folder = SyncthingFolder("skcapstone", sync_root, tmp_path / "config.xml")

    findings = check_syncthing_policy([folder], [identity_root])
    assert findings[0].status is EstateStatus.FAIL
    assert "**/private.*" in findings[0].detail
    assert "**/root-revocation.asc" in findings[0].detail

    (sync_root / ".stignore").write_text(
        "**/private.*\n**/root-revocation.asc\n", encoding="utf-8"
    )
    findings = check_syncthing_policy([folder], [identity_root])
    assert findings[0].status is EstateStatus.OK


def test_conflict_file_is_fingerprint_classified(tmp_path: Path) -> None:
    root = tmp_path / "capauth"
    key = _key()
    identity = root / "identity"
    identity.mkdir(parents=True)
    conflict = identity / "private.sync-conflict-20260820.asc"
    conflict.write_text(str(key), encoding="utf-8")
    manifest_path = _write_manifest(tmp_path / "estate.json", active_key=key, allowed_root=root)

    artifacts, scan_findings = scan_identity_roots([root])
    findings = scan_findings + classify_artifacts(artifacts, EstateManifest.load(manifest_path))

    assert any(
        f.code == "syncthing_conflict"
        and f.status is EstateStatus.FAIL
        and f.fingerprint == _fingerprint(key)
        for f in findings
    )


def test_gpg_scan_lists_primary_public_and_secret_fingerprints(tmp_path: Path) -> None:
    fingerprint = "A" * 40
    gpg_home = tmp_path / ".gnupg"
    gpg_home.mkdir()
    public = Mock(
        returncode=0,
        stdout=f"pub:u:255:22:KEYID:0:0::::::\nfpr:::::::::{fingerprint}:\n",
    )
    secret = Mock(
        returncode=0,
        stdout=f"sec:u:255:22:KEYID:0:0::::::\nfpr:::::::::{fingerprint}:\n",
    )
    with (
        patch("capauth.estate.shutil.which", return_value="/usr/bin/gpg"),
        patch("capauth.estate.subprocess.run", side_effect=[public, secret]),
    ):
        artifacts, findings = scan_gpg_keyring(gpg_home)

    assert findings == []
    assert {(item.source, item.fingerprint) for item in artifacts} == {
        ("gpg-public", fingerprint),
        ("gpg-secret", fingerprint),
    }


def test_gpg_scan_does_not_create_a_missing_home(tmp_path: Path) -> None:
    gpg_home = tmp_path / "absent-gnupg"
    with (
        patch("capauth.estate.shutil.which", return_value="/usr/bin/gpg"),
        patch("capauth.estate.subprocess.run") as run,
    ):
        artifacts, findings = scan_gpg_keyring(gpg_home)

    assert artifacts == []
    assert findings[0].status is EstateStatus.OK
    assert not gpg_home.exists()
    run.assert_not_called()


def test_full_audit_passes_and_emits_no_secret_payload(tmp_path: Path) -> None:
    user_home = tmp_path / "home" / "operator"
    sync_root = user_home / ".skcapstone"
    root = sync_root / "capauth"
    key = _key("Active Human")
    _write_identity(root, key)
    retired = _key("Retired Service")
    archive = tmp_path / "retired-service.tar.gpg"
    # Old-format packet tag 3 (SKESK): enough for the envelope check; the
    # operator attestation represents the separate decrypt/member ceremony.
    archive.write_bytes(b"\x8c\x01\x04ciphertext-only-test-fixture")
    manifest_path = _write_manifest(
        root / "estate.json",
        active_key=key,
        allowed_root=root,
        retired_fingerprint=_fingerprint(retired),
        archive=archive,
    )
    _write_syncthing_config(user_home, sync_root)
    (sync_root / ".stignore").write_text(
        "**/private.*\n**/root-revocation.asc\n", encoding="utf-8"
    )

    report = audit_estate(
        manifest_path,
        user_homes=[user_home],
        include_gpg=False,
    )
    rendered = json.dumps(report.to_dict())

    assert report.overall is EstateStatus.OK
    assert "BEGIN PGP PRIVATE KEY BLOCK" not in rendered
    assert str(key) not in rendered
    assert any(f.code == "quarantine_evidence" for f in report.findings)


def test_cli_json_supports_explicit_alternate_home(tmp_path: Path) -> None:
    user_home = tmp_path / "home" / "mrarch"
    sync_root = user_home / ".skcapstone"
    root = sync_root / "capauth"
    key = _key()
    _write_identity(root, key)
    manifest_path = _write_manifest(root / "estate.json", active_key=key, allowed_root=root)
    _write_syncthing_config(user_home, sync_root)
    (sync_root / ".stignore").write_text(
        "**/private.*\n**/root-revocation.asc\n", encoding="utf-8"
    )

    result = CliRunner().invoke(
        main,
        [
            "--home",
            str(root),
            "doctor",
            "estate",
            "--manifest",
            str(manifest_path),
            "--user-home",
            str(user_home),
            "--no-gpg",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["overall"] == "OK"


def _encrypted_fixture_archive(path: Path) -> Path:
    path.write_bytes(b"-----BEGIN PGP MESSAGE-----\nsynthetic\n")
    return path


def _tar_bytes(names: tuple[str, ...]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:") as archive:
        for name in names:
            info = tarfile.TarInfo(name)
            info.size = 0
            archive.addfile(info)
    return stream.getvalue()


def test_quarantine_archive_decrypts_and_matches_members(tmp_path: Path) -> None:
    archive = _encrypted_fixture_archive(tmp_path / "custody.tar.gpg")
    passphrase = tmp_path / "passphrase"
    passphrase.write_text("synthetic", encoding="utf-8")
    passphrase.chmod(0o600)
    evidence = QuarantineEvidence(
        archive=archive,
        sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        verified_at="2026-08-25T00:00:00Z",
        verified_by="synthetic-test",
        members=("identity/public.asc", "manifest.json"),
    )

    def fake_gpg(command, **kwargs):
        kwargs["stdout"].write(_tar_bytes(evidence.members))
        return Mock(returncode=0, stderr=b"secret stderr")

    with patch("capauth.estate.subprocess.run", side_effect=fake_gpg):
        finding = quarantine_archive_metadata(evidence, passphrase_file=passphrase)
    assert finding.status is EstateStatus.OK
    assert "secret" not in finding.detail


def test_quarantine_archive_wrong_passphrase_fails_without_stderr(tmp_path: Path) -> None:
    archive = _encrypted_fixture_archive(tmp_path / "custody.tar.gpg")
    passphrase = tmp_path / "passphrase"
    passphrase.write_text("wrong", encoding="utf-8")
    passphrase.chmod(0o600)
    evidence = QuarantineEvidence(
        archive=archive,
        sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        verified_at="2026-08-25T00:00:00Z",
        verified_by="synthetic-test",
        members=("manifest.json",),
    )
    with patch(
        "capauth.estate.subprocess.run",
        return_value=Mock(returncode=2, stderr=b"wrong passphrase secret"),
    ) as run:
        finding = quarantine_archive_metadata(evidence, passphrase_file=passphrase)
    assert finding.status is EstateStatus.FAIL
    assert "wrong passphrase secret" not in finding.detail
    run.assert_called_once()


def test_quarantine_archive_rejects_insecure_passphrase_file(tmp_path: Path) -> None:
    archive = _encrypted_fixture_archive(tmp_path / "custody.tar.gpg")
    passphrase = tmp_path / "passphrase"
    passphrase.write_text("synthetic", encoding="utf-8")
    passphrase.chmod(0o644)
    evidence = QuarantineEvidence(
        archive=archive,
        sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        verified_at="2026-08-25T00:00:00Z",
        verified_by="synthetic-test",
        members=("identity/private.asc",),
    )

    finding = quarantine_archive_metadata(evidence, passphrase_file=passphrase)

    assert finding.status is EstateStatus.FAIL
    assert "insecure" in finding.detail
