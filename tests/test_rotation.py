from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pgpy
import pytest
from click.testing import CliRunner
from pgpy.constants import (
    EllipticCurveOID,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SymmetricKeyAlgorithm,
)

from capauth.cli import main
from capauth.rotation import RotationError, RotationPlan, rollback_rotation, rotate_passphrase

OLD = "old-test-passphrase"
NEW = "new-test-passphrase"


def _fixture(tmp_path: Path) -> tuple[RotationPlan, dict[Path, bytes]]:
    key = pgpy.PGPKey.new(PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519)
    uid = pgpy.PGPUID.new("Rotation Test", email="rotation@example.invalid")
    key.add_uid(uid, usage={KeyFlags.Sign}, hashes=[HashAlgorithm.SHA256])
    key.protect(OLD, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
    private = tmp_path / "identity" / "private.asc"
    public = tmp_path / "identity" / "public.asc"
    consumer = tmp_path / "consumer" / "private.asc"
    bundle = tmp_path / "custody" / "active.tar.gpg"
    checksum = bundle.with_suffix(".gpg.sha256")
    for path in (private, public, consumer, bundle):
        path.parent.mkdir(parents=True, exist_ok=True)
    private.write_text(str(key), encoding="utf-8")
    public.write_text(str(key.pubkey), encoding="utf-8")
    consumer.write_bytes(private.read_bytes())
    encrypted = pgpy.PGPMessage.new(b"synthetic custody payload").encrypt(OLD)
    bundle.write_text(str(encrypted), encoding="utf-8")
    for path in (private, consumer, bundle):
        path.chmod(0o600)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(
        json.dumps(
            {
                "version": 1,
                "operator": "test-operator",
                "private_key": str(private),
                "public_key": str(public),
                "credential_consumers": [str(consumer)],
                "custody_bundles": [
                    {"path": str(bundle), "checksum_path": str(checksum)}
                ],
                "rollback_root": str(tmp_path / "rollback"),
                "proton_pass_entry": "test entry",
            }
        ),
        encoding="utf-8",
    )
    plan = RotationPlan.load(plan_path)
    return plan, {path: path.read_bytes() for path in (private, consumer, bundle)}


def test_rotation_rewraps_key_consumers_bundle_and_checksum(tmp_path):
    plan, originals = _fixture(tmp_path)
    receipt = rotate_passphrase(plan, OLD, NEW, approved=True)
    assert plan.private_key.read_bytes() == plan.credential_consumers[0].read_bytes()
    assert plan.private_key.read_bytes() != originals[plan.private_key]
    key, _ = pgpy.PGPKey.from_file(str(plan.private_key))
    with pytest.raises(Exception), key.unlock(OLD):
        pass
    key, _ = pgpy.PGPKey.from_file(str(plan.private_key))
    with key.unlock(NEW):
        signature = key.sign(pgpy.PGPMessage.new(b"probe"))
    assert signature
    bundle, checksum = plan.custody_bundles[0]
    assert pgpy.PGPMessage.from_file(str(bundle)).decrypt(NEW).message == (
        "synthetic custody payload"
    )
    expected = f"{hashlib.sha256(bundle.read_bytes()).hexdigest()}  {bundle.name}\n"
    assert checksum.read_text(encoding="ascii") == expected
    assert Path(receipt.rollback_dir, "journal.json").is_file()
    assert OLD not in json.dumps(receipt.to_dict())
    assert NEW not in json.dumps(receipt.to_dict())


def test_wrong_old_passphrase_changes_nothing(tmp_path):
    plan, originals = _fixture(tmp_path)
    with pytest.raises(RotationError, match="old passphrase verification failed"):
        rotate_passphrase(plan, "wrong", NEW, approved=True)
    assert {path: path.read_bytes() for path in originals} == originals


def test_approval_is_mandatory(tmp_path):
    plan, _ = _fixture(tmp_path)
    with pytest.raises(RotationError, match="approval"):
        rotate_passphrase(plan, OLD, NEW)


def test_rollback_restores_exact_original_bytes(tmp_path):
    plan, originals = _fixture(tmp_path)
    receipt = rotate_passphrase(plan, OLD, NEW, approved=True)
    restored = rollback_rotation(Path(receipt.rollback_dir) / "journal.json", approved=True)
    assert set(restored) >= {str(path) for path in originals}
    assert {path: path.read_bytes() for path in originals} == originals
    assert not plan.custody_bundles[0][1].exists()


def test_plan_rejects_passphrase_fields(tmp_path):
    plan, _ = _fixture(tmp_path)
    raw = json.loads(plan.path.read_text(encoding="utf-8"))
    raw["old_passphrase"] = "forbidden"
    plan.path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(RotationError, match="forbidden"):
        RotationPlan.load(plan.path)


def test_cli_has_no_passphrase_option_and_prompts_are_hidden(tmp_path):
    plan, _ = _fixture(tmp_path)
    runner = CliRunner()
    help_result = runner.invoke(main, ["passphrase", "rotate", "--help"])
    assert "--passphrase" not in help_result.output
    result = runner.invoke(
        main,
        ["passphrase", "rotate", "--plan", str(plan.path), "--approve", "--json"],
        input=f"y\n{OLD}\n{NEW}\n{NEW}\n",
    )
    assert result.exit_code == 0, result.output
    assert OLD not in result.output
    assert NEW not in result.output
