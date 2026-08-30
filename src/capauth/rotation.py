"""Guarded passphrase rotation for local CapAuth custody material.

Passphrases are accepted only as in-memory values supplied by an interactive
caller. They are never accepted as command arguments, written to a journal, or
included in exceptions and reports.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pgpy
from pgpy.constants import HashAlgorithm, SymmetricKeyAlgorithm


class RotationError(RuntimeError):
    """A rotation precondition or validation failed."""


@dataclass(frozen=True)
class RotationPlan:
    """Validated local paths participating in one rotation transaction."""

    path: Path
    private_key: Path
    public_key: Path
    credential_consumers: tuple[Path, ...]
    custody_bundles: tuple[tuple[Path, Path], ...]
    rollback_root: Path
    operator: str
    proton_pass_entry: str

    @classmethod
    def load(cls, path: Path) -> "RotationPlan":
        plan_path = Path(path).expanduser().resolve(strict=True)
        try:
            raw = json.loads(plan_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RotationError(f"invalid rotation plan JSON: {exc}") from exc
        if not isinstance(raw, dict) or raw.get("version") != 1:
            raise RotationError("rotation plan must be an object with version=1")
        if any("passphrase" in str(key).lower() for key in raw):
            raise RotationError("passphrases are forbidden in rotation plans")

        def local(value: object, label: str) -> Path:
            if not isinstance(value, str) or not value.strip():
                raise RotationError(f"rotation plan requires {label}")
            candidate = Path(value).expanduser()
            if not candidate.is_absolute():
                candidate = plan_path.parent / candidate
            return candidate.resolve(strict=False)

        consumers_raw = raw.get("credential_consumers", [])
        bundles_raw = raw.get("custody_bundles", [])
        if not isinstance(consumers_raw, list) or not all(
            isinstance(item, str) for item in consumers_raw
        ):
            raise RotationError("credential_consumers must be a list of paths")
        if not isinstance(bundles_raw, list):
            raise RotationError("custody_bundles must be a list")
        bundles: list[tuple[Path, Path]] = []
        for index, item in enumerate(bundles_raw):
            if not isinstance(item, dict):
                raise RotationError(f"custody_bundles[{index}] must be an object")
            bundle = local(item.get("path"), f"custody_bundles[{index}].path")
            checksum = local(item.get("checksum_path"), f"custody_bundles[{index}].checksum_path")
            bundles.append((bundle, checksum))

        operator = str(raw.get("operator") or "").strip()
        proton_entry = str(raw.get("proton_pass_entry") or "").strip()
        if not operator:
            raise RotationError("rotation plan requires an attributable operator")
        if not proton_entry:
            raise RotationError("rotation plan requires proton_pass_entry for manual handoff")
        rollback_raw = raw.get("rollback_root", ".rotation-rollback")
        result = cls(
            path=plan_path,
            private_key=local(raw.get("private_key"), "private_key"),
            public_key=local(raw.get("public_key"), "public_key"),
            credential_consumers=tuple(
                local(item, f"credential_consumers[{index}]")
                for index, item in enumerate(consumers_raw)
            ),
            custody_bundles=tuple(bundles),
            rollback_root=local(rollback_raw, "rollback_root"),
            operator=operator,
            proton_pass_entry=proton_entry,
        )
        result._validate_paths()
        return result

    def _validate_paths(self) -> None:
        targets = [self.private_key, *self.credential_consumers]
        targets.extend(path for pair in self.custody_bundles for path in pair)
        if len(set(targets)) != len(targets):
            raise RotationError("rotation target paths must be unique")
        if self.private_key in self.credential_consumers:
            raise RotationError("private_key cannot also be a credential consumer")


@dataclass(frozen=True)
class RotationReceipt:
    transaction_id: str
    fingerprint: str
    rotated_paths: tuple[str, ...]
    rollback_dir: str
    completed_at: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": "capauth-passphrase-rotation-v1",
            "transaction_id": self.transaction_id,
            "fingerprint": self.fingerprint,
            "rotated_paths": list(self.rotated_paths),
            "rollback_dir": self.rollback_dir,
            "completed_at": self.completed_at,
            "validation": {
                "old_passphrase_verified": True,
                "bundles_decrypted": True,
                "new_key_unlock": True,
                "sign_verify": True,
                "checksums_regenerated": True,
            },
        }


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_owner_file(path: Path, label: str) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise RotationError(f"{label} must be a regular non-symlink file: {path}")
    if os.name == "posix" and path.stat().st_mode & 0o077:
        raise RotationError(f"{label} must have owner-only permissions: {path}")
    return path.read_bytes()


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _load_and_verify_key(private_bytes: bytes, public_bytes: bytes, passphrase: str):
    try:
        key, _ = pgpy.PGPKey.from_blob(private_bytes)
        public, _ = pgpy.PGPKey.from_blob(public_bytes)
        probe = b"capauth rotation preflight"
        with key.unlock(passphrase):
            signature = key.sign(probe)
        if str(key.fingerprint) != str(public.fingerprint) or not public.verify(probe, signature):
            raise RotationError("private key does not match public key or cannot sign and verify")
        return key, public
    except RotationError:
        raise
    except Exception as exc:
        raise RotationError("old passphrase verification failed") from exc


def _rewrap_key(key: pgpy.PGPKey, old_passphrase: str, new_passphrase: str) -> bytes:
    try:
        with key.unlock(old_passphrase):
            key.protect(new_passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
            return str(key).encode("utf-8")
    except Exception as exc:
        raise RotationError("private-key protection rotation failed") from exc


def _rewrap_bundle(data: bytes, old_passphrase: str, new_passphrase: str) -> bytes:
    try:
        encrypted = pgpy.PGPMessage.from_blob(data)
        plain = encrypted.decrypt(old_passphrase)
        payload = plain.message
        message = pgpy.PGPMessage.new(payload, file=plain.filename or False)
        return str(
            message.encrypt(
                new_passphrase,
                cipher=SymmetricKeyAlgorithm.AES256,
                hash=HashAlgorithm.SHA256,
            )
        ).encode("utf-8")
    except Exception as exc:
        raise RotationError("custody bundle decrypt or re-encryption failed") from exc


def _validate_new_key(private_bytes: bytes, public_bytes: bytes, passphrase: str) -> str:
    try:
        key, _ = pgpy.PGPKey.from_blob(private_bytes)
        public, _ = pgpy.PGPKey.from_blob(public_bytes)
        probe = b"capauth rotation validation"
        with key.unlock(passphrase):
            signature = key.sign(probe)
        if not public.verify(probe, signature):
            raise RotationError("rotated key failed sign and verify validation")
        return str(public.fingerprint).replace(" ", "")
    except RotationError:
        raise
    except Exception as exc:
        raise RotationError("rotated key failed unlock validation") from exc


def _validate_new_bundle(data: bytes, passphrase: str) -> None:
    try:
        pgpy.PGPMessage.from_blob(data).decrypt(passphrase)
    except Exception as exc:
        raise RotationError("rotated custody bundle failed decrypt validation") from exc


def _checksum_bytes(path: Path, data: bytes) -> bytes:
    return f"{_sha256(data)}  {path.name}\n".encode("ascii")


def rotate_passphrase(
    plan: RotationPlan,
    old_passphrase: str,
    new_passphrase: str,
    *,
    approved: bool = False,
) -> RotationReceipt:
    """Execute a validated local rotation with durable rollback material.

    The caller must collect both passphrases interactively. No passphrase is
    accepted through the plan or returned in the receipt.
    """
    if not approved:
        raise RotationError("explicit operator approval is required")
    if not old_passphrase or not new_passphrase or old_passphrase == new_passphrase:
        raise RotationError("old and new passphrases must be non-empty and different")

    public_bytes = plan.public_key.read_bytes()
    private_bytes = _read_owner_file(plan.private_key, "private key")
    key, _ = _load_and_verify_key(private_bytes, public_bytes, old_passphrase)

    originals: dict[Path, bytes] = {plan.private_key: private_bytes}
    absent_before: set[Path] = set()
    for consumer in plan.credential_consumers:
        consumer_bytes = _read_owner_file(consumer, "credential consumer")
        if consumer_bytes != private_bytes:
            raise RotationError(f"credential consumer does not match primary key: {consumer}")
        originals[consumer] = consumer_bytes
    bundle_plaintexts: list[bytes] = []
    for bundle, checksum in plan.custody_bundles:
        data = _read_owner_file(bundle, "custody bundle")
        originals[bundle] = data
        if checksum.exists():
            originals[checksum] = checksum.read_bytes()
        else:
            absent_before.add(checksum)
        try:
            bundle_plaintexts.append(
                pgpy.PGPMessage.from_blob(data).decrypt(old_passphrase).message
            )
        except Exception as exc:
            raise RotationError(
                f"old passphrase could not decrypt custody bundle: {bundle}"
            ) from exc

    rotated_key = _rewrap_key(key, old_passphrase, new_passphrase)
    fingerprint = _validate_new_key(rotated_key, public_bytes, new_passphrase)
    replacements: dict[Path, bytes] = {plan.private_key: rotated_key}
    replacements.update({path: rotated_key for path in plan.credential_consumers})
    for (bundle, checksum), _plain in zip(plan.custody_bundles, bundle_plaintexts):
        rotated = _rewrap_bundle(originals[bundle], old_passphrase, new_passphrase)
        _validate_new_bundle(rotated, new_passphrase)
        replacements[bundle] = rotated
        replacements[checksum] = _checksum_bytes(bundle, rotated)

    transaction_id = uuid.uuid4().hex
    rollback_dir = plan.rollback_root / transaction_id
    rollback_dir.mkdir(parents=True, mode=0o700)
    journal_items = []
    for index, (path, data) in enumerate(originals.items()):
        backup = rollback_dir / f"{index:04d}.original"
        _atomic_write(backup, data)
        journal_items.append(
            {"path": str(path), "existed": True, "backup": backup.name, "sha256": _sha256(data)}
        )
    for path in sorted(absent_before, key=str):
        journal_items.append({"path": str(path), "existed": False})
    journal = {
        "schema": "capauth-passphrase-rotation-rollback-v1",
        "transaction_id": transaction_id,
        "operator": plan.operator,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "items": journal_items,
    }
    _atomic_write(
        rollback_dir / "journal.json",
        (json.dumps(journal, sort_keys=True, indent=2) + "\n").encode("utf-8"),
    )

    changed: list[Path] = []
    try:
        for path, data in replacements.items():
            _atomic_write(path, data)
            changed.append(path)
        if (
            _validate_new_key(plan.private_key.read_bytes(), public_bytes, new_passphrase)
            != fingerprint
        ):
            raise RotationError("installed key fingerprint changed unexpectedly")
        for bundle, checksum in plan.custody_bundles:
            installed = bundle.read_bytes()
            _validate_new_bundle(installed, new_passphrase)
            if checksum.read_bytes() != _checksum_bytes(bundle, installed):
                raise RotationError("installed custody checksum validation failed")
    except BaseException:
        for path in reversed(changed):
            if path in originals:
                _atomic_write(path, originals[path])
            elif path.exists():
                path.unlink()
        raise

    return RotationReceipt(
        transaction_id=transaction_id,
        fingerprint=fingerprint,
        rotated_paths=tuple(str(path) for path in replacements),
        rollback_dir=str(rollback_dir),
        completed_at=datetime.now(timezone.utc).isoformat(),
    )


def rollback_rotation(journal_path: Path, *, approved: bool = False) -> tuple[str, ...]:
    """Restore exact pre-rotation bytes from a validated rollback journal."""
    if not approved:
        raise RotationError("explicit operator approval is required")
    journal_path = Path(journal_path).expanduser().resolve(strict=True)
    try:
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RotationError(f"invalid rollback journal: {exc}") from exc
    if (
        not isinstance(journal, dict)
        or journal.get("schema") != "capauth-passphrase-rotation-rollback-v1"
    ):
        raise RotationError("unsupported rollback journal")
    items = journal.get("items")
    if not isinstance(items, list) or not items:
        raise RotationError("rollback journal has no items")
    validated: list[tuple[Path, bytes | None]] = []
    for item in items:
        if not isinstance(item, dict) or not str(item.get("path") or ""):
            raise RotationError("invalid rollback item")
        target = Path(str(item["path"]))
        if item.get("existed") is False:
            validated.append((target, None))
            continue
        backup = (journal_path.parent / str(item.get("backup") or "")).resolve(strict=True)
        if backup.parent != journal_path.parent:
            raise RotationError("rollback backup escapes its transaction directory")
        data = backup.read_bytes()
        if _sha256(data) != item.get("sha256"):
            raise RotationError("rollback backup checksum mismatch")
        validated.append((target, data))
    for path, data in validated:
        if data is None:
            if path.exists():
                path.unlink()
        else:
            _atomic_write(path, data)
    return tuple(str(path) for path, _ in validated)
