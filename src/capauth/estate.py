"""Read-only identity-estate discovery and retirement policy checks.

Custody validates one configured identity home.  The estate doctor instead
looks for copies which should not be there: legacy CapAuth homes, SKCapstone
agent homes, Syncthing folder roots, conflict files, and GnuPG keyrings.
Reports contain fingerprints and paths, never key or passphrase bytes.

The manifest is authoritative for active/retired state and intentional secret
placement.  Retired material is never removed here.  The audit fails closed
until the manifest names an existing encrypted archive whose ciphertext hash
verifies, providing a pre-removal gate for the operator's approved change.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Iterable, Optional

FINGERPRINT_RE = re.compile(r"^[0-9A-F]{40}(?:[0-9A-F]{24})?$")
CONFLICT_RE = re.compile(r"(?:\.sync-conflict-|\.conflict-)", re.IGNORECASE)
IDENTITY_TYPES = frozenset({"human", "service", "node"})
LIFECYCLE_STATES = frozenset({"active", "retired"})
PRIVATE_IGNORE_RULES = frozenset({"private.*", "**/private.*"})
REVOCATION_IGNORE_RULES = frozenset({"root-revocation.asc", "**/root-revocation.asc"})


class EstateStatus(str, Enum):
    """Outcome severity for one estate finding."""

    OK = "OK"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass(frozen=True)
class QuarantineEvidence:
    """Attested encrypted quarantine metadata for a retired identity."""

    archive: Path
    sha256: str
    verified_at: str
    verified_by: str
    members: tuple[str, ...] = ()


@dataclass(frozen=True)
class IdentityPolicy:
    """Authoritative lifecycle and placement policy for one primary key."""

    fingerprint: str
    status: str
    identity_type: str
    label: str = ""
    allowed_secret_roots: tuple[Path, ...] = ()
    quarantine: Optional[QuarantineEvidence] = None


@dataclass(frozen=True)
class EstateManifest:
    """Validated identity-estate manifest."""

    path: Path
    identities: dict[str, IdentityPolicy]
    digest: str

    @classmethod
    def load(cls, path: Path) -> "EstateManifest":
        """Load and validate a version-1 JSON manifest."""
        manifest_path = Path(path).expanduser().resolve(strict=True)
        raw = manifest_path.read_bytes()
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid estate manifest JSON: {exc}") from exc
        if not isinstance(data, dict) or data.get("version") != 1:
            raise ValueError("estate manifest must be an object with version=1")
        records = data.get("identities")
        if not isinstance(records, list) or not records:
            raise ValueError("estate manifest identities must be a non-empty list")

        identities: dict[str, IdentityPolicy] = {}
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                raise ValueError(f"identities[{index}] must be an object")
            fingerprint = _normalize_fingerprint(record.get("fingerprint"))
            if fingerprint in identities:
                raise ValueError(f"duplicate fingerprint in manifest: {fingerprint}")
            status = str(record.get("status") or "").strip().lower()
            if status not in LIFECYCLE_STATES:
                raise ValueError(f"{fingerprint}: status must be active or retired")
            identity_type = str(record.get("identity_type") or "").strip().lower()
            if identity_type not in IDENTITY_TYPES:
                raise ValueError(f"{fingerprint}: identity_type must be human, service, or node")
            roots_raw = record.get("allowed_secret_roots", [])
            if not isinstance(roots_raw, list) or not all(
                isinstance(item, str) and item.strip() for item in roots_raw
            ):
                raise ValueError(f"{fingerprint}: allowed_secret_roots must be paths")
            roots = tuple(_manifest_path(item, manifest_path.parent) for item in roots_raw)
            quarantine = _parse_quarantine(
                record.get("quarantine"), manifest_path.parent, fingerprint
            )
            identities[fingerprint] = IdentityPolicy(
                fingerprint=fingerprint,
                status=status,
                identity_type=identity_type,
                label=str(record.get("label") or "").strip(),
                allowed_secret_roots=roots,
                quarantine=quarantine,
            )
        return cls(
            path=manifest_path,
            identities=identities,
            digest=hashlib.sha256(raw).hexdigest(),
        )


@dataclass
class EstateFinding:
    """One auditable, secret-free estate result."""

    code: str
    status: EstateStatus
    detail: str
    remediation: str = ""
    fingerprint: Optional[str] = None
    path: Optional[str] = None
    classification: Optional[str] = None
    identity_type: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            key: value
            for key, value in {
                "code": self.code,
                "status": self.status.value,
                "detail": self.detail,
                "remediation": self.remediation,
                "fingerprint": self.fingerprint,
                "path": self.path,
                "classification": self.classification,
                "identity_type": self.identity_type,
            }.items()
            if value not in (None, "")
        }


@dataclass(frozen=True)
class KeyArtifact:
    """A discovered primary key without any secret payload."""

    fingerprint: str
    source: str
    path: Optional[Path]
    secret: bool
    conflict: bool = False


@dataclass(frozen=True)
class SyncthingFolder:
    """A Syncthing folder declaration relevant to the audit."""

    folder_id: str
    path: Path
    config_path: Path


@dataclass
class EstateReport:
    """Complete report plus evidence metadata."""

    manifest: EstateManifest
    roots: list[Path]
    findings: list[EstateFinding] = field(default_factory=list)

    @property
    def overall(self) -> EstateStatus:
        statuses = {finding.status for finding in self.findings}
        if EstateStatus.FAIL in statuses:
            return EstateStatus.FAIL
        if EstateStatus.WARN in statuses:
            return EstateStatus.WARN
        return EstateStatus.OK

    @property
    def exit_code(self) -> int:
        return 1 if self.overall is EstateStatus.FAIL else 0

    def to_dict(self) -> dict:
        return {
            "schema": "capauth-estate-evidence-v1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "manifest": str(self.manifest.path),
            "manifest_sha256": self.manifest.digest,
            "overall": self.overall.value,
            "exit_code": self.exit_code,
            "roots": [str(path) for path in self.roots],
            "findings": [finding.to_dict() for finding in self.findings],
        }


def _normalize_fingerprint(value: object) -> str:
    fingerprint = re.sub(r"\s+", "", str(value or "")).upper()
    if not FINGERPRINT_RE.fullmatch(fingerprint):
        raise ValueError(f"invalid OpenPGP primary fingerprint: {value!r}")
    return fingerprint


def _manifest_path(value: str, base: Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = base / path
    return path.resolve(strict=False)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _looks_encrypted_openpgp(path: Path) -> bool:
    """Recognize an encrypted OpenPGP message without attempting decryption."""
    with path.open("rb") as stream:
        head = stream.read(64)
    if head.startswith(b"-----BEGIN PGP MESSAGE-----"):
        return True
    if not head or not head[0] & 0x80:
        return False
    if head[0] & 0x40:
        packet_tag = head[0] & 0x3F
    else:
        packet_tag = (head[0] >> 2) & 0x0F
    # PKESK, SKESK, symmetrically encrypted data, or integrity-protected
    # encrypted data. This is an envelope check; verified_by/verified_at attest
    # the separate decrypt-and-member verification ceremony.
    return packet_tag in {1, 3, 9, 18}


def _parse_quarantine(value: object, base: Path, fingerprint: str) -> Optional[QuarantineEvidence]:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError(f"{fingerprint}: quarantine must be an object")
    archive = str(value.get("archive") or "").strip()
    sha256 = str(value.get("sha256") or "").strip().lower()
    verified_at = str(value.get("verified_at") or "").strip()
    verified_by = str(value.get("verified_by") or "").strip()
    members_raw = value.get("members", [])
    if not isinstance(members_raw, list) or not all(
        isinstance(item, str) and item.strip() for item in members_raw
    ):
        raise ValueError(f"{fingerprint}: quarantine members must be paths")
    if not archive or not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise ValueError(f"{fingerprint}: quarantine requires archive and SHA-256")
    if not verified_at or not verified_by:
        raise ValueError(f"{fingerprint}: quarantine requires verified_at and verified_by")
    return QuarantineEvidence(
        archive=_manifest_path(archive, base),
        sha256=sha256,
        verified_at=verified_at,
        verified_by=verified_by,
        members=tuple(sorted(members_raw)),
    )


def quarantine_archive_metadata(
    evidence: QuarantineEvidence, *, passphrase_file: Optional[Path] = None
) -> EstateFinding:
    """Verify a declared tar.gpg envelope and exact member list read-only."""
    archive = evidence.archive
    if not archive.is_file() or archive.suffix.lower() != ".gpg":
        return EstateFinding(
            "quarantine_decryptability",
            EstateStatus.FAIL,
            f"quarantine archive unavailable or not .gpg: {archive}",
            path=str(archive),
        )
    if not _looks_encrypted_openpgp(archive):
        return EstateFinding(
            "quarantine_decryptability",
            EstateStatus.FAIL,
            f"quarantine archive is not encrypted OpenPGP: {archive}",
            path=str(archive),
        )
    if _sha256_file(archive) != evidence.sha256:
        return EstateFinding(
            "quarantine_decryptability",
            EstateStatus.FAIL,
            f"quarantine archive SHA-256 mismatch: {archive}",
            path=str(archive),
        )
    if not evidence.members:
        return EstateFinding(
            "quarantine_members",
            EstateStatus.WARN,
            "quarantine archive has no declared member list",
            "record exact members after a verified decrypt-and-list ceremony.",
            path=str(archive),
        )
    if passphrase_file is None:
        return EstateFinding(
            "quarantine_decryptability",
            EstateStatus.WARN,
            "archive envelope and hash verified; decrypt passphrase file not supplied",
            "supply an approved passphrase-file path for the bounded decrypt check.",
            path=str(archive),
        )
    if (
        not passphrase_file.is_file()
        or passphrase_file.is_symlink()
        or passphrase_file.stat().st_mode & 0o777 != 0o600
    ):
        return EstateFinding(
            "quarantine_decryptability",
            EstateStatus.FAIL,
            f"passphrase file unavailable or insecure: {passphrase_file}",
            path=str(passphrase_file),
        )
    try:
        with tempfile.NamedTemporaryFile(
            prefix="capauth-quarantine-", suffix=".tar", mode="w+b"
        ) as output:
            command = [
                "gpg",
                "--batch",
                "--quiet",
                "--passphrase-file",
                str(passphrase_file),
                "--decrypt",
                str(archive),
            ]
            result = subprocess.run(command, stdout=output, stderr=subprocess.PIPE, check=False)
            if result.returncode != 0:
                return EstateFinding(
                    "quarantine_decryptability",
                    EstateStatus.FAIL,
                    "quarantine archive decryption failed",
                    "verify the approved passphrase file and archive custody.",
                    path=str(archive),
                )
            output.flush()
            output.seek(0)
            with tarfile.open(fileobj=output, mode="r:") as tar:
                actual = tuple(sorted(member.name for member in tar.getmembers()))
    except (OSError, tarfile.TarError):
        return EstateFinding(
            "quarantine_decryptability",
            EstateStatus.FAIL,
            "decrypted quarantine is not a readable tar archive",
            path=str(archive),
        )
    if actual != evidence.members:
        return EstateFinding(
            "quarantine_members",
            EstateStatus.FAIL,
            "decrypted quarantine members do not match the declared list",
            "treat the archive as custody drift and reverify the exact member set.",
            path=str(archive),
        )
    return EstateFinding(
        "quarantine_decryptability",
        EstateStatus.OK,
        f"encrypted archive decrypted and matched {len(actual)} declared members",
        path=str(archive),
    )


def discover_roots(
    user_homes: Iterable[Path],
    explicit_roots: Iterable[Path] = (),
) -> tuple[list[Path], list[EstateFinding]]:
    """Discover canonical, legacy, agent, and named identity roots."""
    candidates: list[Path] = [Path(path).expanduser() for path in explicit_roots]
    findings: list[EstateFinding] = []
    for raw_home in user_homes:
        home = Path(raw_home).expanduser()
        legacy = home / ".capauth"
        canonical = home / ".skcapstone" / "capauth"
        if legacy.exists() and canonical.exists():
            if legacy.resolve() == canonical.resolve():
                findings.append(
                    EstateFinding(
                        "legacy_alias",
                        EstateStatus.OK,
                        f"legacy path {legacy} resolves to canonical {canonical.resolve()}",
                        path=str(legacy),
                        classification="alias",
                    )
                )
            else:
                findings.append(
                    EstateFinding(
                        "split_identity_root",
                        EstateStatus.FAIL,
                        f"legacy {legacy} and canonical {canonical} are distinct trees",
                        "quarantine and validate the legacy tree, then replace it with a "
                        "compatibility symlink under an approved change.",
                        path=str(legacy),
                        classification="legacy",
                    )
                )
        candidates.extend((legacy, canonical))
        sk_root = home / ".skcapstone"
        candidates.extend(sk_root.glob("identities/*/capauth"))
        candidates.extend(sk_root.glob("agents/*/capauth"))

    roots: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        if not candidate.exists():
            continue
        resolved = candidate.resolve()
        if resolved in seen or not resolved.is_dir():
            continue
        seen.add(resolved)
        roots.append(resolved)
    roots.sort(key=str)
    if not roots:
        findings.append(
            EstateFinding(
                "identity_roots",
                EstateStatus.WARN,
                "no CapAuth identity roots were discovered",
                "pass each user home with --user-home or an identity root with --root.",
            )
        )
    else:
        findings.append(
            EstateFinding(
                "identity_roots",
                EstateStatus.OK,
                f"discovered {len(roots)} unique identity root(s)",
            )
        )
    return roots, findings


def parse_syncthing_folders(config_path: Path, user_home: Path) -> list[SyncthingFolder]:
    """Parse folder paths from config.xml without returning its API key."""
    config = Path(config_path).expanduser()
    if not config.exists():
        return []
    try:
        root = ET.parse(config).getroot()
    except (ET.ParseError, OSError):
        return []
    folders: list[SyncthingFolder] = []
    for item in root.findall("folder"):
        raw_path = str(item.get("path") or "").strip()
        if not raw_path:
            continue
        if raw_path == "~" or raw_path.startswith("~/"):
            raw_path = str(user_home) + raw_path[1:]
        path = Path(os.path.expandvars(raw_path))
        if not path.is_absolute():
            path = user_home / path
        folders.append(
            SyncthingFolder(
                folder_id=str(item.get("id") or ""),
                path=path.resolve(strict=False),
                config_path=config.resolve(strict=False),
            )
        )
    return folders


def discover_syncthing_folders(user_homes: Iterable[Path]) -> list[SyncthingFolder]:
    """Find Syncthing configs in both supported per-user locations."""
    folders: list[SyncthingFolder] = []
    seen: set[tuple[Path, str, Path]] = set()
    for raw_home in user_homes:
        home = Path(raw_home).expanduser()
        for config in (
            home / ".local" / "state" / "syncthing" / "config.xml",
            home / ".config" / "syncthing" / "config.xml",
        ):
            for folder in parse_syncthing_folders(config, home):
                marker = (folder.config_path, folder.folder_id, folder.path)
                if marker not in seen:
                    seen.add(marker)
                    folders.append(folder)
    return folders


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def _capauth_sync_folder(folder: SyncthingFolder, roots: Iterable[Path]) -> bool:
    if folder.folder_id == "capauth-identity":
        return True
    return any(_is_within(root, folder.path) or _is_within(folder.path, root) for root in roots)


def check_syncthing_policy(
    folders: Iterable[SyncthingFolder], roots: Iterable[Path]
) -> list[EstateFinding]:
    """Require private-key and root-revocation ignores at the folder root."""
    findings: list[EstateFinding] = []
    relevant = [folder for folder in folders if _capauth_sync_folder(folder, roots)]
    if not relevant:
        return [
            EstateFinding(
                "syncthing_policy",
                EstateStatus.WARN,
                "no Syncthing folder containing a discovered CapAuth root was found",
                "confirm public identity distribution is intentionally disabled on this node.",
            )
        ]
    for folder in relevant:
        ignore_path = folder.path / ".stignore"
        rules: set[str] = set()
        try:
            for line in ignore_path.read_text(encoding="utf-8").splitlines():
                rule = line.strip()
                if rule and not rule.startswith(("#", "!")):
                    rules.add(rule)
        except OSError:
            pass
        missing: list[str] = []
        if not rules.intersection(PRIVATE_IGNORE_RULES):
            missing.append("**/private.*")
        if not rules.intersection(REVOCATION_IGNORE_RULES):
            missing.append("**/root-revocation.asc")
        if missing:
            findings.append(
                EstateFinding(
                    "syncthing_policy",
                    EstateStatus.FAIL,
                    f"Syncthing folder {folder.folder_id or '<unnamed>'} at "
                    f"{folder.path} lacks required exclusions: {', '.join(missing)}",
                    f"add the exclusions to {ignore_path} before enabling sync.",
                    path=str(folder.path),
                    classification="unsafe-sync-root",
                )
            )
        else:
            findings.append(
                EstateFinding(
                    "syncthing_policy",
                    EstateStatus.OK,
                    f"Syncthing folder {folder.folder_id or '<unnamed>'} at "
                    f"{folder.path} excludes private keys and root revocations",
                    path=str(folder.path),
                    classification="public-only-sync",
                )
            )
    return findings


def _load_key_fingerprint(path: Path) -> Optional[str]:
    try:
        import pgpy

        key, _ = pgpy.PGPKey.from_file(str(path))
        return _normalize_fingerprint(str(key.fingerprint))
    except Exception:
        return None


def scan_identity_roots(roots: Iterable[Path]) -> tuple[list[KeyArtifact], list[EstateFinding]]:
    """Scan known OpenPGP identity filenames, including conflict copies."""
    artifacts: list[KeyArtifact] = []
    findings: list[EstateFinding] = []
    seen: set[Path] = set()
    for root in roots:
        for path in root.rglob("*.asc"):
            name = path.name.lower()
            is_private = "private" in name
            is_public = "public" in name
            if not (is_private or is_public) or not path.is_file():
                continue
            resolved = path.resolve(strict=False)
            if resolved in seen:
                continue
            seen.add(resolved)
            fingerprint = _load_key_fingerprint(path)
            if fingerprint is None:
                findings.append(
                    EstateFinding(
                        "unreadable_key_artifact",
                        EstateStatus.FAIL,
                        f"OpenPGP-looking identity artifact is not parseable: {path}",
                        "quarantine it for review; do not delete an unclassified key file.",
                        path=str(path),
                        classification="unclassified",
                    )
                )
                continue
            artifacts.append(
                KeyArtifact(
                    fingerprint=fingerprint,
                    source="private-file" if is_private else "public-file",
                    path=path,
                    secret=is_private,
                    conflict=bool(CONFLICT_RE.search(path.name)),
                )
            )
    return artifacts, findings


def scan_gpg_keyring(gnupg_home: Path) -> tuple[list[KeyArtifact], list[EstateFinding]]:
    """List primary public and secret fingerprints from one GnuPG home."""
    if shutil.which("gpg") is None:
        return [], [
            EstateFinding(
                "gpg_keyring",
                EstateStatus.WARN,
                "gpg is unavailable; keyring discovery was skipped",
                "install gpg or rerun the audit on a host with GnuPG available.",
            )
        ]
    home = Path(gnupg_home).expanduser().resolve(strict=False)
    if not home.exists():
        return [], [
            EstateFinding(
                "gpg_keyring",
                EstateStatus.OK,
                f"no GnuPG home exists at {home}; no keyring material to inventory",
                path=str(home),
            )
        ]
    if not home.is_dir():
        return [], [
            EstateFinding(
                "gpg_keyring",
                EstateStatus.WARN,
                f"configured GnuPG home is not a directory: {home}",
                "correct the GnuPG home path and rerun.",
                path=str(home),
            )
        ]
    artifacts: list[KeyArtifact] = []
    findings: list[EstateFinding] = []
    for secret, command in (
        (False, "--list-keys"),
        (True, "--list-secret-keys"),
    ):
        try:
            proc = subprocess.run(
                [
                    "gpg",
                    "--batch",
                    "--homedir",
                    str(home),
                    "--with-colons",
                    "--fingerprint",
                    command,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            findings.append(
                EstateFinding(
                    "gpg_keyring",
                    EstateStatus.WARN,
                    f"could not inspect GnuPG home {home}: {type(exc).__name__}",
                    "check GnuPG availability and permissions, then rerun.",
                    path=str(home),
                )
            )
            continue
        if proc.returncode not in (0, 2):
            findings.append(
                EstateFinding(
                    "gpg_keyring",
                    EstateStatus.WARN,
                    f"gpg could not list {'secret' if secret else 'public'} keys in {home} "
                    f"(exit {proc.returncode})",
                    "check GnuPG home permissions, then rerun.",
                    path=str(home),
                )
            )
            continue
        want_fingerprint = False
        primary_records = {"sec", "sec#"} if secret else {"pub"}
        for line in proc.stdout.splitlines():
            fields = line.split(":")
            record_type = fields[0] if fields else ""
            if record_type in primary_records:
                want_fingerprint = True
                continue
            if want_fingerprint and record_type == "fpr" and len(fields) > 9:
                try:
                    fingerprint = _normalize_fingerprint(fields[9])
                except ValueError:
                    want_fingerprint = False
                    continue
                artifacts.append(
                    KeyArtifact(
                        fingerprint=fingerprint,
                        source="gpg-secret" if secret else "gpg-public",
                        path=home,
                        secret=secret,
                    )
                )
                want_fingerprint = False
            elif record_type in {"sub", "ssb", "pub", "sec", "sec#"}:
                want_fingerprint = False
    return artifacts, findings


def _quarantine_finding(policy: IdentityPolicy) -> EstateFinding:
    evidence = policy.quarantine
    if evidence is None:
        return EstateFinding(
            "quarantine_evidence",
            EstateStatus.FAIL,
            f"retired key {policy.fingerprint} has no encrypted-quarantine evidence",
            "create and decrypt-test an encrypted archive, record its path, SHA-256, "
            "verified_at, and verified_by before removing any copy.",
            fingerprint=policy.fingerprint,
            classification="retired",
            identity_type=policy.identity_type,
        )
    if evidence.archive.suffix.lower() != ".gpg" or not evidence.archive.is_file():
        return EstateFinding(
            "quarantine_evidence",
            EstateStatus.FAIL,
            f"retired key {policy.fingerprint} quarantine archive is unavailable or not .gpg: "
            f"{evidence.archive}",
            "restore the encrypted archive to the declared custody path and reverify it.",
            fingerprint=policy.fingerprint,
            path=str(evidence.archive),
            classification="retired",
            identity_type=policy.identity_type,
        )
    if not _looks_encrypted_openpgp(evidence.archive):
        return EstateFinding(
            "quarantine_evidence",
            EstateStatus.FAIL,
            f"retired key {policy.fingerprint} quarantine archive is not an "
            "encrypted OpenPGP message",
            "recreate the archive with authenticated OpenPGP encryption, "
            "decrypt-test it, and update its attestation.",
            fingerprint=policy.fingerprint,
            path=str(evidence.archive),
            classification="retired",
            identity_type=policy.identity_type,
        )
    digest = _sha256_file(evidence.archive)
    if digest != evidence.sha256:
        return EstateFinding(
            "quarantine_evidence",
            EstateStatus.FAIL,
            f"retired key {policy.fingerprint} quarantine archive SHA-256 mismatch",
            "treat the archive as damaged or replaced; reconstruct and decrypt-test custody.",
            fingerprint=policy.fingerprint,
            path=str(evidence.archive),
            classification="retired",
            identity_type=policy.identity_type,
        )
    return EstateFinding(
        "quarantine_evidence",
        EstateStatus.OK,
        f"retired key {policy.fingerprint} has hash-verified encrypted quarantine "
        f"attested by {evidence.verified_by} at {evidence.verified_at}",
        fingerprint=policy.fingerprint,
        path=str(evidence.archive),
        classification="retired",
        identity_type=policy.identity_type,
    )


def classify_artifacts(
    artifacts: Iterable[KeyArtifact], manifest: EstateManifest
) -> list[EstateFinding]:
    """Classify discovered keys against lifecycle and placement policy."""
    findings: list[EstateFinding] = []
    unique: dict[tuple[str, str, Optional[str]], KeyArtifact] = {}
    for artifact in artifacts:
        marker = (
            artifact.fingerprint,
            artifact.source,
            str(artifact.path.resolve(strict=False)) if artifact.path else None,
        )
        unique[marker] = artifact

    secret_locations: dict[str, set[str]] = {}
    for artifact in unique.values():
        policy = manifest.identities.get(artifact.fingerprint)
        path_text = str(artifact.path) if artifact.path else None
        if artifact.secret:
            secret_locations.setdefault(artifact.fingerprint, set()).add(
                path_text or artifact.source
            )
        if artifact.conflict:
            findings.append(
                EstateFinding(
                    "syncthing_conflict",
                    EstateStatus.FAIL,
                    f"Syncthing conflict key artifact: {artifact.path}",
                    "classify its fingerprint, verify encrypted quarantine, and remove it "
                    "under an approved change.",
                    fingerprint=artifact.fingerprint,
                    path=path_text,
                    classification="sync-conflict",
                    identity_type=policy.identity_type if policy else None,
                )
            )
            continue
        if policy is None:
            findings.append(
                EstateFinding(
                    "unknown_key",
                    EstateStatus.FAIL if artifact.secret else EstateStatus.WARN,
                    f"unmanifested {'secret' if artifact.secret else 'public'} key "
                    f"{artifact.fingerprint} found via {artifact.source}",
                    "identify the owner and add an active or retired manifest record; "
                    "do not delete unknown key material.",
                    fingerprint=artifact.fingerprint,
                    path=path_text,
                    classification="unknown",
                )
            )
            continue
        if policy.status == "retired":
            findings.append(
                EstateFinding(
                    "retired_key_present",
                    EstateStatus.FAIL,
                    f"retired {policy.identity_type} key {artifact.fingerprint} remains in "
                    f"{artifact.source}",
                    "confirm quarantine_evidence is OK, then remove this copy under an "
                    "approved change and rerun the estate doctor.",
                    fingerprint=artifact.fingerprint,
                    path=path_text,
                    classification="retired",
                    identity_type=policy.identity_type,
                )
            )
            continue
        if artifact.secret:
            allowed = any(
                artifact.path is not None and _is_within(artifact.path, root)
                for root in policy.allowed_secret_roots
            )
            if not policy.allowed_secret_roots:
                findings.append(
                    EstateFinding(
                        "secret_placement",
                        EstateStatus.WARN,
                        f"active {policy.identity_type} secret key {artifact.fingerprint} "
                        "has no allowed_secret_roots policy",
                        "declare its intentional custody roots in the manifest.",
                        fingerprint=artifact.fingerprint,
                        path=path_text,
                        classification="active",
                        identity_type=policy.identity_type,
                    )
                )
            elif not allowed:
                findings.append(
                    EstateFinding(
                        "secret_placement",
                        EstateStatus.FAIL,
                        f"active {policy.identity_type} secret key {artifact.fingerprint} is "
                        f"outside its allowed custody roots ({artifact.source})",
                        "quarantine the unexpected copy, or explicitly approve its root in "
                        "the manifest.",
                        fingerprint=artifact.fingerprint,
                        path=path_text,
                        classification="active-misplaced",
                        identity_type=policy.identity_type,
                    )
                )
            else:
                findings.append(
                    EstateFinding(
                        "secret_placement",
                        EstateStatus.OK,
                        f"active {policy.identity_type} secret key {artifact.fingerprint} is "
                        "inside an allowed custody root",
                        fingerprint=artifact.fingerprint,
                        path=path_text,
                        classification="active",
                        identity_type=policy.identity_type,
                    )
                )
        else:
            findings.append(
                EstateFinding(
                    "public_key",
                    EstateStatus.OK,
                    f"active {policy.identity_type} public key {artifact.fingerprint} found "
                    f"via {artifact.source}",
                    fingerprint=artifact.fingerprint,
                    path=path_text,
                    classification="active",
                    identity_type=policy.identity_type,
                )
            )

    for fingerprint, locations in secret_locations.items():
        if len(locations) > 1:
            policy = manifest.identities.get(fingerprint)
            findings.append(
                EstateFinding(
                    "duplicate_secret",
                    EstateStatus.WARN,
                    f"secret key {fingerprint} exists in {len(locations)} distinct locations",
                    "confirm every location is intentional; prefer scoped service/node "
                    "identities over fleet-wide signer copies.",
                    fingerprint=fingerprint,
                    classification=policy.status if policy else "unknown",
                    identity_type=policy.identity_type if policy else None,
                )
            )
    return findings


def audit_estate(
    manifest_path: Path,
    *,
    user_homes: Iterable[Path],
    explicit_roots: Iterable[Path] = (),
    syncthing_configs: Iterable[tuple[Path, Path]] = (),
    include_gpg: bool = True,
    passphrase_file: Optional[Path] = None,
) -> EstateReport:
    """Run the complete read-only identity-estate audit."""
    manifest = EstateManifest.load(manifest_path)
    homes = [Path(path).expanduser() for path in user_homes]
    roots, findings = discover_roots(homes, explicit_roots)

    folders = discover_syncthing_folders(homes)
    for config, home in syncthing_configs:
        folders.extend(parse_syncthing_folders(config, home))
    findings.extend(check_syncthing_policy(folders, roots))

    artifacts, scan_findings = scan_identity_roots(roots)
    findings.extend(scan_findings)
    if include_gpg:
        gpg_homes = {home / ".gnupg" for home in homes}
        if os.environ.get("GNUPGHOME"):
            gpg_homes.add(Path(os.environ["GNUPGHOME"]).expanduser())
        for gpg_home in sorted(gpg_homes, key=str):
            gpg_artifacts, gpg_findings = scan_gpg_keyring(gpg_home)
            artifacts.extend(gpg_artifacts)
            findings.extend(gpg_findings)

    findings.extend(classify_artifacts(artifacts, manifest))
    for policy in manifest.identities.values():
        if policy.status == "retired":
            findings.append(_quarantine_finding(policy))
            if policy.quarantine is not None and (
                policy.quarantine.members or passphrase_file is not None
            ):
                findings.append(
                    quarantine_archive_metadata(policy.quarantine, passphrase_file=passphrase_file)
                )
    return EstateReport(manifest=manifest, roots=roots, findings=findings)


def format_estate_report(report: EstateReport) -> str:
    """Render a stable plain-text report."""
    lines = [
        "capauth doctor estate",
        "",
        f"  manifest  {report.manifest.path}",
        f"  sha256    {report.manifest.digest}",
        "",
    ]
    width = max((len(finding.code) for finding in report.findings), default=0)
    for finding in report.findings:
        lines.append(
            f"  [{finding.status.value:<4}] {finding.code.ljust(width)}  {finding.detail}"
        )
        if finding.remediation and finding.status is not EstateStatus.OK:
            lines.append(f"         -> {finding.remediation}")
    lines.extend(("", f"overall: {report.overall.value}"))
    return "\n".join(lines)


def write_evidence(report: EstateReport, path: Path) -> Path:
    """Atomically write secret-free JSON evidence with owner-only permissions."""
    destination = Path(path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(
            json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        temporary.replace(destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return destination
