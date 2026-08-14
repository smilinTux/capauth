"""Automated key-custody doctor checks for CapAuth.

Custody failure has already bitten this project once: commit ``456cb3a`` records a
Nextcloud code-signing key that was *never stored* and turned out to be
unrecoverable, only discovered when the issued PR #1054 cert had to be discarded
and re-CSR'd. Nothing automated verified the custody preconditions at the time.

This module is that missing verification. It runs a set of read-only ``doctor``
checks over the key-custody state and reports each as ``OK`` / ``WARN`` / ``FAIL``
with a plain-language remediation hint:

  * identity key material is present,
  * the private key is not group/world readable (perms must be ``0600``),
  * the identity key is not revoked or expired (reuses the shipped
    revocation/expiry predicates from :mod:`capauth.crypto.pgpy_backend`),
  * a root revocation certificate exists at the documented path,
  * the service keystore passes a SQLite integrity check,
  * a recent backup exists (the ``scripts/capauth-backup.sh`` / ``capauth-backup``
    timer automation shipped under coord ``0555cef0``),
  * that backup is *restorable*: the identity public key is copied to a throwaway
    temp dir and its fingerprint is checked against the live key WITHOUT touching
    live state,
  * the Nextcloud code-signing key is present in its on-disk home with safe perms.

HARD RULE: no secret key material is ever read into output. Checks report only
paths, public fingerprints, mtimes, byte sizes, octal file modes, and pass/fail.
Private keys are ``stat``-ed for permissions but never opened; only the *public*
key is parsed (to read its fingerprint / revocation / expiry), and public keys
are, by definition, public.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from . import resolve_capauth_home

#: The live classical root fingerprint (see :mod:`capauth.pqc_root_identity`).
#: Used only to *label* whether a home looks like the root identity; a mismatch
#: is never a hard failure (per-agent/operator homes are legitimate).
LIVE_ROOT_FINGERPRINT = "02BC0EB3CAD31DB691A753C70C5629AB893F9746"

#: Documented revocation-cert filename (docs/COLD_MACHINE_BOOTSTRAP_AND_DR.md).
REVOCATION_CERT_FILENAME = "root-revocation.asc"

#: Default freshness window for backups (mirrors CAPAUTH_BACKUP_RETAIN_DAYS=14).
DEFAULT_MAX_BACKUP_AGE_DAYS = 14

#: WARN (not FAIL) when the identity key expires within this many days.
EXPIRY_WARN_DAYS = 30


class Status(str, Enum):
    """Outcome of a single custody check."""

    OK = "OK"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass
class CheckResult:
    """Result of one custody check.

    Attributes:
        name: Short stable identifier for the check.
        status: OK / WARN / FAIL.
        detail: Human-readable finding. NEVER contains secret material - only
            paths, public fingerprints, sizes, mtimes, and modes.
        remediation: Plain-language hint for fixing a WARN/FAIL. Empty on OK.
    """

    name: str
    status: Status
    detail: str
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status.value,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass
class CustodyPaths:
    """Resolved filesystem locations the custody checks operate on.

    All fields are overridable so tests can point checks at synthetic fixtures.
    """

    home: Path
    identity_dir: Path
    private_key: Path
    public_key: Path
    profile: Path
    revocation_cert: Path
    keystore: Path
    backup_root: Path
    nextcloud_key: Path
    expected_fingerprint: Optional[str] = None

    @classmethod
    def resolve(cls, home: Optional[Path] = None) -> "CustodyPaths":
        """Build the default path set from the resolved CapAuth home.

        Environment overrides (shared with the backup automation where they
        already exist):

          * ``CAPAUTH_DB_PATH``          keystore SQLite path
          * ``CAPAUTH_BACKUP_DIR``       backup root
          * ``CAPAUTH_REVOCATION_CERT``  root revocation certificate path
          * ``CAPAUTH_NEXTCLOUD_KEY``    Nextcloud code-signing key path
          * ``CAPAUTH_EXPECTED_ROOT_FP`` fingerprint this home is expected to hold
        """
        base = resolve_capauth_home(home)
        identity_dir = base / "identity"

        keystore = os.environ.get("CAPAUTH_DB_PATH")
        backup_dir = os.environ.get("CAPAUTH_BACKUP_DIR")
        rev_cert = os.environ.get("CAPAUTH_REVOCATION_CERT")
        nc_key = os.environ.get("CAPAUTH_NEXTCLOUD_KEY")

        return cls(
            home=base,
            identity_dir=identity_dir,
            private_key=identity_dir / "private.asc",
            public_key=identity_dir / "public.asc",
            profile=identity_dir / "profile.json",
            revocation_cert=(
                Path(rev_cert).expanduser()
                if rev_cert
                else identity_dir / REVOCATION_CERT_FILENAME
            ),
            keystore=(Path(keystore).expanduser() if keystore else base / "service" / "keys.db"),
            backup_root=(Path(backup_dir).expanduser() if backup_dir else base / "backups"),
            nextcloud_key=(
                Path(nc_key).expanduser()
                if nc_key
                else Path.home() / ".nextcloud" / "certificates" / "capauth.key"
            ),
            expected_fingerprint=os.environ.get("CAPAUTH_EXPECTED_ROOT_FP"),
        )


# ── low-level helpers (no secret material ever leaves these) ──────────────────


def _mtime_iso(path: Path) -> str:
    """UTC ISO mtime of a path, for reporting freshness (not secret)."""
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()


def _mode_octal(path: Path) -> str:
    """Octal permission bits, e.g. ``0o600`` -> ``600`` (not secret)."""
    return oct(stat.S_IMODE(path.stat().st_mode))[2:].rjust(3, "0")


def _group_or_world_accessible(path: Path) -> bool:
    """True if any group/other permission bit is set (r, w, or x)."""
    return bool(stat.S_IMODE(path.stat().st_mode) & 0o077)


def _load_public_fingerprint(public_key_path: Path):
    """Load a PUBLIC key and return ``(fingerprint, pgpy_key)``.

    Only the public key is read - never a private key. Returns ``(None, None)``
    if PGPy is unavailable or the file cannot be parsed as a key.
    """
    try:
        import pgpy  # noqa: F401  (import guarded; PGPy is optional on 3.13+)
    except Exception:
        return None, None
    try:
        key, _ = pgpy.PGPKey.from_file(str(public_key_path))
        fpr = str(key.fingerprint).replace(" ", "")
        return fpr, key
    except Exception:
        return None, None


# ── individual checks ─────────────────────────────────────────────────────────


def check_identity_present(
    private_key: Path,
    public_key: Path,
    profile: Path,
    expected_fingerprint: Optional[str] = None,
) -> CheckResult:
    """The identity key material exists where it is expected."""
    missing = [
        label
        for label, p in (
            ("private.asc", private_key),
            ("public.asc", public_key),
            ("profile.json", profile),
        )
        if not p.exists()
    ]
    if private_key.exists() is False:
        return CheckResult(
            "identity_present",
            Status.FAIL,
            f"no identity private key at {private_key} (missing: {', '.join(missing)})",
            "run 'capauth init' or restore ~/.capauth/identity from offline "
            "custody per docs/COLD_MACHINE_BOOTSTRAP_AND_DR.md (Step 4).",
        )
    if missing:
        return CheckResult(
            "identity_present",
            Status.WARN,
            f"private key present at {private_key} but missing: {', '.join(missing)}",
            "restore the missing identity file(s); re-export the public key with "
            "'capauth export-pubkey' if only public.asc is absent.",
        )

    fpr, _ = _load_public_fingerprint(public_key)
    label = f"fingerprint={fpr}" if fpr else "fingerprint=unreadable(PGPy unavailable)"
    if fpr and fpr.upper() == LIVE_ROOT_FINGERPRINT:
        label += " (ROOT identity)"
    if expected_fingerprint and fpr and fpr.upper() != expected_fingerprint.upper():
        return CheckResult(
            "identity_present",
            Status.WARN,
            f"identity present but {label} != expected {expected_fingerprint}",
            "confirm this home holds the intended key; a wrong key in the "
            "expected place is a custody drift.",
        )
    return CheckResult(
        "identity_present",
        Status.OK,
        f"identity material present at {private_key.parent} ({label})",
    )


def _key_summary(path: Path) -> tuple[Optional[str], str]:
    """``(fingerprint, uid-ish label)`` for a key file, both best-effort."""
    try:
        import pgpy

        key, _ = pgpy.PGPKey.from_file(str(path))
        fpr = str(key.fingerprint).replace(" ", "")
        uids = [str(u.name) for u in key.userids if str(u.name)]
        emails = [str(u.email) for u in key.userids if str(u.email)]
        label = uids[0] if uids else "?"
        if emails:
            label = f"{label} <{emails[0]}>"
        return fpr, label
    except Exception:
        return None, "?"


def check_keypair_match(private_key: Path, public_key: Path) -> CheckResult:
    """private.asc and public.asc are the two halves of ONE key.

    Discovered on Chef's primary node 2026-08-14: the identity held a private
    key for ``test-agent <test-agent@skcapstone.local>`` next to a public key
    for a completely different owner. Every signature it produced was
    unverifiable by anyone holding the published key, and ``identity_present``
    reported OK throughout because it only ever reads public.asc. Same shape as
    the Jarvis incident, where a profile advertised a fingerprint the home did
    not hold.

    A key that cannot verify what it signs is not an identity, hence FAIL.
    Missing halves are someone else's check to fail, so they only WARN here.
    """
    if not private_key.exists() or not public_key.exists():
        return CheckResult(
            "keypair_match",
            Status.WARN,
            "cannot compare the keypair: "
            f"{'private.asc' if not private_key.exists() else 'public.asc'} is missing",
            "restore the missing half; see the identity_present check.",
        )

    priv_fpr, priv_label = _key_summary(private_key)
    pub_fpr, pub_label = _key_summary(public_key)
    if priv_fpr is None or pub_fpr is None:
        return CheckResult(
            "keypair_match",
            Status.WARN,
            "cannot compare the keypair: a key is unreadable (PGPy unavailable "
            "or the armor is malformed)",
            "install PGPy, or re-export the identity keys.",
        )

    if priv_fpr == pub_fpr:
        return CheckResult(
            "keypair_match",
            Status.OK,
            f"private.asc and public.asc are the same key ({priv_fpr}, {pub_label})",
        )

    return CheckResult(
        "keypair_match",
        Status.FAIL,
        "private.asc and public.asc do not match: "
        f"private={priv_fpr} ({priv_label}) vs public={pub_fpr} ({pub_label}). "
        "Nothing this identity signs can be verified against its published key.",
        "identify which half is the stray key (the uid usually says), then "
        "restore the correct counterpart from offline custody. Do NOT simply "
        "re-export public.asc from the private key: that would publish a new "
        "identity under the old name.",
    )


def check_private_key_permissions(private_key: Path) -> CheckResult:
    """The private key file is not group/world accessible (must be 0600)."""
    if not private_key.exists():
        return CheckResult(
            "private_key_perms",
            Status.FAIL,
            f"private key not found at {private_key}",
            "restore or re-init the identity before checking permissions.",
        )
    if os.name != "posix":
        return CheckResult(
            "private_key_perms",
            Status.WARN,
            f"cannot verify POSIX permissions on this platform (os.name={os.name})",
            "ensure the private key is readable only by its owner.",
        )
    mode = _mode_octal(private_key)
    if _group_or_world_accessible(private_key):
        return CheckResult(
            "private_key_perms",
            Status.FAIL,
            f"private key {private_key} is group/world accessible (mode {mode})",
            f"chmod 600 {private_key}",
        )
    return CheckResult(
        "private_key_perms",
        Status.OK,
        f"private key permissions are owner-only (mode {mode})",
    )


def check_key_status(public_key: Path) -> CheckResult:
    """The identity key is neither revoked nor expired.

    Reuses the exact predicates shipped in
    :func:`capauth.crypto.pgpy_backend._assert_key_usable` (revocation
    signatures on the primary key, primary-key expiry).
    """
    if not public_key.exists():
        return CheckResult(
            "key_status",
            Status.WARN,
            f"no public key at {public_key} to check revocation/expiry",
            "restore or export the public key, then re-run.",
        )
    fpr, key = _load_public_fingerprint(public_key)
    if key is None:
        return CheckResult(
            "key_status",
            Status.WARN,
            "cannot parse public key (PGPy unavailable or not a key file); "
            "revocation/expiry not verified",
            "install PGPy on this interpreter to enable revocation/expiry checks.",
        )
    # Same predicates as pgpy_backend._assert_key_usable (lines 47-50).
    for _rev in key.revocation_signatures:
        return CheckResult(
            "key_status",
            Status.FAIL,
            f"identity key {fpr} carries a revocation signature (REVOKED)",
            "this key is revoked and must not be trusted; rotate to a fresh "
            "identity per docs/ROOT_ROTATION_CEREMONY.md.",
        )
    if key.is_expired:
        return CheckResult(
            "key_status",
            Status.FAIL,
            f"identity key {fpr} is EXPIRED (expired {key.expires_at})",
            "extend the key's expiry or rotate to a fresh identity.",
        )
    expires_at = key.expires_at
    if expires_at is not None:
        now = datetime.now(tz=timezone.utc)
        exp = expires_at if expires_at.tzinfo else expires_at.replace(tzinfo=timezone.utc)
        if exp - now <= timedelta(days=EXPIRY_WARN_DAYS):
            return CheckResult(
                "key_status",
                Status.WARN,
                f"identity key {fpr} expires soon ({exp.isoformat()})",
                "plan a key rotation / expiry extension before it lapses.",
            )
    return CheckResult(
        "key_status",
        Status.OK,
        f"identity key {fpr} is not revoked and not expired",
    )


def _revocation_fingerprints(cert_path: Path) -> tuple[bool, set[str]] | None:
    """``(has_revocation_sig, fingerprints)`` for a cert, or None if unparseable.

    Reads only public material: the key packet's fingerprint and the SIGNATURE
    TYPES present. No secret bytes are touched and nothing is imported into a
    keyring, so inspecting a cert can never accidentally arm it.
    """
    try:
        import pgpy
        from pgpy.constants import SignatureType
    except Exception:
        return None

    try:
        raw = cert_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None

    # A real `gpg --gen-revoke` emits a BARE revocation signature packet wrapped
    # in "BEGIN PGP PUBLIC KEY BLOCK" armor. pgpy rejects that both ways: as a
    # key (no key packet) and as a signature (wrong armor label). Try the
    # signature reading first, swapping the label, since that is the artifact
    # operators actually produce.
    try:
        sig = pgpy.PGPSignature.from_blob(raw.replace("PGP PUBLIC KEY BLOCK", "PGP SIGNATURE"))
        if sig.type in (
            SignatureType.KeyRevocation,
            SignatureType.SubkeyRevocation,
            SignatureType.CertRevocation,
        ):
            # A signature names its signer by 16-hex key id, not a full
            # fingerprint. Callers compare against the fingerprint, so hand back
            # the key id and let the comparison be suffix-aware.
            return True, {str(sig.signer).upper()}
        return False, set()
    except Exception:
        pass

    try:
        key, _ = pgpy.PGPKey.from_file(str(cert_path))
    except Exception:
        return None

    fprs = {str(key.fingerprint).replace(" ", "")}
    has_rev = False
    try:
        for sig in key.__sig__:
            if sig.type in (SignatureType.KeyRevocation, SignatureType.SubkeyRevocation):
                has_rev = True
        for uid in key.userids:
            for sig in uid.__sig__:
                if sig.type == SignatureType.CertRevocation:
                    has_rev = True
    except Exception:
        return None
    return has_rev, fprs


def check_revocation_cert(revocation_cert: Path, public_key: Path | None = None) -> CheckResult:
    """A root revocation certificate exists at the documented path.

    Without a pre-generated revocation cert, a compromised/lost key cannot be
    repudiated. We check presence + that it looks armored; we never read its
    body into output.
    """
    if not revocation_cert.exists():
        return CheckResult(
            "revocation_cert",
            Status.FAIL,
            f"no revocation certificate at {revocation_cert}",
            "generate one now (see docs/CRYPTO_SPEC.md 'Generate revocation "
            "certificate') and keep a copy in offline custody; set "
            "CAPAUTH_REVOCATION_CERT if it lives elsewhere.",
        )
    try:
        head = revocation_cert.read_text(encoding="utf-8", errors="ignore")[:64]
    except OSError as exc:
        return CheckResult(
            "revocation_cert",
            Status.WARN,
            f"revocation cert present at {revocation_cert} but unreadable: {exc}",
            "check file permissions on the revocation certificate.",
        )
    if "BEGIN PGP" not in head:
        return CheckResult(
            "revocation_cert",
            Status.WARN,
            f"file at {revocation_cert} is not an ASCII-armored PGP block",
            "confirm this is a real revocation certificate.",
        )
    size = revocation_cert.stat().st_size
    detail = (
        f"revocation certificate present ({revocation_cert}, {size} bytes, "
        f"mtime {_mtime_iso(revocation_cert)})"
    )

    # Presence is not protection. A file that merely LOOKS armored satisfies a
    # presence check while repudiating nothing, so the cert must actually carry
    # a key-revocation signature, and for THIS key.
    parsed = _revocation_fingerprints(revocation_cert)
    if parsed is None:
        return CheckResult(
            "revocation_cert",
            Status.WARN,
            f"{detail}, but it could not be parsed as a PGP key "
            "(PGPy unavailable, or the armor is malformed)",
            "verify the certificate in a throwaway GNUPGHOME; an unparseable "
            "cert cannot be relied on to revoke anything.",
        )
    has_rev, fprs = parsed
    if not has_rev:
        return CheckResult(
            "revocation_cert",
            Status.FAIL,
            f"{detail}, but it carries no key-revocation signature: it repudiates nothing",
            "regenerate it with 'gpg --gen-revoke <fpr>' and verify it flips a "
            "throwaway keyring's validity field to 'r' before trusting it.",
        )
    if public_key is not None and public_key.exists():
        live_fpr, _ = _load_public_fingerprint(public_key)
        known = {f.upper() for f in fprs}
        live_up = live_fpr.upper() if live_fpr else ""
        # A bare revocation signature identifies its signer by KEY ID (the last
        # 16 hex of the fingerprint), so accept an exact match or that suffix.
        matched = bool(live_up) and (
            live_up in known or any(live_up.endswith(f) for f in known if len(f) == 16)
        )
        if live_fpr and not matched:
            return CheckResult(
                "revocation_cert",
                Status.FAIL,
                f"{detail}, but it revokes {', '.join(sorted(fprs))}, not this "
                f"identity's key {live_fpr}",
                "a revocation certificate for a different key protects nothing "
                "here; generate one for the live identity key.",
            )
    return CheckResult(
        "revocation_cert", Status.OK, f"{detail}, carries a key-revocation signature"
    )


def check_keystore_integrity(keystore: Path) -> CheckResult:
    """The service keystore SQLite DB passes an integrity check (read-only)."""
    if not keystore.exists():
        return CheckResult(
            "keystore_integrity",
            Status.WARN,
            f"no service keystore at {keystore}",
            "expected only where the verification service runs; the keystore is "
            "rebuildable from re-enrollment, but confirm this is intentional.",
        )
    try:
        # Read-only URI open: never mutates the live DB.
        uri = f"file:{keystore}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        try:
            row = conn.execute("PRAGMA integrity_check").fetchone()
        finally:
            conn.close()
    except sqlite3.DatabaseError as exc:
        return CheckResult(
            "keystore_integrity",
            Status.FAIL,
            f"keystore {keystore} failed to open / is corrupt: {exc}",
            "restore keys.db from the most recent capauth backup "
            "(scripts/capauth-backup.sh output).",
        )
    result = row[0] if row else "unknown"
    if result != "ok":
        return CheckResult(
            "keystore_integrity",
            Status.FAIL,
            f"keystore {keystore} integrity_check returned: {result}",
            "restore keys.db from the most recent capauth backup.",
        )
    return CheckResult(
        "keystore_integrity",
        Status.OK,
        f"keystore {keystore} passes SQLite integrity_check",
    )


def _newest_backup_dir(backup_root: Path) -> Optional[Path]:
    """Return the most recently modified ``capauth-backup-*`` dir, or None."""
    if not backup_root.exists():
        return None
    candidates = [p for p in backup_root.glob("capauth-backup-*") if p.is_dir()]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def check_backups_configured(
    backup_root: Path,
    max_age_days: int = DEFAULT_MAX_BACKUP_AGE_DAYS,
) -> CheckResult:
    """A recent backup exists (the 0555cef0 backup automation ran)."""
    newest = _newest_backup_dir(backup_root)
    if newest is None:
        return CheckResult(
            "backups_configured",
            Status.FAIL,
            f"no capauth-backup-* snapshot under {backup_root}",
            "run scripts/capauth-backup.sh and enable the capauth-backup.timer "
            "(coord 0555cef0) so identity state is backed up.",
        )
    age_days = (
        datetime.now(tz=timezone.utc)
        - datetime.fromtimestamp(newest.stat().st_mtime, tz=timezone.utc)
    ).total_seconds() / 86400.0
    if age_days > max_age_days:
        return CheckResult(
            "backups_configured",
            Status.WARN,
            f"newest backup {newest.name} is {age_days:.1f} days old (> {max_age_days}d window)",
            "run scripts/capauth-backup.sh or check the capauth-backup.timer; backups are stale.",
        )
    return CheckResult(
        "backups_configured",
        Status.OK,
        f"recent backup present ({newest.name}, {age_days:.1f} days old)",
    )


def _newest_backup_public_key(backup_root: Path) -> Optional[Path]:
    """Find the newest identity ``public.asc`` anywhere under the backup root."""
    if not backup_root.exists():
        return None
    keys = list(backup_root.rglob("public.asc"))
    if not keys:
        return None
    return max(keys, key=lambda p: p.stat().st_mtime)


def check_backup_restorable(live_public_key: Path, backup_root: Path) -> CheckResult:
    """A backed-up identity public key restores and matches the live fingerprint.

    Copies the backed-up ``public.asc`` into a throwaway temp dir and compares
    its fingerprint to the live key. NEVER touches or writes live key state; the
    temp dir is always removed.
    """
    backup_key = _newest_backup_public_key(backup_root)
    if backup_key is None:
        return CheckResult(
            "backup_restorable",
            Status.WARN,
            f"no identity public.asc found under {backup_root} to test restore",
            "include the identity public key in the backup set so restorability "
            "can be verified (the keys.db backup alone cannot prove this).",
        )
    if not live_public_key.exists():
        return CheckResult(
            "backup_restorable",
            Status.WARN,
            f"backup public key found ({backup_key}) but no live key at "
            f"{live_public_key} to compare against",
            "restore the live identity, then re-run to confirm the backup matches.",
        )

    tmpdir = tempfile.mkdtemp(prefix="capauth-restore-check-")
    try:
        restored = Path(tmpdir) / "public.asc"
        shutil.copy2(backup_key, restored)  # read-only against live: copies backup
        backup_fpr, _ = _load_public_fingerprint(restored)
        live_fpr, _ = _load_public_fingerprint(live_public_key)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    if backup_fpr is None or live_fpr is None:
        return CheckResult(
            "backup_restorable",
            Status.WARN,
            "could not read fingerprints (PGPy unavailable); restore not verified",
            "install PGPy on this interpreter to verify backup restorability.",
        )
    if backup_fpr.upper() != live_fpr.upper():
        return CheckResult(
            "backup_restorable",
            Status.FAIL,
            f"restored backup fingerprint {backup_fpr} != live {live_fpr}",
            "the backup does not match the live identity; refresh the backup "
            "with scripts/capauth-backup.sh or investigate key drift.",
        )
    return CheckResult(
        "backup_restorable",
        Status.OK,
        f"backup restores to a temp dir and matches live fingerprint {live_fpr}",
    )


def check_nextcloud_signing_key(nextcloud_key: Path) -> CheckResult:
    """The Nextcloud code-signing key is present with safe perms.

    This is the exact failure mode of commit ``456cb3a`` (key never stored,
    unrecoverable). We check on-disk presence + permissions only; the key
    material is never read.
    """
    if not nextcloud_key.exists():
        return CheckResult(
            "nextcloud_signing_key",
            Status.FAIL,
            f"Nextcloud code-signing key absent at {nextcloud_key}",
            "restore/store the signing key in its on-disk home AND a second "
            "custody (skvault/KeePass); cf. commit 456cb3a where a lost key "
            "forced a re-CSR. Set CAPAUTH_NEXTCLOUD_KEY if it lives elsewhere.",
        )
    if os.name == "posix" and _group_or_world_accessible(nextcloud_key):
        return CheckResult(
            "nextcloud_signing_key",
            Status.FAIL,
            f"signing key {nextcloud_key} is group/world accessible "
            f"(mode {_mode_octal(nextcloud_key)})",
            f"chmod 600 {nextcloud_key}",
        )
    size = nextcloud_key.stat().st_size
    return CheckResult(
        "nextcloud_signing_key",
        Status.OK,
        f"Nextcloud signing key present ({nextcloud_key}, {size} bytes, owner-only perms)",
    )


# ── orchestration ──────────────────────────────────────────────────────────────


def run_custody_checks(
    home: Optional[Path] = None,
    *,
    paths: Optional[CustodyPaths] = None,
    max_backup_age_days: int = DEFAULT_MAX_BACKUP_AGE_DAYS,
) -> list[CheckResult]:
    """Run every custody check and return the ordered results.

    Args:
        home: Optional CapAuth home override.
        paths: Optional fully-resolved path set (tests inject fixtures here).
        max_backup_age_days: Freshness window for the backup check.
    """
    p = paths or CustodyPaths.resolve(home)
    return [
        check_identity_present(p.private_key, p.public_key, p.profile, p.expected_fingerprint),
        check_keypair_match(p.private_key, p.public_key),
        check_private_key_permissions(p.private_key),
        check_key_status(p.public_key),
        check_revocation_cert(p.revocation_cert, p.public_key),
        check_keystore_integrity(p.keystore),
        check_backups_configured(p.backup_root, max_backup_age_days),
        check_backup_restorable(p.public_key, p.backup_root),
        check_nextcloud_signing_key(p.nextcloud_key),
    ]


def overall_status(results: list[CheckResult]) -> Status:
    """FAIL if any check failed, WARN if any warned, else OK."""
    statuses = {r.status for r in results}
    if Status.FAIL in statuses:
        return Status.FAIL
    if Status.WARN in statuses:
        return Status.WARN
    return Status.OK


def exit_code(results: list[CheckResult]) -> int:
    """Process exit code: nonzero when any check FAILed."""
    return 1 if any(r.status is Status.FAIL for r in results) else 0


def report_to_dict(results: list[CheckResult]) -> dict:
    """Serialize the report for ``--json`` automation consumers."""
    return {
        "overall": overall_status(results).value,
        "exit_code": exit_code(results),
        "checks": [r.to_dict() for r in results],
    }


def format_report(results: list[CheckResult]) -> str:
    """Plain-text report (no rich markup; statuses use brackets)."""
    lines = ["capauth doctor custody", ""]
    width = max((len(r.name) for r in results), default=0)
    for r in results:
        lines.append(f"  [{r.status.value:<4}] {r.name.ljust(width)}  {r.detail}")
        if r.remediation and r.status is not Status.OK:
            lines.append(f"         -> {r.remediation}")
    lines.append("")
    lines.append(f"overall: {overall_status(results).value}")
    return "\n".join(lines)
