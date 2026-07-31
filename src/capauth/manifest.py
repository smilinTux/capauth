"""capauth.manifest -- detached signatures for SKWorld module manifests.

The SKWorld umbrella shell ships a *signed module registry* (umbrella-shell
design section 5.3): every module manifest a subapp authors (skchat, skcode,
skos, skdashboard) must carry a DETACHED capauth signature, and the shell
verifies that signature against the operator identity BEFORE it mounts the
module.

Until now capauth exposed no inline "sign these bytes" primitive. Capability
tokens and trust records carry their own JSON envelopes, and ``capauth.seal`` is
encryption-at-rest, not a bare detached signature. This module fills that gap
WITHOUT introducing any new crypto scheme: it reuses the exact
operator-identity OpenPGP detached-signature mechanism that ``capauth.tokens``
already uses to sign capability tokens. The signer is the operator identity key
(resolved from ``<home>/identity/identity.json`` -> ``fingerprint``, the same
field ``capauth.tokens`` reads for the token issuer) wielded through the system
``gpg`` keyring. A manifest signature is therefore the same class of artifact as
a capability-token signature, just made over a manifest's canonical bytes.

Canonicalization: the bytes signed and verified are the manifest's DETERMINISTIC
sorted-key JSON, byte-for-byte what producers emit. skos'
``render_manifest_json()`` is the reference form,
``json.dumps(obj, indent=2, sort_keys=True) + "\\n"`` encoded UTF-8, and
:func:`canonical_manifest_bytes` reproduces it so the signer and the shell agree
on the exact bytes under signature. Because producers already write those
canonical bytes to disk, a signature over the file's bytes also validates under
a plain ``gpg --verify`` of the file.

Fail-closed contract: :func:`verify_manifest` returns ``True`` only when a
present, valid detached signature covers exactly the given bytes AND (when an
expected signer is supplied) the signing key matches it. A missing, empty,
tampered, revoked/expired, or wrong-signer signature returns ``False`` and never
raises, so a caller that forgets to check the result still fails safe.

Operator flow:

    1. A subapp emits its manifest file, e.g. ``skos skworld-manifest emit`` ->
       deterministic sorted-key JSON.
    2. The operator signs it::

           capauth manifest sign skos.skworld-module.json

       which writes ``skos.skworld-module.json.sig`` (detached, ASCII-armored).
    3. The operator registers ``{manifest, signature}`` in the shell registry
       (``~/.skcapstone/shell/modules.json``, section 5.3).
    4. The shell verifies the detached signature against the operator identity
       BEFORE mounting::

           capauth.verify_manifest(manifest_bytes, signature, expected_signer=fp)

       and refuses to mount on any bad, absent, or wrong-signer signature.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .exceptions import CapAuthError
from .seal import gpg_available

logger = logging.getLogger("capauth.manifest")

#: Conventional suffix for a manifest's detached signature file.
DEFAULT_SIG_SUFFIX = ".sig"

#: Schema version stamped into a freshly created registry file.
REGISTRY_SCHEMA_VERSION = "1.0"


class ManifestSigningError(CapAuthError):
    """Signing a manifest failed: gpg unavailable, no signer key, or a gpg error.

    Subclasses :class:`~capauth.exceptions.CapAuthError` so existing callers that
    catch ``CapAuthError`` keep working. Only the *signing* path raises;
    verification never raises (it fails closed by returning ``False``).
    """


class ManifestRegistryError(CapAuthError):
    """A registry operation failed: unreadable/corrupt ``modules.json``, a
    manifest with no ``id``, or an unknown module id on update/removal.

    Subclasses :class:`~capauth.exceptions.CapAuthError`. Registry *mutations*
    (register/unregister/toggle) raise on bad input, but :func:`list_registered`
    never raises for a bad entry -- it fails that entry closed instead (marks it
    NOT ok) so one broken module cannot blind the operator to the rest.
    """


def canonical_manifest_bytes(manifest: Any) -> bytes:
    """Return a manifest's deterministic sorted-key JSON bytes.

    Accepts a mapping, a JSON string, or raw JSON bytes and returns the canonical
    form the signer and the shell both agree on::

        json.dumps(obj, indent=2, sort_keys=True) + "\\n"

    encoded UTF-8. This is byte-for-byte identical to skos'
    ``render_manifest_json()``, so a manifest emitted there and canonicalized here
    hash and sign to the same bytes. The function is idempotent: canonicalizing
    already-canonical bytes returns them unchanged.

    Args:
        manifest: A JSON-serialisable mapping, or JSON already rendered to
            ``str``/``bytes``.

    Returns:
        The canonical UTF-8 bytes to sign or verify.

    Raises:
        ManifestSigningError: if ``str``/``bytes`` input is not valid JSON.
    """
    if isinstance(manifest, (bytes, bytearray)):
        try:
            obj = json.loads(bytes(manifest).decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ManifestSigningError(f"manifest is not valid JSON: {exc}") from exc
    elif isinstance(manifest, str):
        try:
            obj = json.loads(manifest)
        except ValueError as exc:
            raise ManifestSigningError(f"manifest is not valid JSON: {exc}") from exc
    else:
        obj = manifest
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8")


def is_canonical(manifest_bytes: bytes) -> bool:
    """Whether ``manifest_bytes`` already equals its canonical sorted-key form.

    Useful before signing: the shell hashes the file as-is, so signing a
    non-canonical file yields a signature that a canonical re-emit would break.

    Returns:
        ``True`` if the bytes are valid JSON already in canonical form, else
        ``False`` (including when they are not valid JSON).
    """
    try:
        return canonical_manifest_bytes(manifest_bytes) == bytes(manifest_bytes)
    except ManifestSigningError:
        return False


def operator_fingerprint(home: Path | None = None) -> str:
    """Return the operator identity's PGP fingerprint -- the manifest signer.

    Reuses the exact resolution ``capauth.tokens`` uses to pick the token issuer
    key: it reads ``<home>/identity/identity.json`` and returns its
    ``fingerprint``. ``home`` defaults to ``~/.skcapstone`` (``SKCAPSTONE_HOME``),
    where the shared operator identity lives.

    Args:
        home: Base directory holding ``identity/identity.json``. Defaults to
            ``SKCAPSTONE_HOME``.

    Returns:
        The operator's 40/64-hex PGP fingerprint.

    Raises:
        ManifestSigningError: if no operator fingerprint can be resolved.
    """
    from . import SKCAPSTONE_HOME
    from .tokens import _get_issuer_fingerprint

    base = Path(home).expanduser() if home is not None else SKCAPSTONE_HOME
    fp = _get_issuer_fingerprint(base)
    if not fp or fp == "unknown":
        raise ManifestSigningError(
            f"no operator identity fingerprint found at {base}/identity/identity.json; "
            "run `capauth init` or pass an explicit signer"
        )
    return fp


def sign_manifest(
    manifest_bytes: bytes,
    *,
    signer: str | None = None,
    home: Path | None = None,
    passphrase: str | None = "",
) -> str:
    """Create a detached ASCII-armored OpenPGP signature over ``manifest_bytes``.

    Signs with the operator identity key through the system ``gpg`` keyring -- the
    SAME key and mechanism ``capauth.tokens`` uses to sign capability tokens (no
    new crypto scheme). ``manifest_bytes`` should already be the manifest's
    canonical bytes (see :func:`canonical_manifest_bytes`); they are signed
    verbatim, so the resulting signature also validates under a plain
    ``gpg --verify`` of the on-disk file.

    Args:
        manifest_bytes: The canonical manifest bytes to sign.
        signer: Signer key fingerprint or uid. Defaults to the operator identity
            resolved via :func:`operator_fingerprint`.
        home: Base dir for operator-identity resolution (see
            :func:`operator_fingerprint`).
        passphrase: ``""`` (default) signs via loopback with an empty passphrase,
            matching ``capauth.tokens``' unprotected-operator-key convention. Pass
            a string for a passphrase-protected key, or ``None`` to defer to the
            running gpg agent.

    Returns:
        The ASCII-armored detached signature.

    Raises:
        ManifestSigningError: if gpg is unavailable, no signer resolves, or gpg
            reports a signing failure.
    """
    if not gpg_available():
        raise ManifestSigningError("gpg binary not found on PATH; cannot sign manifest")
    key = signer or operator_fingerprint(home)
    cmd = ["gpg", "--batch", "--yes", "--armor", "--detach-sign", "--local-user", key]
    if passphrase is not None:
        cmd += ["--pinentry-mode", "loopback", "--passphrase", passphrase]
    proc = subprocess.run(cmd, input=bytes(manifest_bytes), capture_output=True)
    if proc.returncode != 0:
        raise ManifestSigningError(
            f"gpg detached-sign failed (signer={key!r}): "
            f"{proc.stderr.decode(errors='replace')[:200]}"
        )
    return proc.stdout.decode()


def _normalize_fpr(text: str) -> str:
    """Uppercase, strip spaces and any ``0x`` prefix from a fingerprint/uid string."""
    s = text.strip().replace(" ", "").upper()
    if s.startswith("0X"):
        s = s[2:]
    return s


def verify_manifest(
    manifest_bytes: bytes,
    signature: str | bytes | None,
    *,
    expected_signer: str | None = None,
) -> bool:
    """Verify a detached OpenPGP signature over ``manifest_bytes``. Fails closed.

    Returns ``True`` only when ALL of these hold:

    * gpg is available on PATH;
    * ``signature`` is present, non-empty, and a valid detached signature over
      exactly ``manifest_bytes`` (so any tamper flips it ``False``);
    * the signing key is not revoked or expired (those never yield ``VALIDSIG``);
    * when ``expected_signer`` is given, the signing key's fingerprint matches it.

    Every other condition -- missing/empty signature, tampered bytes, bad
    signature, revoked/expired key, or a different signer -- returns ``False`` and
    never raises, so a forgotten result check still fails safe.

    Args:
        manifest_bytes: The exact bytes the signature should cover (typically the
            manifest's canonical bytes).
        signature: The ASCII-armored detached signature, or ``None``.
        expected_signer: A fingerprint or uid to pin the signer to. Matched
            case-insensitively against the signature's signing- and primary-key
            fingerprints, allowing a partial (suffix) fingerprint. Pass the
            operator fingerprint to pin manifests to the operator identity, as the
            shell registry does before mounting.

    Returns:
        ``True`` if the signature is valid (and matches ``expected_signer`` when
        given), else ``False``.
    """
    if not gpg_available():
        return False
    if not signature:
        return False
    sig_bytes = signature.encode() if isinstance(signature, str) else bytes(signature)

    expected = _normalize_fpr(expected_signer) if expected_signer else None

    with tempfile.TemporaryDirectory() as tmp:
        data_path = Path(tmp) / "manifest"
        sig_path = Path(tmp) / "manifest.sig"
        data_path.write_bytes(bytes(manifest_bytes))
        sig_path.write_bytes(sig_bytes)

        with tempfile.TemporaryFile() as statusf:
            subprocess.run(
                [
                    "gpg",
                    "--batch",
                    "--quiet",
                    "--status-fd",
                    str(statusf.fileno()),
                    "--verify",
                    str(sig_path),
                    str(data_path),
                ],
                capture_output=True,
                pass_fds=(statusf.fileno(),),
            )
            statusf.seek(0)
            status = statusf.read().decode(errors="replace")

    valid = False
    signer_fprs: list[str] = []
    for line in status.splitlines():
        if not line.startswith("[GNUPG:] "):
            continue
        parts = line[len("[GNUPG:] ") :].split()
        if not parts:
            continue
        # VALIDSIG <signing-key-fpr> <sign-date> <ts> ... <primary-key-fpr>.
        # Its mere presence means: good signature, key not revoked/expired.
        if parts[0] == "VALIDSIG":
            valid = True
            if len(parts) >= 2:
                signer_fprs.append(parts[1].upper())
            signer_fprs.append(parts[-1].upper())

    if not valid:
        return False
    if expected is not None:
        if not any(
            fp == expected or fp.endswith(expected) or expected.endswith(fp)
            for fp in signer_fprs
            if fp
        ):
            return False
    return True


# ---------------------------------------------------------------------------
# Shell module registry (umbrella-shell design section 5.3)
# ---------------------------------------------------------------------------
#
# The umbrella shell mounts a subapp only from a *signed* index. That index is a
# static, capauth-signed config on each node -- ``<skcapstone-home>/shell/
# modules.json`` -- listing each module's manifest by local-file path (or a
# ``/.well-known/`` URL) plus its detached capauth signature and the operator's
# enable flag. The shell REFUSES any manifest whose detached signature does not
# verify. The functions below are the register/list/verify index tooling on top
# of the sign/verify primitives above; they add no new crypto -- verification is
# always :func:`verify_manifest` over the manifest's canonical bytes.
#
# On-disk schema (``modules.json``)::
#
#     {
#       "schema_version": "1.0",
#       "modules": [
#         {
#           "id": "skos",                       # from the manifest's `id` field
#           "path": "/abs/skos.skworld-module.json",   # local file or well-known URL
#           "sig": "/abs/skos.skworld-module.json.sig", # detached signature path
#           "enabled": true,                    # operator enable flag
#           "registered_at": "2026-07-31T12:00:00Z"     # first-registration UTC
#         }
#       ]
#     }
#
# ``list_registered`` annotates each entry with a LIVE ``signature`` verdict --
# one of ``ok`` / ``failed`` / ``missing-sig`` / ``missing-manifest`` -- computed
# by re-verifying the signature against the manifest's current canonical bytes.


def shell_home(home: Path | str | None = None) -> Path:
    """Resolve the skcapstone home that holds the shell registry.

    Honors ``$SKCAPSTONE_HOME`` (mirroring skos' ``_skcapstone_home``) so the
    registry the shell reads and the one capauth writes always agree:

    1. explicit ``home`` argument;
    2. ``$SKCAPSTONE_HOME`` if set and non-empty;
    3. ``~/.skcapstone``.

    Args:
        home: Explicit skcapstone home override.

    Returns:
        The resolved skcapstone home directory (not the ``shell/`` subdir).
    """
    if home is not None:
        return Path(home).expanduser()
    env = os.environ.get("SKCAPSTONE_HOME", "").strip()
    return Path(env).expanduser() if env else Path.home() / ".skcapstone"


def registry_path(home: Path | str | None = None) -> Path:
    """Return the shell module-registry file path (``<home>/shell/modules.json``)."""
    return shell_home(home) / "shell" / "modules.json"


def load_registry(home: Path | str | None = None) -> dict[str, Any]:
    """Load ``modules.json``, or an empty skeleton when it does not exist yet.

    Args:
        home: skcapstone home override (see :func:`shell_home`).

    Returns:
        The registry document ``{"schema_version": ..., "modules": [...]}``. A
        missing file yields a fresh in-memory skeleton (not written to disk).

    Raises:
        ManifestRegistryError: if the file exists but is not readable, is not
            valid JSON, or does not carry a ``modules`` list.
    """
    path = registry_path(home)
    if not path.exists():
        return {"schema_version": REGISTRY_SCHEMA_VERSION, "modules": []}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ManifestRegistryError(f"unreadable registry {path}: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("modules"), list):
        raise ManifestRegistryError(
            f"registry {path} is malformed: expected an object with a 'modules' list"
        )
    doc.setdefault("schema_version", REGISTRY_SCHEMA_VERSION)
    return doc


def save_registry(doc: dict[str, Any], home: Path | str | None = None) -> Path:
    """Write ``doc`` to ``modules.json`` deterministically, creating dirs as needed.

    Args:
        doc: The registry document to persist.
        home: skcapstone home override (see :func:`shell_home`).

    Returns:
        The path written.
    """
    path = registry_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return path


def _manifest_id(manifest_path: Path) -> str:
    """Read a manifest file and return its ``id`` field.

    Raises:
        ManifestRegistryError: if the file is unreadable, is not valid JSON, or
            has no non-empty string ``id``.
    """
    try:
        obj = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ManifestRegistryError(
            f"cannot read manifest {manifest_path}: {exc}"
        ) from exc
    mid = obj.get("id") if isinstance(obj, dict) else None
    if not isinstance(mid, str) or not mid.strip():
        raise ManifestRegistryError(
            f"manifest {manifest_path} has no non-empty string 'id' field"
        )
    return mid.strip()


def register_manifest(
    manifest_path: Path | str,
    *,
    sig_path: Path | str | None = None,
    enabled: bool = True,
    home: Path | str | None = None,
) -> dict[str, Any]:
    """Add or update a module entry in ``modules.json`` (idempotent upsert by id).

    The module id is derived from the manifest's ``id`` field. The default
    signature path is ``<manifest_path>.sig``. Local file paths are stored
    absolute (resolved); a ``/.well-known/`` URL is stored verbatim. Creates
    ``modules.json`` if absent. Re-registering the same id updates its
    path/sig/enabled in place while preserving the original ``registered_at``.

    Args:
        manifest_path: Path to the manifest file whose ``id`` names the module.
        sig_path: Detached-signature path. Defaults to ``manifest_path + ".sig"``.
        enabled: Whether the shell may mount this module.
        home: skcapstone home override (see :func:`shell_home`).

    Returns:
        The stored entry dict.

    Raises:
        ManifestRegistryError: if the manifest is unreadable or has no ``id``.
    """
    mpath = Path(manifest_path).expanduser()
    if _is_url(str(manifest_path)):
        raise ManifestRegistryError(
            "register_manifest needs a local manifest file to read its id; "
            "a well-known URL cannot be registered without a local copy"
        )
    mid = _manifest_id(mpath)
    stored_manifest = str(mpath.resolve())

    if sig_path is not None:
        stored_sig = (
            str(sig_path)
            if _is_url(str(sig_path))
            else str(Path(sig_path).expanduser().resolve())
        )
    else:
        stored_sig = stored_manifest + DEFAULT_SIG_SUFFIX

    doc = load_registry(home)
    entry: dict[str, Any] | None = None
    for existing in doc["modules"]:
        if existing.get("id") == mid:
            entry = existing
            break

    if entry is None:
        entry = {
            "id": mid,
            "path": stored_manifest,
            "sig": stored_sig,
            "enabled": bool(enabled),
            "registered_at": datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
        }
        doc["modules"].append(entry)
    else:
        entry["path"] = stored_manifest
        entry["sig"] = stored_sig
        entry["enabled"] = bool(enabled)

    save_registry(doc, home)
    return dict(entry)


def unregister_manifest(module_id: str, home: Path | str | None = None) -> bool:
    """Remove a module entry by id.

    Args:
        module_id: The module id to drop.
        home: skcapstone home override (see :func:`shell_home`).

    Returns:
        ``True`` if an entry was removed, ``False`` if no such id was registered.
    """
    doc = load_registry(home)
    before = len(doc["modules"])
    doc["modules"] = [m for m in doc["modules"] if m.get("id") != module_id]
    if len(doc["modules"]) == before:
        return False
    save_registry(doc, home)
    return True


def set_module_enabled(
    module_id: str, enabled: bool, home: Path | str | None = None
) -> dict[str, Any]:
    """Toggle a module's ``enabled`` flag.

    Args:
        module_id: The module id to toggle.
        enabled: New enabled state.
        home: skcapstone home override (see :func:`shell_home`).

    Returns:
        The updated entry dict.

    Raises:
        ManifestRegistryError: if ``module_id`` is not registered.
    """
    doc = load_registry(home)
    for entry in doc["modules"]:
        if entry.get("id") == module_id:
            entry["enabled"] = bool(enabled)
            save_registry(doc, home)
            return dict(entry)
    raise ManifestRegistryError(f"module id not registered: {module_id!r}")


def _is_url(value: str) -> bool:
    """Whether ``value`` looks like a fetchable http(s) URL rather than a path."""
    return value.startswith("http://") or value.startswith("https://")


def _verify_entry_signature(
    entry: dict[str, Any], *, expected_signer: str | None
) -> str:
    """Return the live signature verdict for one registry entry. Never raises.

    Verdicts:

    * ``ok`` -- a present detached signature verifies over the manifest's
      canonical bytes (and matches ``expected_signer`` when given);
    * ``failed`` -- signature present but does not verify (tampered manifest,
      bad/expired/revoked or wrong-signer signature);
    * ``missing-sig`` -- the signature file is absent or empty;
    * ``missing-manifest`` -- the manifest file is absent or unreadable, or the
      entry references a remote URL this tooling cannot fetch.
    """
    mpath = entry.get("path", "")
    spath = entry.get("sig", "")
    if not isinstance(mpath, str) or _is_url(mpath):
        # v1 tooling verifies local files only; a remote manifest is unfetchable
        # here, so it fails closed rather than reporting a bogus ``ok``.
        return "missing-manifest"
    try:
        raw = Path(mpath).expanduser().read_bytes()
    except OSError:
        return "missing-manifest"
    try:
        canon = canonical_manifest_bytes(raw)
    except ManifestSigningError:
        return "failed"

    if not isinstance(spath, str) or _is_url(spath):
        return "missing-sig"
    try:
        sig = Path(spath).expanduser().read_text(encoding="utf-8")
    except OSError:
        return "missing-sig"
    if not sig.strip():
        return "missing-sig"

    return "ok" if verify_manifest(canon, sig, expected_signer=expected_signer) else "failed"


def list_registered(
    home: Path | str | None = None, *, expected_signer: str | None = None
) -> list[dict[str, Any]]:
    """Return registry entries, each annotated with a live signature verdict.

    Each returned dict is a copy of the stored entry plus a ``signature`` key
    holding one of ``ok`` / ``failed`` / ``missing-sig`` / ``missing-manifest``
    (see :func:`_verify_entry_signature`) and preserves the entry's ``enabled``
    flag. Fail-closed: a broken entry is marked NOT ok rather than crashing the
    listing, so one bad module cannot hide the rest.

    Args:
        home: skcapstone home override (see :func:`shell_home`).
        expected_signer: Optional fingerprint/uid to pin every entry's signer to
            (e.g. the operator identity). ``None`` accepts any cryptographically
            valid signature.

    Returns:
        A list of annotated entry dicts, in registry order.
    """
    doc = load_registry(home)
    annotated: list[dict[str, Any]] = []
    for entry in doc["modules"]:
        out = dict(entry)
        out["enabled"] = bool(entry.get("enabled", True))
        out["signature"] = _verify_entry_signature(
            entry, expected_signer=expected_signer
        )
        annotated.append(out)
    return annotated


__all__ = [
    "canonical_manifest_bytes",
    "is_canonical",
    "operator_fingerprint",
    "sign_manifest",
    "verify_manifest",
    "ManifestSigningError",
    "ManifestRegistryError",
    "DEFAULT_SIG_SUFFIX",
    "REGISTRY_SCHEMA_VERSION",
    "shell_home",
    "registry_path",
    "load_registry",
    "save_registry",
    "register_manifest",
    "unregister_manifest",
    "set_module_enabled",
    "list_registered",
]
