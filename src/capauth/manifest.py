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
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .exceptions import CapAuthError
from .seal import gpg_available

logger = logging.getLogger("capauth.manifest")

#: Conventional suffix for a manifest's detached signature file.
DEFAULT_SIG_SUFFIX = ".sig"


class ManifestSigningError(CapAuthError):
    """Signing a manifest failed: gpg unavailable, no signer key, or a gpg error.

    Subclasses :class:`~capauth.exceptions.CapAuthError` so existing callers that
    catch ``CapAuthError`` keep working. Only the *signing* path raises;
    verification never raises (it fails closed by returning ``False``).
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


__all__ = [
    "canonical_manifest_bytes",
    "is_canonical",
    "operator_fingerprint",
    "sign_manifest",
    "verify_manifest",
    "ManifestSigningError",
    "DEFAULT_SIG_SUFFIX",
]
