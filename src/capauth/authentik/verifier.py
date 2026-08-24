"""CapAuth signature verification for the Authentik stage.

Handles:
- Building the canonical nonce payload string
- Building the canonical claims payload string
- Verifying PGP signatures via the CapAuth crypto backend
- Looking up stored public keys for a fingerprint

The verifier intentionally knows nothing about Django or Authentik's
model layer. It operates purely on strings and bytes so it can be
unit-tested in isolation.
"""

from __future__ import annotations

import json
from typing import Optional

from ..crypto import get_backend
from ..models import CryptoBackendType


def canonical_nonce_payload(
    nonce: str,
    client_nonce_echo: str,
    timestamp: str,
    service: str,
    expires: str,
    origin: Optional[str] = None,
) -> bytes:
    """Build the deterministic string that both server and client sign/verify.

    When ``origin`` is provided, the V2 canonical payload is emitted with the
    ``origin`` line inserted between ``client_nonce`` and ``timestamp`` (the
    origin-binding format, ``CAPAUTH_NONCE_V2``). When ``origin`` is ``None`` the
    legacy ``CAPAUTH_NONCE_V1`` payload (no origin) is emitted for backward
    compatibility during the dual-accept migration window.

    The byte layout MUST be kept identical across all five implementations
    (Python verifier, the two Nextcloud PHP services, the Nextcloud login JS,
    the browser-extension/stage signers). A shared cross-impl test vector
    asserts this.

    Args:
        nonce: UUID v4 nonce string.
        client_nonce_echo: Base64 client nonce as echoed in the challenge.
        timestamp: ISO 8601 UTC timestamp.
        service: Service identifier (hostname).
        expires: ISO 8601 UTC expiry timestamp.
        origin: RP origin (``scheme://host[:port]``). When set, emits V2;
            when ``None``, emits the legacy V1 payload.

    Returns:
        bytes: UTF-8 encoded canonical payload.
    """
    if origin is None:
        lines = [
            "CAPAUTH_NONCE_V1",
            f"nonce={nonce}",
            f"client_nonce={client_nonce_echo}",
            f"timestamp={timestamp}",
            f"service={service}",
            f"expires={expires}",
        ]
    else:
        lines = [
            "CAPAUTH_NONCE_V2",
            f"nonce={nonce}",
            f"client_nonce={client_nonce_echo}",
            f"origin={origin}",
            f"timestamp={timestamp}",
            f"service={service}",
            f"expires={expires}",
        ]
    return "\n".join(lines).encode("utf-8")


def canonical_claims_payload(
    fingerprint: str,
    nonce: str,
    claims: dict,
) -> bytes:
    """Build the deterministic string the client signs over their claims.

    Claims are serialized with sorted keys and no whitespace so the payload
    is identical regardless of Python dict ordering or serialization library.

    Args:
        fingerprint: Authenticating client's PGP fingerprint.
        nonce: Nonce UUID this auth event is bound to.
        claims: Dict of client-asserted profile claims.

    Returns:
        bytes: UTF-8 encoded canonical payload.
    """
    claims_compact = json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    lines = [
        "CAPAUTH_CLAIMS_V1",
        f"fingerprint={fingerprint}",
        f"nonce={nonce}",
        f"claims={claims_compact}",
    ]
    return "\n".join(lines).encode("utf-8")


def payload_version(payload: bytes) -> Optional[str]:
    """Return the canonical payload version from its first line.

    Dispatches V1 vs V2 acceptance on the self-describing header. Returns
    ``"V1"``, ``"V2"`` or ``None`` if the header is not recognised.

    Args:
        payload: Canonical nonce payload bytes.

    Returns:
        Optional[str]: ``"V1"``, ``"V2"``, or ``None``.
    """
    try:
        first_line = payload.split(b"\n", 1)[0].decode("utf-8", "replace").strip()
    except Exception:
        return None
    if first_line == "CAPAUTH_NONCE_V1":
        return "V1"
    if first_line == "CAPAUTH_NONCE_V2":
        return "V2"
    return None


def check_origin(
    issued_origin: Optional[str],
    allowed_origins,
    require_origin_binding: bool = False,
) -> tuple[bool, str]:
    """Tier-A origin assertion check.

    Verifies that the origin bound into the (already signature-validated)
    canonical payload matches one of the RP's configured allowed origins.

    Migration semantics:
      * ``issued_origin is None`` (a V1 payload, no origin): accepted while
        ``require_origin_binding`` is False; rejected (``v1_rejected``) when True.
      * ``issued_origin`` present (V2): MUST match an allowed origin, else
        ``invalid_origin``.

    Args:
        issued_origin: The ``origin`` value carried in the signed payload, or
            ``None`` for a legacy V1 payload.
        allowed_origins: A single origin string or an iterable of allowed
            origin strings (the RP's configured ``allowed_origins``).
        require_origin_binding: When True, V1 (origin-less) payloads are
            rejected — the post-migration enforced mode.

    Returns:
        tuple[bool, str]: ``(ok, error_code)``. ``error_code`` is ``""`` on
        success, ``"v1_rejected"`` or ``"invalid_origin"`` on failure.
    """
    if isinstance(allowed_origins, str):
        allowed = [allowed_origins]
    else:
        allowed = list(allowed_origins or [])
    allowed_norm = {_normalize_origin(o) for o in allowed if o}

    if issued_origin is None:
        if require_origin_binding:
            return False, "v1_rejected"
        return True, ""

    if _normalize_origin(issued_origin) in allowed_norm:
        return True, ""
    return False, "invalid_origin"


def _normalize_origin(origin: str) -> str:
    """Normalise an origin for comparison (strip trailing slash, lowercase host).

    Keeps the comparison robust to a trailing slash or scheme/host casing while
    preserving the port. Does NOT alter the bytes that are signed — this is only
    used for the equality check.

    Args:
        origin: An origin string (``scheme://host[:port]``).

    Returns:
        str: Normalised origin.
    """
    o = (origin or "").strip().rstrip("/")
    if "://" in o:
        scheme, rest = o.split("://", 1)
        return f"{scheme.lower()}://{rest.lower()}"
    return o.lower()


def _is_detach_sig(signature_armor: str) -> bool:
    """Return True if the armor is a PGP SIGNATURE block (detach-sig) rather than a signed message.

    Args:
        signature_armor: ASCII-armored PGP blob.

    Returns:
        bool: True for detach-sig format.
    """
    return "BEGIN PGP SIGNATURE" in signature_armor


def _verify_with_gnupg(payload: bytes, signature_armor: str, public_key_armor: str) -> bool:
    """Verify a detach-sig using an isolated GnuPG keyring.

    Used as a fallback when the signature is in raw detach-sig format
    rather than a PGPy signed message.

    Args:
        payload: Data that was signed.
        signature_armor: ASCII-armored PGP SIGNATURE block.
        public_key_armor: ASCII-armored signer public key.

    Returns:
        bool: True if the signature is valid.
    """
    import os as _os
    import tempfile as _tmp

    try:
        import gnupg
    except ImportError:
        return _verify_with_pgpy(payload, signature_armor, public_key_armor)
    try:
        gpg = gnupg.GPG(gnupghome=_tmp.mkdtemp(prefix="capauth_verify_"))
        gpg.import_keys(public_key_armor)
        with _tmp.NamedTemporaryFile(suffix=".sig", delete=False) as sf:
            sf.write(signature_armor.encode())
            sig_path = sf.name
        try:
            result = gpg.verify_data(sig_path, payload)
            return bool(result.valid)
        finally:
            _os.unlink(sig_path)
    except Exception:
        return False


def _verify_with_pgpy(payload: bytes, signature_armor: str, public_key_armor: str) -> bool:
    """Verify a detached signature with the mandatory pure-Python backend.

    This is the dependency-free fallback for service installations that do not
    include the optional ``python-gnupg`` package.  Keep the same key usability
    checks as the regular PGPy backend before accepting the signature.
    """
    try:
        import pgpy

        from ..crypto.pgpy_backend import _assert_key_usable

        public_key, _ = pgpy.PGPKey.from_blob(public_key_armor)
        signature = pgpy.PGPSignature.from_blob(signature_armor)
        _assert_key_usable(public_key, {signature.signer})
        return bool(public_key.verify(payload, signature))
    except Exception:
        return False


def verify_nonce_signature(
    payload: bytes,
    signature_armor: str,
    public_key_armor: str,
    backend_type: CryptoBackendType = CryptoBackendType.PGPY,
) -> bool:
    """Verify the nonce signature from the client's signed response.

    Accepts both PGPy signed messages and raw GPG detach-sigs.
    Detach-sig format is auto-detected and routed to the GnuPG verifier.

    Args:
        payload: Canonical nonce payload bytes.
        signature_armor: ASCII-armored PGP signature or signed message.
        public_key_armor: ASCII-armored PGP public key of the claimed fingerprint.
        backend_type: Preferred backend (used for signed-message format).

    Returns:
        bool: True if the signature is valid.
    """
    if _is_detach_sig(signature_armor):
        return _verify_with_gnupg(payload, signature_armor, public_key_armor)
    try:
        backend = get_backend(backend_type)
        return backend.verify(payload, signature_armor, public_key_armor)
    except Exception:
        return False


def verify_claims_signature(
    payload: bytes,
    signature_armor: str,
    public_key_armor: str,
    backend_type: CryptoBackendType = CryptoBackendType.PGPY,
) -> bool:
    """Verify the claims signature from the client's signed response.

    Accepts both PGPy signed messages and raw GPG detach-sigs.

    Args:
        payload: Canonical claims payload bytes.
        signature_armor: ASCII-armored PGP signature or signed message.
        public_key_armor: ASCII-armored PGP public key of the claimed fingerprint.
        backend_type: Preferred backend (used for signed-message format).

    Returns:
        bool: True if the signature is valid.
    """
    if _is_detach_sig(signature_armor):
        return _verify_with_gnupg(payload, signature_armor, public_key_armor)
    try:
        backend = get_backend(backend_type)
        return backend.verify(payload, signature_armor, public_key_armor)
    except Exception:
        return False


def fingerprint_from_armor(
    public_key_armor: str,
    backend_type: CryptoBackendType = CryptoBackendType.PGPY,
) -> Optional[str]:
    """Extract the fingerprint from an ASCII-armored public key.

    Args:
        public_key_armor: ASCII-armored PGP public key.
        backend_type: Which crypto backend to use.

    Returns:
        Optional[str]: 40 (v4) or 64 (v6) hex fingerprint, or None on failure.
    """
    try:
        backend = get_backend(backend_type)
        return backend.fingerprint_from_armor(public_key_armor)
    except Exception:
        return None
