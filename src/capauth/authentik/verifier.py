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
) -> bytes:
    """Build the deterministic string that both server and client sign/verify.

    Args:
        nonce: UUID v4 nonce string.
        client_nonce_echo: Base64 client nonce as echoed in the challenge.
        timestamp: ISO 8601 UTC timestamp.
        service: Service identifier (hostname).
        expires: ISO 8601 UTC expiry timestamp.

    Returns:
        bytes: UTF-8 encoded canonical payload.
    """
    lines = [
        "CAPAUTH_NONCE_V1",
        f"nonce={nonce}",
        f"client_nonce={client_nonce_echo}",
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
    import tempfile as _tmp
    import os as _os
    try:
        import gnupg
    except ImportError:
        return False
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
        Optional[str]: 40-character hex fingerprint, or None on failure.
    """
    try:
        backend = get_backend(backend_type)
        return backend.fingerprint_from_armor(public_key_armor)
    except Exception:
        return None
