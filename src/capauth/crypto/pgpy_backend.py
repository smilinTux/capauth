"""PGPy (pure-Python) crypto backend for CapAuth.

Default backend — zero system dependencies, pip-install-and-go.
Uses the PGPy library for all PGP operations.
"""

from __future__ import annotations

import pgpy
from pgpy.constants import (
    CompressionAlgorithm,
    EllipticCurveOID,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SymmetricKeyAlgorithm,
)

from ..exceptions import BackendError, KeyGenerationError
from ..models import Algorithm
from .base import CryptoBackend, KeyBundle


class PGPyBackend(CryptoBackend):
    """Pure-Python PGP backend powered by the PGPy library.

    Supports Ed25519 (signing) + Curve25519 (encryption) as default,
    with RSA-4096 fallback for legacy compatibility.
    """

    def available(self) -> bool:
        """Check PGPy is importable.

        Returns:
            bool: Always True since PGPy is a hard dependency.
        """
        try:
            import importlib.util

            return importlib.util.find_spec("pgpy") is not None
        except Exception:
            return False

    def generate_keypair(
        self,
        name: str,
        email: str,
        passphrase: str,
        algorithm: Algorithm = Algorithm.RSA4096,
    ) -> KeyBundle:
        """Generate a PGP keypair using PGPy.

        Args:
            name: Display name for the UID.
            email: Email address for the UID.
            passphrase: Passphrase to protect the private key.
            algorithm: Ed25519 or RSA-4096.

        Returns:
            KeyBundle: The generated keypair material.

        Raises:
            KeyGenerationError: On any PGPy failure.
        """
        try:
            if algorithm == Algorithm.ED25519:
                key = pgpy.PGPKey.new(PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519)
            else:
                key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)

            uid = pgpy.PGPUID.new(name, email=email)
            key.add_uid(
                uid,
                usage={KeyFlags.Sign, KeyFlags.Certify},
                hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA512],
                ciphers=[SymmetricKeyAlgorithm.AES256],
                compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.Uncompressed],
            )

            if algorithm == Algorithm.ED25519:
                enc_subkey = pgpy.PGPKey.new(PubKeyAlgorithm.ECDH, EllipticCurveOID.Curve25519)
            else:
                enc_subkey = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)

            key.add_subkey(
                enc_subkey,
                usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
            )

            key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

            fingerprint = str(key.fingerprint).replace(" ", "")
            public_armor = str(key.pubkey)
            private_armor = str(key)

            return KeyBundle(
                fingerprint=fingerprint,
                public_armor=public_armor,
                private_armor=private_armor,
                algorithm=algorithm,
            )
        except Exception as exc:
            raise KeyGenerationError(f"PGPy key generation failed: {exc}") from exc

    def sign(
        self,
        data: bytes,
        private_key_armor: str,
        passphrase: str,
    ) -> str:
        """Sign data with a PGPy private key.

        Returns a PGP signed message (data + embedded signature)
        for reliable round-trip verification with PGPy.

        Args:
            data: Raw bytes to sign.
            private_key_armor: ASCII-armored private key.
            passphrase: Passphrase to unlock the key.

        Returns:
            str: ASCII-armored PGP signed message.

        Raises:
            BackendError: On signing failure.
        """
        try:
            key, _ = pgpy.PGPKey.from_blob(private_key_armor)

            with key.unlock(passphrase):
                message = pgpy.PGPMessage.new(data, cleartext=False)
                sig = key.sign(message)
                message |= sig

            return str(message)
        except Exception as exc:
            raise BackendError(f"PGPy signing failed: {exc}") from exc

    def verify(
        self,
        data: bytes,
        signature_armor: str,
        public_key_armor: str,
    ) -> bool:
        """Verify a PGP signed message using PGPy.

        Parses the signed message, checks that the embedded
        payload matches ``data``, and validates the signature.

        Args:
            data: Original bytes that were signed.
            signature_armor: ASCII-armored PGP signed message.
            public_key_armor: ASCII-armored signer's public key.

        Returns:
            bool: True if the signature is cryptographically valid.
        """
        try:
            pub_key, _ = pgpy.PGPKey.from_blob(public_key_armor)
            signed_msg = pgpy.PGPMessage.from_blob(signature_armor)

            # Reason: PGPy verifies the embedded payload, so we must
            # also confirm the embedded data matches what we expect
            # to prevent a substitution attack. PGPy returns .message
            # as str even when the input was bytes.
            embedded = signed_msg.message
            if isinstance(embedded, str):
                embedded = embedded.encode("utf-8")
            if embedded != data:
                return False

            verification = pub_key.verify(signed_msg)
            return bool(verification)
        except Exception:
            return False

    def fingerprint_from_armor(self, key_armor: str) -> str:
        """Extract fingerprint from an ASCII-armored key.

        Args:
            key_armor: ASCII-armored public or private key.

        Returns:
            str: 40-character hex fingerprint.

        Raises:
            BackendError: If parsing fails.
        """
        try:
            key, _ = pgpy.PGPKey.from_blob(key_armor)
            return str(key.fingerprint).replace(" ", "")
        except Exception as exc:
            raise BackendError(f"Failed to parse key armor: {exc}") from exc
