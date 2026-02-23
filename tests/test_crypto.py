"""Tests for the CapAuth crypto backend abstraction.

Covers:
  - PGPy backend keygen (RSA-4096)
  - Sign + verify round-trip
  - Verify rejects tampered data
  - Fingerprint extraction
  - Backend factory
"""

from __future__ import annotations

import pytest

from capauth.crypto import get_backend
from capauth.crypto.base import KeyBundle
from capauth.crypto.pgpy_backend import PGPyBackend
from capauth.exceptions import BackendError
from capauth.models import Algorithm, CryptoBackendType


class TestPGPyBackendKeygen:
    """Key generation tests."""

    def test_rsa4096_generates_valid_bundle(self, pgpy_backend, rsa_keybundle):
        """Expected: RSA-4096 keygen produces a well-formed KeyBundle."""
        assert isinstance(rsa_keybundle, KeyBundle)
        assert len(rsa_keybundle.fingerprint) == 40
        assert rsa_keybundle.algorithm == Algorithm.RSA4096
        assert "BEGIN PGP PUBLIC KEY BLOCK" in rsa_keybundle.public_armor
        assert "BEGIN PGP PRIVATE KEY BLOCK" in rsa_keybundle.private_armor

    def test_fingerprint_is_hex(self, rsa_keybundle):
        """Edge: fingerprint should be all hex characters."""
        assert all(c in "0123456789ABCDEFabcdef" for c in rsa_keybundle.fingerprint)

    def test_empty_passphrase_still_generates(self, pgpy_backend):
        """Edge: empty passphrase should still produce a keypair."""
        bundle = pgpy_backend.generate_keypair("No Pass", "nopass@test.io", "", Algorithm.RSA4096)
        assert len(bundle.fingerprint) == 40


class TestPGPyBackendSignVerify:
    """Signing and verification round-trip tests."""

    def test_sign_and_verify_roundtrip(self, pgpy_backend, rsa_keybundle):
        """Expected: data signed with private key verifies with public key."""
        data = b"sovereignty is not negotiable"
        passphrase = "test-sovereign-passphrase-2026"
        sig = pgpy_backend.sign(data, rsa_keybundle.private_armor, passphrase)
        assert "BEGIN PGP MESSAGE" in sig

        valid = pgpy_backend.verify(data, sig, rsa_keybundle.public_armor)
        assert valid is True

    def test_verify_rejects_tampered_data(self, pgpy_backend, rsa_keybundle):
        """Failure: tampered data should fail verification."""
        data = b"original message"
        passphrase = "test-sovereign-passphrase-2026"
        sig = pgpy_backend.sign(data, rsa_keybundle.private_armor, passphrase)

        tampered = b"tampered message"
        valid = pgpy_backend.verify(tampered, sig, rsa_keybundle.public_armor)
        assert valid is False

    def test_verify_rejects_wrong_key(self, pgpy_backend):
        """Failure: signature from key A should not verify with key B."""
        bundle_a = pgpy_backend.generate_keypair(
            "Alice", "alice@test.io", "pass-a", Algorithm.RSA4096
        )
        bundle_b = pgpy_backend.generate_keypair(
            "Bob", "bob@test.io", "pass-b", Algorithm.RSA4096
        )

        data = b"alice's message"
        sig = pgpy_backend.sign(data, bundle_a.private_armor, "pass-a")

        valid = pgpy_backend.verify(data, sig, bundle_b.public_armor)
        assert valid is False


class TestPGPyBackendFingerprint:
    """Fingerprint extraction tests."""

    def test_extract_from_public_key(self, pgpy_backend, rsa_keybundle):
        """Expected: fingerprint matches the one from keygen."""
        fp = pgpy_backend.fingerprint_from_armor(rsa_keybundle.public_armor)
        assert fp == rsa_keybundle.fingerprint

    def test_extract_from_private_key(self, pgpy_backend, rsa_keybundle):
        """Expected: private key also yields the same fingerprint."""
        fp = pgpy_backend.fingerprint_from_armor(rsa_keybundle.private_armor)
        assert fp == rsa_keybundle.fingerprint

    def test_invalid_armor_raises(self, pgpy_backend):
        """Failure: garbage input should raise BackendError."""
        with pytest.raises(BackendError):
            pgpy_backend.fingerprint_from_armor("not a real key")


class TestBackendFactory:
    """Backend factory tests."""

    def test_default_returns_pgpy(self):
        """Expected: default factory returns PGPy backend."""
        backend = get_backend()
        assert isinstance(backend, PGPyBackend)

    def test_explicit_pgpy(self):
        """Expected: explicit PGPY type returns PGPy backend."""
        backend = get_backend(CryptoBackendType.PGPY)
        assert isinstance(backend, PGPyBackend)

    def test_gnupg_raises_if_unavailable(self):
        """Edge: GNUPG backend may raise if gpg2 not available."""
        try:
            backend = get_backend(CryptoBackendType.GNUPG)
            assert backend is not None
        except BackendError:
            pass  # expected on systems without gpg2
