"""Shared fixtures for CapAuth tests."""

from __future__ import annotations

from pathlib import Path

import pytest

TEST_NAME = "Test User"
TEST_EMAIL = "test@capauth.local"
TEST_PASSPHRASE = "test-sovereign-passphrase-2026"

# Reason: PGPy fails on Python 3.13+ due to removed imghdr module;
# guard crypto imports so non-crypto tests can still run.
try:
    from capauth.crypto import get_backend
    from capauth.crypto.base import KeyBundle
    from capauth.models import Algorithm, CryptoBackendType

    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

_requires_crypto = pytest.mark.skipif(
    not _HAS_CRYPTO, reason="PGPy unavailable on this Python version"
)


@pytest.fixture
def pgpy_backend():
    """Return a PGPy crypto backend instance."""
    if not _HAS_CRYPTO:
        pytest.skip("PGPy unavailable")
    return get_backend(CryptoBackendType.PGPY)


@pytest.fixture
def rsa_keybundle(pgpy_backend) -> "KeyBundle":
    """Generate an RSA-4096 test keypair (cached per test)."""
    return pgpy_backend.generate_keypair(TEST_NAME, TEST_EMAIL, TEST_PASSPHRASE, Algorithm.RSA4096)


@pytest.fixture
def tmp_capauth_home(tmp_path) -> Path:
    """Provide a temporary directory for profile tests."""
    return tmp_path / ".capauth"
