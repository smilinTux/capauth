"""Shared fixtures for CapAuth tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from capauth.crypto import get_backend
from capauth.crypto.base import KeyBundle
from capauth.models import Algorithm, CryptoBackendType

TEST_NAME = "Test User"
TEST_EMAIL = "test@capauth.local"
TEST_PASSPHRASE = "test-sovereign-passphrase-2026"


@pytest.fixture
def pgpy_backend():
    """Return a PGPy crypto backend instance."""
    return get_backend(CryptoBackendType.PGPY)


@pytest.fixture
def rsa_keybundle(pgpy_backend) -> KeyBundle:
    """Generate an RSA-4096 test keypair (cached per test)."""
    return pgpy_backend.generate_keypair(
        TEST_NAME, TEST_EMAIL, TEST_PASSPHRASE, Algorithm.RSA4096
    )


@pytest.fixture
def tmp_capauth_home(tmp_path) -> Path:
    """Provide a temporary directory for profile tests."""
    return tmp_path / ".capauth"
