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


# --- Trust domain fixtures (kernel track M1) -------------------------------
# The moved trust-web tests build a full skcapstone agent home. These fixtures
# are ported from skcapstone's conftest so the copied tests run byte-identically.


@pytest.fixture
def tmp_agent_home(tmp_path: Path) -> Path:
    """Provide a temporary agent home directory (~/.skcapstone) for testing."""
    agent_home = tmp_path / ".skcapstone"
    agent_home.mkdir()
    return agent_home


@pytest.fixture(autouse=True)
def _isolate_skcapstone_agent_env(monkeypatch):
    """Keep host SKCAPSTONE_AGENT / SKMEMORY_AGENT out of the trust tests.

    skcapstone's profile-aware runtime routes memory/trust writes to the active
    agent (from the env vars and a live ~/.skcapstone/agents/ scan). On a dev box
    that would send the moved trust tests' writes into a real agent's home. Clear
    both vars and stub the active-agent detector so the pillars use the flat
    ``home/`` layout the tests pass explicitly. No-op when skcapstone is absent
    (capauth standalone CI), so capauth's own tests are unaffected.
    """
    try:
        import skcapstone
    except ImportError:
        return

    monkeypatch.delenv("SKCAPSTONE_AGENT", raising=False)
    monkeypatch.delenv("SKMEMORY_AGENT", raising=False)
    monkeypatch.setenv("SKAGENT", "")
    monkeypatch.setattr(skcapstone, "SKCAPSTONE_AGENT", "", raising=False)
    if hasattr(skcapstone, "_detect_active_agent"):
        monkeypatch.setattr(skcapstone, "_detect_active_agent", lambda root=None: None)
