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


# --- Enrollment proof helpers (card N10, 09a6d6f3) --------------------------
# capauth.pairing.enroll_device now VALIDATES proof for verified/attested
# mode instead of storing a caller-asserted claim unchecked. These build real,
# fast (Ed25519) keypairs and real signatures over the exact challenge
# enroll_device itself verifies, so pairing/authz/provisioning tests exercise
# actual proof, not a placeholder string a pre-N10 enroll_device would have
# accepted regardless.
#
# CI only runs Python 3.11/3.12 (see .github/workflows/pytest.yml -- PGPy
# needs the stdlib ``imghdr`` module, removed in 3.13), so unlike the
# ``_requires_crypto``-guarded fixtures above these are NOT skip-guarded: real
# crypto is always available where these tests run.


def enrolled_verified_credentials(subject: str) -> tuple[str, str]:
    """A ``(pubkey_armor, proof_armor)`` pair that legitimately enrolls VERIFIED.

    ``subject`` must be the CANONICAL subject :func:`capauth.pairing.enroll_device`
    will resolve to (i.e. already the fqid it will store, not a legacy shape it
    would still translate) -- the proof is bound to that exact string via
    :func:`capauth.pairing.verified_challenge`, so a mismatch here fails the
    same way a forged proof would.
    """
    from capauth.crypto import get_backend
    from capauth.models import Algorithm as _Algorithm
    from capauth.pairing import verified_challenge
    from capauth.pairing.store import fingerprint_for

    backend = get_backend()
    bundle = backend.generate_keypair(TEST_NAME, TEST_EMAIL, TEST_PASSPHRASE, _Algorithm.ED25519)
    fingerprint = fingerprint_for(bundle.public_armor)
    proof = backend.sign(
        verified_challenge(fingerprint, subject), bundle.private_armor, TEST_PASSPHRASE
    )
    return bundle.public_armor, proof


def enrolled_attested_credentials(device_pubkey: str, subject: str) -> tuple[str, str]:
    """An ``(operator_pubkey_armor, attestation_armor)`` pair proving ATTESTED.

    Mints a fresh "operator" keypair and signs :func:`capauth.pairing.attested_challenge`
    for ``device_pubkey``'s fingerprint + ``subject`` (see
    :func:`enrolled_verified_credentials` for the same canonical-subject caveat).
    """
    from capauth.crypto import get_backend
    from capauth.models import Algorithm as _Algorithm
    from capauth.pairing import attested_challenge
    from capauth.pairing.store import fingerprint_for

    backend = get_backend()
    op_bundle = backend.generate_keypair(
        TEST_NAME, TEST_EMAIL, TEST_PASSPHRASE, _Algorithm.ED25519
    )
    device_fingerprint = fingerprint_for(device_pubkey)
    attestation = backend.sign(
        attested_challenge(device_fingerprint, subject), op_bundle.private_armor, TEST_PASSPHRASE
    )
    return op_bundle.public_armor, attestation


def enrolled_device_key_credentials(
    subject: str, *, sig_encoding: str = "p1363"
) -> tuple[str, str]:
    """A ``(pubkey_b64, proof_b64)`` pair for a WebCrypto ECDSA P-256 device key.

    Mirrors :func:`enrolled_verified_credentials` but for the non-PGP key shape
    skchat's operator devices actually present: ``pubkey_b64`` is a base64 DER
    SubjectPublicKeyInfo (what ``window.crypto.subtle.exportKey("spki", ...)``
    yields, base64-encoded), and ``proof_b64`` is a base64 ECDSA signature over
    the exact :func:`capauth.pairing.verified_challenge` bytes for this key's
    :func:`capauth.pairing.store.fingerprint_for` fingerprint + ``subject`` --
    the same binding :func:`enrolled_verified_credentials` proves, just with a
    real ``cryptography`` P-256 keypair instead of a PGPy one, and no mock of
    any verifier.

    ``sig_encoding`` picks which of the two shapes a real WebCrypto signature
    may arrive in: ``"p1363"`` (WebCrypto's native raw ``r||s``, 64 bytes) or
    ``"der"`` (ASN.1 DER, the shape most non-browser ECDSA libraries emit).
    Both must verify identically.
    """
    import base64

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    from capauth.pairing import verified_challenge
    from capauth.pairing.store import fingerprint_for

    private_key = ec.generate_private_key(ec.SECP256R1())
    spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pubkey_b64 = base64.b64encode(spki).decode("ascii")
    fingerprint = fingerprint_for(pubkey_b64)
    challenge = verified_challenge(fingerprint, subject)
    der_sig = private_key.sign(challenge, ec.ECDSA(hashes.SHA256()))

    if sig_encoding == "der":
        sig_bytes = der_sig
    elif sig_encoding == "p1363":
        r, s = decode_dss_signature(der_sig)
        sig_bytes = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        raise ValueError(f"unknown sig_encoding: {sig_encoding!r}")

    return pubkey_b64, base64.b64encode(sig_bytes).decode("ascii")


@pytest.fixture
def tmp_capauth_home(tmp_path) -> Path:
    """Provide a temporary directory for profile tests."""
    return tmp_path / ".capauth"


@pytest.fixture
def capability_rule_test_ceiling(monkeypatch):
    """Use an explicit test class while isolating lower PDP rule tests.

    These suites test capability-specific enrollment floors, signatures, and
    revocation. Their synthetic subjects still receive an explicit class, but
    its test-only tofu floor keeps the production operator floor from replacing
    the lower-layer result under test. Production ceilings have direct coverage
    in ``test_identity_class.py``.
    """
    import capauth.authz as authz_module
    from capauth.identity_class import DEFAULT_CLASSES, IdentityClassName
    from capauth.pairing import EnrollmentMode

    operator = DEFAULT_CLASSES[IdentityClassName.OPERATOR.value].model_copy(
        update={"minimum_mode": EnrollmentMode.TOFU}
    )
    monkeypatch.setattr(
        authz_module,
        "DEFAULT_CLASSES",
        {**DEFAULT_CLASSES, IdentityClassName.OPERATOR.value: operator},
    )


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


# --- Token signing stub (PDP signature gate) --------------------------------
# The stub itself now lives in SHIPPED code, ``capauth.testing``, because the
# problem it solves is not CapAuth's alone: ``decide()`` requires a verifying
# signature on the granting token and ``issue_token`` raises rather than storing
# an unsigned one, so every downstream repo that mints a token in its tests
# needs the same gpg-free seam on a CI runner that has no secret key. While this
# fixture was private to this file, CapAuth's own suite was the only one that
# could stay green, and skchat's went red on inheritance alone.
#
# Imported, not re-implemented: a second copy would drift, and the copy that
# drifts toward "just return True" is the one that silently re-opens SEC-CRIT
# bc56b98b (an unsigned token granting skcode.dispatch). See
# ``capauth.testing`` for what the stub does and does not fake, and
# ``tests/test_testing_helper.py`` for the negative controls that pin it.
#
# NOTE: the non-autouse ``stub_token_signing`` is the right import here, NOT
# ``capauth.testing.capauth_signing_stub``. This suite contains tests that must
# run against the REAL gpg path (``tests/test_authz_signature_gate.py``) and
# against a genuine signing FAILURE (``tests/test_testing_helper.py``), so the
# stub has to stay opt-in per module.
from capauth.testing import stub_token_signing  # noqa: E402,F401 - re-exported fixture
