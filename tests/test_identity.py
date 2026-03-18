"""Tests for identity verification (challenge-response).

Covers:
  - Challenge creation
  - Challenge signing (respond)
  - Full verification round-trip
  - Tampered challenge rejection
  - Wrong-key rejection
"""

from __future__ import annotations

import pytest

from capauth.crypto import get_backend
from capauth.exceptions import VerificationError
from capauth.identity import create_challenge, respond_to_challenge, verify_challenge
from capauth.models import Algorithm

PASS_A = "alice-sovereign-2026"
PASS_B = "bob-sovereign-2026"


@pytest.fixture
def alice_keys():
    """Generate a test keypair for Alice."""
    backend = get_backend()
    return backend.generate_keypair("Alice", "alice@capauth.local", PASS_A, Algorithm.RSA4096)


@pytest.fixture
def bob_keys():
    """Generate a test keypair for Bob."""
    backend = get_backend()
    return backend.generate_keypair("Bob", "bob@capauth.local", PASS_B, Algorithm.RSA4096)


class TestChallengeCreation:
    """Challenge creation tests."""

    def test_creates_valid_challenge(self, alice_keys, bob_keys):
        """Expected: challenge has correct fingerprints and random hex."""
        challenge = create_challenge(alice_keys.fingerprint, bob_keys.fingerprint)
        assert challenge.from_fingerprint == alice_keys.fingerprint
        assert challenge.to_fingerprint == bob_keys.fingerprint
        assert len(challenge.challenge_hex) == 64  # 32 bytes = 64 hex chars
        assert challenge.challenge_id  # non-empty UUID

    def test_challenges_are_unique(self, alice_keys, bob_keys):
        """Edge: two challenges should never have the same hex."""
        c1 = create_challenge(alice_keys.fingerprint, bob_keys.fingerprint)
        c2 = create_challenge(alice_keys.fingerprint, bob_keys.fingerprint)
        assert c1.challenge_hex != c2.challenge_hex
        assert c1.challenge_id != c2.challenge_id


class TestFullVerification:
    """End-to-end challenge-response verification."""

    def test_valid_roundtrip(self, alice_keys, bob_keys):
        """Expected: Bob can prove his identity to Alice."""
        challenge = create_challenge(alice_keys.fingerprint, bob_keys.fingerprint)

        response = respond_to_challenge(challenge, bob_keys.private_armor, PASS_B)
        assert response.challenge_id == challenge.challenge_id
        assert response.responder_fingerprint == bob_keys.fingerprint

        verified = verify_challenge(challenge, response, bob_keys.public_armor)
        assert verified is True

    def test_wrong_key_fails(self, alice_keys, bob_keys):
        """Failure: response signed by Alice should not verify as Bob."""
        challenge = create_challenge(alice_keys.fingerprint, bob_keys.fingerprint)

        # Reason: Alice signs instead of Bob — fingerprint mismatch expected
        response = respond_to_challenge(challenge, alice_keys.private_armor, PASS_A)

        with pytest.raises(VerificationError, match="Fingerprint mismatch"):
            verify_challenge(challenge, response, alice_keys.public_armor)

    def test_tampered_challenge_hex_fails(self, alice_keys, bob_keys):
        """Failure: modifying challenge hex after signing should break verification."""
        challenge = create_challenge(alice_keys.fingerprint, bob_keys.fingerprint)

        response = respond_to_challenge(challenge, bob_keys.private_armor, PASS_B)

        challenge.challenge_hex = "deadbeef" * 8
        with pytest.raises(VerificationError, match="tampered"):
            verify_challenge(challenge, response, bob_keys.public_armor)
