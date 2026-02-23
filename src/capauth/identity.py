"""Identity verification via PGP challenge-response.

Replaces "Login with Google" — the user's PGP key IS their identity.
No redirect, no token exchange, no corporate middleman.

Flow:
  1. Verifier generates a random challenge
  2. Prover signs the challenge with their private key
  3. Verifier checks the signature against the prover's public key
  4. Valid signature = authenticated. Done.
"""

from __future__ import annotations

import secrets

from .crypto import get_backend
from .exceptions import VerificationError
from .models import ChallengeRequest, ChallengeResponse, CryptoBackendType

CHALLENGE_BYTES = 32


def create_challenge(
    from_fingerprint: str,
    to_fingerprint: str,
) -> ChallengeRequest:
    """Generate a fresh identity verification challenge.

    Args:
        from_fingerprint: PGP fingerprint of the entity issuing the challenge.
        to_fingerprint: PGP fingerprint of the entity being challenged.

    Returns:
        ChallengeRequest: The challenge to send to the prover.
    """
    challenge_hex = secrets.token_hex(CHALLENGE_BYTES)
    return ChallengeRequest(
        challenge_hex=challenge_hex,
        from_fingerprint=from_fingerprint,
        to_fingerprint=to_fingerprint,
    )


def respond_to_challenge(
    challenge: ChallengeRequest,
    private_key_armor: str,
    passphrase: str,
    backend_type: CryptoBackendType = CryptoBackendType.PGPY,
) -> ChallengeResponse:
    """Sign a challenge to prove identity.

    The prover signs the challenge bytes with their private key,
    producing a ChallengeResponse that can be verified by anyone
    who has the prover's public key.

    Args:
        challenge: The challenge to respond to.
        private_key_armor: ASCII-armored private key of the prover.
        passphrase: Passphrase to unlock the private key.
        backend_type: Crypto backend to use.

    Returns:
        ChallengeResponse: Signed response.

    Raises:
        VerificationError: If signing fails.
    """
    backend = get_backend(backend_type)

    try:
        data = challenge.challenge_hex.encode("utf-8")
        signature = backend.sign(data, private_key_armor, passphrase)
        fingerprint = backend.fingerprint_from_armor(private_key_armor)

        return ChallengeResponse(
            challenge_id=challenge.challenge_id,
            challenge_hex=challenge.challenge_hex,
            signature=signature,
            responder_fingerprint=fingerprint,
        )
    except Exception as exc:
        raise VerificationError(f"Failed to sign challenge: {exc}") from exc


def verify_challenge(
    challenge: ChallengeRequest,
    response: ChallengeResponse,
    public_key_armor: str,
    backend_type: CryptoBackendType = CryptoBackendType.PGPY,
) -> bool:
    """Verify a signed challenge response.

    Checks that:
    1. The response matches the original challenge
    2. The PGP signature is valid
    3. The responder fingerprint matches the challenged entity

    Args:
        challenge: The original challenge that was issued.
        response: The signed response from the prover.
        public_key_armor: ASCII-armored public key of the prover.
        backend_type: Crypto backend to use.

    Returns:
        bool: True if the identity is verified.

    Raises:
        VerificationError: If the challenge IDs don't match or
            the fingerprint doesn't match the challenged entity.
    """
    if challenge.challenge_id != response.challenge_id:
        raise VerificationError(
            f"Challenge ID mismatch: expected {challenge.challenge_id}, "
            f"got {response.challenge_id}"
        )

    if challenge.challenge_hex != response.challenge_hex:
        raise VerificationError("Challenge content was tampered with")

    if response.responder_fingerprint != challenge.to_fingerprint:
        raise VerificationError(
            f"Fingerprint mismatch: challenge was for {challenge.to_fingerprint}, "
            f"but response came from {response.responder_fingerprint}"
        )

    backend = get_backend(backend_type)
    data = challenge.challenge_hex.encode("utf-8")

    return backend.verify(data, response.signature, public_key_armor)
