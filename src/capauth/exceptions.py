"""Custom exception hierarchy for CapAuth."""


class CapAuthError(Exception):
    """Base exception for all CapAuth errors."""


class KeyGenerationError(CapAuthError):
    """Raised when PGP key generation fails."""


class KeyNotFoundError(CapAuthError):
    """Raised when a required PGP key cannot be located."""


class VerificationError(CapAuthError):
    """Raised when identity verification (challenge-response) fails."""


class ChallengeExpiredError(VerificationError):
    """Raised when a challenge is older than the allowed max age.

    Subclass of VerificationError so existing callers that catch
    VerificationError keep working unchanged.
    """


class ChallengeReplayError(VerificationError):
    """Raised when a challenge response is presented more than once.

    Only raised when the caller supplies a replay_guard to
    verify_challenge; the bare primitive does NOT track single-use.
    Subclass of VerificationError for back-compat.
    """


class KeyRevokedError(VerificationError):
    """Raised when the signer's key (or signing subkey) carries a revocation signature.

    Distinct from a bad signature: the crypto may be valid, but the key
    was explicitly revoked and must never authenticate. Subclass of
    VerificationError so existing callers keep working unchanged.
    """


class KeyExpiredError(VerificationError):
    """Raised when the signer's key (or signing subkey) has expired.

    Distinct from a bad signature: the crypto may be valid, but the key
    material is past its declared expiration and must not authenticate.
    Subclass of VerificationError for back-compat.
    """


class SubjectNamingError(CapAuthError):
    """Raised when a subject string fails canonical fqid normalization.

    Raised by :func:`capauth.subject.canonical_subject` for non-ASCII input,
    a trailing dot or empty label, or a string that does not match the fqid
    grammar (IDENTITY_NAMING_STANDARD.md) even after alias translation. This
    is a naming-format defect, distinct from :class:`VerificationError`
    (which signals a cryptographic proof failed).
    """


class ProfileError(CapAuthError):
    """Raised for sovereign profile creation or loading issues."""


class ProfileExistsError(ProfileError):
    """Raised when trying to init a profile that already exists."""


class StorageError(CapAuthError):
    """Raised for filesystem storage read/write failures."""


class BackendError(CapAuthError):
    """Raised when the requested crypto backend is unavailable or misconfigured."""
