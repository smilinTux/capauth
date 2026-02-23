"""Custom exception hierarchy for CapAuth."""


class CapAuthError(Exception):
    """Base exception for all CapAuth errors."""


class KeyGenerationError(CapAuthError):
    """Raised when PGP key generation fails."""


class KeyNotFoundError(CapAuthError):
    """Raised when a required PGP key cannot be located."""


class VerificationError(CapAuthError):
    """Raised when identity verification (challenge-response) fails."""


class ProfileError(CapAuthError):
    """Raised for sovereign profile creation or loading issues."""


class ProfileExistsError(ProfileError):
    """Raised when trying to init a profile that already exists."""


class StorageError(CapAuthError):
    """Raised for filesystem storage read/write failures."""


class BackendError(CapAuthError):
    """Raised when the requested crypto backend is unavailable or misconfigured."""
