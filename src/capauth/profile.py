"""Sovereign profile management for CapAuth.

Handles creation, loading, signing, and export of sovereign profiles —
the decentralized replacement for a "user account."
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from .crypto import CryptoBackend, get_backend
from .exceptions import ProfileError, ProfileExistsError, StorageError
from .models import (
    Algorithm,
    CryptoBackendType,
    EntityInfo,
    EntityType,
    KeyInfo,
    SovereignProfile,
    StorageConfig,
)

DEFAULT_CAPAUTH_DIR = Path.home() / ".capauth"

IDENTITY_DIR = "identity"
DATA_DIR = "data"
ACL_DIR = "acl"
ADVOCATE_DIR = "advocate"

PROFILE_FILENAME = "profile.json"
PUBLIC_KEY_FILENAME = "public.asc"
PRIVATE_KEY_FILENAME = "private.asc"


def _ensure_dir(path: Path) -> None:
    """Create a directory and parents, raising StorageError on failure.

    Args:
        path: Directory path to create.

    Raises:
        StorageError: If creation fails.
    """
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise StorageError(f"Cannot create directory {path}: {exc}") from exc


def init_profile(
    name: str,
    email: str,
    passphrase: str,
    entity_type: EntityType = EntityType.HUMAN,
    algorithm: Algorithm = Algorithm.RSA4096,
    backend_type: CryptoBackendType = CryptoBackendType.PGPY,
    base_dir: Optional[Path] = None,
) -> SovereignProfile:
    """Create a new sovereign profile with a fresh PGP keypair.

    This is the main entry point for ``capauth init``. It:
    1. Generates a PGP keypair
    2. Writes keys to the identity directory
    3. Creates the profile JSON (self-signed)
    4. Scaffolds the directory structure

    Args:
        name: Display name for the entity.
        email: Email or AI identifier.
        passphrase: Passphrase to protect the private key.
        entity_type: human, ai, or organization.
        algorithm: Ed25519 or RSA-4096.
        backend_type: Which crypto backend to use.
        base_dir: Root directory for the profile. Defaults to ~/.capauth/.

    Returns:
        SovereignProfile: The newly created profile.

    Raises:
        ProfileExistsError: If a profile already exists at base_dir.
        KeyGenerationError: If keypair generation fails.
        StorageError: If writing to disk fails.
    """
    base = base_dir or DEFAULT_CAPAUTH_DIR
    identity_dir = base / IDENTITY_DIR

    if (identity_dir / PROFILE_FILENAME).exists():
        raise ProfileExistsError(
            f"Profile already exists at {base}. Use 'capauth profile show' to view it."
        )

    backend = get_backend(backend_type)
    bundle = backend.generate_keypair(name, email, passphrase, algorithm)

    _ensure_dir(identity_dir)
    for subdir in [DATA_DIR, ACL_DIR, ADVOCATE_DIR]:
        _ensure_dir(base / subdir)

    pub_path = identity_dir / PUBLIC_KEY_FILENAME
    priv_path = identity_dir / PRIVATE_KEY_FILENAME

    try:
        pub_path.write_text(bundle.public_armor, encoding="utf-8")
        priv_path.write_text(bundle.private_armor, encoding="utf-8")
        priv_path.chmod(0o600)
    except OSError as exc:
        raise StorageError(f"Failed to write keys: {exc}") from exc

    key_info = KeyInfo(
        fingerprint=bundle.fingerprint,
        algorithm=algorithm,
        public_key_path=str(pub_path),
        private_key_path=str(priv_path),
    )

    entity = EntityInfo(
        entity_type=entity_type,
        name=name,
        email=email,
        handle=f"{name.lower().replace(' ', '-')}@capauth.local",
    )

    storage = StorageConfig(primary=str(base))

    profile = SovereignProfile(
        entity=entity,
        key_info=key_info,
        storage=storage,
        crypto_backend=backend_type,
    )

    profile = _sign_profile(profile, backend, bundle.private_armor, passphrase)
    _save_profile(profile, identity_dir)

    return profile


def _sign_profile(
    profile: SovereignProfile,
    backend: CryptoBackend,
    private_armor: str,
    passphrase: str,
) -> SovereignProfile:
    """Sign the profile JSON with the entity's private key.

    Args:
        profile: Profile to sign (signature field will be set).
        backend: Crypto backend to use.
        private_armor: ASCII-armored private key.
        passphrase: Passphrase for the private key.

    Returns:
        SovereignProfile: The profile with its signature field populated.
    """
    profile.signature = None
    profile_bytes = profile.model_dump_json(indent=2).encode("utf-8")
    sig = backend.sign(profile_bytes, private_armor, passphrase)
    profile.signature = sig
    return profile


def _save_profile(profile: SovereignProfile, identity_dir: Path) -> None:
    """Write the profile JSON to disk.

    Args:
        profile: Profile to persist.
        identity_dir: Directory to write profile.json into.

    Raises:
        StorageError: If writing fails.
    """
    path = identity_dir / PROFILE_FILENAME
    try:
        path.write_text(profile.model_dump_json(indent=2), encoding="utf-8")
    except OSError as exc:
        raise StorageError(f"Failed to write profile: {exc}") from exc


def load_profile(base_dir: Optional[Path] = None) -> SovereignProfile:
    """Load an existing sovereign profile from disk.

    Args:
        base_dir: Root directory of the profile. Defaults to ~/.capauth/.

    Returns:
        SovereignProfile: The loaded profile.

    Raises:
        ProfileError: If no profile exists or JSON is invalid.
    """
    base = base_dir or DEFAULT_CAPAUTH_DIR
    profile_path = base / IDENTITY_DIR / PROFILE_FILENAME

    if not profile_path.exists():
        raise ProfileError(f"No profile found at {profile_path}. Run 'capauth init' first.")

    try:
        raw = profile_path.read_text(encoding="utf-8")
        return SovereignProfile.model_validate_json(raw)
    except Exception as exc:
        raise ProfileError(f"Failed to load profile: {exc}") from exc


def export_public_key(base_dir: Optional[Path] = None) -> str:
    """Read and return the ASCII-armored public key.

    Args:
        base_dir: Root directory of the profile.

    Returns:
        str: ASCII-armored public key.

    Raises:
        ProfileError: If the key file is missing.
    """
    base = base_dir or DEFAULT_CAPAUTH_DIR
    pub_path = base / IDENTITY_DIR / PUBLIC_KEY_FILENAME

    if not pub_path.exists():
        raise ProfileError(f"Public key not found at {pub_path}. Run 'capauth init' first.")

    return pub_path.read_text(encoding="utf-8")


def verify_profile_signature(
    profile: SovereignProfile,
    base_dir: Optional[Path] = None,
) -> bool:
    """Verify that a profile's signature matches its content.

    Args:
        profile: The profile to verify.
        base_dir: Root directory to find the public key.

    Returns:
        bool: True if the signature is valid.
    """
    if not profile.signature:
        return False

    base = base_dir or DEFAULT_CAPAUTH_DIR
    pub_armor = export_public_key(base)
    backend = get_backend(profile.crypto_backend)

    sig = profile.signature
    profile_copy = profile.model_copy()
    profile_copy.signature = None
    profile_bytes = profile_copy.model_dump_json(indent=2).encode("utf-8")

    return backend.verify(profile_bytes, sig, pub_armor)
