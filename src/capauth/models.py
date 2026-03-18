"""Pydantic models for CapAuth sovereign profiles and identity verification."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class EntityType(str, Enum):
    """Type of sovereign entity."""

    HUMAN = "human"
    AI = "ai"
    ORGANIZATION = "organization"


class Algorithm(str, Enum):
    """Supported PGP key algorithms."""

    ED25519 = "ed25519"
    RSA4096 = "rsa4096"


class CryptoBackendType(str, Enum):
    """Available crypto backend implementations."""

    PGPY = "pgpy"
    GNUPG = "gnupg"


class KeyInfo(BaseModel):
    """Metadata about a PGP keypair."""

    fingerprint: str = Field(description="Full 40-character PGP fingerprint")
    algorithm: Algorithm = Field(default=Algorithm.ED25519)
    created: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    public_key_path: str = Field(description="Path to exported public key (.asc)")
    private_key_path: str = Field(description="Path to encrypted private key (.asc)")


class EntityInfo(BaseModel):
    """Identity metadata for a sovereign entity."""

    entity_type: EntityType = Field(default=EntityType.HUMAN)
    name: str = Field(description="Display name")
    email: Optional[str] = Field(default=None, description="Contact email or AI identifier")
    handle: Optional[str] = Field(default=None, description="Unique handle (name@domain)")


class StorageConfig(BaseModel):
    """Storage configuration for a sovereign profile."""

    primary: str = Field(description="Primary storage path (e.g. ~/.capauth/)")


class SovereignProfile(BaseModel):
    """A sovereign entity's CapAuth profile — the decentralized replacement for a user account."""

    capauth_version: str = Field(default="0.1.0")
    profile_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity: EntityInfo
    key_info: KeyInfo
    storage: StorageConfig
    crypto_backend: CryptoBackendType = Field(default=CryptoBackendType.PGPY)
    created: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    signature: Optional[str] = Field(
        default=None, description="PGP signature over the profile JSON"
    )


class ChallengeRequest(BaseModel):
    """An identity verification challenge sent to a peer."""

    challenge_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    challenge_hex: str = Field(description="Random hex bytes the peer must sign")
    from_fingerprint: str = Field(description="Challenger's PGP fingerprint")
    to_fingerprint: str = Field(description="Target's PGP fingerprint")
    created: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ChallengeResponse(BaseModel):
    """A signed response to an identity verification challenge."""

    challenge_id: str = Field(description="ID of the challenge being responded to")
    challenge_hex: str = Field(description="The original challenge hex")
    signature: str = Field(description="PGP signature over the challenge bytes")
    responder_fingerprint: str = Field(description="Responder's PGP fingerprint")
    created: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# Django models for Authentik custom stage (loaded only when Django is available).
# Ensures CapAuthStage and CapAuthKeyRegistry are discovered when "capauth" is in INSTALLED_APPS.
try:
    from capauth.authentik.stage import CapAuthKeyRegistry, CapAuthStage  # noqa: F401
except ImportError:
    pass
