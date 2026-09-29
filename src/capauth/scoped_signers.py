"""Declarative policy for fleet-scoped signing identities.

The policy contains public metadata and local secret *locators*, never private
key or passphrase bytes. It is intentionally separate from key generation and
deployment so validation and review can run without touching live custody.
"""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ScopedSignerPolicyError(ValueError):
    """A signer policy is malformed or violates a custody boundary."""


class SignerKind(str, Enum):
    """Kinds of principals represented in a signer policy."""

    HUMAN = "human"
    NODE = "node"
    SERVICE = "service"


class SignerStatus(str, Enum):
    """Lifecycle states with explicit verification behavior."""

    PENDING = "pending"
    ACTIVE = "active"
    DRAINING = "draining"
    REVOKED = "revoked"


class EnrollmentEvidence(BaseModel):
    """Public, attributable evidence approving one public signing key."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    proof_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    approved_by: str = Field(min_length=1)
    approved_at: str = Field(min_length=1)


class ScopedSigner(BaseModel):
    """One node, service, or offline human signing identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    identity_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    fingerprint: str = Field(pattern=r"^[0-9A-F]{40}(?:[0-9A-F]{24})?$")
    kind: SignerKind
    node_id: str | None = None
    service_id: str | None = None
    status: SignerStatus
    purposes: frozenset[str] = Field(default_factory=frozenset)
    audiences: frozenset[str] = Field(default_factory=frozenset)
    secret_ref: str | None = None
    enrollment: EnrollmentEvidence
    failover_to: tuple[str, ...] = ()
    attribution_label: str = Field(min_length=1)
    offline_only: bool = False
    revoked_at: str | None = None
    revocation_reason: str | None = None
    successor_id: str | None = None

    @model_validator(mode="after")
    def validate_scope_and_lifecycle(self) -> "ScopedSigner":
        if self.kind is SignerKind.NODE and (not self.node_id or self.service_id):
            raise ValueError("node signer requires node_id and forbids service_id")
        if self.kind is SignerKind.SERVICE and (not self.node_id or not self.service_id):
            raise ValueError("service signer requires node_id and service_id")
        if self.kind is SignerKind.HUMAN:
            if self.node_id or self.service_id or not self.offline_only:
                raise ValueError("human signer must be offline_only and unbound from fleet nodes")
            if self.purposes or self.audiences or self.failover_to:
                raise ValueError("offline human signer cannot be in automated signing scope or failover")
        elif self.offline_only:
            raise ValueError("node and service signers cannot be marked offline_only")
        elif not self.purposes or not self.audiences or not self.secret_ref:
            raise ValueError("fleet signer requires purpose, audience, and local secret_ref")

        revoked = self.status is SignerStatus.REVOKED
        if revoked != bool(self.revoked_at and self.revocation_reason):
            raise ValueError("revoked status requires revoked_at and revocation_reason, and only revoked does")
        if self.status is SignerStatus.DRAINING and not self.successor_id:
            raise ValueError("draining signer requires successor_id")
        return self


class TrustedIssuer(BaseModel):
    """Exact SKLegal verifier trust granted to one signer and scope."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    issuer_id: str
    fingerprint: str = Field(pattern=r"^[0-9A-F]{40}(?:[0-9A-F]{24})?$")
    purposes: frozenset[str] = Field(min_length=1)
    audiences: frozenset[str] = Field(min_length=1)
    principal_kinds: frozenset[SignerKind] = Field(min_length=1)
    integration: str = Field(pattern=r"^sklegal:[a-z0-9._:-]+$")
    trust_revision: str = Field(min_length=1)


class ScopedSignerPolicy(BaseModel):
    """Complete public policy for a fleet signer migration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = Field(ge=1)
    expected_nodes: frozenset[str] = Field(min_length=1)
    synced_roots: tuple[str, ...] = ()
    identities: tuple[ScopedSigner, ...]
    trusted_issuers: tuple[TrustedIssuer, ...]

    @model_validator(mode="after")
    def validate_graph(self) -> "ScopedSignerPolicy":
        by_id = {item.identity_id: item for item in self.identities}
        if len(by_id) != len(self.identities):
            raise ValueError("identity_id values must be unique")
        fingerprints = [item.fingerprint for item in self.identities]
        if len(set(fingerprints)) != len(fingerprints):
            raise ValueError("fingerprints must be unique per node or service identity")

        casey = [item for item in self.identities if item.identity_id == "human:casey"]
        if len(casey) != 1 or casey[0].kind is not SignerKind.HUMAN:
            raise ValueError("exactly one offline human:casey identity is required")

        active_nodes = {
            item.node_id
            for item in self.identities
            if item.kind is SignerKind.NODE and item.status is SignerStatus.ACTIVE
        }
        if active_nodes != set(self.expected_nodes):
            raise ValueError("every expected node requires one active node signer")

        for item in self.identities:
            for target_id in (*item.failover_to, *((item.successor_id,) if item.successor_id else ())):
                target = by_id.get(target_id)
                if target is None:
                    raise ValueError(f"{item.identity_id} references unknown signer {target_id}")
                if target.kind is SignerKind.HUMAN or target.status is SignerStatus.REVOKED:
                    raise ValueError("failover and rotation cannot target human or revoked identities")
                if not item.purposes.issubset(target.purposes) or not item.audiences.issubset(
                    target.audiences
                ):
                    raise ValueError("failover and successor scope must cover the source scope")

        trusted = {(entry.issuer_id, entry.fingerprint) for entry in self.trusted_issuers}
        for item in self.identities:
            if item.kind is SignerKind.HUMAN or item.status is SignerStatus.REVOKED:
                continue
            if (item.identity_id, item.fingerprint) not in trusted:
                raise ValueError(f"{item.identity_id} has no exact SKLegal trusted-issuer entry")

        sync_roots = tuple(Path(root).expanduser().resolve() for root in self.synced_roots)
        for item in self.identities:
            if not item.secret_ref:
                continue
            secret = Path(item.secret_ref).expanduser()
            if not secret.is_absolute():
                raise ValueError(f"{item.identity_id} secret_ref must be an absolute local path")
            resolved = secret.resolve()
            if any(resolved == root or root in resolved.parents for root in sync_roots):
                raise ValueError(f"{item.identity_id} private material is inside a synced root")
        return self

    def permits(self, identity_id: str, purpose: str, audience: str) -> bool:
        """Return whether an active signer and exact trust row permit signing."""
        signer = next((item for item in self.identities if item.identity_id == identity_id), None)
        if signer is None or signer.status is not SignerStatus.ACTIVE:
            return False
        if purpose not in signer.purposes or audience not in signer.audiences:
            return False
        return any(
            trust.issuer_id == signer.identity_id
            and trust.fingerprint == signer.fingerprint
            and purpose in trust.purposes
            and audience in trust.audiences
            and signer.kind in trust.principal_kinds
            for trust in self.trusted_issuers
        )


_FORBIDDEN_KEYS = {
    "private_key",
    "private_key_bytes",
    "passphrase",
    "passphrase_bytes",
    "secret_key",
}


def load_scoped_signer_policy(path: Path) -> tuple[ScopedSignerPolicy, str]:
    """Load public policy JSON, reject embedded secrets, and return its SHA-256."""
    raw = Path(path).read_bytes()
    try:
        data: Any = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScopedSignerPolicyError(f"invalid signer policy JSON: {exc}") from exc

    def reject_secret_fields(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if str(key).lower() in _FORBIDDEN_KEYS:
                    raise ScopedSignerPolicyError(f"private material field {key!r} is forbidden")
                reject_secret_fields(child)
        elif isinstance(value, list):
            for child in value:
                reject_secret_fields(child)

    reject_secret_fields(data)
    try:
        policy = ScopedSignerPolicy.model_validate(data)
    except ValueError as exc:
        raise ScopedSignerPolicyError(str(exc)) from exc
    return policy, hashlib.sha256(raw).hexdigest()
