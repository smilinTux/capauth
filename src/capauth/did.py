"""W3C DID (Decentralized Identity Document) generator for CapAuth sovereign profiles.

Generates three tiers of DID documents:
  Tier 1 (did:key)      — self-contained, zero infrastructure
  Tier 2 (did:web mesh) — Tailscale-mesh-private, full service endpoints
  Tier 3 (did:web pub)  — Public internet, minimal info only

Security invariants enforced by structure:
  - ``from_profile()`` reads ONLY ``public_key_path`` — private key is never accessed.
  - No Tailscale 100.x IPs appear in any generated document.
  - ``memory``, ``journal``, and detailed ``soul`` fields are never included.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("capauth.did")

# W3C context URIs
_W3C_DID_CONTEXT = "https://www.w3.org/ns/did/v1"
_JWS2020_CONTEXT = "https://w3id.org/security/suites/jws-2020/v1"

# RSA multicodec varint prefix: 0x1205 → LEB128 → [0x85, 0x24]
_RSA_MULTICODEC = bytes([0x85, 0x24])

# Base58btc alphabet (Bitcoin)
_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class DIDTier(str, Enum):
    """DID document privacy tier."""

    KEY = "key"  # Tier 1: did:key — self-contained, no infrastructure
    WEB_MESH = "mesh"  # Tier 2: did:web via Tailscale Serve — mesh-private
    WEB_PUBLIC = "public"  # Tier 3: did:web:skworld.io — public, minimal


@dataclass
class DIDContext:
    """Resolved identity fields needed to build DID documents."""

    fingerprint: str
    name: str
    entity_type: str  # "ai", "human", "organization"
    email: Optional[str]
    public_key_armor: str  # ASCII-armored PGP public key (read-only)
    jwk: dict  # JWK representation of the public key
    did_key_id: str  # did:key:z<base58btc>
    capabilities: list[str] = field(default_factory=list)
    vibe: Optional[str] = None
    core_traits: list[str] = field(default_factory=list)
    publish_to_skworld: bool = True  # opt-out flag for public DID publishing


# ---------------------------------------------------------------------------
# Low-level crypto helpers (pure functions, no FastAPI dependency)
# ---------------------------------------------------------------------------


def _int_to_b64url(i: int) -> str:
    """Encode a large integer as URL-safe base64 (no padding)."""
    length = (i.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(i.to_bytes(length, "big")).rstrip(b"=").decode()


def _b58encode(payload: bytes) -> str:
    """Base58btc-encode bytes using the Bitcoin alphabet."""
    leading = 0
    for byte in payload:
        if byte == 0:
            leading += 1
        else:
            break

    n = int.from_bytes(payload, "big")
    result = b""
    while n > 0:
        n, rem = divmod(n, 58)
        result = bytes([_B58_ALPHABET[rem]]) + result

    return (bytes([_B58_ALPHABET[0]]) * leading + result).decode("ascii")


def _pgp_armor_to_rsa_numbers(armor: str) -> tuple[int, int]:
    """Extract RSA modulus (n) and public exponent (e) from ASCII-armored PGP key.

    Tries three approaches to handle pgpy 0.5.x and 0.6.x differences.

    Args:
        armor: ASCII-armored PGP public key.

    Returns:
        Tuple of (n, e) as Python integers.

    Raises:
        ValueError: If RSA numbers cannot be extracted.
    """
    import pgpy  # type: ignore[import]

    key, _ = pgpy.PGPKey.from_blob(armor)

    # Approach 1: pgpy 0.6+ exposes `.public_key` returning a cryptography RSAPublicKey.
    try:
        pub = key.pubkey.public_key  # type: ignore[attr-defined]
        if pub is not None:
            nums = pub.public_numbers()
            return nums.n, nums.e
    except Exception:
        pass

    # Approach 2: pgpy 0.5.x — access keymaterial directly via _key.
    try:
        km = key.pubkey._key.keymaterial  # type: ignore[attr-defined]
        n, e = km.n, km.e
        if isinstance(n, int) and isinstance(e, int):
            return n, e
        if isinstance(n, bytes):
            return int.from_bytes(n, "big"), int.from_bytes(e, "big")
    except Exception:
        pass

    # Approach 3: Primary key keymaterial (alternate pgpy 0.5.x path).
    try:
        km = key._key.keymaterial  # type: ignore[attr-defined]
        n, e = km.n, km.e
        return (
            int.from_bytes(n, "big") if isinstance(n, bytes) else int(n),
            int.from_bytes(e, "big") if isinstance(e, bytes) else int(e),
        )
    except Exception:
        pass

    raise ValueError(
        "Could not extract RSA public key numbers — ensure pgpy and cryptography are installed"
    )


def _rsa_numbers_to_der(n: int, e: int) -> bytes:
    """Convert RSA n, e to DER-encoded SubjectPublicKeyInfo bytes.

    Args:
        n: RSA modulus.
        e: RSA public exponent.

    Returns:
        DER-encoded SubjectPublicKeyInfo bytes.
    """
    from cryptography.hazmat.backends import default_backend  # type: ignore[import]
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPublicNumbers,  # type: ignore[import]
    )
    from cryptography.hazmat.primitives.serialization import (  # type: ignore[import]
        Encoding,
        PublicFormat,
    )

    pub_key = RSAPublicNumbers(e=e, n=n).public_key(default_backend())
    return pub_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def _compute_did_key(der_bytes: bytes) -> str:
    """Compute a did:key identifier from DER SubjectPublicKeyInfo bytes.

    Format: ``did:key:z<base58btc(multicodec_varint + der_bytes)>``
    Multicodec RSA: 0x1205 → LEB128 → ``[0x85, 0x24]``

    Args:
        der_bytes: DER-encoded SubjectPublicKeyInfo bytes.

    Returns:
        ``did:key:z...`` string.
    """
    if not der_bytes:
        return "did:key:zINVALID"
    return f"did:key:z{_b58encode(_RSA_MULTICODEC + der_bytes)}"


def _build_jwk(n: int, e: int) -> dict:
    """Build a JWK dict from RSA n and e.

    Args:
        n: RSA modulus.
        e: RSA public exponent.

    Returns:
        JWK dictionary.
    """
    return {
        "kty": "RSA",
        "use": "sig",
        "n": _int_to_b64url(n),
        "e": _int_to_b64url(e),
        "key_ops": ["verify"],
    }


# ---------------------------------------------------------------------------
# DIDDocumentGenerator
# ---------------------------------------------------------------------------


class DIDDocumentGenerator:
    """Generate W3C DID documents from a CapAuth sovereign profile.

    Security guarantees:
    - ``from_profile()`` reads ONLY the public key file — no private key access.
    - Tailscale 100.x.x.x IPs never appear in any document.
    - Memory, journal, and detailed soul fields are never included.
    """

    def __init__(self, ctx: DIDContext) -> None:
        self._ctx = ctx

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_profile(cls, base_dir: Optional[Path] = None) -> "DIDDocumentGenerator":
        """Build a DIDDocumentGenerator from the local CapAuth profile.

        Reads the public key from ``~/.capauth/identity/public.asc``.
        Never accesses the private key file.

        Args:
            base_dir: CapAuth root directory. Defaults to ``~/.capauth``.

        Returns:
            DIDDocumentGenerator ready to generate documents.

        Raises:
            ProfileError: If no profile exists at base_dir.
            ValueError: If the public key cannot be parsed.
        """
        from .profile import DEFAULT_CAPAUTH_DIR, export_public_key, load_profile

        base = base_dir or DEFAULT_CAPAUTH_DIR
        profile = load_profile(base)

        # Read PUBLIC key only — private key is never opened.
        pub_armor = export_public_key(base)

        try:
            n, e = _pgp_armor_to_rsa_numbers(pub_armor)
            jwk = _build_jwk(n, e)
            der_bytes = _rsa_numbers_to_der(n, e)
            did_key_id = _compute_did_key(der_bytes)
        except Exception as exc:
            logger.warning(
                "RSA extraction failed (%s) — generating fingerprint-based placeholder", exc
            )
            fp_clean = profile.key_info.fingerprint.replace(" ", "")
            fp_bytes = (
                bytes.fromhex(fp_clean)
                if len(fp_clean) >= 2 and all(c in "0123456789abcdefABCDEF" for c in fp_clean)
                else fp_clean.encode()
            )
            did_key_id = f"did:key:z{_b58encode(fp_bytes)}"
            jwk = {
                "kty": "RSA",
                "use": "sig",
                "key_ops": ["verify"],
                "note": f"JWK extraction failed: {exc}",
            }

        # Optional: load soul vibe + core_traits (used in Tier 2 agentCard + identity card)
        vibe: Optional[str] = None
        core_traits: list[str] = []
        soul_path = Path.home() / ".skcapstone" / "soul" / "active.yaml"
        if soul_path.exists():
            try:
                import yaml  # type: ignore[import]

                soul_data = yaml.safe_load(soul_path.read_text(encoding="utf-8")) or {}
                vibe = soul_data.get("vibe")
                core_traits = soul_data.get("core_traits", [])[:5]
            except Exception:
                pass

        # Optional: load capabilities from skcapstone identity
        capabilities: list[str] = []
        identity_path = Path.home() / ".skcapstone" / "identity" / "identity.json"
        if identity_path.exists():
            try:
                data = json.loads(identity_path.read_text(encoding="utf-8"))
                capabilities = data.get("capabilities", [])
            except Exception:
                pass

        # Load publish_to_skworld preference from config or registry entry.
        # Default is True (opt-in to public publishing for full transparency).
        # Users can set publish_to_skworld: false in ~/.capauth/config.yaml
        # or in their registry entry to opt out of public DID publishing.
        publish_to_skworld = True
        config_path = base / "config.yaml"
        if config_path.exists():
            try:
                import yaml as _yaml

                cfg = _yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
                if "publish_to_skworld" in cfg:
                    publish_to_skworld = bool(cfg["publish_to_skworld"])
            except Exception:
                pass

        ctx = DIDContext(
            fingerprint=profile.key_info.fingerprint,
            name=profile.entity.name,
            entity_type=profile.entity.entity_type.value,
            email=profile.entity.email,
            public_key_armor=pub_armor,
            jwk=jwk,
            did_key_id=did_key_id,
            capabilities=capabilities,
            vibe=vibe,
            core_traits=core_traits,
            publish_to_skworld=publish_to_skworld,
        )
        return cls(ctx)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(
        self,
        tier: DIDTier,
        *,
        tailnet_hostname: str = "",
        tailnet_name: str = "",
        org_domain: str = "skworld.io",
        agent_slug: str = "",
    ) -> dict:
        """Generate a DID document for the specified tier.

        Args:
            tier: Which DID tier to generate.
            tailnet_hostname: Short Tailscale hostname (e.g. ``opus-node``).
                              Required for WEB_MESH; falls back to KEY if absent.
            tailnet_name: Tailnet magic-DNS suffix (e.g. ``tailnet-xyz.ts.net``).
            org_domain: Organisation domain for Tier 3 (default: ``skworld.io``).
            agent_slug: URL-safe slug (default: lowercased entity name).

        Returns:
            DID document dict.
        """
        ctx = self._ctx
        slug = agent_slug or ctx.name.lower().replace(" ", "-")

        if tier == DIDTier.KEY:
            return self._generate_key_did(ctx)
        if tier == DIDTier.WEB_MESH:
            return self._generate_mesh_did(ctx, tailnet_hostname, tailnet_name, slug)
        if tier == DIDTier.WEB_PUBLIC:
            if not ctx.publish_to_skworld:
                logger.info(
                    "Skipping public DID generation — publish_to_skworld is disabled. "
                    "Set publish_to_skworld: true in ~/.capauth/config.yaml to re-enable."
                )
                return {"opted_out": True, "tier": "public", "reason": "publish_to_skworld=false"}
            return self._generate_public_did(ctx, org_domain, slug)
        raise ValueError(f"Unknown DID tier: {tier!r}")

    def generate_all(
        self,
        *,
        tailnet_hostname: str = "",
        tailnet_name: str = "",
        org_domain: str = "skworld.io",
        agent_slug: str = "",
    ) -> dict[DIDTier, dict]:
        """Generate DID documents for all three tiers.

        Returns:
            Mapping of DIDTier → document dict.
        """
        kw: dict[str, Any] = dict(
            tailnet_hostname=tailnet_hostname,
            tailnet_name=tailnet_name,
            org_domain=org_domain,
            agent_slug=agent_slug,
        )
        result = {
            DIDTier.KEY: self.generate(DIDTier.KEY, **kw),
            DIDTier.WEB_MESH: self.generate(DIDTier.WEB_MESH, **kw),
        }
        # Only include public DID if not opted out
        if self._ctx.publish_to_skworld:
            result[DIDTier.WEB_PUBLIC] = self.generate(DIDTier.WEB_PUBLIC, **kw)
        else:
            logger.info("Public DID (Tier 3) skipped — publish_to_skworld is disabled")
        return result

    def generate_identity_card(self, include_soul: bool = True) -> dict:
        """Generate a full sovereign identity card.

        Combines: DID anchor + entity info + soul vibe/traits + capabilities.
        The ``pgp_signature`` field is present but ``null`` — signing requires
        an interactive passphrase and is handled externally.

        This is a LOCAL-ONLY artifact — never published to the internet.

        Args:
            include_soul: Whether to include vibe/traits (default: True).

        Returns:
            Sovereign identity card dict.
        """
        ctx = self._ctx

        also_known_as = [
            x
            for x in [
                f"capauth:{ctx.email}" if ctx.email else None,
                f"capauth:{ctx.fingerprint}",
            ]
            if x
        ]

        card: dict[str, Any] = {
            "card_type": "sovereign_identity",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "entity": {
                "name": ctx.name,
                "entity_type": ctx.entity_type,
                "email": ctx.email,
                "fingerprint": ctx.fingerprint,
                "capauth_uri": (
                    f"capauth:{ctx.email}" if ctx.email else f"capauth:{ctx.fingerprint}"
                ),
            },
            "did_anchor": {
                "key": ctx.did_key_id,
                "also_known_as": also_known_as,
            },
            "verification_method": {
                "id": f"{ctx.did_key_id}#key",
                "type": "JsonWebKey2020",
                "publicKeyJwk": ctx.jwk,
            },
            "capabilities": ctx.capabilities,
            # pgp_signature: None — signing requires interactive passphrase.
            # Use `capauth sign` CLI or a future signing-daemon integration.
            "pgp_signature": None,
        }

        if include_soul and (ctx.vibe or ctx.core_traits):
            card["soul"] = {
                "vibe": ctx.vibe,
                "core_traits": ctx.core_traits,
            }

        return card

    # ------------------------------------------------------------------
    # Internal generation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _vm_id(did_id: str, fragment: str = "key-1") -> str:
        """Build a verification method reference ID."""
        return f"{did_id}#{fragment}"

    def _generate_key_did(self, ctx: DIDContext) -> dict:
        """Tier 1: self-contained did:key document."""
        did_id = ctx.did_key_id
        vm_id = self._vm_id(did_id)
        also_known_as = [
            x
            for x in [
                f"capauth:{ctx.email}" if ctx.email else None,
                f"capauth:{ctx.fingerprint}",
            ]
            if x
        ]

        return {
            "@context": [_W3C_DID_CONTEXT, _JWS2020_CONTEXT],
            "id": did_id,
            "alsoKnownAs": also_known_as,
            "verificationMethod": [
                {
                    "id": vm_id,
                    "type": "JsonWebKey2020",
                    "controller": did_id,
                    "publicKeyJwk": ctx.jwk,
                }
            ],
            "authentication": [vm_id],
            "assertionMethod": [vm_id],
        }

    def _generate_mesh_did(
        self,
        ctx: DIDContext,
        tailnet_hostname: str,
        tailnet_name: str,
        slug: str,
    ) -> dict:
        """Tier 2: did:web accessible only within the Tailscale mesh.

        Service endpoints reference the Tailscale HTTPS hostname (NOT 100.x.x.x IPs).
        Falls back to did:key if no Tailscale hostname is available.
        """
        if tailnet_hostname:
            ts_host = (
                f"{tailnet_hostname}.{tailnet_name}"
                if tailnet_name
                else f"{tailnet_hostname}.ts.net"
            )
            did_id = f"did:web:{ts_host}"
            base_url = f"https://{ts_host}"
        else:
            # No Tailscale hostname — degrade gracefully to did:key
            return self._generate_key_did(ctx)

        vm_id = self._vm_id(did_id)

        doc: dict[str, Any] = {
            "@context": [
                _W3C_DID_CONTEXT,
                _JWS2020_CONTEXT,
                {"skworld": "https://skworld.io/vocab#"},
            ],
            "id": did_id,
            "alsoKnownAs": [
                ctx.did_key_id,
                f"capauth:{ctx.fingerprint}",
            ],
            "verificationMethod": [
                {
                    "id": vm_id,
                    "type": "JsonWebKey2020",
                    "controller": did_id,
                    "publicKeyJwk": ctx.jwk,
                }
            ],
            "authentication": [vm_id],
            "assertionMethod": [vm_id],
            "service": [
                {
                    "id": f"{did_id}#messaging",
                    "type": "SKCommMessaging",
                    "serviceEndpoint": f"{base_url}/api/v1/profile",
                },
                {
                    "id": f"{did_id}#capauth",
                    "type": "CapAuthVerification",
                    "serviceEndpoint": f"{base_url}/api/v1/did/verify",
                },
                {
                    "id": f"{did_id}#agent",
                    "type": "AgentProfile",
                    "serviceEndpoint": f"{base_url}/api/v1/profile/identity",
                },
            ],
        }

        if ctx.capabilities:
            doc["skworld:agentCard"] = {
                "capabilities": ctx.capabilities,
                "entity_type": ctx.entity_type,
            }

        return doc

    def _generate_public_did(
        self,
        ctx: DIDContext,
        org_domain: str,
        slug: str,
    ) -> dict:
        """Tier 3: minimal public DID document.

        Contains ONLY: public key JWK, name, entity_type, org affiliation.
        NO service endpoints. NO Tailscale hostnames. NO capabilities.
        """
        did_id = f"did:web:{org_domain}:agents:{slug}"
        vm_id = self._vm_id(did_id)

        return {
            "@context": [_W3C_DID_CONTEXT, _JWS2020_CONTEXT],
            "id": did_id,
            "alsoKnownAs": [ctx.did_key_id],
            "verificationMethod": [
                {
                    "id": vm_id,
                    "type": "JsonWebKey2020",
                    "controller": did_id,
                    "publicKeyJwk": ctx.jwk,
                }
            ],
            "authentication": [vm_id],
            "assertionMethod": [vm_id],
            # Minimal public metadata — no mesh details, no capabilities
            "skworld:entityType": ctx.entity_type,
            "skworld:name": ctx.name,
            "skworld:organization": org_domain,
        }
