"""Tests for the Zero-Knowledge Profile protocol invariants.

Verifies that the server NEVER stores PII — only fingerprint + public key.
Tests the claims relay path: client claims → signed bundle → OIDC token.
"""

from __future__ import annotations

import json

import pytest

from capauth.authentik.claims_mapper import map_claims, preferred_username_fallback
from capauth.authentik.verifier import canonical_claims_payload


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FINGERPRINT = "9B3AB00F411B064646879B92D10E637B4F8367DA"
NONCE = "test-nonce-uuid-1234-5678"


# ---------------------------------------------------------------------------
# ZK Invariant: server sub = fingerprint ONLY
# ---------------------------------------------------------------------------


class TestServerSubIsFingerprint:
    """The ``sub`` claim must always be the PGP fingerprint."""

    def test_sub_equals_fingerprint(self):
        claims = map_claims(FINGERPRINT, {"name": "Alice"})
        assert claims["sub"] == FINGERPRINT

    def test_sub_is_not_name(self):
        claims = map_claims(FINGERPRINT, {"name": "Alice"})
        assert claims["sub"] != "Alice"

    def test_sub_is_not_email(self):
        claims = map_claims(FINGERPRINT, {"email": "alice@example.com"})
        assert claims["sub"] != "alice@example.com"

    def test_capauth_fingerprint_always_present(self):
        claims = map_claims(FINGERPRINT, {})
        assert claims["capauth_fingerprint"] == FINGERPRINT

    def test_amr_always_pgp(self):
        claims = map_claims(FINGERPRINT, {})
        assert claims["amr"] == ["pgp"]

    def test_anonymous_auth_sub_is_fingerprint(self):
        """Even with no claims at all, sub is the fingerprint."""
        claims = map_claims(FINGERPRINT, {})
        assert claims["sub"] == FINGERPRINT
        assert "name" not in claims
        assert "email" not in claims


# ---------------------------------------------------------------------------
# ZK Invariant: no PII stored — claims come from client only
# ---------------------------------------------------------------------------


class TestClientAssertedClaims:
    """Claims originate from the client. Server maps but does not persist."""

    def test_name_is_client_asserted(self):
        raw = {"name": "Chef Jonathan"}
        claims = map_claims(FINGERPRINT, raw)
        assert claims["name"] == "Chef Jonathan"
        assert claims["preferred_username"] == "Chef Jonathan"

    def test_email_is_client_asserted(self):
        raw = {"email": "chef@skworld.io"}
        claims = map_claims(FINGERPRINT, raw)
        assert claims["email"] == "chef@skworld.io"

    def test_email_verified_is_always_false(self):
        """Server cannot verify email ownership — client-asserted only."""
        raw = {"email": "legit@example.com"}
        claims = map_claims(FINGERPRINT, raw)
        assert claims["email_verified"] is False

    def test_groups_are_client_asserted(self):
        raw = {"groups": ["admins", "developers"]}
        claims = map_claims(FINGERPRINT, raw)
        assert claims["groups"] == ["admins", "developers"]

    def test_agent_type_is_client_asserted(self):
        raw = {"agent_type": "ai"}
        claims = map_claims(FINGERPRINT, raw)
        assert claims["agent_type"] == "ai"

    def test_no_claims_yields_minimal_token(self):
        """With no claims, token contains only fingerprint + amr."""
        claims = map_claims(FINGERPRINT, {})
        assert set(claims.keys()) == {"sub", "capauth_fingerprint", "amr"}

    def test_unknown_non_prefixed_claims_are_dropped(self):
        """Server silently drops unknown claims not prefixed with capauth_."""
        raw = {"random_field": "should-be-dropped"}
        claims = map_claims(FINGERPRINT, raw)
        assert "random_field" not in claims

    def test_capauth_prefixed_passthrough(self):
        """Custom capauth_ claims relay through to the token."""
        raw = {"capauth_org_id": "sovereign-stack", "capauth_tier": "king"}
        claims = map_claims(FINGERPRINT, raw)
        assert claims["capauth_org_id"] == "sovereign-stack"
        assert claims["capauth_tier"] == "king"


# ---------------------------------------------------------------------------
# ZK Invariant: claims bundle is nonce-bound (replay protection)
# ---------------------------------------------------------------------------


class TestClaimsBundleProtocol:
    """The canonical claims payload binds claims to a specific nonce."""

    def test_canonical_payload_includes_nonce(self):
        payload = canonical_claims_payload(
            FINGERPRINT,
            NONCE,
            {"name": "Alice"},
        )
        assert NONCE.encode() in payload

    def test_canonical_payload_includes_fingerprint(self):
        payload = canonical_claims_payload(
            FINGERPRINT,
            NONCE,
            {"name": "Alice"},
        )
        assert FINGERPRINT.encode() in payload

    def test_canonical_payload_has_version_header(self):
        payload = canonical_claims_payload(FINGERPRINT, NONCE, {})
        assert payload.startswith(b"CAPAUTH_CLAIMS_V1")

    def test_claims_sorted_for_determinism(self):
        """Same claims in different order produce identical payload."""
        p1 = canonical_claims_payload(FINGERPRINT, NONCE, {"b": 2, "a": 1})
        p2 = canonical_claims_payload(FINGERPRINT, NONCE, {"a": 1, "b": 2})
        assert p1 == p2

    def test_different_claims_different_payload(self):
        p1 = canonical_claims_payload(FINGERPRINT, NONCE, {"name": "Alice"})
        p2 = canonical_claims_payload(FINGERPRINT, NONCE, {"name": "Bob"})
        assert p1 != p2

    def test_different_nonces_different_payload(self):
        """Nonce-binding: same claims, different nonce → different payload."""
        p1 = canonical_claims_payload(FINGERPRINT, "nonce-a", {"name": "Alice"})
        p2 = canonical_claims_payload(FINGERPRINT, "nonce-b", {"name": "Alice"})
        assert p1 != p2

    def test_payload_is_bytes(self):
        payload = canonical_claims_payload(FINGERPRINT, NONCE, {})
        assert isinstance(payload, bytes)


# ---------------------------------------------------------------------------
# ZK Invariant: preferred_username fallback from fingerprint
# ---------------------------------------------------------------------------


class TestPreferredUsernameFallback:
    """When no name is claimed, username derives from fingerprint."""

    def test_fallback_stable_for_same_fingerprint(self):
        u1 = preferred_username_fallback(FINGERPRINT)
        u2 = preferred_username_fallback(FINGERPRINT)
        assert u1 == u2

    def test_fallback_uses_first_8_chars(self):
        username = preferred_username_fallback(FINGERPRINT)
        assert FINGERPRINT[:8].upper() in username

    def test_fallback_is_capauth_prefix(self):
        username = preferred_username_fallback(FINGERPRINT)
        assert username.startswith("capauth-")

    def test_different_fingerprints_different_usernames(self):
        u1 = preferred_username_fallback("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        u2 = preferred_username_fallback("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
        assert u1 != u2


# ---------------------------------------------------------------------------
# ZK Invariant: scope-based claim filtering
# ---------------------------------------------------------------------------


class TestScopeFiltering:
    """Claims only appear in token if the corresponding scope is requested."""

    def test_profile_scope_required_for_name(self):
        raw = {"name": "Alice", "email": "alice@example.com"}

        # With profile scope → name is included
        with_scope = map_claims(FINGERPRINT, raw, ["openid", "profile"])
        assert "name" in with_scope

        # Without profile scope → name excluded
        without_scope = map_claims(FINGERPRINT, raw, ["openid", "email"])
        assert "name" not in without_scope

    def test_email_scope_required_for_email(self):
        raw = {"name": "Alice", "email": "alice@example.com"}

        with_email = map_claims(FINGERPRINT, raw, ["openid", "email"])
        assert "email" in with_email

        without_email = map_claims(FINGERPRINT, raw, ["openid", "profile"])
        assert "email" not in without_email

    def test_groups_scope_required_for_groups(self):
        raw = {"groups": ["admins"]}

        with_groups = map_claims(FINGERPRINT, raw, ["openid", "groups"])
        assert "groups" in with_groups

        without_groups = map_claims(FINGERPRINT, raw, ["openid"])
        assert "groups" not in without_groups

    def test_no_scope_filter_includes_all(self):
        """None scopes = include everything (for backward compat)."""
        raw = {
            "name": "Alice",
            "email": "alice@example.com",
            "groups": ["admins"],
        }
        claims = map_claims(FINGERPRINT, raw, requested_scopes=None)
        assert "name" in claims
        assert "email" in claims
        assert "groups" in claims


# ---------------------------------------------------------------------------
# AI Agent ZK Profile
# ---------------------------------------------------------------------------


class TestAIAgentProfile:
    """AI agents assert their identity the same way humans do."""

    def test_ai_agent_type(self):
        raw = {"name": "Lumina", "agent_type": "ai"}
        claims = map_claims(FINGERPRINT, raw)
        assert claims["agent_type"] == "ai"

    def test_soul_blueprint_category(self):
        raw = {
            "name": "Lumina",
            "agent_type": "ai",
            "soul_blueprint": {"category": "authentic-connection"},
        }
        claims = map_claims(FINGERPRINT, raw)
        assert claims["soul_blueprint_category"] == "authentic-connection"

    def test_ai_sub_still_fingerprint(self):
        """AI agents use fingerprints too — same ZK invariant."""
        raw = {"name": "Opus", "agent_type": "ai"}
        claims = map_claims(FINGERPRINT, raw)
        assert claims["sub"] == FINGERPRINT
        assert "Opus" not in claims["sub"]

    def test_ai_email_not_verified(self):
        """Agent emails are self-asserted, not verified."""
        raw = {"name": "Lumina", "agent_type": "ai", "email": "lumina@skworld.io"}
        claims = map_claims(FINGERPRINT, raw)
        assert claims["email_verified"] is False
