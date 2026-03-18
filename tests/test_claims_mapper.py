"""Tests for the CapAuth → OIDC claims mapper."""

from __future__ import annotations

import pytest

from capauth.authentik.claims_mapper import map_claims, preferred_username_fallback


FINGERPRINT = "8A3FC2D1E4B5A09F" * 2 + "12345678"
# Truncate to 40 chars for a realistic fingerprint
FP = (FINGERPRINT + "X" * 40)[:40]


class TestMapClaimsMinimal:
    def test_sub_is_always_fingerprint(self):
        """sub claim is always the PGP fingerprint."""
        result = map_claims(FP, {})
        assert result["sub"] == FP

    def test_capauth_fingerprint_always_present(self):
        """capauth_fingerprint custom claim is always included."""
        result = map_claims(FP, {})
        assert result["capauth_fingerprint"] == FP

    def test_amr_contains_pgp(self):
        """amr (auth methods references) always includes 'pgp'."""
        result = map_claims(FP, {})
        assert "pgp" in result["amr"]

    def test_anonymous_auth_valid(self):
        """Empty claims produce a valid minimal token."""
        result = map_claims(FP, {})
        assert "name" not in result
        assert "email" not in result
        assert "groups" not in result


class TestMapClaimsProfile:
    def test_name_maps_to_name_and_preferred_username(self):
        """name claim maps to both name and preferred_username."""
        result = map_claims(FP, {"name": "Chef"})
        assert result["name"] == "Chef"
        assert result["preferred_username"] == "Chef"

    def test_avatar_url_maps_to_picture(self):
        """avatar_url maps to the OIDC picture claim."""
        result = map_claims(FP, {"avatar_url": "https://example.com/avatar.png"})
        assert result["picture"] == "https://example.com/avatar.png"

    def test_locale_and_zoneinfo_pass_through(self):
        """locale and zoneinfo map directly."""
        result = map_claims(FP, {"locale": "en-US", "zoneinfo": "Europe/Rome"})
        assert result["locale"] == "en-US"
        assert result["zoneinfo"] == "Europe/Rome"

    def test_agent_type_maps_to_custom_claim(self):
        """agent_type passes through as a custom claim."""
        result = map_claims(FP, {"agent_type": "ai"})
        assert result["agent_type"] == "ai"

    def test_soul_blueprint_dict_extracts_category(self):
        """soul_blueprint dict extracts category to soul_blueprint_category."""
        result = map_claims(FP, {"soul_blueprint": {"category": "companion"}})
        assert result["soul_blueprint_category"] == "companion"

    def test_soul_blueprint_string_passes_through(self):
        """soul_blueprint as a string maps to soul_blueprint_category."""
        result = map_claims(FP, {"soul_blueprint": "guardian"})
        assert result["soul_blueprint_category"] == "guardian"


class TestMapClaimsEmail:
    def test_email_maps_and_email_verified_is_false(self):
        """Email is passed through, but email_verified is always False."""
        result = map_claims(FP, {"email": "chef@skworld.io"})
        assert result["email"] == "chef@skworld.io"
        assert result["email_verified"] is False

    def test_no_email_means_no_email_claim(self):
        """If client asserts no email, no email claim appears."""
        result = map_claims(FP, {"name": "Chef"})
        assert "email" not in result


class TestMapClaimsGroups:
    def test_groups_list_passes_through(self):
        """groups list maps to groups claim."""
        result = map_claims(FP, {"groups": ["admins", "sovereign-stack"]})
        assert result["groups"] == ["admins", "sovereign-stack"]

    def test_groups_string_wraps_in_list(self):
        """A string groups value is wrapped in a list."""
        result = map_claims(FP, {"groups": "admins"})
        assert result["groups"] == ["admins"]


class TestMapClaimsScopes:
    def test_scope_filtering_excludes_profile_without_scope(self):
        """Without profile scope, name and picture are excluded."""
        result = map_claims(
            FP, {"name": "Chef", "email": "x@y.com"}, requested_scopes=["openid", "email"]
        )
        assert "name" not in result
        assert "email" in result

    def test_scope_filtering_excludes_email_without_scope(self):
        """Without email scope, email is excluded."""
        result = map_claims(
            FP, {"name": "Chef", "email": "x@y.com"}, requested_scopes=["openid", "profile"]
        )
        assert "email" not in result
        assert "name" in result

    def test_none_scopes_includes_everything(self):
        """None scopes means include all known claims."""
        result = map_claims(
            FP,
            {"name": "Chef", "email": "x@y.com", "groups": ["admins"]},
            requested_scopes=None,
        )
        assert "name" in result
        assert "email" in result
        assert "groups" in result


class TestCustomClaims:
    def test_capauth_prefixed_unknown_claims_pass_through(self):
        """Unknown claims with capauth_ prefix are relayed."""
        result = map_claims(FP, {"capauth_custom_field": "value"})
        assert result["capauth_custom_field"] == "value"

    def test_unknown_claims_without_prefix_are_dropped(self):
        """Unknown claims without capauth_ prefix are silently dropped."""
        result = map_claims(FP, {"totally_unknown": "should_not_appear"})
        assert "totally_unknown" not in result


class TestPreferredUsernameFallback:
    def test_fallback_includes_fingerprint_prefix(self):
        """Fallback username includes the first 8 chars of fingerprint."""
        result = preferred_username_fallback("AABBCCDD" + "X" * 32)
        assert result == "capauth-AABBCCDD"
