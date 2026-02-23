"""Tests for sovereign profile management.

Covers:
  - Profile creation (init_profile)
  - Profile loading
  - Profile signature verification
  - Public key export
  - Duplicate profile rejection
"""

from __future__ import annotations

import pytest

from capauth.exceptions import ProfileError, ProfileExistsError
from capauth.models import SovereignProfile
from capauth.profile import (
    export_public_key,
    init_profile,
    load_profile,
    verify_profile_signature,
)

TEST_NAME = "Test Sovereign"
TEST_EMAIL = "sovereign@capauth.local"
TEST_PASS = "test-sovereign-passphrase-2026"


class TestInitProfile:
    """Profile creation tests."""

    def test_creates_profile_and_keys(self, tmp_capauth_home):
        """Expected: init creates profile.json, public.asc, private.asc."""
        profile = init_profile(
            name=TEST_NAME,
            email=TEST_EMAIL,
            passphrase=TEST_PASS,
            base_dir=tmp_capauth_home,
        )

        assert isinstance(profile, SovereignProfile)
        assert profile.entity.name == TEST_NAME
        assert profile.entity.email == TEST_EMAIL
        assert len(profile.key_info.fingerprint) == 40
        assert profile.signature is not None

        identity_dir = tmp_capauth_home / "identity"
        assert (identity_dir / "profile.json").exists()
        assert (identity_dir / "public.asc").exists()
        assert (identity_dir / "private.asc").exists()

    def test_scaffolds_directory_structure(self, tmp_capauth_home):
        """Expected: init creates data/, acl/, advocate/ subdirs."""
        init_profile(
            name=TEST_NAME,
            email=TEST_EMAIL,
            passphrase=TEST_PASS,
            base_dir=tmp_capauth_home,
        )

        assert (tmp_capauth_home / "data").is_dir()
        assert (tmp_capauth_home / "acl").is_dir()
        assert (tmp_capauth_home / "advocate").is_dir()

    def test_private_key_has_restrictive_perms(self, tmp_capauth_home):
        """Edge: private key file should be 0600 (owner-only)."""
        init_profile(
            name=TEST_NAME,
            email=TEST_EMAIL,
            passphrase=TEST_PASS,
            base_dir=tmp_capauth_home,
        )
        priv = tmp_capauth_home / "identity" / "private.asc"
        mode = oct(priv.stat().st_mode)[-3:]
        assert mode == "600"

    def test_duplicate_init_raises(self, tmp_capauth_home):
        """Failure: calling init twice on the same dir should fail."""
        init_profile(
            name=TEST_NAME,
            email=TEST_EMAIL,
            passphrase=TEST_PASS,
            base_dir=tmp_capauth_home,
        )
        with pytest.raises(ProfileExistsError):
            init_profile(
                name="Another",
                email="another@test.io",
                passphrase="pass2",
                base_dir=tmp_capauth_home,
            )


class TestLoadProfile:
    """Profile loading tests."""

    def test_load_roundtrip(self, tmp_capauth_home):
        """Expected: load returns the same profile that was created."""
        original = init_profile(
            name=TEST_NAME,
            email=TEST_EMAIL,
            passphrase=TEST_PASS,
            base_dir=tmp_capauth_home,
        )
        loaded = load_profile(tmp_capauth_home)

        assert loaded.profile_id == original.profile_id
        assert loaded.entity.name == original.entity.name
        assert loaded.key_info.fingerprint == original.key_info.fingerprint

    def test_load_nonexistent_raises(self, tmp_path):
        """Failure: loading from empty dir should raise ProfileError."""
        with pytest.raises(ProfileError):
            load_profile(tmp_path / "nonexistent")


class TestProfileSignature:
    """Profile signature verification tests."""

    def test_valid_signature(self, tmp_capauth_home):
        """Expected: freshly created profile has a valid signature."""
        profile = init_profile(
            name=TEST_NAME,
            email=TEST_EMAIL,
            passphrase=TEST_PASS,
            base_dir=tmp_capauth_home,
        )
        assert verify_profile_signature(profile, tmp_capauth_home) is True

    def test_tampered_profile_fails_verification(self, tmp_capauth_home):
        """Failure: modifying profile after signing should break verification."""
        profile = init_profile(
            name=TEST_NAME,
            email=TEST_EMAIL,
            passphrase=TEST_PASS,
            base_dir=tmp_capauth_home,
        )
        profile.entity.name = "Tampered Name"
        assert verify_profile_signature(profile, tmp_capauth_home) is False


class TestExportPublicKey:
    """Public key export tests."""

    def test_export_returns_armor(self, tmp_capauth_home):
        """Expected: export returns valid ASCII armor."""
        init_profile(
            name=TEST_NAME,
            email=TEST_EMAIL,
            passphrase=TEST_PASS,
            base_dir=tmp_capauth_home,
        )
        armor = export_public_key(tmp_capauth_home)
        assert "BEGIN PGP PUBLIC KEY BLOCK" in armor

    def test_export_without_init_raises(self, tmp_path):
        """Failure: exporting before init should raise."""
        with pytest.raises(ProfileError):
            export_public_key(tmp_path / "nonexistent")
