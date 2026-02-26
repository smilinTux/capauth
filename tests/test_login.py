"""Tests for the capauth login module.

Tests URL resolution, claims loading, token caching, GPG signing helpers,
identity loading, and the full do_login flow with mocked HTTP.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from capauth.login import (
    _fingerprint_in_gpg_keyring,
    _load_claims,
    _load_identity,
    _resolve_urls,
    load_cached_token,
)


class TestResolveUrls:
    def test_bare_hostname_gets_https(self):
        """A bare hostname is treated as HTTPS."""
        service_id, challenge, verify = _resolve_urls("nextcloud.penguin.kingdom")
        assert challenge.startswith("https://")
        assert service_id == "nextcloud.penguin.kingdom"

    def test_https_url_preserved(self):
        """An explicit https:// URL is preserved."""
        service_id, challenge, verify = _resolve_urls("https://auth.example.com")
        assert challenge.startswith("https://auth.example.com")
        assert service_id == "auth.example.com"

    def test_challenge_and_verify_endpoints(self):
        """Challenge and verify endpoints are correctly appended."""
        _, challenge, verify = _resolve_urls("myservice.io")
        assert challenge.endswith("/capauth/v1/challenge")
        assert verify.endswith("/capauth/v1/verify")

    def test_custom_path_prefix_preserved(self):
        """A URL with a custom path prefix is respected."""
        _, challenge, _ = _resolve_urls("https://auth.example.com/custom")
        assert "/custom/capauth/v1/challenge" in challenge


class TestLoadClaims:
    def test_returns_default_claims(self, tmp_path):
        """Loads the default claims block from profile.yml."""
        profile_yml = tmp_path / "profile.yml"
        profile_yml.write_text(yaml.dump({
            "claims": {
                "name": "Chef",
                "email": "chef@example.com",
            }
        }), encoding="utf-8")

        claims = _load_claims(base=tmp_path, service_id="any.service", service_profile_name=None)
        assert claims["name"] == "Chef"
        assert claims["email"] == "chef@example.com"

    def test_service_override_takes_precedence(self, tmp_path):
        """Service-specific profile overrides the default claims."""
        profile_yml = tmp_path / "profile.yml"
        profile_yml.write_text(yaml.dump({
            "claims": {"name": "Chef", "email": "chef@example.com"},
            "service_profiles": {
                "gitea.example.com": {"name": "chef-dev", "email": "dev@example.com"},
            },
        }), encoding="utf-8")

        claims = _load_claims(
            base=tmp_path,
            service_id="gitea.example.com",
            service_profile_name=None,
        )
        assert claims["name"] == "chef-dev"
        assert claims["email"] == "dev@example.com"

    def test_explicit_profile_name_overrides_service_id(self, tmp_path):
        """Explicit --service-profile name takes precedence over service hostname."""
        profile_yml = tmp_path / "profile.yml"
        profile_yml.write_text(yaml.dump({
            "claims": {"name": "Chef"},
            "service_profiles": {
                "dev-mode": {"name": "hacker-chef"},
            },
        }), encoding="utf-8")

        claims = _load_claims(
            base=tmp_path,
            service_id="prod.example.com",
            service_profile_name="dev-mode",
        )
        assert claims["name"] == "hacker-chef"

    def test_missing_profile_yml_returns_empty(self, tmp_path):
        """If profile.yml doesn't exist, returns empty dict (anonymous auth)."""
        claims = _load_claims(base=tmp_path, service_id="any.service", service_profile_name=None)
        assert claims == {}


class TestLoadCachedToken:
    def test_valid_cached_token_returned(self, tmp_path):
        """A valid, non-expired token is returned."""
        from datetime import datetime, timezone

        service_id = "test.example.com"
        token_dir = tmp_path / "tokens" / service_id
        token_dir.mkdir(parents=True)
        token_file = token_dir / "tokens.json"

        token_file.write_text(json.dumps({
            "access_token": "test-token",
            "expires_in": 3600,
            "cached_at": datetime.now(timezone.utc).isoformat(),
        }), encoding="utf-8")

        result = load_cached_token(f"https://{service_id}", base_dir=tmp_path)
        assert result is not None
        assert result["access_token"] == "test-token"

    def test_expired_cached_token_returns_none(self, tmp_path):
        """An expired token is not returned."""
        service_id = "expired.example.com"
        token_dir = tmp_path / "tokens" / service_id
        token_dir.mkdir(parents=True)
        token_file = token_dir / "tokens.json"

        token_file.write_text(json.dumps({
            "access_token": "old-token",
            "expires_in": 1,
            "cached_at": "2020-01-01T00:00:00+00:00",  # ancient
        }), encoding="utf-8")

        result = load_cached_token(f"https://{service_id}", base_dir=tmp_path)
        assert result is None

    def test_missing_token_file_returns_none(self, tmp_path):
        """If no token is cached, returns None."""
        result = load_cached_token("https://unknown.example.com", base_dir=tmp_path)
        assert result is None


class TestGpgSigningHelpers:
    """Tests for GPG subprocess signing helpers."""

    def test_fingerprint_in_gpg_keyring_found(self) -> None:
        """Returns True when key exists in keyring."""
        with patch("capauth.login.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="sec  ...", stderr="")
            assert _fingerprint_in_gpg_keyring("A" * 40) is True

    def test_fingerprint_in_gpg_keyring_not_found(self) -> None:
        """Returns False when key is absent from keyring."""
        with patch("capauth.login.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=2, stdout="", stderr="no secret key")
            assert _fingerprint_in_gpg_keyring("B" * 40) is False

    def test_fingerprint_in_gpg_keyring_gpg_missing(self) -> None:
        """Returns False gracefully when gpg binary is not found."""
        with patch("capauth.login.subprocess.run", side_effect=FileNotFoundError):
            assert _fingerprint_in_gpg_keyring("C" * 40) is False


class TestLoadIdentity:
    """Tests for the _load_identity function."""

    def test_uses_gpg_keyring_when_available(self, tmp_path: Path) -> None:
        """Prefers GPG keyring when fingerprint is found there."""
        profile_yml = tmp_path / "profile.yml"
        profile_yml.write_text(
            yaml.dump({"fingerprint": "D" * 40, "claims": {"name": "Test"}}),
            encoding="utf-8",
        )

        fake_pub = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----"
        with (
            patch("capauth.login._fingerprint_in_gpg_keyring", return_value=True),
            patch("capauth.login._gpg_export_pubkey", return_value=fake_pub),
            patch("capauth.login._gpg_sign", return_value="-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----") as mock_sign,
        ):
            fp, pub, sign_fn = _load_identity(tmp_path, passphrase="", use_gpg_keyring=True)
            # Call sign_fn inside the patch context so the mock is still active
            sign_fn(b"test")
            mock_sign.assert_called_once_with(b"test", "D" * 40)

        assert fp == "D" * 40
        assert pub == fake_pub

    def test_reads_fingerprint_from_profile_yml(self, tmp_path: Path) -> None:
        """Reads fingerprint from profile.yml when present."""
        profile_yml = tmp_path / "profile.yml"
        profile_yml.write_text(
            yaml.dump({"fingerprint": "E" * 40}),
            encoding="utf-8",
        )

        fake_pub = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----"
        with (
            patch("capauth.login._fingerprint_in_gpg_keyring", return_value=True),
            patch("capauth.login._gpg_export_pubkey", return_value=fake_pub),
        ):
            fp, _, _ = _load_identity(tmp_path, passphrase="", use_gpg_keyring=True)

        assert fp == "E" * 40

    def test_no_gpg_keyring_falls_back_to_profile(self, tmp_path: Path) -> None:
        """Falls back to PGPy profile when GPG keyring is disabled."""
        from capauth.exceptions import CapAuthError

        # No profile.json exists → should raise CapAuthError
        with pytest.raises(CapAuthError):
            _load_identity(tmp_path, passphrase="pass", use_gpg_keyring=False)


class TestDoLoginWithGpg:
    """Tests for the complete do_login flow using system GPG signing."""

    def _make_fake_challenge(self) -> dict:
        """Minimal challenge response fixture."""
        return {
            "capauth_version": "1.0",
            "nonce": "test-nonce-uuid-1234",
            "client_nonce_echo": "",  # will be overwritten in test
            "timestamp": "2026-02-24T00:00:00+00:00",
            "service": "test.service",
            "expires": "2026-02-24T00:01:00+00:00",
            "server_signature": "",
            "server_public_key": "",
        }

    def test_do_login_with_gpg_keyring(self, tmp_path: Path) -> None:
        """do_login uses GPG keyring when fingerprint is in keyring."""
        from capauth.login import do_login

        FP = "F" * 40
        FAKE_PUB = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----"
        FAKE_SIG = "-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----"

        profile_yml = tmp_path / "profile.yml"
        profile_yml.write_text(
            yaml.dump({"fingerprint": FP, "claims": {"name": "GPG User", "email": "gpg@example.com"}}),
            encoding="utf-8",
        )

        challenge = self._make_fake_challenge()

        # The challenge endpoint echoes back the client nonce
        def fake_post(url, json=None, timeout=None):
            resp = MagicMock()
            resp.is_success = True
            resp.status_code = 200
            if "challenge" in url:
                challenge["client_nonce_echo"] = json["client_nonce"]
                resp.json.return_value = challenge
            else:
                resp.json.return_value = {
                    "authenticated": True,
                    "fingerprint": FP,
                    "access_token": "test-jwt",
                    "expires_in": 3600,
                    "oidc_claims": {},
                }
            return resp

        with (
            patch("capauth.login._fingerprint_in_gpg_keyring", return_value=True),
            patch("capauth.login._gpg_export_pubkey", return_value=FAKE_PUB),
            patch("capauth.login._gpg_sign", return_value=FAKE_SIG),
            patch("capauth.login.httpx.post", side_effect=fake_post),
        ):
            result = do_login(
                service_url="https://test.service",
                passphrase="",
                no_claims=False,
                base_dir=tmp_path,
                use_gpg_keyring=True,
            )

        assert result["fingerprint"] == FP
        assert result["access_token"] == "test-jwt"
        assert result["name"] == "GPG User"

        # Token should be cached on disk
        assert Path(result["token_path"]).exists()
        cached = json.loads(Path(result["token_path"]).read_text())
        assert cached["access_token"] == "test-jwt"

    def test_do_login_anonymous_no_claims(self, tmp_path: Path) -> None:
        """do_login with --no-claims sends empty claims."""
        from capauth.login import do_login

        FP = "G" * 40
        FAKE_PUB = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----"
        FAKE_SIG = "-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----"

        profile_yml = tmp_path / "profile.yml"
        profile_yml.write_text(yaml.dump({"fingerprint": FP, "claims": {"name": "Hidden"}}), encoding="utf-8")

        challenge = self._make_fake_challenge()
        verify_body_received: dict = {}

        def fake_post(url, json=None, timeout=None):
            resp = MagicMock()
            resp.is_success = True
            resp.status_code = 200
            if "challenge" in url:
                challenge["client_nonce_echo"] = json["client_nonce"]
                resp.json.return_value = challenge
            else:
                verify_body_received.update(json)
                resp.json.return_value = {
                    "authenticated": True,
                    "fingerprint": FP,
                    "access_token": "anon-jwt",
                    "expires_in": 3600,
                    "oidc_claims": {},
                }
            return resp

        with (
            patch("capauth.login._fingerprint_in_gpg_keyring", return_value=True),
            patch("capauth.login._gpg_export_pubkey", return_value=FAKE_PUB),
            patch("capauth.login._gpg_sign", return_value=FAKE_SIG),
            patch("capauth.login.httpx.post", side_effect=fake_post),
        ):
            result = do_login(
                service_url="https://test.service",
                passphrase="",
                no_claims=True,  # anonymous
                base_dir=tmp_path,
            )

        # Claims should be empty in the posted body
        assert verify_body_received.get("claims") == {}
        assert result["name"] is None

    def test_do_login_caches_token_to_correct_path(self, tmp_path: Path) -> None:
        """Token is cached at ~/.capauth/tokens/<service_host>/tokens.json."""
        from capauth.login import do_login

        FP = "H" * 40
        FAKE_PUB = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----"
        FAKE_SIG = "-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----"

        profile_yml = tmp_path / "profile.yml"
        profile_yml.write_text(yaml.dump({"fingerprint": FP}), encoding="utf-8")

        challenge = self._make_fake_challenge()

        def fake_post(url, json=None, timeout=None):
            resp = MagicMock()
            resp.is_success = True
            resp.status_code = 200
            if "challenge" in url:
                challenge["client_nonce_echo"] = json["client_nonce"]
                resp.json.return_value = challenge
            else:
                resp.json.return_value = {
                    "authenticated": True,
                    "fingerprint": FP,
                    "access_token": "cached-jwt",
                    "expires_in": 3600,
                    "oidc_claims": {},
                }
            return resp

        with (
            patch("capauth.login._fingerprint_in_gpg_keyring", return_value=True),
            patch("capauth.login._gpg_export_pubkey", return_value=FAKE_PUB),
            patch("capauth.login._gpg_sign", return_value=FAKE_SIG),
            patch("capauth.login.httpx.post", side_effect=fake_post),
        ):
            result = do_login(
                service_url="https://my.service.local",
                passphrase="",
                no_claims=True,
                base_dir=tmp_path,
            )

        expected_token_dir = tmp_path / "tokens" / "my.service.local"
        assert expected_token_dir.exists()
        assert (expected_token_dir / "tokens.json").exists()
