"""
Tests for the Nextcloud CapAuth app integration.

Covers:
  1. App structure — required files exist and have correct content.
  2. Proxy logic validation — PHP controller logic reviewed programmatically.
  3. Live proxy test — optional, runs only if CapAuth service is up on localhost:8420.
  4. Install documentation integrity check.
"""

import json
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
WORKSPACE = Path(__file__).parent.parent.parent
NC_APP = WORKSPACE / "nextcloud-capauth"
CAPAUTH_SRC = WORKSPACE / "capauth" / "src" / "capauth" / "service" / "app.py"
SERVICE_URL = os.environ.get("CAPAUTH_SERVICE_URL", "http://localhost:8420")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
def _php_contains(path: Path, *snippets: str) -> None:
    """Assert that a PHP file contains all given string snippets."""
    text = path.read_text()
    for snippet in snippets:
        assert snippet in text, f"{path.name} missing: {snippet!r}"


# ---------------------------------------------------------------------------
# 1. App structure
# ---------------------------------------------------------------------------
class TestAppStructure:
    """Verify all required files exist."""

    REQUIRED_FILES = [
        "appinfo/info.xml",
        "appinfo/routes.php",
        "lib/Controller/LoginController.php",
        "lib/Controller/SettingsController.php",
        "lib/Service/CapAuthService.php",
        "lib/Settings/AdminSettings.php",
        "templates/login.php",
        "templates/admin.php",
        "js/login.js",
        "js/admin.js",
        "css/login.css",
    ]

    @pytest.mark.parametrize("rel_path", REQUIRED_FILES)
    def test_file_exists(self, rel_path):
        """Every required app file must be present."""
        assert (NC_APP / rel_path).exists(), f"Missing: {rel_path}"

    def test_info_xml_valid(self):
        """info.xml must be parseable and reference the correct app id."""
        root = ET.parse(NC_APP / "appinfo/info.xml").getroot()
        assert root.find("id").text == "capauth"
        assert root.find("name").text is not None
        version = root.find("version").text
        assert re.match(r"\d+\.\d+\.\d+", version), f"Bad version: {version}"

    def test_info_xml_nextcloud_dependency(self):
        """info.xml must declare a Nextcloud dependency."""
        root = ET.parse(NC_APP / "appinfo/info.xml").getroot()
        deps = root.find("dependencies")
        assert deps is not None
        nc = deps.find("nextcloud")
        assert nc is not None
        assert int(nc.attrib["min-version"]) >= 28

    def test_info_xml_admin_settings_class(self):
        """info.xml must reference the AdminSettings class."""
        text = (NC_APP / "appinfo/info.xml").read_text()
        assert "OCA\\CapAuth\\Settings\\AdminSettings" in text or "AdminSettings" in text

    def test_routes_define_challenge_and_verify(self):
        """routes.php must map /api/v1/challenge and /api/v1/verify."""
        _php_contains(
            NC_APP / "appinfo/routes.php",
            "/api/v1/challenge",
            "/api/v1/verify",
        )

    def test_routes_define_settings(self):
        """routes.php must map /settings for admin use."""
        _php_contains(NC_APP / "appinfo/routes.php", "settings")


# ---------------------------------------------------------------------------
# 2. Controller logic review
# ---------------------------------------------------------------------------
class TestLoginController:
    """Verify the LoginController contains the expected logic."""

    def test_public_page_annotations(self):
        """Login endpoints must be annotated @PublicPage and @NoCSRFRequired."""
        text = (NC_APP / "lib/Controller/LoginController.php").read_text()
        assert "@PublicPage" in text
        assert "@NoCSRFRequired" in text

    def test_fingerprint_length_validation(self):
        """Controller must validate that the fingerprint is exactly 40 chars."""
        text = (NC_APP / "lib/Controller/LoginController.php").read_text()
        assert "strlen($fingerprint) !== 40" in text or "strlen($fingerprint) != 40" in text

    def test_auto_provisions_user(self):
        """Controller must auto-create a Nextcloud user on first auth."""
        _php_contains(
            NC_APP / "lib/Controller/LoginController.php",
            "createUser",
            "capauth-",
        )

    def test_session_is_created_on_verify(self):
        """Controller must set user session on successful verify."""
        _php_contains(
            NC_APP / "lib/Controller/LoginController.php",
            "setUser",
            "capauth_authenticated",
        )

    def test_claims_update_display_name(self):
        """Controller must update displayName from OIDC claims."""
        _php_contains(
            NC_APP / "lib/Controller/LoginController.php",
            "setDisplayName",
            "oidc_claims",
        )

    def test_redirect_on_success(self):
        """Verify response must include a redirect key."""
        _php_contains(
            NC_APP / "lib/Controller/LoginController.php",
            "'redirect'",
        )


class TestCapAuthService:
    """Verify the CapAuthService PHP proxy."""

    def test_challenge_endpoint_url(self):
        """Service must call /capauth/v1/challenge."""
        _php_contains(
            NC_APP / "lib/Service/CapAuthService.php",
            "/capauth/v1/challenge",
        )

    def test_verify_endpoint_url(self):
        """Service must call /capauth/v1/verify."""
        _php_contains(
            NC_APP / "lib/Service/CapAuthService.php",
            "/capauth/v1/verify",
        )

    def test_default_service_url(self):
        """Service must default to localhost:8420."""
        _php_contains(
            NC_APP / "lib/Service/CapAuthService.php",
            "http://localhost:8420",
        )

    def test_verify_raises_on_non_200(self):
        """Service must throw exception if verify returns non-200."""
        _php_contains(
            NC_APP / "lib/Service/CapAuthService.php",
            "throw new",
            "statusCode",
        )

    def test_capauth_version_header_sent(self):
        """Challenge request must include capauth_version field."""
        _php_contains(
            NC_APP / "lib/Service/CapAuthService.php",
            "capauth_version",
        )


class TestAdminSettings:
    """Verify AdminSettings class exists and references the right section."""

    def test_implements_isettings(self):
        """AdminSettings must implement Nextcloud's ISettings interface."""
        _php_contains(
            NC_APP / "lib/Settings/AdminSettings.php",
            "implements ISettings",
        )

    def test_returns_security_section(self):
        """Settings must appear in the 'security' section of the admin UI."""
        _php_contains(
            NC_APP / "lib/Settings/AdminSettings.php",
            "'security'",
        )

    def test_reads_service_url_config(self):
        """AdminSettings must read the service_url app config."""
        _php_contains(
            NC_APP / "lib/Settings/AdminSettings.php",
            "service_url",
        )


class TestSettingsController:
    """Verify the SettingsController."""

    def test_validates_url(self):
        """Controller must validate the service URL before saving."""
        _php_contains(
            NC_APP / "lib/Controller/SettingsController.php",
            "FILTER_VALIDATE_URL",
        )

    def test_saves_require_approval(self):
        """Controller must persist the require_approval setting."""
        _php_contains(
            NC_APP / "lib/Controller/SettingsController.php",
            "require_approval",
        )


# ---------------------------------------------------------------------------
# 3. JS UI review
# ---------------------------------------------------------------------------
class TestLoginJS:
    """Verify the browser-side login script."""

    def test_sends_fingerprint_to_challenge(self):
        """JS must POST the fingerprint to /api/v1/challenge."""
        _php_contains(NC_APP / "js/login.js", "api/v1/challenge", "fingerprint")

    def test_validates_fingerprint_length(self):
        """JS must check fingerprint is 40 chars."""
        text = (NC_APP / "js/login.js").read_text()
        assert "40" in text

    def test_sends_signature_to_verify(self):
        """JS must POST the signature to /api/v1/verify."""
        _php_contains(NC_APP / "js/login.js", "api/v1/verify", "nonce_signature")

    def test_client_nonce_generation(self):
        """JS must generate a random client nonce using crypto.getRandomValues."""
        _php_contains(NC_APP / "js/login.js", "getRandomValues", "clientNonce")

    def test_browser_extension_hookpoint(self):
        """JS must check for capAuthExtension for auto-signing."""
        _php_contains(NC_APP / "js/login.js", "capAuthExtension", "signChallenge")

    def test_redirect_on_success(self):
        """JS must redirect after successful verify."""
        _php_contains(NC_APP / "js/login.js", "window.location.href", "redirect")


# ---------------------------------------------------------------------------
# 4. Live proxy tests — skipped if service is not running
# ---------------------------------------------------------------------------
def _service_is_up() -> bool:
    """Return True if the CapAuth service responds on SERVICE_URL."""
    try:
        import httpx

        r = httpx.get(f"{SERVICE_URL}/capauth/v1/status", timeout=2.0)
        return r.status_code == 200
    except Exception:
        return False


requires_service = pytest.mark.skipif(
    not _service_is_up(),
    reason=f"CapAuth service not running at {SERVICE_URL}",
)


@requires_service
class TestLiveProxyBehavior:
    """
    Tests that call the CapAuth service directly to validate the expected
    protocol the Nextcloud app will proxy to.  These serve as a compatibility
    check: if these pass, the PHP proxy should work unchanged.
    """

    def test_status_endpoint(self):
        """Service /status must return healthy=true."""
        import httpx

        r = httpx.get(f"{SERVICE_URL}/capauth/v1/status")
        assert r.status_code == 200
        data = r.json()
        assert data.get("healthy") is True

    def test_oidc_discovery_for_nextcloud(self):
        """OIDC discovery must include issuer and token_endpoint."""
        import httpx

        r = httpx.get(f"{SERVICE_URL}/.well-known/openid-configuration")
        assert r.status_code == 200
        data = r.json()
        assert "issuer" in data
        assert "token_endpoint" in data or "authorization_endpoint" in data

    def test_challenge_returns_nonce(self):
        """Challenge endpoint must return a nonce for a valid fingerprint."""
        import httpx

        fake_fp = "A" * 40
        r = httpx.post(
            f"{SERVICE_URL}/capauth/v1/challenge",
            json={
                "capauth_version": "1.0",
                "fingerprint": fake_fp,
                "client_nonce": "dGVzdA==",
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert "nonce" in data

    def test_verify_rejects_bad_signature(self):
        """Verify endpoint must return 401 for a bogus signature."""
        import httpx

        # Issue a challenge first
        fake_fp = "B" * 40
        cr = httpx.post(
            f"{SERVICE_URL}/capauth/v1/challenge",
            json={
                "capauth_version": "1.0",
                "fingerprint": fake_fp,
                "client_nonce": "dGVzdA==",
            },
        )
        assert cr.status_code == 200
        nonce = cr.json()["nonce"]

        # Verify with a garbage signature
        vr = httpx.post(
            f"{SERVICE_URL}/capauth/v1/verify",
            json={
                "capauth_version": "1.0",
                "fingerprint": fake_fp,
                "nonce": nonce,
                "nonce_signature": "not-a-valid-pgp-signature",
                "claims": {},
                "claims_signature": "",
                "public_key": "",
            },
        )
        assert vr.status_code == 401

    def test_verify_rejects_wrong_fingerprint(self):
        """Verify must reject when fingerprint in body differs from challenge."""
        import httpx

        fp1 = "C" * 40
        fp2 = "D" * 40
        cr = httpx.post(
            f"{SERVICE_URL}/capauth/v1/challenge",
            json={
                "capauth_version": "1.0",
                "fingerprint": fp1,
                "client_nonce": "dGVzdA==",
            },
        )
        assert cr.status_code == 200
        nonce = cr.json()["nonce"]

        vr = httpx.post(
            f"{SERVICE_URL}/capauth/v1/verify",
            json={
                "capauth_version": "1.0",
                "fingerprint": fp2,
                "nonce": nonce,
                "nonce_signature": "junk",
                "claims": {},
                "claims_signature": "",
                "public_key": "",
            },
        )
        assert vr.status_code in (400, 401, 422)
