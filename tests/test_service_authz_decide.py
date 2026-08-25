"""Tests for the capauth service ``POST /v1/authz/decide`` endpoint.

This endpoint is the platform's ONE decision point (``capauth.authz.decide``)
exposed over HTTP so a non-Python subapp backend (skgateway) can delegate the
allow/deny instead of porting the PDP. See the SKWorld Authorization Standard
section 1 and spec 2026-08-06 L1.8.

All hermetic: the PDP fact lookups (pairing devices + capability tokens) are
rooted at a per-test ``tmp_path`` via ``CAPAUTH_AUTHZ_BASE_DIR`` /
``svc_app.AUTHZ_BASE_DIR``, so nothing touches the real ``~/.skcapstone``.

Covered:

* gating: an unconfigured endpoint is 503 (never an open oracle);
* gating: a caller with no / wrong service token is 403 (before any decision);
* allow path: a verified subject holding the grant -> ``allow: true`` + audit;
* deny path: no grant -> ``allow: false`` + audit obligation still present;
* fail closed on a malformed body (missing / blank fields);
* the authz token is SEPARATE from the admin token (least privilege).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from capauth.identity_class import IdentityClassName, assign_identity_class
from capauth.pairing import EnrollmentMode, approve, enroll_device
from capauth.tokens import issue_token

from .conftest import enrolled_attested_credentials, enrolled_verified_credentials

SUBJECT = "alice@chef.skworld.io"
PUBKEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----"
AUTHZ_TOKEN = "test-authz-service-token"
AUTH_HEADER = {"Authorization": f"Bearer {AUTHZ_TOKEN}"}

# ``decide`` requires the granting token to carry a verifying signature, so
# tokens here are issued SIGNED against the hermetic gpg stub (see conftest).
pytestmark = pytest.mark.usefixtures("stub_token_signing")


def _enroll(base: Path, *, mode: EnrollmentMode, subject: str = SUBJECT):
    # Card N10: verified/attested enrollment now requires real evidence, so a
    # module-level fake PUBKEY no longer enrolls at those tiers. Mint genuine
    # credentials bound to this exact subject. Enrollment is incidental setup
    # in this file; the assertions below are unchanged.
    pubkey = PUBKEY
    extra: dict = {}
    if mode == EnrollmentMode.VERIFIED:
        pubkey, proof = enrolled_verified_credentials(subject)
        extra = {"proof": proof}
    elif mode == EnrollmentMode.ATTESTED:
        operator_pubkey, attestation = enrolled_attested_credentials(pubkey, subject)
        extra = {"operator_pubkey": operator_pubkey, "attestation": attestation}

    enrollment = enroll_device(
        pubkey,
        ["skchat.send", "skchat.inbox"],
        mode=mode,
        base_dir=base,
        subject=subject,
        **extra,
    )
    record = approve(enrollment.enrollment_id, "operator@chef.skworld", base_dir=base)
    assign_identity_class(subject, IdentityClassName.OPERATOR, base_dir=base)
    return record


def _issue(base: Path, capabilities, *, subject: str = SUBJECT, ttl_hours=24):
    return issue_token(
        home=base,
        subject=subject,
        capabilities=capabilities,
        ttl_hours=ttl_hours,
        sign=True,
    )


class TestAuthzDecideEndpoint:
    """The gated endpoint, configured with a service token + a tmp PDP store."""

    @pytest.fixture(autouse=True)
    def setup_app(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CAPAUTH_DB_PATH", str(tmp_path / "authz_test.db"))
        monkeypatch.setenv("CAPAUTH_AUTHZ_TOKEN", AUTHZ_TOKEN)
        monkeypatch.setenv("CAPAUTH_AUTHZ_BASE_DIR", str(tmp_path))

        import capauth.service.app as svc_app

        # Module-level config is read at import time; force it to the test values.
        svc_app.AUTHZ_TOKEN = AUTHZ_TOKEN
        svc_app.AUTHZ_BASE_DIR = str(tmp_path)
        # The authz endpoint MUST NOT ride on the admin credential.
        svc_app.ADMIN_TOKEN = "different-admin-token"

        from fastapi.testclient import TestClient

        self.svc_app = svc_app
        self.base = tmp_path
        self.client = TestClient(svc_app.app)

    # --- allow / deny -------------------------------------------------------
    def test_allow_path(self) -> None:
        """A verified subject holding the grant -> allow, with an audit obligation."""
        _enroll(self.base, mode=EnrollmentMode.VERIFIED)
        _issue(self.base, ["skchat.send"])

        resp = self.client.post(
            "/v1/authz/decide",
            json={"subject": SUBJECT, "capability": "skchat.send", "resource": {"peer": "bob"}},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["allow"] is True
        assert "granted" in body["reason"]
        audits = [o for o in body["obligations"] if o["kind"] == "audit"]
        assert len(audits) == 1
        assert audits[0]["data"]["decision"] == "allow"
        assert audits[0]["data"]["subject"] == SUBJECT

    def test_deny_path_no_grant(self) -> None:
        """No token grants the capability -> deny, audit obligation still present."""
        _enroll(self.base, mode=EnrollmentMode.VERIFIED)
        _issue(self.base, ["skchat.inbox"])  # no skchat.send grant

        resp = self.client.post(
            "/v1/authz/decide",
            json={"subject": SUBJECT, "capability": "skchat.send"},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["allow"] is False
        assert "no token grants" in body["reason"]
        audits = [o for o in body["obligations"] if o["kind"] == "audit"]
        assert len(audits) == 1
        assert audits[0]["data"]["decision"] == "deny"

    def test_unknown_subject_fails_closed(self) -> None:
        """An arbitrary unclassified subject is denied before device lookup."""
        resp = self.client.post(
            "/v1/authz/decide",
            json={"subject": "mallory@evil.example", "capability": "skchat.send"},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["allow"] is False
        assert "has no identity class assignment" in body["reason"]

    # --- fail closed on bad input ------------------------------------------
    def test_malformed_body_missing_capability(self) -> None:
        """A body missing a required field is rejected (422), never decided."""
        resp = self.client.post(
            "/v1/authz/decide",
            json={"subject": SUBJECT},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 422

    def test_blank_fields_rejected(self) -> None:
        """Structurally present but blank subject/capability -> 400, never decided."""
        resp = self.client.post(
            "/v1/authz/decide",
            json={"subject": "   ", "capability": "skchat.send"},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 400

    # --- gating -------------------------------------------------------------
    def test_missing_token_refused(self) -> None:
        """A caller with no service credential is refused BEFORE any decision."""
        _enroll(self.base, mode=EnrollmentMode.VERIFIED)
        _issue(self.base, ["skchat.send"])

        resp = self.client.post(
            "/v1/authz/decide",
            json={"subject": SUBJECT, "capability": "skchat.send"},
        )
        assert resp.status_code == 403

    def test_wrong_token_refused(self) -> None:
        """A caller with the WRONG service credential is refused."""
        resp = self.client.post(
            "/v1/authz/decide",
            json={"subject": SUBJECT, "capability": "skchat.send"},
            headers={"Authorization": "Bearer not-the-authz-token"},
        )
        assert resp.status_code == 403

    def test_admin_token_is_not_accepted(self) -> None:
        """Least privilege: the admin credential does NOT unlock the authz endpoint."""
        resp = self.client.post(
            "/v1/authz/decide",
            json={"subject": SUBJECT, "capability": "skchat.send"},
            headers={"Authorization": "Bearer different-admin-token"},
        )
        assert resp.status_code == 403


class TestAuthzDecideDisabledByDefault:
    """With no service token configured, the endpoint is DISABLED (fail closed)."""

    @pytest.fixture(autouse=True)
    def setup_app(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CAPAUTH_DB_PATH", str(tmp_path / "authz_off.db"))
        monkeypatch.delenv("CAPAUTH_AUTHZ_TOKEN", raising=False)

        import capauth.service.app as svc_app

        svc_app.AUTHZ_TOKEN = ""  # unconfigured
        svc_app.AUTHZ_BASE_DIR = str(tmp_path)

        from fastapi.testclient import TestClient

        self.client = TestClient(svc_app.app)

    def test_endpoint_disabled_when_unconfigured(self) -> None:
        """No CAPAUTH_AUTHZ_TOKEN -> 503; never an open oracle by default."""
        resp = self.client.post(
            "/v1/authz/decide",
            json={"subject": SUBJECT, "capability": "skchat.send"},
        )
        assert resp.status_code == 503
