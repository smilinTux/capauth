"""Tests for CapAuth QR login flow — mobile scans QR, desktop polls."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from capauth.service.app import (
    QRChallengeResponse,
    QRStatusResponse,
    _qr_results,
    app,
)

client = TestClient(app)

FAKE_FP = "A" * 40
FAKE_ARMOR = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----"


class TestQRChallenge:
    """Tests for the QR challenge generation endpoint."""

    def test_qr_challenge_returns_nonce(self):
        """QR challenge should return a nonce and callback URL."""
        resp = client.post("/capauth/v1/qr-challenge")
        assert resp.status_code == 200

        data = resp.json()
        assert data["capauth_qr"] == "1.0"
        assert data["nonce"] != ""
        assert data["service"] != ""
        assert "/capauth/v1/qr-verify/" in data["callback"]
        assert data["expires"] != ""

    def test_qr_challenge_nonce_in_callback(self):
        """The callback URL should contain the nonce."""
        resp = client.post("/capauth/v1/qr-challenge")
        data = resp.json()
        assert data["nonce"] in data["callback"]

    def test_qr_challenge_qr_data_url(self):
        """QR data URL should be a data:image/png if segno is available."""
        resp = client.post("/capauth/v1/qr-challenge")
        data = resp.json()
        # May be empty if segno not installed, but should not error
        if data["qr_data_url"]:
            assert data["qr_data_url"].startswith("data:image/png;base64,")

    def test_qr_challenge_unique_nonces(self):
        """Each QR challenge should generate a unique nonce."""
        resp1 = client.post("/capauth/v1/qr-challenge")
        resp2 = client.post("/capauth/v1/qr-challenge")
        assert resp1.json()["nonce"] != resp2.json()["nonce"]


class TestQRStatus:
    """Tests for the QR status polling endpoint."""

    def test_poll_pending(self):
        """Polling a fresh nonce should return pending status."""
        # Create a QR challenge first
        challenge = client.post("/capauth/v1/qr-challenge").json()
        nonce = challenge["nonce"]

        resp = client.get(f"/capauth/v1/qr-status/{nonce}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "pending"
        assert data["access_token"] == ""

    def test_poll_expired_nonce(self):
        """Polling a nonexistent nonce should return expired."""
        resp = client.get("/capauth/v1/qr-status/nonexistent-nonce-id")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "expired"

    def test_poll_authenticated(self):
        """Polling after mobile auth should return authenticated with token."""
        # Simulate a completed QR auth by injecting into _qr_results
        test_nonce = "test-qr-nonce-123"
        _qr_results[test_nonce] = {
            "authenticated": True,
            "fingerprint": FAKE_FP,
            "oidc_claims": {"sub": FAKE_FP, "name": "Test"},
            "access_token": "fake-jwt-token",
            "expires_in": 3600,
        }

        resp = client.get(f"/capauth/v1/qr-status/{test_nonce}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "authenticated"
        assert data["access_token"] == "fake-jwt-token"
        assert data["fingerprint"] == FAKE_FP

    def test_poll_consumes_result(self):
        """Authenticated result should be consumed after first poll."""
        test_nonce = "test-qr-consume-456"
        _qr_results[test_nonce] = {
            "authenticated": True,
            "fingerprint": FAKE_FP,
            "oidc_claims": {},
            "access_token": "jwt",
            "expires_in": 3600,
        }

        # First poll gets the result
        resp1 = client.get(f"/capauth/v1/qr-status/{test_nonce}")
        assert resp1.json()["status"] == "authenticated"

        # Second poll should show expired (result consumed, nonce gone)
        resp2 = client.get(f"/capauth/v1/qr-status/{test_nonce}")
        assert resp2.json()["status"] == "expired"


class TestQRVerify:
    """Tests for the QR verify callback endpoint."""

    def test_verify_missing_fingerprint(self):
        """QR verify without fingerprint should return 400."""
        challenge = client.post("/capauth/v1/qr-challenge").json()
        nonce = challenge["nonce"]

        resp = client.post(
            f"/capauth/v1/qr-verify/{nonce}",
            json={
                "fingerprint": "",
                "nonce": nonce,
                "nonce_signature": "fake-sig",
            },
        )
        assert resp.status_code == 400

    def test_verify_unknown_fingerprint(self):
        """QR verify with unknown fingerprint and no public key should 401."""
        challenge = client.post("/capauth/v1/qr-challenge").json()
        nonce = challenge["nonce"]

        resp = client.post(
            f"/capauth/v1/qr-verify/{nonce}",
            json={
                "fingerprint": FAKE_FP,
                "nonce": nonce,
                "nonce_signature": "fake-sig",
            },
        )
        assert resp.status_code == 401

    def test_verify_expired_nonce(self):
        """QR verify with an expired/nonexistent nonce should 401."""
        resp = client.post(
            "/capauth/v1/qr-verify/expired-nonce-id",
            json={
                "fingerprint": FAKE_FP,
                "nonce": "expired-nonce-id",
                "nonce_signature": "fake-sig",
                "public_key": FAKE_ARMOR,
            },
        )
        assert resp.status_code == 401


class TestQRFlowIntegration:
    """Integration tests for the full QR flow (challenge → verify → poll)."""

    def test_full_flow_stores_result_for_polling(self):
        """A successful QR verify should store a result for desktop polling."""
        # Step 1: Get QR challenge
        challenge = client.post("/capauth/v1/qr-challenge").json()
        nonce = challenge["nonce"]

        # Step 2: Verify the nonce is pending
        status = client.get(f"/capauth/v1/qr-status/{nonce}").json()
        assert status["status"] == "pending"

        # Step 3: Simulate mobile completing auth by injecting result directly
        # (Real crypto verification is tested in test_verifier.py)
        _qr_results[nonce] = {
            "authenticated": True,
            "fingerprint": FAKE_FP,
            "oidc_claims": {"sub": FAKE_FP, "name": "Mobile User"},
            "access_token": "real-jwt-from-qr",
            "expires_in": 3600,
        }

        # Step 4: Desktop polls and gets authenticated
        status = client.get(f"/capauth/v1/qr-status/{nonce}").json()
        assert status["status"] == "authenticated"
        assert status["access_token"] == "real-jwt-from-qr"
        assert status["fingerprint"] == FAKE_FP

    def test_qr_challenge_response_model(self):
        """QR challenge response should match the Pydantic model."""
        resp = client.post("/capauth/v1/qr-challenge")
        data = resp.json()
        model = QRChallengeResponse(**data)
        assert model.capauth_qr == "1.0"
        assert model.nonce != ""

    def test_qr_status_response_model(self):
        """QR status response should match the Pydantic model."""
        resp = client.get("/capauth/v1/qr-status/nonexistent")
        data = resp.json()
        model = QRStatusResponse(**data)
        assert model.status == "expired"
