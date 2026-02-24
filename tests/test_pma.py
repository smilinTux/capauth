"""Tests for the PMA (Private Membership Association) module.

Covers request creation, approval, verification, revocation,
status queries, and CLI commands.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from capauth.pma import (
    MembershipClaim,
    MembershipRequest,
    PMACapability,
    approve_request,
    create_request,
    get_membership_status,
    load_claims,
    load_requests,
    revoke_claim,
    verify_claim,
)


@pytest.fixture
def pma_home(tmp_path):
    """Create a minimal capauth home for PMA tests."""
    identity_dir = tmp_path / "identity"
    identity_dir.mkdir()
    pma_dir = tmp_path / "pma"
    pma_dir.mkdir()
    (pma_dir / "requests").mkdir()
    (pma_dir / "claims").mkdir()
    return tmp_path


@pytest.fixture
def sample_request():
    """A basic membership request."""
    return MembershipRequest(
        requestor_name="Chef",
        requestor_fingerprint="AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555",
        requestor_type="human",
        reason="Sovereign computing",
    )


@pytest.fixture
def sample_claim():
    """A basic membership claim."""
    return MembershipClaim(
        member_name="Chef",
        member_fingerprint="AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555",
        member_type="human",
        steward_name="Lumina",
        steward_fingerprint="FFFF6666GGGG7777HHHH8888IIII9999JJJJ0000",
        capabilities=[PMACapability(name="pma:member")],
        request_id="test-request-id",
    )


class TestPMACapability:
    """Tests for PMACapability model."""

    def test_not_expired_when_no_expiry(self):
        cap = PMACapability(name="pma:member")
        assert not cap.is_expired

    def test_not_expired_when_future(self):
        cap = PMACapability(
            name="pma:member",
            expires_at=datetime.now(timezone.utc) + timedelta(days=365),
        )
        assert not cap.is_expired

    def test_expired_when_past(self):
        cap = PMACapability(
            name="pma:member",
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        assert cap.is_expired

    def test_default_grant_time(self):
        cap = PMACapability(name="pma:steward")
        assert cap.granted_at is not None
        assert cap.name == "pma:steward"


class TestMembershipRequest:
    """Tests for MembershipRequest model."""

    def test_defaults(self, sample_request):
        assert sample_request.request_id
        assert sample_request.requestor_name == "Chef"
        assert sample_request.requestor_signature is None
        assert sample_request.created_at is not None

    def test_serialization_roundtrip(self, sample_request):
        data = json.loads(sample_request.model_dump_json())
        loaded = MembershipRequest.model_validate(data)
        assert loaded.requestor_name == sample_request.requestor_name
        assert loaded.requestor_fingerprint == sample_request.requestor_fingerprint


class TestMembershipClaim:
    """Tests for MembershipClaim model."""

    def test_defaults(self, sample_claim):
        assert sample_claim.claim_id
        assert sample_claim.member_name == "Chef"
        assert sample_claim.steward_name == "Lumina"
        assert not sample_claim.revoked
        assert len(sample_claim.capabilities) == 1

    def test_serialization_roundtrip(self, sample_claim):
        data = json.loads(sample_claim.model_dump_json())
        loaded = MembershipClaim.model_validate(data)
        assert loaded.member_name == sample_claim.member_name
        assert loaded.steward_fingerprint == sample_claim.steward_fingerprint
        assert loaded.capabilities[0].name == "pma:member"


class TestCreateRequest:
    """Tests for create_request."""

    def test_creates_request_file(self, pma_home):
        req = create_request(
            name="TestUser",
            fingerprint="ABCD1234" * 5,
            entity_type="human",
            reason="Testing",
            base_dir=pma_home,
        )
        assert req.requestor_name == "TestUser"
        req_dir = pma_home / "pma" / "requests"
        files = list(req_dir.glob("*.json"))
        assert len(files) == 1

        data = json.loads(files[0].read_text())
        assert data["requestor_name"] == "TestUser"

    def test_creates_ai_request(self, pma_home):
        req = create_request(
            name="Opus",
            fingerprint="DEAD0000" * 5,
            entity_type="ai",
            reason="Sovereign agent",
            base_dir=pma_home,
        )
        assert req.requestor_type == "ai"

    def test_request_without_signature(self, pma_home):
        req = create_request(
            name="TestUser",
            fingerprint="ABCD1234" * 5,
            base_dir=pma_home,
        )
        assert req.requestor_signature is None


class TestApproveRequest:
    """Tests for approve_request."""

    def test_approves_and_creates_claim(self, pma_home, sample_request):
        claim = approve_request(
            request=sample_request,
            steward_name="Lumina",
            steward_fingerprint="FFFF" * 10,
            base_dir=pma_home,
        )
        assert claim.member_name == "Chef"
        assert claim.steward_name == "Lumina"
        assert len(claim.capabilities) == 1
        assert claim.capabilities[0].name == "pma:member"
        assert claim.request_id == sample_request.request_id

        claims_dir = pma_home / "pma" / "claims"
        files = list(claims_dir.glob("*.json"))
        assert len(files) == 1

    def test_custom_capabilities(self, pma_home, sample_request):
        claim = approve_request(
            request=sample_request,
            steward_name="Lumina",
            steward_fingerprint="FFFF" * 10,
            capabilities=["pma:member", "pma:vote", "pma:steward"],
            base_dir=pma_home,
        )
        cap_names = {c.name for c in claim.capabilities}
        assert cap_names == {"pma:member", "pma:vote", "pma:steward"}

    def test_claim_not_revoked_by_default(self, pma_home, sample_request):
        claim = approve_request(
            request=sample_request,
            steward_name="Lumina",
            steward_fingerprint="FFFF" * 10,
            base_dir=pma_home,
        )
        assert not claim.revoked
        assert claim.revoked_at is None


class TestVerifyClaim:
    """Tests for verify_claim."""

    def test_valid_claim(self, sample_claim):
        assert verify_claim(sample_claim) is True

    def test_revoked_claim(self, sample_claim):
        sample_claim.revoked = True
        assert verify_claim(sample_claim) is False

    def test_expired_capability_claim(self):
        claim = MembershipClaim(
            member_name="Test",
            member_fingerprint="AAAA" * 10,
            steward_name="Lumina",
            steward_fingerprint="BBBB" * 10,
            capabilities=[
                PMACapability(
                    name="pma:member",
                    expires_at=datetime.now(timezone.utc) - timedelta(days=1),
                )
            ],
        )
        assert verify_claim(claim) is False

    def test_claim_with_valid_future_expiry(self):
        claim = MembershipClaim(
            member_name="Test",
            member_fingerprint="AAAA" * 10,
            steward_name="Lumina",
            steward_fingerprint="BBBB" * 10,
            capabilities=[
                PMACapability(
                    name="pma:member",
                    expires_at=datetime.now(timezone.utc) + timedelta(days=365),
                )
            ],
        )
        assert verify_claim(claim) is True


class TestRevokeClaim:
    """Tests for revoke_claim."""

    def test_revoke_existing_claim(self, pma_home, sample_request):
        claim = approve_request(
            request=sample_request,
            steward_name="Lumina",
            steward_fingerprint="FFFF" * 10,
            base_dir=pma_home,
        )
        result = revoke_claim(claim.claim_id, base_dir=pma_home)
        assert result is True

        claims = load_claims(pma_home)
        assert claims[0].revoked is True
        assert claims[0].revoked_at is not None

    def test_revoke_nonexistent_claim(self, pma_home):
        result = revoke_claim("nonexistent-id", base_dir=pma_home)
        assert result is False


class TestMembershipStatus:
    """Tests for get_membership_status."""

    def test_no_membership(self, pma_home):
        status = get_membership_status(pma_home)
        assert status["is_member"] is False
        assert status["active_claims"] == 0
        assert status["capabilities"] == []

    def test_active_membership(self, pma_home, sample_request):
        approve_request(
            request=sample_request,
            steward_name="Lumina",
            steward_fingerprint="FFFF" * 10,
            base_dir=pma_home,
        )
        status = get_membership_status(pma_home)
        assert status["is_member"] is True
        assert status["active_claims"] == 1
        assert "pma:member" in status["capabilities"]
        assert status["steward"] == "Lumina"

    def test_revoked_membership(self, pma_home, sample_request):
        claim = approve_request(
            request=sample_request,
            steward_name="Lumina",
            steward_fingerprint="FFFF" * 10,
            base_dir=pma_home,
        )
        revoke_claim(claim.claim_id, base_dir=pma_home)
        status = get_membership_status(pma_home)
        assert status["is_member"] is False
        assert status["revoked_claims"] == 1

    def test_pending_requests_count(self, pma_home):
        create_request(
            name="User1",
            fingerprint="AAAA" * 10,
            base_dir=pma_home,
        )
        create_request(
            name="User2",
            fingerprint="BBBB" * 10,
            base_dir=pma_home,
        )
        status = get_membership_status(pma_home)
        assert status["pending_requests"] == 2


class TestLoadFunctions:
    """Tests for load_claims and load_requests."""

    def test_load_empty_claims(self, pma_home):
        claims = load_claims(pma_home)
        assert claims == []

    def test_load_claims(self, pma_home, sample_request):
        approve_request(
            request=sample_request,
            steward_name="Lumina",
            steward_fingerprint="FFFF" * 10,
            base_dir=pma_home,
        )
        claims = load_claims(pma_home)
        assert len(claims) == 1
        assert claims[0].member_name == "Chef"

    def test_load_empty_requests(self, pma_home):
        requests = load_requests(pma_home)
        assert requests == []

    def test_load_requests(self, pma_home):
        create_request(
            name="Test",
            fingerprint="AAAA" * 10,
            base_dir=pma_home,
        )
        requests = load_requests(pma_home)
        assert len(requests) == 1


class TestPMACLI:
    """Tests for PMA CLI commands."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    @pytest.fixture
    def mock_profile(self):
        profile = MagicMock()
        profile.entity.name = "Chef"
        profile.entity.entity_type.value = "human"
        profile.key_info.fingerprint = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
        return profile

    def test_pma_request_success(self, runner, mock_profile, pma_home):
        from capauth.cli import main

        with patch("capauth.profile.load_profile", return_value=mock_profile):
            result = runner.invoke(
                main,
                ["--home", str(pma_home), "pma", "request", "-r", "Testing"],
                input="testpass\n",
            )
        assert result.exit_code == 0
        assert "request created" in result.output.lower() or "Request" in result.output

    def test_pma_status_no_membership(self, runner, pma_home):
        from capauth.cli import main

        result = runner.invoke(
            main,
            ["--home", str(pma_home), "pma", "status"],
        )
        assert result.exit_code == 0
        assert "NOT A MEMBER" in result.output or "0" in result.output

    def test_pma_status_json(self, runner, pma_home, sample_request):
        from capauth.cli import main

        approve_request(
            request=sample_request,
            steward_name="Lumina",
            steward_fingerprint="FFFF" * 10,
            base_dir=pma_home,
        )

        result = runner.invoke(
            main,
            ["--home", str(pma_home), "pma", "status", "--json-out"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["is_member"] is True
