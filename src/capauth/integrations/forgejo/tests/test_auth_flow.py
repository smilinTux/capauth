"""Tests for ForgejoAuthFlow — session lifecycle and token exchange."""

from __future__ import annotations

import base64
import hashlib

import jwt
import pytest

from capauth.integrations.forgejo.auth_flow import ForgejoAuthFlow
from capauth.integrations.forgejo.config import ForgejoConfig

FINGERPRINT = "A" * 40
SECRET = "test-jwt-secret-32-bytes-padding!!"


@pytest.fixture
def config() -> ForgejoConfig:
    return ForgejoConfig(
        capauth_base_url="https://auth.example.com",
        capauth_jwt_secret=SECRET,
        forgejo_base_url="https://git.example.com",
        client_id="capauth",
        client_secret="any-secret",
        auth_code_ttl=120,
    )


@pytest.fixture
def flow(config: ForgejoConfig) -> ForgejoAuthFlow:
    return ForgejoAuthFlow(config)


REDIRECT_URI = "https://git.example.com/user/oauth2/capauth/callback"
STATE = "forgejo-state-abc123"
CLAIMS = {"sub": FINGERPRINT, "name": "Alice", "email": "alice@example.com"}


class TestSessionLifecycle:
    def test_create_session_ok(self, flow: ForgejoAuthFlow) -> None:
        session = flow.create_session(
            state=STATE,
            redirect_uri=REDIRECT_URI,
            client_id="capauth",
        )
        assert session.state == STATE
        assert session.client_id == "capauth"
        assert session.fingerprint == ""

    def test_create_session_unknown_client(self, flow: ForgejoAuthFlow) -> None:
        with pytest.raises(ValueError, match="Unknown client_id"):
            flow.create_session(state=STATE, redirect_uri=REDIRECT_URI, client_id="evil")

    def test_create_session_redirect_mismatch(self, flow: ForgejoAuthFlow) -> None:
        with pytest.raises(ValueError, match="redirect_uri mismatch"):
            flow.create_session(
                state=STATE,
                redirect_uri="https://evil.example.com/callback",
                client_id="capauth",
            )

    def test_create_session_empty_redirect_uses_default(self, flow: ForgejoAuthFlow) -> None:
        session = flow.create_session(state=STATE, redirect_uri="", client_id="capauth")
        assert session.redirect_uri == REDIRECT_URI

    def test_get_session(self, flow: ForgejoAuthFlow) -> None:
        flow.create_session(state=STATE, redirect_uri=REDIRECT_URI, client_id="capauth")
        session = flow.get_session(STATE)
        assert session is not None
        assert session.state == STATE

    def test_attach_fingerprint(self, flow: ForgejoAuthFlow) -> None:
        flow.create_session(state=STATE, redirect_uri=REDIRECT_URI, client_id="capauth")
        ok = flow.attach_fingerprint(STATE, FINGERPRINT, "nonce-uuid")
        assert ok is True
        session = flow.get_session(STATE)
        assert session is not None
        assert session.fingerprint == FINGERPRINT
        assert session.nonce == "nonce-uuid"

    def test_attach_fingerprint_missing_session(self, flow: ForgejoAuthFlow) -> None:
        ok = flow.attach_fingerprint("nonexistent-state", FINGERPRINT, "nonce")
        assert ok is False


class TestAuthCodeIssuance:
    def _prepare(self, flow: ForgejoAuthFlow) -> None:
        flow.create_session(state=STATE, redirect_uri=REDIRECT_URI, client_id="capauth")

    def test_issue_code_ok(self, flow: ForgejoAuthFlow) -> None:
        self._prepare(flow)
        code = flow.issue_auth_code(STATE, FINGERPRINT, CLAIMS)
        assert isinstance(code, str)
        assert len(code) > 20

    def test_code_is_single_use(self, flow: ForgejoAuthFlow) -> None:
        """Session is consumed when the code is issued."""
        self._prepare(flow)
        flow.issue_auth_code(STATE, FINGERPRINT, CLAIMS)
        # Session should be gone
        assert flow.get_session(STATE) is None

    def test_issue_code_missing_session(self, flow: ForgejoAuthFlow) -> None:
        with pytest.raises(ValueError, match="No pending session"):
            flow.issue_auth_code("bad-state", FINGERPRINT, CLAIMS)

    def test_issue_code_expired_session(
        self, flow: ForgejoAuthFlow, config: ForgejoConfig
    ) -> None:
        cfg = ForgejoConfig(
            capauth_base_url=config.capauth_base_url,
            capauth_jwt_secret=config.capauth_jwt_secret,
            forgejo_base_url=config.forgejo_base_url,
            client_id=config.client_id,
            auth_code_ttl=-1,  # already expired
        )
        f = ForgejoAuthFlow(cfg)
        f.create_session(state=STATE, redirect_uri=REDIRECT_URI, client_id="capauth", ttl=-1)
        with pytest.raises(ValueError, match="expired"):
            f.issue_auth_code(STATE, FINGERPRINT, CLAIMS)

    def test_pending_counts(self, flow: ForgejoAuthFlow) -> None:
        assert flow.pending_sessions == 0
        assert flow.pending_codes == 0
        self._prepare(flow)
        assert flow.pending_sessions == 1
        flow.issue_auth_code(STATE, FINGERPRINT, CLAIMS)
        assert flow.pending_sessions == 0
        assert flow.pending_codes == 1


class TestCodeExchange:
    def _issue_code(self, flow: ForgejoAuthFlow) -> str:
        flow.create_session(state=STATE, redirect_uri=REDIRECT_URI, client_id="capauth")
        return flow.issue_auth_code(STATE, FINGERPRINT, CLAIMS)

    def test_exchange_returns_tokens(self, flow: ForgejoAuthFlow) -> None:
        code = self._issue_code(flow)
        tokens = flow.exchange_code(
            code=code,
            client_id="capauth",
            client_secret="any",
            redirect_uri=REDIRECT_URI,
        )
        assert "access_token" in tokens
        assert tokens["token_type"] == "Bearer"
        assert tokens["expires_in"] == 3600
        assert "id_token" in tokens

    def test_exchange_jwt_payload(self, flow: ForgejoAuthFlow, config: ForgejoConfig) -> None:
        code = self._issue_code(flow)
        tokens = flow.exchange_code(
            code=code, client_id="capauth", client_secret="x", redirect_uri=REDIRECT_URI
        )
        payload = jwt.decode(
            tokens["access_token"],
            config.capauth_jwt_secret,
            algorithms=["HS256"],
            audience="capauth",
        )
        assert payload["sub"] == FINGERPRINT
        assert payload["capauth_fingerprint"] == FINGERPRINT
        assert payload["amr"] == ["pgp"]
        assert payload["name"] == "Alice"

    def test_exchange_invalid_code(self, flow: ForgejoAuthFlow) -> None:
        with pytest.raises(ValueError, match="invalid_grant"):
            flow.exchange_code(
                code="bad-code", client_id="capauth", client_secret="x", redirect_uri=REDIRECT_URI
            )

    def test_exchange_wrong_client(self, flow: ForgejoAuthFlow) -> None:
        code = self._issue_code(flow)
        with pytest.raises(ValueError, match="invalid_client"):
            flow.exchange_code(
                code=code, client_id="wrong", client_secret="x", redirect_uri=REDIRECT_URI
            )

    def test_exchange_redirect_mismatch(self, flow: ForgejoAuthFlow) -> None:
        code = self._issue_code(flow)
        with pytest.raises(ValueError, match="redirect_uri mismatch"):
            flow.exchange_code(
                code=code,
                client_id="capauth",
                client_secret="x",
                redirect_uri="https://evil.example.com/callback",
            )

    def test_code_is_single_use_on_exchange(self, flow: ForgejoAuthFlow) -> None:
        code = self._issue_code(flow)
        flow.exchange_code(
            code=code, client_id="capauth", client_secret="x", redirect_uri=REDIRECT_URI
        )
        with pytest.raises(ValueError, match="invalid_grant"):
            flow.exchange_code(
                code=code, client_id="capauth", client_secret="x", redirect_uri=REDIRECT_URI
            )


class TestPKCE:
    def test_s256_valid(self) -> None:
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        assert ForgejoAuthFlow.verify_pkce(verifier, challenge, "S256") is True

    def test_s256_invalid(self) -> None:
        assert ForgejoAuthFlow.verify_pkce("wrong", "challenge", "S256") is False

    def test_plain_valid(self) -> None:
        assert ForgejoAuthFlow.verify_pkce("myverifier", "myverifier", "plain") is True

    def test_plain_invalid(self) -> None:
        assert ForgejoAuthFlow.verify_pkce("wrong", "right", "plain") is False

    def test_no_challenge_passes(self) -> None:
        assert ForgejoAuthFlow.verify_pkce("any", "", "S256") is True
