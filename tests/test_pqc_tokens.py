"""Hybrid PQC signature leg for capability TOKENS (CR-3.7 token surface).

Additive and opt-in, mirroring test_pqc_identity.py for the challenge surface.
The hybrid Ed25519 + ML-DSA-65 leg rides ALONGSIDE the classical PGP token
signature, over the exact payload bytes the classical leg signs. Classical-only
tokens are byte-identical on the wire and verify exactly as before.
"""

from __future__ import annotations

import base64

import pytest

pqsig = pytest.importorskip("skcomms.pqsig")
pytestmark = pytest.mark.skipif(not pqsig.is_available(), reason="liboqs (oqs) not available")

from pathlib import Path  # noqa: E402

from capauth.pqc_tokens import (  # noqa: E402
    HYBRID_SIG_SUITE,
    issue_token_hybrid,
    verify_token_hybrid,
)
from capauth.tokens import (  # noqa: E402
    export_token,
    import_token,
    issue_token,
    verify_token,
)


@pytest.fixture
def agent_home(tmp_path: Path) -> Path:
    home = tmp_path / ".skcapstone"
    (home / "identity").mkdir(parents=True, exist_ok=True)
    (home / "security").mkdir(parents=True, exist_ok=True)
    (home / "identity" / "identity.json").write_text(
        '{"name":"t","fingerprint":"AABBCCDDEE1122334455","capauth_managed":true}',
        encoding="utf-8",
    )
    return home


@pytest.fixture
def hybrid_kp():
    return pqsig.generate_keypair()


def test_issue_token_hybrid_attaches_the_hybrid_leg(agent_home, hybrid_kp):
    tok = issue_token_hybrid(
        agent_home, "operator:abc123", ["skchat.inbox"], hybrid_keypair=hybrid_kp
    )
    assert tok.sig_suite == HYBRID_SIG_SUITE
    assert tok.is_hybrid
    assert tok.hybrid_signature and tok.hybrid_ed25519_pub and tok.hybrid_mldsa_pub


def test_verify_token_hybrid_accepts_a_valid_hybrid_token(agent_home, hybrid_kp):
    tok = issue_token_hybrid(
        agent_home, "operator:abc123", ["skchat.inbox"], hybrid_keypair=hybrid_kp
    )
    assert verify_token_hybrid(tok, agent_home) is True


def test_verify_token_hybrid_rejects_a_tampered_hybrid_signature(agent_home, hybrid_kp):
    tok = issue_token_hybrid(
        agent_home, "operator:abc123", ["skchat.inbox"], hybrid_keypair=hybrid_kp
    )
    raw = bytearray(base64.b64decode(tok.hybrid_signature))
    raw[0] ^= 0xFF
    tok.hybrid_signature = base64.b64encode(bytes(raw)).decode("ascii")
    assert verify_token_hybrid(tok, agent_home) is False


def test_verify_token_hybrid_rejects_a_tampered_payload(agent_home, hybrid_kp):
    tok = issue_token_hybrid(
        agent_home, "operator:abc123", ["skchat.inbox"], hybrid_keypair=hybrid_kp
    )
    tok.payload.capabilities.append("skchat.send")  # changed after signing
    assert verify_token_hybrid(tok, agent_home) is False


def test_hybrid_leg_survives_export_import_round_trip(agent_home, hybrid_kp):
    tok = issue_token_hybrid(
        agent_home, "operator:abc123", ["skchat.inbox"], hybrid_keypair=hybrid_kp
    )
    reloaded = import_token(export_token(tok))
    assert reloaded.is_hybrid
    assert reloaded.hybrid_signature == tok.hybrid_signature
    assert verify_token_hybrid(reloaded, agent_home) is True


def test_classical_token_export_is_byte_identical_no_hybrid_keys(agent_home):
    tok = issue_token(agent_home, "operator:abc123", ["skchat.inbox"], sign=False)
    wire = export_token(tok)
    assert "hybrid_signature" not in wire
    assert "sig_suite" not in wire


def test_classical_only_token_matches_plain_verify(agent_home):
    tok = issue_token(agent_home, "operator:abc123", ["skchat.inbox"], sign=False)
    assert tok.is_hybrid is False
    assert verify_token_hybrid(tok, agent_home) == verify_token(tok, agent_home)


def test_require_hybrid_rejects_a_classical_only_token(agent_home):
    tok = issue_token(agent_home, "operator:abc123", ["skchat.inbox"], sign=False)
    assert verify_token_hybrid(tok, agent_home, require_hybrid=True) is False


def test_issue_token_hybrid_needs_a_keypair_or_agent(agent_home):
    with pytest.raises(ValueError):
        issue_token_hybrid(agent_home, "operator:abc123", ["skchat.inbox"])
