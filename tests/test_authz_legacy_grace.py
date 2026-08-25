"""Tests for the CAPAUTH_LEGACY_UNSIGNED_GRACE_UNTIL exception (card f47e2558).

``capauth.authz.decide`` requires a granting token to carry a signature that
verifies (SEC-CRIT bc56b98b). On a Syncthing-replicated fleet, other nodes may
still hold genuinely unsigned tokens issued before signing worked at all, so a
bare hard flip could lock every one of them out at once. This module covers the
deliberate, bounded escape hatch for that migration window:
``CAPAUTH_LEGACY_UNSIGNED_GRACE_UNTIL``, an operator-set ISO-8601 UTC deadline.

Three properties are locked down:

1. Unconfigured (the default) denies an unsigned token, same as ever. This is
   the default-deny posture the flag must not weaken.
2. A well-formed, still-future deadline allows a genuinely unsigned token
   through, and every such grant is logged at WARNING and says so in its own
   ``reason`` string, distinctly from a normal signed grant.
3. The grace NEVER covers a token that carries a signature which fails to
   verify (tamper, wrong signer, unreachable key): only a token with NO
   signature at all is eligible. An expired or malformed deadline also denies.

All hermetic: no real gpg, using the ``stub_token_signing`` fixture from
conftest for the ALLOW-side cases that need a genuinely verifying signature (so
the "invalid signature is never graced" case is exercised against something
that actually verifies when the grace isn't in play). The unsigned cases need
no crypto at all: ``sign=False`` never touches gpg.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from capauth.authz import LEGACY_UNSIGNED_GRACE_ENV, decide
from capauth.identity_class import IdentityClassName, assign_identity_class
from capauth.pairing import EnrollmentMode, approve, enroll_device
from capauth.subject import canonical_subject
from capauth.tokens import issue_token

from .conftest import enrolled_verified_credentials

SUBJECT = "alice@chef.skworld"
PUBKEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----"
CAPABILITY = "skchat.send"

# ``enroll_device`` now validates proof for verified/attested (card N10,
# 09a6d6f3), so this module's only enrollment mode (VERIFIED) needs a real
# keypair + a real signature over the challenge, not the ``PUBKEY``
# placeholder this file used before that landed. Enrollment here is
# incidental setup for this module's actual subject (the legacy-unsigned-
# TOKEN grace window, card f47e2558): the proof must bind to SUBJECT's
# CANONICAL form (``enroll_device`` still normalizes the missing-TLD legacy
# shape, card N3), not the legacy spelling this file otherwise exercises
# throughout, so it is resolved once here rather than inlined per call.
_CANONICAL_SUBJECT = canonical_subject(SUBJECT)


def _enroll(base: Path, *, mode: EnrollmentMode = EnrollmentMode.VERIFIED) -> None:
    pubkey, proof = enrolled_verified_credentials(_CANONICAL_SUBJECT)
    enrollment = enroll_device(
        pubkey, [CAPABILITY], mode=mode, base_dir=base, subject=SUBJECT, proof=proof
    )
    approve(enrollment.enrollment_id, "operator@chef.skworld", base_dir=base)
    assign_identity_class(_CANONICAL_SUBJECT, IdentityClassName.OPERATOR, base_dir=base)


def _future_deadline(**kwargs) -> str:
    return (datetime.now(timezone.utc) + timedelta(**kwargs)).isoformat()


def _past_deadline(**kwargs) -> str:
    return (datetime.now(timezone.utc) - timedelta(**kwargs)).isoformat()


# --------------------------------------------------------------------------- #
# 1. unconfigured (default) still denies an unsigned token
# --------------------------------------------------------------------------- #
def test_unconfigured_flag_denies_unsigned_token(tmp_path, monkeypatch):
    """The default posture: no env var set -> an unsigned token still denies."""
    monkeypatch.delenv(LEGACY_UNSIGNED_GRACE_ENV, raising=False)
    _enroll(tmp_path)
    issue_token(home=tmp_path, subject=SUBJECT, capabilities=[CAPABILITY], sign=False)

    decision = decide(SUBJECT, CAPABILITY, base_dir=tmp_path)

    assert decision.allow is False
    assert "is unsigned" in decision.reason


def test_blank_flag_denies_unsigned_token(tmp_path, monkeypatch):
    """An env var present but empty/blank is treated as unconfigured, not armed."""
    monkeypatch.setenv(LEGACY_UNSIGNED_GRACE_ENV, "   ")
    _enroll(tmp_path)
    issue_token(home=tmp_path, subject=SUBJECT, capabilities=[CAPABILITY], sign=False)

    assert decide(SUBJECT, CAPABILITY, base_dir=tmp_path).allow is False


def test_malformed_flag_denies_unsigned_token(tmp_path, monkeypatch, caplog):
    """A typo'd deadline fails closed (deny), not open (allow), and is logged."""
    monkeypatch.setenv(LEGACY_UNSIGNED_GRACE_ENV, "not-a-timestamp")
    _enroll(tmp_path)
    issue_token(home=tmp_path, subject=SUBJECT, capabilities=[CAPABILITY], sign=False)

    with caplog.at_level(logging.WARNING, logger="capauth.authz"):
        decision = decide(SUBJECT, CAPABILITY, base_dir=tmp_path)

    assert decision.allow is False
    assert any("not a valid ISO-8601 timestamp" in record.message for record in caplog.records)


def test_expired_flag_denies_unsigned_token(tmp_path, monkeypatch):
    """A deadline that has already passed is the same as unconfigured: deny."""
    monkeypatch.setenv(LEGACY_UNSIGNED_GRACE_ENV, _past_deadline(hours=1))
    _enroll(tmp_path)
    issue_token(home=tmp_path, subject=SUBJECT, capabilities=[CAPABILITY], sign=False)

    decision = decide(SUBJECT, CAPABILITY, base_dir=tmp_path)

    assert decision.allow is False
    assert "is unsigned" in decision.reason


# --------------------------------------------------------------------------- #
# 2. a well-formed, still-future deadline grants, logged, clearly labeled
# --------------------------------------------------------------------------- #
def test_future_flag_grants_unsigned_token_and_logs(tmp_path, monkeypatch, caplog):
    """The one case this flag exists for: explicit, logged, time-boxed tolerance."""
    deadline = _future_deadline(days=7)
    monkeypatch.setenv(LEGACY_UNSIGNED_GRACE_ENV, deadline)
    _enroll(tmp_path)
    issue_token(home=tmp_path, subject=SUBJECT, capabilities=[CAPABILITY], sign=False)

    with caplog.at_level(logging.WARNING, logger="capauth.authz"):
        decision = decide(SUBJECT, CAPABILITY, base_dir=tmp_path)

    assert decision.allow is True
    # Never confused with an ordinary signed grant: the reason says exactly
    # what happened and that the token still needs to be fixed.
    assert "LEGACY GRACE" in decision.reason
    assert "UNSIGNED" in decision.reason
    assert "re-issued signed" in decision.reason
    assert any("LEGACY GRACE" in record.message for record in caplog.records)
    # And the grant is still audited like every other decision.
    assert [o for o in decision.obligations if o.kind == "audit"]


def test_future_flag_does_not_change_a_normal_signed_grant(
    tmp_path, monkeypatch, stub_token_signing
):
    """The flag being armed must not alter the ordinary allow path at all."""
    monkeypatch.setenv(LEGACY_UNSIGNED_GRACE_ENV, _future_deadline(days=7))
    _enroll(tmp_path)
    issue_token(home=tmp_path, subject=SUBJECT, capabilities=[CAPABILITY], sign=True)

    decision = decide(SUBJECT, CAPABILITY, base_dir=tmp_path)

    assert decision.allow is True
    assert "granted" in decision.reason
    assert "LEGACY GRACE" not in decision.reason


# --------------------------------------------------------------------------- #
# 3. the grace never covers a signature that was attempted and failed
# --------------------------------------------------------------------------- #
def test_future_flag_never_grants_a_tampered_signature(tmp_path, monkeypatch, stub_token_signing):
    """A signed-but-tampered token is NEVER graced, armed flag or not.

    This is the sharp edge the grace flag must not blunt: an unsigned token is
    (probably) a migration gap, but a token that carries a signature which
    fails to verify may be an active tamper attempt, and the two must never be
    treated the same way.
    """
    monkeypatch.setenv(LEGACY_UNSIGNED_GRACE_ENV, _future_deadline(days=7))
    _enroll(tmp_path)
    issue_token(home=tmp_path, subject=SUBJECT, capabilities=[CAPABILITY], sign=True)
    assert decide(SUBJECT, CAPABILITY, base_dir=tmp_path).allow is True

    # Tamper the stored token's signature after a valid one was issued.
    token_dir = tmp_path / "security" / "tokens"
    (path,) = sorted(token_dir.glob("*.json"))
    data = json.loads(path.read_text(encoding="utf-8"))
    data["signature"] = "-----BEGIN PGP SIGNATURE-----\ntampered\n-----END PGP SIGNATURE-----\n"
    path.write_text(json.dumps(data), encoding="utf-8")

    decision = decide(SUBJECT, CAPABILITY, base_dir=tmp_path)

    assert decision.allow is False
    assert "does not verify" in decision.reason
    assert "LEGACY GRACE" not in decision.reason
    assert "is unsigned" not in decision.reason
