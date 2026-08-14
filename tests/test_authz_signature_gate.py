"""The PDP signature gate, against REAL OpenPGP keys (SEC-CRIT bc56b98b).

Regression suite for the defect where ``capauth.authz.decide`` granted the two
skcode RCE capabilities on a token that was never signed. ``issue_token`` failed
to sign (``gpg: skipped ...: No secret key``), stored the unsigned token anyway,
and ``decide`` then answered ``allow=True`` because it gated on exactly four
facts (known capability, enrolled device, enrollment mode, an active non-revoked
token) and never once looked at the signature.

Two properties are locked down here:

1. ``decide`` treats a token whose signature is absent, corrupt, made over
   different bytes, made by a different key than the issuer it declares, or
   unverifiable because the key is not reachable, exactly as if the token were
   not there at all.
2. ``issue_token`` RAISES on a signing failure and writes nothing, rather than
   degrading to an unsigned token that looks issued.

Unlike the hermetic suites (test_authz.py and friends, which stub the gpg
boundary via the ``stub_token_signing`` fixture), everything here runs against a
real generated key and the real ``gpg`` binary, so the signing and verification
path is exercised for real end to end.

Only the tests that need to PRODUCE a valid signature require gpg and skip
without it. The deny-side tests, including the headline unsigned-RCE regression,
run unconditionally: a missing gpg must never be able to turn this file green by
skipping the part that catches the bug.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from capauth.authz import decide
from capauth.pairing import EnrollmentMode, approve, enroll_device
from capauth.tokens import TokenSigningError, issue_token, list_tokens, signature_verifies

SUBJECT = "lumina@chef.skworld.io"
PUBKEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----"

#: The two RCE capabilities. capauth's own rule text calls skcode.dispatch
#: "arbitrary command execution AS the subject; the most sensitive capability".
RCE_CAPABILITIES = ("skcode.dispatch", "skcode.inject")

#: A non-RCE capability, so the blast radius of a mistake in this gate is
#: visible in the suite rather than confined to the RCE rows.
ORDINARY_CAPABILITY = "skchat.send"

ALL_CAPABILITIES = (*RCE_CAPABILITIES, ORDINARY_CAPABILITY)

#: A fingerprint with no secret key anywhere: the one from the live incident.
ABSENT_KEY_FPR = "D8920EA86742260161A220C30355DE4AA63CCD69"

_gpg_missing = pytest.mark.skipif(
    shutil.which("gpg") is None, reason="gpg binary not available to produce a real signature"
)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _make_home(tmp_path: Path, issuer_fpr: str, *, mode=EnrollmentMode.VERIFIED) -> Path:
    """A capauth home with an identity fingerprint and one enrolled device."""
    home = tmp_path / "home"
    (home / "identity").mkdir(parents=True, exist_ok=True)
    (home / "identity" / "identity.json").write_text(
        json.dumps({"fingerprint": issuer_fpr}), encoding="utf-8"
    )
    enrollment = enroll_device(
        PUBKEY, list(ALL_CAPABILITIES), mode=mode, base_dir=home, subject=SUBJECT
    )
    approve(enrollment.enrollment_id, "operator@chef.skworld.io", base_dir=home)
    return home


def _token_files(home: Path) -> list[Path]:
    token_dir = home / "security" / "tokens"
    return sorted(token_dir.glob("*.json")) if token_dir.exists() else []


def _rewrite_stored_token(home: Path, **changes) -> Path:
    """Patch the single stored token file on disk (the store-write adversary)."""
    (path,) = _token_files(home)
    data = json.loads(path.read_text(encoding="utf-8"))
    for key, value in changes.items():
        data[key] = value
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def _new_gnupghome(monkeypatch) -> Path:
    """An isolated, empty GNUPGHOME that gpg and capauth both pick up."""
    home = Path(tempfile.mkdtemp(prefix="capauth-gate-"))
    home.chmod(0o700)
    monkeypatch.setenv("GNUPGHOME", str(home))
    return home


def _generate_key(uid: str) -> str:
    """Generate a signing key in the ambient GNUPGHOME; return its fingerprint."""
    subprocess.run(
        [
            "gpg",
            "--batch",
            "--quiet",
            "--passphrase",
            "",
            "--pinentry-mode",
            "loopback",
            "--quick-generate-key",
            uid,
            "ed25519",
            "sign",
            "1d",
        ],
        capture_output=True,
        check=True,
        timeout=60,
    )
    # Filter by uid: a bare listing returns the FIRST key in the keyring, which
    # is the wrong one as soon as a test generates a second key.
    listing = subprocess.run(
        ["gpg", "--list-secret-keys", "--with-colons", uid],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    for line in listing.stdout.splitlines():
        parts = line.split(":")
        if parts and parts[0] == "fpr":
            return parts[9]
    raise AssertionError(f"no fingerprint after generating {uid!r}")


def _detach_sign(fingerprint: str, data: bytes) -> str:
    """Detached-sign ``data`` with ``fingerprint`` in the ambient GNUPGHOME."""
    result = subprocess.run(
        ["gpg", "--batch", "--yes", "--armor", "--detach-sign", "--local-user", fingerprint],
        input=data,
        capture_output=True,
        check=True,
        timeout=30,
    )
    return result.stdout.decode()


@pytest.fixture
def signing_key(monkeypatch):
    """A real, generated signing key; yields ``(gnupghome, fingerprint)``."""
    if shutil.which("gpg") is None:
        pytest.skip("gpg binary not available")
    gnupghome = _new_gnupghome(monkeypatch)
    fingerprint = _generate_key("CapAuth Gate Test <gate@capauth.local>")
    yield gnupghome, fingerprint
    subprocess.run(
        ["gpgconf", "--homedir", str(gnupghome), "--kill", "gpg-agent"],
        capture_output=True,
        timeout=30,
    )
    shutil.rmtree(gnupghome, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 1. the headline regression: an UNSIGNED token must not grant RCE
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("capability", RCE_CAPABILITIES)
def test_unsigned_token_does_not_grant_rce_capability(tmp_path, capability):
    """The live defect: unsigned token in the store -> decide said allow=True.

    Everything else about this subject is in order (enrolled, verified, an
    active non-revoked token that names the capability). The ONLY thing wrong is
    that nothing ever signed it, which is precisely the case that used to pass.
    """
    home = _make_home(tmp_path, ABSENT_KEY_FPR)
    issue_token(
        home=home, subject=SUBJECT, capabilities=list(ALL_CAPABILITIES), sign=False, ttl_hours=24
    )

    decision = decide(SUBJECT, capability, base_dir=home)

    assert decision.allow is False
    # The unsigned reason, and specifically NOT the invalid-signature reason:
    # those are different operator problems (see
    # test_unsigned_reason_and_invalid_reason_are_distinct below) and this is
    # the "never signed at all" case.
    assert "is unsigned" in decision.reason
    assert "does not verify" not in decision.reason
    # And the deny is still audited, like every other branch.
    assert [o for o in decision.obligations if o.kind == "audit"]


def test_unsigned_token_does_not_grant_ordinary_capability(tmp_path):
    """The gate is not RCE-specific; an unsigned token grants nothing at all."""
    home = _make_home(tmp_path, ABSENT_KEY_FPR)
    issue_token(
        home=home, subject=SUBJECT, capabilities=list(ALL_CAPABILITIES), sign=False, ttl_hours=24
    )

    assert decide(SUBJECT, ORDINARY_CAPABILITY, base_dir=home).allow is False


def test_token_with_unattributable_issuer_does_not_grant(tmp_path, signing_key):
    """A token naming no usable issuer is refused even if something signed it.

    ``_get_issuer_fingerprint`` falls back to the literal ``"unknown"`` when a
    node has no identity file. Such a token cannot be pinned to any key, so it
    must not be verified against "whoever happened to sign it".
    """
    from capauth.tokens import TokenPayload

    _, fingerprint = signing_key
    home = _make_home(tmp_path, fingerprint)
    issue_token(
        home=home, subject=SUBJECT, capabilities=list(ALL_CAPABILITIES), sign=False, ttl_hours=24
    )

    # Rebuild the payload with a placeholder issuer and sign THOSE exact bytes,
    # so the only thing wrong with the token is that it names no usable issuer.
    (path,) = _token_files(home)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["payload"]["issuer"] = "unknown"
    payload = TokenPayload(**data["payload"])
    data["signature"] = _detach_sign(fingerprint, payload.model_dump_json().encode())
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    decision = decide(SUBJECT, "skcode.dispatch", base_dir=home)
    assert decision.allow is False
    # Signed, but the signature is invalid -- NOT the "unsigned" bucket, even
    # though the token failed for a reason rooted in the issuer field.
    assert "does not verify" in decision.reason
    assert "is unsigned" not in decision.reason


# --------------------------------------------------------------------------- #
# 2. corrupted / mismatched signatures
# --------------------------------------------------------------------------- #
def test_corrupted_signature_does_not_grant(tmp_path, signing_key):
    """A validly signed token whose signature is then mangled stops granting."""
    _, fingerprint = signing_key
    home = _make_home(tmp_path, fingerprint)
    issue_token(
        home=home, subject=SUBJECT, capabilities=list(ALL_CAPABILITIES), sign=True, ttl_hours=24
    )
    assert decide(SUBJECT, "skcode.dispatch", base_dir=home).allow is True

    _rewrite_stored_token(
        home,
        signature="-----BEGIN PGP SIGNATURE-----\nnot-a-signature\n-----END PGP SIGNATURE-----\n",
    )

    for capability in ALL_CAPABILITIES:
        decision = decide(SUBJECT, capability, base_dir=home)
        assert decision.allow is False, capability
        # A mangled-but-present signature is "invalid", never "unsigned": the
        # operator needs to know a signature WAS there and failed, which reads
        # very differently from "nobody ever signed this".
        assert "does not verify" in decision.reason
        assert "is unsigned" not in decision.reason


def test_signature_over_different_bytes_does_not_grant(tmp_path, signing_key):
    """Escalating the stored capabilities while keeping the signature fails.

    This is the sharpest form of the store-write attack: keep a genuine
    signature, widen what the payload claims. The signature covers the exact
    payload bytes, so the swap has to be detected.
    """
    _, fingerprint = signing_key
    home = _make_home(tmp_path, fingerprint)
    issue_token(
        home=home, subject=SUBJECT, capabilities=[ORDINARY_CAPABILITY], sign=True, ttl_hours=24
    )
    assert decide(SUBJECT, ORDINARY_CAPABILITY, base_dir=home).allow is True

    (path,) = _token_files(home)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["payload"]["capabilities"] = ["*"]  # the wildcard grant: everything
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    for capability in ALL_CAPABILITIES:
        decision = decide(SUBJECT, capability, base_dir=home)
        assert decision.allow is False, capability
        assert "does not verify" in decision.reason
        assert "is unsigned" not in decision.reason


def test_signature_by_a_different_key_than_the_declared_issuer_does_not_grant(
    tmp_path, signing_key
):
    """A real signature by key B on a payload that declares issuer A is refused.

    Without pinning the signer, any key the verifier happens to hold could mint
    a token claiming to come from the root. The payload bytes here are untouched
    and the signature is genuine, so ONLY the issuer pinning can catch this.
    """
    _, issuer_fpr = signing_key
    other_fpr = _generate_key("CapAuth Other <other@capauth.local>")
    assert other_fpr != issuer_fpr

    home = _make_home(tmp_path, issuer_fpr)
    token = issue_token(
        home=home, subject=SUBJECT, capabilities=list(ALL_CAPABILITIES), sign=False, ttl_hours=24
    )
    assert token.payload.issuer == issuer_fpr

    signed_bytes = token.payload.model_dump_json().encode()
    _rewrite_stored_token(home, signature=_detach_sign(other_fpr, signed_bytes))

    decision = decide(SUBJECT, "skcode.dispatch", base_dir=home)
    assert decision.allow is False
    assert "does not verify" in decision.reason
    assert "is unsigned" not in decision.reason


def test_unreachable_key_material_denies(tmp_path, signing_key, monkeypatch):
    """Fail closed, not open, when the issuer's key cannot be reached.

    Same token, same valid signature, evaluated on a node whose keyring does not
    hold the issuer's public key. The signature fact cannot be established, so
    the request is DENIED rather than waved through. This is the "invalid"
    bucket, not "unsigned": the token DOES carry a signature, it just cannot be
    checked here, and that must never be reported as if nothing were signed.
    """
    _, fingerprint = signing_key
    home = _make_home(tmp_path, fingerprint)
    token = issue_token(
        home=home, subject=SUBJECT, capabilities=list(ALL_CAPABILITIES), sign=True, ttl_hours=24
    )
    assert signature_verifies(token) is True
    assert decide(SUBJECT, "skcode.dispatch", base_dir=home).allow is True

    empty_keyring = Path(tempfile.mkdtemp(prefix="capauth-empty-"))
    empty_keyring.chmod(0o700)
    try:
        monkeypatch.setenv("GNUPGHOME", str(empty_keyring))
        assert signature_verifies(token) is False
        for capability in ALL_CAPABILITIES:
            decision = decide(SUBJECT, capability, base_dir=home)
            assert decision.allow is False
            assert "does not verify" in decision.reason
            assert "is unsigned" not in decision.reason
    finally:
        subprocess.run(
            ["gpgconf", "--homedir", str(empty_keyring), "--kill", "gpg-agent"],
            capture_output=True,
            timeout=30,
        )
        shutil.rmtree(empty_keyring, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 3. a validly signed token still grants (the fleet must not brick)
# --------------------------------------------------------------------------- #
@_gpg_missing
@pytest.mark.parametrize("capability", ALL_CAPABILITIES)
def test_validly_signed_token_still_grants(tmp_path, signing_key, capability):
    """Every PEP in the fleet calls decide(); the allow path must survive.

    Covers both RCE rows and an ordinary capability, so a mistake in this gate
    shows up as a broad failure here rather than as a quiet outage in skharness,
    skgateway, skchat and sk-access at once.
    """
    _, fingerprint = signing_key
    home = _make_home(tmp_path, fingerprint)
    token = issue_token(
        home=home, subject=SUBJECT, capabilities=list(ALL_CAPABILITIES), sign=True, ttl_hours=24
    )

    assert token.signature, "issue_token(sign=True) must produce a signature"
    assert token.verified is True

    decision = decide(SUBJECT, capability, {"peer": "bob@chef.skworld.io"}, base_dir=home)
    assert decision.allow is True, decision.reason
    assert "granted" in decision.reason


@_gpg_missing
def test_validly_signed_wildcard_token_still_grants(tmp_path, signing_key):
    """The Capability.ALL chain keeps working once signatures are required."""
    _, fingerprint = signing_key
    home = _make_home(tmp_path, fingerprint)
    issue_token(home=home, subject=SUBJECT, capabilities=["*"], sign=True, ttl_hours=24)

    for capability in ALL_CAPABILITIES:
        assert decide(SUBJECT, capability, base_dir=home).allow is True


@_gpg_missing
def test_revocation_still_beats_a_valid_signature(tmp_path, signing_key):
    """A perfectly signed token that has been revoked still denies."""
    from capauth.tokens import revoke_token

    _, fingerprint = signing_key
    home = _make_home(tmp_path, fingerprint)
    token = issue_token(
        home=home, subject=SUBJECT, capabilities=list(ALL_CAPABILITIES), sign=True, ttl_hours=24
    )
    assert decide(SUBJECT, "skcode.dispatch", base_dir=home).allow is True

    revoke_token(home, token.payload.token_id)
    assert decide(SUBJECT, "skcode.dispatch", base_dir=home).allow is False


# --------------------------------------------------------------------------- #
# 4. issue_token must fail loudly and write nothing
# --------------------------------------------------------------------------- #
def test_issue_token_raises_and_stores_nothing_when_signing_fails(tmp_path):
    """The exact live repro: no secret key for the issuer fingerprint.

    Previously this logged a warning, returned a token with ``signature=None``,
    and left it in the store where the PDP honoured it.
    """
    home = _make_home(tmp_path, ABSENT_KEY_FPR)
    assert _token_files(home) == []

    with pytest.raises(TokenSigningError) as excinfo:
        issue_token(
            home=home,
            subject=SUBJECT,
            capabilities=list(RCE_CAPABILITIES),
            sign=True,
            ttl_hours=24,
        )

    assert ABSENT_KEY_FPR in str(excinfo.value)
    assert _token_files(home) == [], "a failed signing must leave nothing in the store"
    assert list_tokens(home) == []
    # And with nothing in the store, the subject is denied.
    for capability in RCE_CAPABILITIES:
        assert decide(SUBJECT, capability, base_dir=home).allow is False


def test_mint_audience_token_raises_and_stores_nothing_when_signing_fails(tmp_path):
    """The audience-mint path had the identical fail-open and is fixed with it."""
    from capauth.tokens import mint_audience_token

    home = _make_home(tmp_path, ABSENT_KEY_FPR)

    with pytest.raises(TokenSigningError):
        mint_audience_token(
            home=home,
            subject=SUBJECT,
            audience="skcode",
            scopes=list(RCE_CAPABILITIES),
            sign=True,
        )

    assert _token_files(home) == []


@_gpg_missing
def test_issue_token_succeeds_and_stores_when_signing_works(tmp_path, signing_key):
    """The negative control: with a usable key, issuance still stores a token."""
    _, fingerprint = signing_key
    home = _make_home(tmp_path, fingerprint)

    token = issue_token(
        home=home, subject=SUBJECT, capabilities=list(RCE_CAPABILITIES), sign=True, ttl_hours=24
    )

    assert token.signature
    assert len(_token_files(home)) == 1
    assert signature_verifies(token) is True
