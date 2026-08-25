"""Negative controls for the shipped signing test seam (``capauth.testing``).

The seam exists so a downstream repo can mint and verify capability tokens on a
CI runner that has no gpg secret key. The danger in shipping such a thing is
obvious: a stub that is even slightly too generous turns every consuming suite
green while proving nothing, and re-opens SEC-CRIT ``bc56b98b`` (an unsigned
token granting ``skcode.dispatch``, the RCE capability) in the process.

So this file spends most of its length on what must STILL be denied while the
stub is active:

* an UNSIGNED token, for the RCE capability, denied;
* a token whose payload was tampered with after signing, denied;
* a signature lifted from a different token, denied;
* a well-formed signature made under a DIFFERENT issuer, denied;
* the verified-tier enrollment floor, still enforced.

Plus the structural claims that keep the seam out of a deployed process:

* ``import capauth`` does not import ``capauth.testing``;
* importing ``capauth.testing`` patches nothing;
* every activation is scoped and reverts, including on an exception;
* no ``pytest11`` entry point, so pytest never auto-loads it;
* no env var or global flag anywhere in it.

And one control that must run OUTSIDE this process entirely: that
``issue_token`` still raises on a genuine signing failure when the seam is NOT
active. That assertion is the only one here about the UNPATCHED path, which
makes it the one that could pass for the wrong reason. If it ran in this
session it would be at the mercy of a module-scope import or an autouse fixture
someone adds later, and it would then be asserting "the stub raises", which is
not the claim. It runs in a fresh subprocess with an empty ``sys.modules``
instead, and asserts its own isolation before it asserts anything else.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import capauth
from capauth.authz import LEGACY_UNSIGNED_GRACE_ENV, decide
from capauth.identity_class import IdentityClassName, assign_identity_class
from capauth.pairing import EnrollmentMode, approve, enroll_device
from capauth.testing import (
    STUB_ISSUER_FPR,
    _stub_verify_manifest,
    install_signing_stub,
    signing_stub,
    stub_signature_for,
)
from capauth.tokens import TokenPayload, issue_token

from .conftest import enrolled_verified_credentials

# The fingerprint from the live incident, with no secret key anywhere, so real
# gpg genuinely fails to sign for it. Imported rather than re-declared: it is a
# 40-hex-digit string that gitleaks reads as a generic API key, and the one
# existing occurrence is already in ``.gitleaks-baseline.json``. A second copy
# would be a second finding, and baselining a literal twice teaches the scanner
# that this shape is fine.
from .test_authz_signature_gate import ABSENT_KEY_FPR

SUBJECT = "lumina@chef.skworld.io"

#: The RCE capability. capauth's own rule text calls it "arbitrary command
#: execution AS the subject; the most sensitive capability". Every deny-side
#: assertion here uses it deliberately: if the seam is too generous, this is
#: exactly what it hands over.
RCE_CAPABILITY = "skcode.dispatch"

#: A fingerprint that is not the one the stub signs as.
OTHER_ISSUER_FPR = "0123456789ABCDEF0123456789ABCDEF01234567"

pytestmark = pytest.mark.usefixtures("capability_rule_test_ceiling")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
@pytest.fixture(autouse=True)
def _no_legacy_grace(monkeypatch):
    """Keep the unsigned-token grace window out of every case in this file.

    ``CAPAUTH_LEGACY_UNSIGNED_GRACE_UNTIL`` can legitimately allow an unsigned
    token (card ``f47e2558``). It is covered in its own suite; here it would
    quietly turn a deny-side control into an allow for a reason that has
    nothing to do with the seam under test.
    """
    monkeypatch.delenv(LEGACY_UNSIGNED_GRACE_ENV, raising=False)


def _make_home(tmp_path: Path, *, mode: EnrollmentMode = EnrollmentMode.VERIFIED) -> Path:
    """A capauth home with one enrolled, approved device for ``SUBJECT``.

    Enrollment uses a real keypair and a real proof (card N10), so the
    enrollment floor is genuinely satisfied rather than asserted. The seam under
    test does not touch :mod:`capauth.pairing` at all.
    """
    home = tmp_path / "home"
    (home / "identity").mkdir(parents=True, exist_ok=True)
    (home / "identity" / "identity.json").write_text(
        json.dumps({"fingerprint": STUB_ISSUER_FPR}), encoding="utf-8"
    )
    pubkey, proof = enrolled_verified_credentials(SUBJECT)
    enrollment = enroll_device(
        pubkey,
        [RCE_CAPABILITY, "skchat.send"],
        mode=mode,
        base_dir=home,
        subject=SUBJECT,
        proof=proof,
    )
    approve(enrollment.enrollment_id, "operator@chef.skworld.io", base_dir=home)
    assign_identity_class(SUBJECT, IdentityClassName.OPERATOR, base_dir=home)
    return home


def _token_files(home: Path) -> list[Path]:
    token_dir = home / "security" / "tokens"
    return sorted(token_dir.glob("*.json")) if token_dir.exists() else []


def _rewrite_token(path: Path, **changes) -> None:
    """Patch a stored token file in place (the store-write adversary)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    payload_changes = changes.pop("payload", {})
    data.update(changes)
    data["payload"].update(payload_changes)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# --------------------------------------------------------------------------- #
# 0. positive control -- the seam has to actually do its job
# --------------------------------------------------------------------------- #
def test_stub_lets_a_signed_token_grant_the_rce_capability(tmp_path, stub_token_signing):
    """Without this passing, every deny below would be vacuous.

    This is the whole reason the seam exists: on a runner with no gpg key, a
    normally-issued token still signs, still verifies, and still authorizes.
    """
    home = _make_home(tmp_path)

    token = issue_token(
        home=home, subject=SUBJECT, capabilities=[RCE_CAPABILITY], sign=True, ttl_hours=24
    )

    assert token.signature, "the seam must produce a signature, not skip signing"
    decision = decide(SUBJECT, RCE_CAPABILITY, base_dir=home)
    assert decision.allow is True, decision.reason


# --------------------------------------------------------------------------- #
# 1. an UNSIGNED token is still denied, for the RCE capability
# --------------------------------------------------------------------------- #
def test_unsigned_token_is_still_denied_for_rce_with_the_stub_active(tmp_path, stub_token_signing):
    """The headline property. This is SEC-CRIT bc56b98b's exact shape."""
    home = _make_home(tmp_path)

    issue_token(
        home=home, subject=SUBJECT, capabilities=[RCE_CAPABILITY], sign=False, ttl_hours=24
    )

    decision = decide(SUBJECT, RCE_CAPABILITY, base_dir=home)

    assert decision.allow is False
    assert "is unsigned" in decision.reason


def test_signature_stripped_from_the_store_is_still_denied(tmp_path, stub_token_signing):
    """A token issued signed, then stripped on disk, is denied like any unsigned one.

    The store is Syncthing-replicated, so "wrote a file into the store" is the
    realistic adversary, not "called issue_token".
    """
    home = _make_home(tmp_path)
    issue_token(home=home, subject=SUBJECT, capabilities=[RCE_CAPABILITY], sign=True, ttl_hours=24)
    (path,) = _token_files(home)

    _rewrite_token(path, signature=None, verified=True)

    decision = decide(SUBJECT, RCE_CAPABILITY, base_dir=home)
    assert decision.allow is False
    assert "is unsigned" in decision.reason


# --------------------------------------------------------------------------- #
# 2. a signature over DIFFERENT bytes, or from a different issuer, is denied
# --------------------------------------------------------------------------- #
def test_tampered_payload_is_still_denied_with_the_stub_active(tmp_path, stub_token_signing):
    """Widening the capabilities after signing must invalidate the signature.

    The stand-in signature is a digest of the exact payload bytes, so this fails
    for the same structural reason a real detached OpenPGP signature would.
    """
    home = _make_home(tmp_path)
    issue_token(home=home, subject=SUBJECT, capabilities=["skchat.send"], sign=True, ttl_hours=24)
    (path,) = _token_files(home)

    _rewrite_token(path, payload={"capabilities": ["skchat.send", RCE_CAPABILITY]})

    decision = decide(SUBJECT, RCE_CAPABILITY, base_dir=home)
    assert decision.allow is False
    assert "does not verify against its declared issuer" in decision.reason


def test_signature_lifted_from_another_token_is_still_denied(tmp_path, stub_token_signing):
    """A perfectly valid signature, over the wrong bytes, grants nothing."""
    home = _make_home(tmp_path)
    issue_token(home=home, subject=SUBJECT, capabilities=["skchat.send"], sign=True, ttl_hours=24)
    donor = issue_token(
        home=home,
        subject=SUBJECT,
        capabilities=["skchat.send"],
        sign=True,
        ttl_hours=48,
        store=False,
    )
    (path,) = _token_files(home)

    _rewrite_token(
        path,
        signature=donor.signature,
        payload={"capabilities": ["skchat.send", RCE_CAPABILITY]},
    )

    decision = decide(SUBJECT, RCE_CAPABILITY, base_dir=home)
    assert decision.allow is False
    assert "does not verify against its declared issuer" in decision.reason


def test_token_signed_by_a_different_issuer_is_still_denied(tmp_path, stub_token_signing):
    """Internally consistent, and still denied, because the issuer is not the signer.

    The strongest form of this control: the token is rewritten so its signature
    IS a correct stand-in over its own exact bytes. The only thing wrong with it
    is that it declares an issuer the seam never signs as. A stub that checked
    only "does the digest match" would allow this, and would thereby drop the
    issuer pinning that :func:`capauth.tokens.signature_verifies` exists to
    provide.
    """
    home = _make_home(tmp_path)
    issue_token(home=home, subject=SUBJECT, capabilities=[RCE_CAPABILITY], sign=True, ttl_hours=24)
    (path,) = _token_files(home)

    data = json.loads(path.read_text(encoding="utf-8"))
    data["payload"]["issuer"] = OTHER_ISSUER_FPR
    forged = TokenPayload(**data["payload"])
    forged_bytes = forged.model_dump_json().encode()
    data["signature"] = stub_signature_for(forged_bytes)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    # Sanity: the digest really is correct for these exact bytes, so the deny
    # below is about the ISSUER and not about a signature that simply does not
    # match. Only the issuer pinning stands between this token and an allow.
    assert (
        _stub_verify_manifest(forged_bytes, data["signature"], expected_signer=STUB_ISSUER_FPR)
        is True
    )
    assert (
        _stub_verify_manifest(forged_bytes, data["signature"], expected_signer=OTHER_ISSUER_FPR)
        is False
    )

    decision = decide(SUBJECT, RCE_CAPABILITY, base_dir=home)
    assert decision.allow is False
    assert "does not verify against its declared issuer" in decision.reason


def test_unattributable_issuer_is_still_denied(tmp_path, stub_token_signing):
    """The ``"unknown"`` placeholder issuer stays unattributable under the seam."""
    home = _make_home(tmp_path)
    issue_token(home=home, subject=SUBJECT, capabilities=[RCE_CAPABILITY], sign=True, ttl_hours=24)
    (path,) = _token_files(home)

    data = json.loads(path.read_text(encoding="utf-8"))
    data["payload"]["issuer"] = "unknown"
    forged = TokenPayload(**data["payload"])
    data["signature"] = stub_signature_for(forged.model_dump_json().encode())
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    assert decide(SUBJECT, RCE_CAPABILITY, base_dir=home).allow is False


# --------------------------------------------------------------------------- #
# 3. the enrollment floor is untouched by the seam
# --------------------------------------------------------------------------- #
def test_tofu_enrollment_is_still_below_the_rce_floor(tmp_path, stub_token_signing):
    """A perfectly signed token does not lift a TOFU device to an RCE grant.

    ``skcode.dispatch`` is VERIFIED-only. The seam replaces nothing in
    :mod:`capauth.pairing`, and this pins that.
    """
    home = _make_home(tmp_path, mode=EnrollmentMode.TOFU)
    issue_token(home=home, subject=SUBJECT, capabilities=[RCE_CAPABILITY], sign=True, ttl_hours=24)

    decision = decide(SUBJECT, RCE_CAPABILITY, base_dir=home)
    assert decision.allow is False
    assert "verified" in decision.reason


# --------------------------------------------------------------------------- #
# 4. issue_token still raises on a GENUINE signing failure, proven out-of-process
# --------------------------------------------------------------------------- #
#
# This is the only control in the file that asserts on the UNPATCHED path, so it
# is the one that could pass for the wrong reason: with the stub applied it
# would be asserting "the stub raises", which is not the claim. It therefore
# runs in a fresh interpreter that:
#
#   * starts with an empty ``sys.modules``, so it cannot inherit this session's
#     module-scope ``from capauth.testing import ...``;
#   * has no pytest session at all, so it cannot inherit an autouse fixture or a
#     ``monkeypatch`` from the parent;
#   * asserts BOTH of those before it asserts anything else -- it checks that
#     ``capauth.testing`` is absent from ``sys.modules`` and that each of the
#     three seams is still the real function defined in ``capauth.tokens``.
#
# Those in-child assertions are the actual isolation proof. "It is a subprocess"
# is an argument; "the child looked and the seams were real" is evidence.

_UNPATCHED_RAISE_PROBE = textwrap.dedent("""
    import json, pathlib, sys, tempfile

    # (a) prove isolation BEFORE proving anything else.
    assert "capauth.testing" not in sys.modules, "seam module leaked into the child"

    import capauth
    assert "capauth.testing" not in sys.modules, "import capauth pulled in the seam"

    from capauth import tokens
    from capauth.tokens import TokenSigningError, issue_token, list_tokens

    assert "capauth.testing" not in sys.modules, "import capauth.tokens pulled in the seam"
    for name in ("_get_issuer_fingerprint", "_pgp_sign_payload", "verify_manifest"):
        seam = getattr(tokens, name)
        assert getattr(seam, "__module__", None) in ("capauth.tokens", "capauth.manifest"), (
            f"seam {name} is not the real function: {seam!r}"
        )

    # (b) a home whose issuer fingerprint has no secret key anywhere, so gpg
    #     genuinely fails (and if gpg is absent entirely, signing fails too).
    home = pathlib.Path(tempfile.mkdtemp(prefix="capauth-unpatched-")) / "home"
    (home / "identity").mkdir(parents=True)
    (home / "identity" / "identity.json").write_text(
        json.dumps({"fingerprint": "%(absent_fpr)s"}), encoding="utf-8"
    )

    try:
        issue_token(
            home=home,
            subject="%(subject)s",
            capabilities=["%(capability)s"],
            sign=True,
            ttl_hours=24,
        )
    except TokenSigningError as exc:
        assert "%(absent_fpr)s" in str(exc), f"raise did not name the issuer key: {exc}"
    else:
        raise AssertionError("issue_token did NOT raise on a genuine signing failure")

    token_dir = home / "security" / "tokens"
    stored = sorted(token_dir.glob("*.json")) if token_dir.exists() else []
    assert stored == [], f"a failed signing left something in the store: {stored}"
    assert list_tokens(home) == []

    print("UNPATCHED-RAISE-OK")
    """)


def _run_probe(source: str) -> subprocess.CompletedProcess:
    """Run ``source`` in a fresh interpreter that can import this checkout's capauth."""
    src_root = str(Path(capauth.__file__).resolve().parents[1])
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([src_root, env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    # An empty GNUPGHOME so no ambient keyring on a dev box can accidentally
    # hold a secret key and turn the signing failure into a success.
    env["GNUPGHOME"] = str(Path(env.get("TMPDIR", "/tmp")) / "capauth-probe-empty-gnupghome")
    Path(env["GNUPGHOME"]).mkdir(mode=0o700, parents=True, exist_ok=True)
    return subprocess.run(
        [sys.executable, "-c", source],
        capture_output=True,
        text=True,
        timeout=90,
        env=env,
    )


def test_issue_token_still_raises_when_signing_fails_and_the_seam_is_not_active():
    """Out-of-process control: no seam, no pytest, real signing failure, real raise."""
    probe = _UNPATCHED_RAISE_PROBE % {
        "absent_fpr": ABSENT_KEY_FPR,
        "subject": SUBJECT,
        "capability": RCE_CAPABILITY,
    }

    result = _run_probe(probe)

    assert result.returncode == 0, (
        f"probe failed (rc={result.returncode})\n--- stdout ---\n{result.stdout}\n"
        f"--- stderr ---\n{result.stderr}"
    )
    assert "UNPATCHED-RAISE-OK" in result.stdout


def test_the_unpatched_probe_can_actually_fail():
    """The probe's own negative control: it must go red when the raise is gone.

    A test that has never failed has not been shown to be capable of failing.
    Here the child is handed a ``issue_token`` that returns an unsigned token
    instead of raising -- precisely the pre-``0d412ab`` behaviour -- and the
    probe must detect it. If this passes while the probe body is broken, the
    probe is decorative.
    """
    neutered = _UNPATCHED_RAISE_PROBE.replace(
        "\ntry:\n",
        "\ntokens._apply_signature = lambda token, home, *, sign: None\ntry:\n",
        1,
    )
    assert neutered != _UNPATCHED_RAISE_PROBE, "the neutering patch did not apply"
    probe = neutered % {
        "absent_fpr": ABSENT_KEY_FPR,
        "subject": SUBJECT,
        "capability": RCE_CAPABILITY,
    }

    result = _run_probe(probe)

    assert result.returncode != 0, "the probe passed against an issue_token that never raises"
    assert "issue_token did NOT raise on a genuine signing failure" in result.stderr


# --------------------------------------------------------------------------- #
# 5. structural: the seam cannot switch itself on
# --------------------------------------------------------------------------- #
def test_importing_capauth_does_not_import_the_seam():
    """``import capauth`` must not pull the seam in, in a fresh interpreter."""
    result = _run_probe(
        textwrap.dedent("""
            import sys
            import capauth
            import capauth.authz, capauth.tokens, capauth.pairing, capauth.manifest
            assert "capauth.testing" not in sys.modules, sorted(
                m for m in sys.modules if m.startswith("capauth")
            )
            print("NO-SEAM-IMPORT-OK")
            """)
    )

    assert result.returncode == 0, result.stderr
    assert "NO-SEAM-IMPORT-OK" in result.stdout


def test_importing_the_seam_patches_nothing():
    """Merely importing ``capauth.testing`` must leave every seam untouched."""
    result = _run_probe(
        textwrap.dedent("""
            from capauth import tokens
            before = {
                name: getattr(tokens, name)
                for name in ("_get_issuer_fingerprint", "_pgp_sign_payload", "verify_manifest")
            }
            import capauth.testing  # noqa: F401
            after = {name: getattr(tokens, name) for name in before}
            assert before == after, "importing capauth.testing replaced a seam"
            print("IMPORT-IS-INERT-OK")
            """)
    )

    assert result.returncode == 0, result.stderr
    assert "IMPORT-IS-INERT-OK" in result.stdout


def test_context_manager_reverts_the_seams_including_on_an_exception():
    """Activation is lexically scoped: nothing survives the ``with`` block."""
    from capauth import tokens

    names = ("_get_issuer_fingerprint", "_pgp_sign_payload", "verify_manifest")
    before = {name: getattr(tokens, name) for name in names}

    with signing_stub():
        assert {name: getattr(tokens, name) for name in names} != before

    assert {name: getattr(tokens, name) for name in names} == before

    with pytest.raises(RuntimeError):
        with signing_stub():
            raise RuntimeError("boom")

    assert {name: getattr(tokens, name) for name in names} == before


def test_monkeypatch_activation_reverts_at_teardown(tmp_path, monkeypatch):
    """The ``monkeypatch`` form is scoped to the requesting test, not the session."""
    from capauth import tokens

    real = tokens._pgp_sign_payload
    install_signing_stub(monkeypatch)
    assert tokens._pgp_sign_payload is not real

    monkeypatch.undo()
    assert tokens._pgp_sign_payload is real


def test_the_seam_registers_no_pytest_entry_point():
    """No ``pytest11`` entry point, so pytest can never auto-load it.

    Adoption has to be a line a consuming repo writes in its own test code.
    Implicit activation is how a test helper ends up live in production.
    """
    pyproject = (Path(capauth.__file__).resolve().parents[2] / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    assert "pytest11" not in pyproject


def test_the_seam_reads_no_environment_variable():
    """No env var, config key, or global flag can enable it.

    Deliberately source-level: the claim is that no such switch EXISTS, which a
    behavioural test cannot establish (it can only fail to find the one it
    thought of).
    """
    source = Path(capauth.__file__).resolve().parent / "testing.py"
    text = source.read_text(encoding="utf-8")
    body = text.split('"""', 2)[-1]  # skip the module docstring
    for forbidden in ("os.environ", "getenv", "environb"):
        assert forbidden not in body, f"{forbidden} appears in capauth/testing.py"
