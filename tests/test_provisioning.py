"""provision_subject enrolls + tokenizes so authz.decide allows the subject."""

from __future__ import annotations

import pytest

from capauth import provision_subject
from capauth.authz import decide
from capauth.identity_class import IdentityClassError, IdentityClassName, resolve_identity_class
from capauth.pairing import PairingError, list_devices

# ``decide`` requires the granting token to carry a verifying signature, so
# tokens here are issued SIGNED against the hermetic gpg stub (see conftest).
pytestmark = pytest.mark.usefixtures("stub_token_signing", "capability_rule_test_ceiling")


def test_provision_makes_decide_allow_all_skchat_caps(tmp_path):
    base = tmp_path / "home"
    out = provision_subject(
        "lumina@chef.skworld.io",
        identity_class=IdentityClassName.OPERATOR,
        mode="verified",
        sign=True,
        base_dir=base,
    )
    assert out["subject"] == "lumina@chef.skworld.io"
    assert out["mode"] == "verified"
    for cap in ("skchat.send", "skchat.inbox", "skchat.prekey"):
        d = decide("lumina@chef.skworld.io", cap, base_dir=base)
        assert d.allow is True, (cap, d.reason)


def test_provision_normalizes_a_legacy_missing_tld_subject(tmp_path):
    # "lumina@chef.skworld" is the missing-TLD legacy shape agent_identity has
    # shipped as its fqid field (IDENTITY_NAMING_STANDARD.md sec 2.5). provision_subject
    # (via enroll_device, card N3) normalizes it, and issues the token under the
    # SAME canonical spelling, so decide() can still correlate device + token.
    base = tmp_path / "home"
    out = provision_subject(
        "lumina@chef.skworld",
        identity_class=IdentityClassName.OPERATOR,
        mode="verified",
        sign=True,
        base_dir=base,
    )
    assert out["subject"] == "lumina@chef.skworld.io"
    d = decide("lumina@chef.skworld.io", "skchat.send", base_dir=base)
    assert d.allow is True, d.reason


def test_unprovisioned_subject_is_denied(tmp_path):
    base = tmp_path / "home"
    d = decide("stranger@chef.skworld.io", "skchat.send", base_dir=base)
    assert d.allow is False
    assert "has no identity class assignment" in d.reason


def test_tofu_mode_provisioning_allows_only_inbox(tmp_path):
    # A tofu device satisfies inbox (min tofu) but not send (min verified).
    base = tmp_path / "home"
    provision_subject(
        "guest@chef.skworld.io",
        identity_class=IdentityClassName.OPERATOR,
        mode="tofu",
        sign=True,
        base_dir=base,
    )
    assert decide("guest@chef.skworld.io", "skchat.inbox", base_dir=base).allow is True
    send = decide("guest@chef.skworld.io", "skchat.send", base_dir=base)
    assert send.allow is False
    assert "enrollment mode" in send.reason


def test_provision_returns_ids(tmp_path):
    out = provision_subject(
        "op@chef.skworld.io",
        identity_class=IdentityClassName.OPERATOR,
        sign=True,
        base_dir=tmp_path,
    )
    assert out["device_id"] and out["token_id"]
    assert out["identity_class"] == "operator"
    assert (
        resolve_identity_class("op@chef.skworld.io", base_dir=tmp_path).name
        is IdentityClassName.OPERATOR
    )
    assert out["scopes"] == ["skchat.send", "skchat.inbox", "skchat.prekey"]


def test_provision_rejects_unknown_class_before_writing(tmp_path):
    with pytest.raises(IdentityClassError, match="unknown identity class"):
        provision_subject(
            "op@chef.skworld.io",
            identity_class="overlord",
            sign=True,
            base_dir=tmp_path,
        )

    assert list_devices("op@chef.skworld.io", base_dir=tmp_path) == []


# --------------------------------------------------------------------------- #
# card N10 (09a6d6f3), item 4: provision_subject used to pass ``pubkey or
# subject`` straight to enroll_device, so with no real device key to hand the
# bare SUBJECT STRING stood in as if it were public key material. Now that
# enroll_device actually validates proof for verified/attested (this same
# card), that placeholder could never verify anyway; provision_subject mints
# a real, throwaway keypair and proves it instead.
# --------------------------------------------------------------------------- #


def test_provision_mints_real_key_material_not_the_subject_string(tmp_path):
    base = tmp_path / "home"
    out = provision_subject(
        "nadia@chef.skworld.io",
        identity_class=IdentityClassName.OPERATOR,
        mode="verified",
        sign=True,
        base_dir=base,
    )

    devices = list_devices(out["subject"], base_dir=base)
    assert len(devices) == 1
    pubkey = devices[0].pubkey
    # the old defect: pubkey == the subject string, standing in as "key material"
    assert pubkey != "nadia@chef.skworld.io"
    assert "BEGIN PGP PUBLIC KEY BLOCK" in pubkey


def test_provision_attested_also_mints_real_key_material(tmp_path):
    base = tmp_path / "home"
    out = provision_subject(
        "keiko@chef.skworld.io",
        identity_class=IdentityClassName.AGENT,
        mode="attested",
        sign=True,
        base_dir=base,
    )

    devices = list_devices(out["subject"], base_dir=base)
    assert len(devices) == 1
    assert devices[0].pubkey != "keiko@chef.skworld.io"
    assert "BEGIN PGP PUBLIC KEY BLOCK" in devices[0].pubkey
    # attested still requires proof to have actually checked out (this is
    # only reachable at all because it did): the mode landed as claimed.
    assert devices[0].mode.value == "attested"


def test_provision_with_a_caller_supplied_pubkey_still_requires_real_proof(tmp_path):
    # When the caller DOES pass a real device pubkey, provision_subject no
    # longer auto-mints on its behalf (that path is only for "no pubkey
    # given"); an unproven verified claim is refused exactly as a direct
    # enroll_device call would refuse it.
    base = tmp_path / "home"
    with pytest.raises(PairingError, match="verified enrollment requires"):
        provision_subject(
            "priya@chef.skworld.io",
            identity_class=IdentityClassName.OPERATOR,
            mode="verified",
            pubkey="-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----",
            sign=True,
            base_dir=base,
        )
    assert list_devices("priya@chef.skworld.io", base_dir=base) == []
