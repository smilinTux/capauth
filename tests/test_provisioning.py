"""provision_subject enrolls + tokenizes so authz.decide allows the subject."""

from __future__ import annotations

from capauth import provision_subject
from capauth.authz import decide


def test_provision_makes_decide_allow_all_skchat_caps(tmp_path):
    base = tmp_path / "home"
    out = provision_subject("lumina@host", mode="verified", sign=False, base_dir=base)
    assert out["subject"] == "lumina@host"
    assert out["mode"] == "verified"
    for cap in ("skchat.send", "skchat.inbox", "skchat.prekey"):
        d = decide("lumina@host", cap, base_dir=base)
        assert d.allow is True, (cap, d.reason)


def test_unprovisioned_subject_is_denied(tmp_path):
    base = tmp_path / "home"
    d = decide("stranger@host", "skchat.send", base_dir=base)
    assert d.allow is False
    assert "unknown subject" in d.reason


def test_tofu_mode_provisioning_allows_only_inbox(tmp_path):
    # A tofu device satisfies inbox (min tofu) but not send (min verified).
    base = tmp_path / "home"
    provision_subject("guest@host", mode="tofu", sign=False, base_dir=base)
    assert decide("guest@host", "skchat.inbox", base_dir=base).allow is True
    send = decide("guest@host", "skchat.send", base_dir=base)
    assert send.allow is False
    assert "enrollment mode" in send.reason


def test_provision_returns_ids(tmp_path):
    out = provision_subject("op@host", sign=False, base_dir=tmp_path)
    assert out["device_id"] and out["token_id"]
    assert out["scopes"] == ["skchat.send", "skchat.inbox", "skchat.prekey"]
