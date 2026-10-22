"""Tests for the CapAuth Bunker Web Push registry (push.py).

Covers VAPID key generation + persistence, the fingerprint→subscription
registry, and notify() send/prune behaviour (pywebpush mocked).
"""

from __future__ import annotations

import base64

import pytest

from capauth.service.push import PushRegistry, default_data_dir


def test_default_data_dir_uses_capauth_service_root(monkeypatch, tmp_path):
    monkeypatch.setenv("CAPAUTH_HOME", str(tmp_path / "capauth-home"))
    monkeypatch.delenv("CAPAUTH_DATA_DIR", raising=False)

    assert default_data_dir() == tmp_path / "capauth-home" / "service"


def test_configured_data_dir_overrides_capauth_service_root(monkeypatch, tmp_path):
    configured = tmp_path / "configured"
    monkeypatch.setenv("CAPAUTH_DATA_DIR", str(configured))

    assert default_data_dir() == configured


def test_vapid_key_generated_and_stable(tmp_path):
    reg = PushRegistry(data_dir=str(tmp_path))
    key = reg.application_server_key()
    # base64url of a raw uncompressed P-256 point = 65 bytes -> 87 chars.
    raw = base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))
    assert len(raw) == 65 and raw[0] == 0x04
    # A second registry over the same dir reuses the persisted key.
    assert PushRegistry(data_dir=str(tmp_path)).application_server_key() == key


def test_subscribe_dedups_by_endpoint(tmp_path):
    reg = PushRegistry(data_dir=str(tmp_path))
    fp = "BD7EEECA23D90A594400751CFDB582D9CB7272A6"
    reg.subscribe(fp, {"endpoint": "https://push/x", "keys": {"p256dh": "a", "auth": "b"}})
    reg.subscribe(fp, {"endpoint": "https://push/x", "keys": {"p256dh": "c", "auth": "d"}})
    reg.subscribe(fp, {"endpoint": "https://push/y", "keys": {"p256dh": "e", "auth": "f"}})
    assert reg.subscription_count(fp) == 2  # x de-duped, y added
    # persisted across reloads
    assert PushRegistry(data_dir=str(tmp_path)).subscription_count(fp) == 2


def test_subscribe_requires_fingerprint_and_endpoint(tmp_path):
    reg = PushRegistry(data_dir=str(tmp_path))
    with pytest.raises(ValueError):
        reg.subscribe("", {"endpoint": "https://x"})
    with pytest.raises(ValueError):
        reg.subscribe("FP", {})


def test_notify_no_subscriptions(tmp_path):
    reg = PushRegistry(data_dir=str(tmp_path))
    assert reg.notify("FP", {"title": "t"})["error"] == "no_subscriptions"


def test_notify_sends_and_prunes(tmp_path, monkeypatch):
    import pywebpush

    reg = PushRegistry(data_dir=str(tmp_path))
    fp = "FP"
    reg.subscribe(fp, {"endpoint": "https://push/live", "keys": {"p256dh": "a", "auth": "b"}})
    reg.subscribe(fp, {"endpoint": "https://push/dead", "keys": {"p256dh": "c", "auth": "d"}})

    class FakeResp:
        def __init__(self, code):
            self.status_code = code

    calls = []

    def fake_webpush(subscription_info, data, vapid_private_key, vapid_claims):
        calls.append(subscription_info["endpoint"])
        if subscription_info["endpoint"].endswith("dead"):
            raise pywebpush.WebPushException("gone", response=FakeResp(410))

    monkeypatch.setattr(pywebpush, "webpush", fake_webpush)

    result = reg.notify(fp, {"title": "Sign in", "url": "capauth-bunker://x"})
    assert result["sent"] == 1
    assert result["pruned"] == 1
    assert len(calls) == 2
    # the dead endpoint was removed
    assert reg.subscription_count(fp) == 1
