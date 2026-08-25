"""Tests for the WebAuthn passkey front-door (oidc/passkey.py).

Drives the FULL registration + authentication ceremony with a simulated
authenticator (soft-webauthn), so the begin/complete logic, persistence, and
challenge binding are all exercised without a browser.
"""

from __future__ import annotations

import base64
import json
import stat
from unittest.mock import patch

import pytest

soft = pytest.importorskip("soft_webauthn")
from soft_webauthn import SoftWebauthnDevice  # noqa: E402

from capauth.service.oidc.passkey import (  # noqa: E402
    PasskeyRPUnavailableError,
    PasskeyStore,
    PasskeyStoreUnavailableError,
    rp_origin_and_id,
)

FP = "A1B2C3D4E5F6A7B8C9D0A1B2C3D4E5F6A7B8C9D0"


def _u2b(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b2u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _create_input(options: dict) -> dict:
    pk = dict(options)
    pk["challenge"] = _u2b(options["challenge"])
    pk["user"] = dict(options["user"], id=_u2b(options["user"]["id"]))
    if options.get("excludeCredentials"):
        pk["excludeCredentials"] = [
            dict(c, id=_u2b(c["id"])) for c in options["excludeCredentials"]
        ]
    return {"publicKey": pk}


def _att_json(att: dict) -> dict:
    return {
        "id": _b2u(att["rawId"]),
        "rawId": _b2u(att["rawId"]),
        "type": "public-key",
        "response": {
            "attestationObject": _b2u(att["response"]["attestationObject"]),
            "clientDataJSON": _b2u(att["response"]["clientDataJSON"]),
            "transports": [],
        },
        "clientExtensionResults": {},
    }


def _get_input(options: dict) -> dict:
    pk = dict(options)
    pk["challenge"] = _u2b(options["challenge"])
    if options.get("allowCredentials"):
        pk["allowCredentials"] = [dict(c, id=_u2b(c["id"])) for c in options["allowCredentials"]]
    return {"publicKey": pk}


def _assert_json(asr: dict) -> dict:
    uh = asr["response"].get("userHandle")
    return {
        "id": _b2u(asr["rawId"]),
        "rawId": _b2u(asr["rawId"]),
        "type": "public-key",
        "response": {
            "authenticatorData": _b2u(asr["response"]["authenticatorData"]),
            "clientDataJSON": _b2u(asr["response"]["clientDataJSON"]),
            "signature": _b2u(asr["response"]["signature"]),
            "userHandle": _b2u(uh) if uh else None,
        },
        "clientExtensionResults": {},
    }


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("CAPAUTH_OIDC_ISSUER", "https://example.test")
    monkeypatch.setenv("CAPAUTH_WEBAUTHN_RP_ID", "example.test")


def test_origin_and_rpid(env):
    origin, rpid = rp_origin_and_id()
    assert origin == "https://example.test"
    assert rpid == "example.test"


def test_named_subdomain_origin_and_parent_rpid(monkeypatch):
    monkeypatch.setenv("CAPAUTH_OIDC_ISSUER", "https://login.example.test:8443/oidc")
    monkeypatch.setenv("CAPAUTH_WEBAUTHN_RP_ID", "example.test")

    assert rp_origin_and_id() == ("https://login.example.test:8443", "example.test")


@pytest.mark.parametrize(
    ("issuer", "rp_id"),
    [
        ("https://100.81.238.58:8420", "100.81.238.58"),
        ("http://capauth.example.test", "capauth.example.test"),
        ("https://capauth.example.test", "other.example.test"),
        ("https://capauth.example.test", ""),
    ],
)
def test_unsafe_or_implicit_rp_configuration_fails_closed(monkeypatch, issuer, rp_id):
    monkeypatch.setenv("CAPAUTH_OIDC_ISSUER", issuer)
    if rp_id:
        monkeypatch.setenv("CAPAUTH_WEBAUTHN_RP_ID", rp_id)
    else:
        monkeypatch.delenv("CAPAUTH_WEBAUTHN_RP_ID", raising=False)

    with pytest.raises(PasskeyRPUnavailableError):
        rp_origin_and_id()


@pytest.mark.parametrize("data_dir", [None, "relative/passkeys"])
def test_passkey_store_requires_explicit_absolute_directory(env, data_dir):
    with pytest.raises(PasskeyStoreUnavailableError):
        PasskeyStore(data_dir=data_dir).preflight()


def test_passkey_store_rejects_broad_directory_permissions(env, tmp_path):
    tmp_path.chmod(0o755)

    with pytest.raises(PasskeyStoreUnavailableError):
        PasskeyStore(data_dir=str(tmp_path)).preflight()


def test_full_register_then_authenticate(env, tmp_path):
    origin, _ = rp_origin_and_id()
    store = PasskeyStore(data_dir=str(tmp_path))
    device = SoftWebauthnDevice()

    # --- register (gating PGP proof is verified at the HTTP layer, not here) ---
    ticket, options = store.begin_registration(FP)
    att = device.create(_create_input(options), origin)
    fp, cid = store.complete_registration(ticket, _att_json(att))
    assert fp == FP
    assert cid in store.credentials_for(FP)
    assert store.has_any(FP)

    # persisted across a reload
    assert PasskeyStore(data_dir=str(tmp_path)).has_any(FP)
    assert stat.S_IMODE((tmp_path / "passkeys.json").stat().st_mode) == 0o600

    # --- authenticate (with a fingerprint hint → allowCredentials) ---
    req_options = store.begin_authentication("req-1", FP)
    asr = device.get(_get_input(req_options), origin)
    got = store.complete_authentication("req-1", _assert_json(asr))
    assert got == FP

    # A fresh process can load the credential and authenticate again.
    restarted_store = PasskeyStore(data_dir=str(tmp_path))
    restarted_options = restarted_store.begin_authentication("req-after-restart", FP)
    restarted_assertion = device.get(_get_input(restarted_options), origin)
    assert (
        restarted_store.complete_authentication(
            "req-after-restart", _assert_json(restarted_assertion)
        )
        == FP
    )


def test_authenticate_discoverable_no_hint(env, tmp_path):
    origin, _ = rp_origin_and_id()
    store = PasskeyStore(data_dir=str(tmp_path))
    device = SoftWebauthnDevice()
    ticket, options = store.begin_registration(FP)
    store.complete_registration(ticket, _att_json(device.create(_create_input(options), origin)))

    # no fingerprint hint → empty allowCredentials (resident/discoverable)
    req_options = store.begin_authentication("req-2", "")
    asr = device.get(_get_input(req_options), origin)
    assert store.complete_authentication("req-2", _assert_json(asr)) == FP


def test_unknown_credential_rejected(env, tmp_path):
    store = PasskeyStore(data_dir=str(tmp_path))
    store.begin_authentication("req-3", "")
    with pytest.raises(ValueError):
        store.complete_authentication(
            "req-3",
            {"id": "bogus", "rawId": "bogus", "type": "public-key", "response": {}},
        )


def test_expired_or_unknown_ticket(env, tmp_path):
    store = PasskeyStore(data_dir=str(tmp_path))
    with pytest.raises(ValueError):
        store.complete_registration("nope", {"id": "x"})


def test_registration_fails_closed_and_rolls_back_when_save_fails(env, tmp_path):
    origin, _ = rp_origin_and_id()
    store = PasskeyStore(data_dir=str(tmp_path))
    device = SoftWebauthnDevice()
    ticket, options = store.begin_registration(FP)
    attestation = _att_json(device.create(_create_input(options), origin))

    with patch("os.replace", side_effect=OSError("read-only filesystem")):
        with pytest.raises(PasskeyStoreUnavailableError):
            store.complete_registration(ticket, attestation)

    assert not store.has_any(FP)
    assert not (tmp_path / "passkeys.json").exists()


@pytest.mark.parametrize("payload", ["not-json", "[]"])
def test_malformed_passkey_state_is_unavailable(tmp_path, payload):
    (tmp_path / "passkeys.json").write_text(payload, encoding="utf-8")

    with pytest.raises(PasskeyStoreUnavailableError):
        PasskeyStore(data_dir=str(tmp_path))


def test_authentication_rolls_back_counter_when_save_fails(env, tmp_path):
    origin, _ = rp_origin_and_id()
    store = PasskeyStore(data_dir=str(tmp_path))
    device = SoftWebauthnDevice()
    ticket, options = store.begin_registration(FP)
    store.complete_registration(ticket, _att_json(device.create(_create_input(options), origin)))
    before = json.loads((tmp_path / "passkeys.json").read_text(encoding="utf-8"))

    request_options = store.begin_authentication("req-save-fail", FP)
    assertion = _assert_json(device.get(_get_input(request_options), origin))
    with patch("os.replace", side_effect=OSError("read-only filesystem")):
        with pytest.raises(PasskeyStoreUnavailableError):
            store.complete_authentication("req-save-fail", assertion)

    credential_id = next(iter(before))
    assert store._creds[credential_id]["sign_count"] == before[credential_id]["sign_count"]
