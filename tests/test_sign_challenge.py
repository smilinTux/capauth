"""capauth sign-challenge: copy the login challenge, sign it, paste the signature.

The command reads the CapAuth login challenge (the CAPAUTH_NONCE_V1/V2
message shown on the login page) from the clipboard or stdin, signs it with
the configured key through gpg (gpg-agent asks for the passphrase with its
own pinentry, the tool never sees it) and puts the ASCII-armored detached
signature back on the clipboard. Tests use a throwaway, passphrase-less key
in a temporary GnuPG home and the server's real verifier.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from capauth.authentik.verifier import canonical_nonce_payload, verify_nonce_signature
from capauth.cli import main
from capauth.sign_challenge import ChallengeError, normalize_challenge

FIELDS = dict(
    nonce="0d6c2b8e-3b8f-4c55-9d1f-6a1f5e0c9b11",
    client_nonce_echo="q83vEjRWeJA=",
    timestamp="2026-09-28T20:00:00+00:00",
    service="capauth.example.test",
    expires="2026-09-28T20:05:00+00:00",
)
PAYLOAD = canonical_nonce_payload(**FIELDS).decode()

needs_gpg = pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg not installed")


# --- the challenge text ---------------------------------------------------------


def test_normalize_accepts_the_page_text_with_clipboard_noise():
    """Copy/paste adds CRLF, trailing newlines or surrounding blanks: the
    signed bytes must still be exactly the canonical payload."""
    noisy = "\r\n  " + PAYLOAD.replace("\n", "\r\n") + "\r\n\n"
    assert normalize_challenge(noisy) == PAYLOAD.encode()
    v2 = canonical_nonce_payload(**FIELDS, origin="https://capauth.example.test").decode()
    assert normalize_challenge(v2 + "\n") == v2.encode()


@pytest.mark.parametrize(
    "text",
    [
        "",
        "rm -rf ~",
        "-----BEGIN PGP MESSAGE-----\nabc\n-----END PGP MESSAGE-----",
        PAYLOAD.replace("service=", "servce="),  # a field renamed
        "\n".join(PAYLOAD.split("\n")[:4]),  # truncated copy
        PAYLOAD + "\nextra=1",  # something appended
        "\n".join([PAYLOAD.split("\n")[0]] + PAYLOAD.split("\n")[2:] + [PAYLOAD.split("\n")[1]]),
    ],
)
def test_normalize_refuses_anything_but_a_capauth_challenge(text):
    """Signing whatever happens to be on the clipboard would turn the tool
    into a signing oracle: only a complete, well-formed challenge is signed."""
    with pytest.raises(ChallengeError):
        normalize_challenge(text)


# --- a throwaway key --------------------------------------------------------------


@pytest.fixture
def gpg_home():
    # short path: gpg-agent's socket path must fit in sun_path (108 bytes)
    home = Path(tempfile.mkdtemp(prefix="cagpg"))
    home.chmod(0o700)
    env = dict(os.environ, GNUPGHOME=str(home))
    subprocess.run(
        [
            "gpg",
            "--batch",
            "--passphrase",
            "",
            "--quick-gen-key",
            "Throwaway <throwaway@example.invalid>",
            "ed25519",
            "sign",
            "never",
        ],
        env=env,
        check=True,
        capture_output=True,
    )
    out = subprocess.run(
        ["gpg", "--batch", "--with-colons", "--list-secret-keys"],
        env=env,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    fp = next(line.split(":")[9] for line in out.splitlines() if line.startswith("fpr:"))
    pub = subprocess.run(
        ["gpg", "--batch", "--armor", "--export", fp],
        env=env,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    yield home, fp, pub
    subprocess.run(["gpgconf", "--kill", "gpg-agent"], env=env, capture_output=True)
    shutil.rmtree(home, ignore_errors=True)


def _run(args, gpg_home, env=None, input=None):
    home, _fp, _pub = gpg_home
    full_env = {"GNUPGHOME": str(home)}
    full_env.update(env or {})
    return CliRunner().invoke(main, args, input=input, env=full_env, catch_exceptions=False)


@needs_gpg
def test_signs_stdin_to_stdout_and_the_server_verifies_it(gpg_home):
    _home, fp, pub = gpg_home
    res = _run(
        ["sign-challenge", "--stdin", "--stdout", "--key", fp], gpg_home, input=PAYLOAD + "\n"
    )
    assert res.exit_code == 0, res.output
    sig = res.output
    assert "-----BEGIN PGP SIGNATURE-----" in sig and "-----END PGP SIGNATURE-----" in sig
    assert verify_nonce_signature(canonical_nonce_payload(**FIELDS), sig, pub)
    tampered = canonical_nonce_payload(
        **dict(FIELDS, nonce="11111111-2222-4333-8444-555555555555")
    )
    assert not verify_nonce_signature(tampered, sig, pub)


def _fake_clipboard(tmp_path, content):
    """wl-paste / wl-copy stand-ins backed by a file."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    clip = tmp_path / "clipboard.txt"
    clip.write_text(content)
    for name, body in (
        ("wl-paste", f'#!/bin/sh\ncat "{clip}"\n'),
        ("wl-copy", f'#!/bin/sh\ncat > "{clip}"\n'),
    ):
        path = bindir / name
        path.write_text(body)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    env = {"PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}", "WAYLAND_DISPLAY": "wayland-test"}
    return clip, env


@needs_gpg
def test_clipboard_in_clipboard_out_prints_one_line(gpg_home, tmp_path):
    _home, fp, pub = gpg_home
    clip, env = _fake_clipboard(tmp_path, PAYLOAD + "\n")
    res = _run(["sign-challenge", "--key", fp], gpg_home, env=env)
    assert res.exit_code == 0, res.output
    assert res.output == "signed, paste it now\n"
    sig = clip.read_text()
    assert verify_nonce_signature(canonical_nonce_payload(**FIELDS), sig, pub)


@needs_gpg
def test_refuses_to_sign_a_clipboard_that_is_not_a_challenge(gpg_home, tmp_path):
    _home, fp, _pub = gpg_home
    clip, env = _fake_clipboard(tmp_path, "transfer 100 coins to mallory")
    res = _run(["sign-challenge", "--key", fp], gpg_home, env=env)
    assert res.exit_code == 1
    assert "CapAuth login challenge" in res.output
    assert clip.read_text() == "transfer 100 coins to mallory"  # untouched


@needs_gpg
def test_key_gpg_does_not_hold_fails_with_the_import_hint(gpg_home, tmp_path):
    clip, env = _fake_clipboard(tmp_path, PAYLOAD)
    res = _run(["sign-challenge", "--key", "AB" * 20], gpg_home, env=env)
    assert res.exit_code == 1
    assert "gpg --import" in res.output
    assert clip.read_text() == PAYLOAD


@needs_gpg
def test_key_comes_from_the_environment_when_not_given(gpg_home):
    _home, fp, pub = gpg_home
    res = _run(
        ["sign-challenge", "--stdin", "--stdout"],
        gpg_home,
        env={"CAPAUTH_SIGN_KEY": fp},
        input=PAYLOAD,
    )
    assert res.exit_code == 0, res.output
    assert verify_nonce_signature(canonical_nonce_payload(**FIELDS), res.output, pub)


def test_key_falls_back_to_the_capauth_profile(tmp_path, monkeypatch):
    from capauth import sign_challenge as mod

    class _Profile:
        class key_info:
            fingerprint = "CD" * 20

    monkeypatch.delenv("CAPAUTH_SIGN_KEY", raising=False)
    monkeypatch.setattr(mod, "_load_profile", lambda home: _Profile())
    assert mod.resolve_key(None, tmp_path) == "CD" * 20
    assert mod.resolve_key("ab" * 20, tmp_path) == "AB" * 20
    monkeypatch.setenv("CAPAUTH_SIGN_KEY", "EF" * 20)
    assert mod.resolve_key(None, tmp_path) == "EF" * 20


def test_bad_fingerprint_is_refused_before_gpg_runs():
    res = CliRunner().invoke(
        main, ["sign-challenge", "--stdin", "--stdout", "--key", "nope"], input=PAYLOAD
    )
    assert res.exit_code == 1 and "fingerprint" in res.output


def test_no_clipboard_tool_says_what_to_install(monkeypatch, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    res = CliRunner().invoke(
        main,
        ["sign-challenge", "--key", "AB" * 20],
        env={"PATH": str(empty), "WAYLAND_DISPLAY": "", "DISPLAY": ""},
    )
    assert res.exit_code == 1
    assert "wl-clipboard" in res.output and "--stdin" in res.output
