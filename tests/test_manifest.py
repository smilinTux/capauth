"""Tests for capauth.manifest -- detached SKWorld module-manifest signatures.

Covers:
  - canonical-bytes determinism (and byte-for-byte match with skos' reference form)
  - sign + verify round-trip against the operator-style gpg keyring path
  - tamper detection (any manifest change flips verify False)
  - wrong-signer rejection (signature from key A does not verify as key B)
  - fail-closed behaviour (absent/empty signature, garbage signature)

The signing path reuses capauth's operator-identity gpg mechanism, so these
tests generate a throwaway signing key inside an isolated GNUPGHOME rather than
touching the real operator keyring.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from capauth.manifest import (
    ManifestSigningError,
    canonical_manifest_bytes,
    is_canonical,
    sign_manifest,
    verify_manifest,
)

_HAS_GPG = shutil.which("gpg") is not None
_requires_gpg = pytest.mark.skipif(not _HAS_GPG, reason="gpg not available")

# A representative SKWorld module manifest (shape mirrors skos' emitted form).
SAMPLE_MANIFEST = {
    "schema_version": "1.0",
    "module": "skos",
    "audience": "skos",
    "display_name": "SKOS",
    "entrypoints": {"web": "/app/", "api": "/api/v1"},
    "capabilities": ["gtd", "itil", "autopilot"],
    "version": "0.2.14",
}


def _gen_key(gnupghome, uid: str) -> str:
    """Generate a throwaway signing key in ``gnupghome``; return its fingerprint."""
    env = {"GNUPGHOME": str(gnupghome)}
    subprocess.run(
        [
            "gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
            "--quick-generate-key", uid, "default", "sign", "never",
        ],
        env=env, capture_output=True, check=True, timeout=60,
    )
    listing = subprocess.run(
        ["gpg", "--batch", "--with-colons", "--list-secret-keys", uid],
        env=env, capture_output=True, text=True, check=True,
    )
    for line in listing.stdout.splitlines():
        parts = line.split(":")
        if parts[0] == "fpr":
            return parts[9]
    raise RuntimeError("could not read generated key fingerprint")


@pytest.fixture
def signer(tmp_path, monkeypatch):
    """An isolated GNUPGHOME with one signing key; yields its fingerprint."""
    gnupghome = tmp_path / "gnupg"
    gnupghome.mkdir(mode=0o700)
    monkeypatch.setenv("GNUPGHOME", str(gnupghome))
    fp = _gen_key(gnupghome, "Manifest Signer <sign@test.local>")
    return fp


# --- canonicalization ----------------------------------------------------------


def test_canonical_bytes_are_sorted_and_deterministic():
    a = canonical_manifest_bytes({"b": 2, "a": 1, "c": {"z": 1, "y": 2}})
    b = canonical_manifest_bytes({"c": {"y": 2, "z": 1}, "a": 1, "b": 2})
    assert a == b, "key order in the source dict must not change canonical bytes"
    assert a == b'{\n  "a": 1,\n  "b": 2,\n  "c": {\n    "y": 2,\n    "z": 1\n  }\n}\n'


def test_canonical_bytes_accepts_dict_str_and_bytes_equivalently():
    from_dict = canonical_manifest_bytes(SAMPLE_MANIFEST)
    from_str = canonical_manifest_bytes(json.dumps(SAMPLE_MANIFEST))
    from_bytes = canonical_manifest_bytes(json.dumps(SAMPLE_MANIFEST).encode("utf-8"))
    assert from_dict == from_str == from_bytes


def test_canonical_bytes_is_idempotent():
    once = canonical_manifest_bytes(SAMPLE_MANIFEST)
    twice = canonical_manifest_bytes(once)
    assert once == twice
    assert is_canonical(once)


def test_canonical_bytes_matches_skos_reference_form():
    """Alignment with skos.render_manifest_json is the interop contract."""
    skos_manifest = pytest.importorskip("skos.skworld_manifest")
    expected = skos_manifest.render_manifest_json().encode("utf-8")
    assert canonical_manifest_bytes(skos_manifest.render_manifest_json()) == expected
    assert canonical_manifest_bytes(skos_manifest.skos_module_manifest(
        skos_manifest.DEFAULT_BASE_URL
    )) == expected


def test_canonical_bytes_rejects_non_json():
    with pytest.raises(ManifestSigningError):
        canonical_manifest_bytes(b"not json {{{")


def test_is_canonical_false_for_reformatted_json():
    non_canonical = json.dumps(SAMPLE_MANIFEST).encode("utf-8")  # compact, unsorted spacing
    assert not is_canonical(non_canonical)
    assert is_canonical(canonical_manifest_bytes(non_canonical))


# --- sign + verify round-trip --------------------------------------------------


@_requires_gpg
def test_sign_and_verify_roundtrip(signer):
    canon = canonical_manifest_bytes(SAMPLE_MANIFEST)
    sig = sign_manifest(canon, signer=signer)
    assert "BEGIN PGP SIGNATURE" in sig
    assert verify_manifest(canon, sig, expected_signer=signer) is True
    # And with no signer pin, a valid signature still verifies.
    assert verify_manifest(canon, sig) is True


@_requires_gpg
def test_verify_accepts_partial_fingerprint(signer):
    canon = canonical_manifest_bytes(SAMPLE_MANIFEST)
    sig = sign_manifest(canon, signer=signer)
    assert verify_manifest(canon, sig, expected_signer=signer[-16:]) is True


# --- tamper detection ----------------------------------------------------------


@_requires_gpg
def test_verify_rejects_tampered_manifest(signer):
    canon = canonical_manifest_bytes(SAMPLE_MANIFEST)
    sig = sign_manifest(canon, signer=signer)
    tampered = dict(SAMPLE_MANIFEST)
    tampered["capabilities"] = ["gtd", "itil", "autopilot", "root"]  # privilege bump
    tampered_bytes = canonical_manifest_bytes(tampered)
    assert verify_manifest(tampered_bytes, sig, expected_signer=signer) is False


@_requires_gpg
def test_verify_rejects_single_byte_flip(signer):
    canon = canonical_manifest_bytes(SAMPLE_MANIFEST)
    sig = sign_manifest(canon, signer=signer)
    flipped = bytearray(canon)
    flipped[-2] ^= 0x01
    assert verify_manifest(bytes(flipped), sig, expected_signer=signer) is False


# --- wrong-signer rejection ----------------------------------------------------


@_requires_gpg
def test_verify_rejects_wrong_signer(signer, tmp_path):
    canon = canonical_manifest_bytes(SAMPLE_MANIFEST)
    sig = sign_manifest(canon, signer=signer)  # signed by key A (the fixture key)
    # Generate an unrelated key B in the SAME keyring; pin verify to B.
    other_fp = _gen_key(tmp_path / "gnupg", "Impostor <evil@test.local>")
    assert other_fp != signer
    assert verify_manifest(canon, sig, expected_signer=other_fp) is False


# --- fail-closed ---------------------------------------------------------------


@_requires_gpg
def test_verify_fails_closed_on_absent_signature(signer):
    canon = canonical_manifest_bytes(SAMPLE_MANIFEST)
    assert verify_manifest(canon, None) is False
    assert verify_manifest(canon, "") is False


@_requires_gpg
def test_verify_fails_closed_on_garbage_signature(signer):
    canon = canonical_manifest_bytes(SAMPLE_MANIFEST)
    assert verify_manifest(canon, "-----BEGIN PGP SIGNATURE-----\nnope\n----") is False


@_requires_gpg
def test_sign_raises_on_unknown_signer(signer):
    canon = canonical_manifest_bytes(SAMPLE_MANIFEST)
    with pytest.raises(ManifestSigningError):
        sign_manifest(canon, signer="DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF")
