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
    ManifestRegistryError,
    ManifestSigningError,
    canonical_manifest_bytes,
    is_canonical,
    list_registered,
    load_registry,
    register_manifest,
    registry_path,
    set_module_enabled,
    sign_manifest,
    unregister_manifest,
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


# --- shell module registry (section 5.3) ---------------------------------------


def _module_manifest(module_id: str) -> dict:
    """A minimal SKWorld module manifest carrying an ``id`` field."""
    return {"id": module_id, "schemaVersion": "1.0", "name": module_id.upper()}


def _write_manifest(dir_path, module_id: str):
    """Write a canonical manifest file for ``module_id``; return its Path."""
    path = dir_path / f"{module_id}.skworld-module.json"
    path.write_bytes(canonical_manifest_bytes(_module_manifest(module_id)))
    return path


def _sign_file(manifest_path, signer_fp):
    """Sign a manifest file into ``<path>.sig`` and return the sig Path."""
    canon = canonical_manifest_bytes(manifest_path.read_bytes())
    sig = sign_manifest(canon, signer=signer_fp)
    sig_path = manifest_path.with_name(manifest_path.name + ".sig")
    sig_path.write_text(sig, encoding="utf-8")
    return sig_path


@pytest.fixture
def shell_home(tmp_path, monkeypatch):
    """An isolated $SKCAPSTONE_HOME so the registry never touches the real one."""
    home = tmp_path / "skcapstone"
    home.mkdir()
    monkeypatch.setenv("SKCAPSTONE_HOME", str(home))
    return home


def test_registry_path_honors_skcapstone_home(shell_home):
    assert registry_path() == shell_home / "shell" / "modules.json"


def test_load_registry_returns_empty_skeleton_when_absent(shell_home):
    doc = load_registry()
    assert doc["modules"] == []
    assert not registry_path().exists(), "load must not create the file"


def test_register_creates_registry_and_derives_id(shell_home, tmp_path):
    manifest = _write_manifest(tmp_path, "skos")
    entry = register_manifest(manifest)
    assert entry["id"] == "skos"
    assert entry["enabled"] is True
    assert entry["path"] == str(manifest.resolve())
    assert entry["sig"] == str(manifest.resolve()) + ".sig"
    assert "registered_at" in entry
    assert registry_path().exists()
    assert len(load_registry()["modules"]) == 1


def test_register_is_idempotent_upsert_by_id(shell_home, tmp_path):
    manifest = _write_manifest(tmp_path, "skos")
    first = register_manifest(manifest)
    # Re-register the same id disabled with an explicit sig path.
    other_sig = tmp_path / "custom.sig"
    other_sig.write_text("x", encoding="utf-8")
    second = register_manifest(manifest, sig_path=other_sig, enabled=False)
    modules = load_registry()["modules"]
    assert len(modules) == 1, "same id must upsert, not duplicate"
    assert second["enabled"] is False
    assert second["sig"] == str(other_sig.resolve())
    assert second["registered_at"] == first["registered_at"], "registered_at preserved"


def test_register_rejects_manifest_without_id(shell_home, tmp_path):
    bad = tmp_path / "noid.json"
    bad.write_bytes(canonical_manifest_bytes({"name": "no id here"}))
    with pytest.raises(ManifestRegistryError):
        register_manifest(bad)


def test_unregister_removes_entry(shell_home, tmp_path):
    manifest = _write_manifest(tmp_path, "skos")
    register_manifest(manifest)
    assert unregister_manifest("skos") is True
    assert load_registry()["modules"] == []
    assert unregister_manifest("skos") is False, "second removal is a no-op"


def test_set_module_enabled_toggles(shell_home, tmp_path):
    manifest = _write_manifest(tmp_path, "skos")
    register_manifest(manifest)
    set_module_enabled("skos", False)
    assert load_registry()["modules"][0]["enabled"] is False
    set_module_enabled("skos", True)
    assert load_registry()["modules"][0]["enabled"] is True
    with pytest.raises(ManifestRegistryError):
        set_module_enabled("nonesuch", True)


def test_list_reports_missing_sig(shell_home, tmp_path):
    manifest = _write_manifest(tmp_path, "skos")  # no .sig written
    register_manifest(manifest)
    (annotated,) = list_registered()
    assert annotated["signature"] == "missing-sig"
    assert annotated["enabled"] is True


def test_list_reports_missing_manifest(shell_home, tmp_path):
    manifest = _write_manifest(tmp_path, "skos")
    register_manifest(manifest)
    manifest.unlink()  # delete the manifest after registering
    (annotated,) = list_registered()
    assert annotated["signature"] == "missing-manifest"


@_requires_gpg
def test_list_reports_ok_failed_and_missing_together(shell_home, tmp_path, signer):
    """Good, tampered, and missing-sig entries coexist; one bad entry never
    crashes the listing (fail-closed per section 5.3)."""
    # good: canonical manifest + valid sig
    good = _write_manifest(tmp_path, "skos")
    _sign_file(good, signer)
    register_manifest(good)

    # bad: valid sig, then the manifest is tampered on disk after signing
    bad = _write_manifest(tmp_path, "skchat")
    _sign_file(bad, signer)
    bad.write_bytes(canonical_manifest_bytes({"id": "skchat", "name": "TAMPERED"}))
    register_manifest(bad)

    # missing-sig: manifest with no signature file
    nosig = _write_manifest(tmp_path, "skcode")
    register_manifest(nosig)

    verdicts = {e["id"]: e["signature"] for e in list_registered()}
    assert verdicts == {"skos": "ok", "skchat": "failed", "skcode": "missing-sig"}


@_requires_gpg
def test_list_expected_signer_pin_rejects_wrong_key(shell_home, tmp_path, signer):
    good = _write_manifest(tmp_path, "skos")
    _sign_file(good, signer)
    register_manifest(good)
    assert list_registered()[0]["signature"] == "ok"
    # Pin to a fingerprint that did not sign -> fails closed.
    wrong = "0" * 40
    assert list_registered(expected_signer=wrong)[0]["signature"] == "failed"
    assert list_registered(expected_signer=signer)[0]["signature"] == "ok"


# --- CLI: verify-all exit code -------------------------------------------------


@_requires_gpg
def test_cli_verify_all_exit_code(shell_home, tmp_path, signer):
    from click.testing import CliRunner

    from capauth.cli import main

    good = _write_manifest(tmp_path, "skos")
    _sign_file(good, signer)
    register_manifest(good)

    runner = CliRunner()
    # All enabled entries verify -> exit 0.
    ok = runner.invoke(main, ["manifest", "verify-all"])
    assert ok.exit_code == 0, ok.output

    # Add a tampered (enabled) entry -> exit nonzero.
    bad = _write_manifest(tmp_path, "skchat")
    _sign_file(bad, signer)
    bad.write_bytes(canonical_manifest_bytes({"id": "skchat", "name": "TAMPERED"}))
    register_manifest(bad)
    failed = runner.invoke(main, ["manifest", "verify-all"])
    assert failed.exit_code != 0, failed.output

    # Disabling the bad entry restores a clean pass (verify-all skips disabled).
    set_module_enabled("skchat", False)
    passes = runner.invoke(main, ["manifest", "verify-all"])
    assert passes.exit_code == 0, passes.output


@_requires_gpg
def test_cli_register_and_list_roundtrip(shell_home, tmp_path, signer):
    from click.testing import CliRunner

    from capauth.cli import main

    manifest = _write_manifest(tmp_path, "skos")
    _sign_file(manifest, signer)

    runner = CliRunner()
    reg = runner.invoke(main, ["manifest", "register", str(manifest)])
    assert reg.exit_code == 0, reg.output
    assert "skos" in reg.output

    listing = runner.invoke(main, ["manifest", "list"])
    assert listing.exit_code == 0, listing.output
    assert "skos" in listing.output
    assert "ok" in listing.output
