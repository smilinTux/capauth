"""Tests for the canonical-subject store rewrite (card N5, ``754265a7``).

All hermetic: every test injects a ``tmp_path`` ``base_dir``, never the real
``~/.skcapstone``. Covers:

* the device-record scan finds every legacy shape (``operator:`` prefix,
  ``capauth:`` prefix, missing-TLD) and skips already-canonical ones;
* a device sidecar entry with no ``subject`` key of its own (falling back to
  the peer record's identity fields) gets one added;
* apply is additive on the v1 peer record (byte-verbatim outside the
  ``pairing`` sidecar) and stamps a one-time migration paper trail;
* dry-run never writes;
* the whole thing is idempotent: scan-apply-scan finds nothing left the
  second time, and a second apply is a no-op;
* token re-issuance: an active, non-canonical token is superseded by a fresh,
  signed, canonical-subject token and the original is revoked;
* a revoked or expired non-canonical token is left alone, not re-issued;
* ``capauth.authz._subject_tokens`` dual-reads a legacy query against a
  canonical stored token (and vice versa), mirroring
  ``capauth.pairing.list_devices``'s existing dual read.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from capauth.authz import _subject_tokens
from capauth.pairing.canonicalize import (
    apply_canonical_rewrite,
    format_rewrite_plan,
    scan_canonical_rewrite,
)
from capauth.tokens import is_revoked, issue_token, list_tokens

# A representative v1 peer record for a device-seat entry, as the shipped
# skchat pairing_mirror actually writes it (see capauth/pairing/store.py's
# ``_minimal_v1_peer``), with an added legacy ``pairing`` sidecar.
_LEGACY_DEVICE_PEER = {
    "name": "operator:aabbccdd00112233",
    "identity": "operator:aabbccdd00112233",
    "fingerprint": "AABBCCDD00112233445566778899AABBCCDD0011",
    "public_key": "PUBKEY",
    "entity_type": "device",
    "handle": "operator:aabbccdd00112233",
    "email": None,
    "capabilities": ["skchat.send"],
    "contact_uris": [],
    "trust_level": "verified",
    "added_at": "2026-08-09T00:25:13.080694+00:00",
    "last_seen": None,
    "source": "capauth.pairing",
    "agent_type": "device",
    "notes": "",
    "transport_addresses": {},
    "capauth_uri": "operator:aabbccdd00112233",
    "fqid": None,
    "pairing": {
        "version": 1,
        "devices": [
            {
                "device_id": "835077b5-bdbf-43fc-b3ed-144f849885e1",
                "subject": "operator:aabbccdd00112233",
                "enrollment_id": "835077b5-bdbf-43fc-b3ed-144f849885e1",
                "pubkey": "PUBKEY",
                "fingerprint": "AABBCCDD00112233445566778899AABBCCDD0011",
                "mode": "verified",
                "scopes": ["skchat.send"],
                "approved_by": "skchat",
                "approved_at": "2026-08-09T00:25:13.076169+00:00",
                "revoked": False,
                "revoked_reason": None,
                "revoked_at": None,
            }
        ],
    },
}


def _write_peer(base: Path, name: str, record: dict) -> Path:
    peers = base / "peers"
    peers.mkdir(parents=True, exist_ok=True)
    path = peers / f"{name}.json"
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# device scan
# --------------------------------------------------------------------------- #
def test_scan_finds_operator_prefixed_device(tmp_path):
    _write_peer(tmp_path, "aabbccdd00112233", _LEGACY_DEVICE_PEER)

    plan = scan_canonical_rewrite(tmp_path)

    assert len(plan.devices) == 1
    rewrite = plan.devices[0]
    assert rewrite.old_subject == "operator:aabbccdd00112233"
    assert rewrite.new_subject == "device:aabbccdd00112233"
    assert not plan.tokens
    assert not plan.is_empty


def test_scan_finds_capauth_prefixed_and_missing_tld_device(tmp_path):
    import copy

    record = copy.deepcopy(_LEGACY_DEVICE_PEER)
    record["pairing"]["devices"] = [
        {
            **_LEGACY_DEVICE_PEER["pairing"]["devices"][0],
            "device_id": "d1",
            "subject": "capauth:opus@skworld.io",
        },
        {
            **_LEGACY_DEVICE_PEER["pairing"]["devices"][0],
            "device_id": "d2",
            "subject": "opus@chef.skworld",
        },
        {
            **_LEGACY_DEVICE_PEER["pairing"]["devices"][0],
            "device_id": "d3",
            "subject": "opus@chef.skworld.io",
        },
    ]
    _write_peer(tmp_path, "opus", record)

    plan = scan_canonical_rewrite(tmp_path)

    by_device = {r.device_id: r for r in plan.devices}
    assert by_device["d1"].new_subject == "opus@chef.skworld.io"
    assert by_device["d2"].new_subject == "opus@chef.skworld.io"
    # d3 was already canonical: not in the plan at all.
    assert "d3" not in by_device
    assert len(plan.devices) == 2


def test_scan_falls_back_to_peer_level_identity_when_entry_has_no_subject(tmp_path):
    import copy

    record = copy.deepcopy(_LEGACY_DEVICE_PEER)
    del record["pairing"]["devices"][0]["subject"]
    record["identity"] = "capauth:lumina@skworld.io"
    _write_peer(tmp_path, "lumina", record)

    plan = scan_canonical_rewrite(tmp_path)

    assert len(plan.devices) == 1
    assert plan.devices[0].old_subject == "capauth:lumina@skworld.io"
    assert plan.devices[0].new_subject == "lumina@chef.skworld.io"


def test_scan_skips_already_canonical_store(tmp_path):
    import copy

    record = copy.deepcopy(_LEGACY_DEVICE_PEER)
    record["pairing"]["devices"][0]["subject"] = "device:aabbccdd00112233"
    _write_peer(tmp_path, "aabbccdd00112233", record)

    plan = scan_canonical_rewrite(tmp_path)

    assert plan.is_empty


def test_scan_against_empty_store_is_empty(tmp_path):
    plan = scan_canonical_rewrite(tmp_path)
    assert plan.is_empty
    assert "already fully canonical" in format_rewrite_plan(plan)


# --------------------------------------------------------------------------- #
# device apply
# --------------------------------------------------------------------------- #
def test_apply_rewrites_subject_and_preserves_v1_shape(tmp_path):
    import copy

    path = _write_peer(tmp_path, "aabbccdd00112233", copy.deepcopy(_LEGACY_DEVICE_PEER))

    plan = scan_canonical_rewrite(tmp_path)
    report = apply_canonical_rewrite(plan)

    assert len(report.devices_rewritten) == 1
    on_disk = json.loads(path.read_text())
    entry = on_disk["pairing"]["devices"][0]
    assert entry["subject"] == "device:aabbccdd00112233"
    assert entry["subject_migrated_from"] == "operator:aabbccdd00112233"
    assert "subject_migrated_at" in entry

    # Every v1 top-level field is byte-identical to what was written.
    for key, value in _LEGACY_DEVICE_PEER.items():
        if key == "pairing":
            continue
        assert on_disk[key] == value, f"v1 field {key!r} was touched"


def test_apply_adds_subject_key_when_entry_had_none(tmp_path):
    import copy

    record = copy.deepcopy(_LEGACY_DEVICE_PEER)
    del record["pairing"]["devices"][0]["subject"]
    record["identity"] = "capauth:lumina@skworld.io"
    path = _write_peer(tmp_path, "lumina", record)

    plan = scan_canonical_rewrite(tmp_path)
    apply_canonical_rewrite(plan)

    entry = json.loads(path.read_text())["pairing"]["devices"][0]
    assert entry["subject"] == "lumina@chef.skworld.io"
    # peer-level identity, untouched (M2 rule).
    assert json.loads(path.read_text())["identity"] == "capauth:lumina@skworld.io"


def test_dry_run_never_writes(tmp_path):
    path = _write_peer(tmp_path, "aabbccdd00112233", dict(_LEGACY_DEVICE_PEER))
    before = path.read_text()

    plan = scan_canonical_rewrite(tmp_path)
    assert not plan.is_empty
    # scan_canonical_rewrite is read-only by construction; assert the file is
    # untouched byte-for-byte (nothing calls apply here).
    assert path.read_text() == before


def test_migration_is_idempotent(tmp_path):
    import copy

    _write_peer(tmp_path, "aabbccdd00112233", copy.deepcopy(_LEGACY_DEVICE_PEER))

    first_plan = scan_canonical_rewrite(tmp_path)
    apply_canonical_rewrite(first_plan)

    second_plan = scan_canonical_rewrite(tmp_path)
    assert second_plan.is_empty

    # Applying an empty plan again changes nothing and stays a no-op.
    report = apply_canonical_rewrite(second_plan)
    assert not report.devices_rewritten
    assert not report.tokens_reissued


def test_apply_only_touches_non_canonical_entries_in_a_mixed_file(tmp_path):
    import copy

    record = copy.deepcopy(_LEGACY_DEVICE_PEER)
    record["pairing"]["devices"] = [
        {
            **_LEGACY_DEVICE_PEER["pairing"]["devices"][0],
            "device_id": "d1",
            "subject": "operator:aabbccdd00112233",
        },
        {
            **_LEGACY_DEVICE_PEER["pairing"]["devices"][0],
            "device_id": "d2",
            "subject": "device:aabbccdd00112233",
        },
    ]
    path = _write_peer(tmp_path, "aabbccdd00112233", record)

    plan = scan_canonical_rewrite(tmp_path)
    apply_canonical_rewrite(plan)

    devices = {d["device_id"]: d for d in json.loads(path.read_text())["pairing"]["devices"]}
    assert devices["d1"]["subject"] == "device:aabbccdd00112233"
    assert "subject_migrated_from" in devices["d1"]
    # d2 was already canonical: untouched, no migration stamp added.
    assert devices["d2"]["subject"] == "device:aabbccdd00112233"
    assert "subject_migrated_from" not in devices["d2"]


# --------------------------------------------------------------------------- #
# token re-issuance
# --------------------------------------------------------------------------- #
@pytest.fixture
def _security_dir(tmp_path):
    (tmp_path / "security").mkdir(parents=True, exist_ok=True)
    return tmp_path


class TestTokenReissue:
    def test_active_noncanonical_token_is_reissued_and_old_revoked(
        self, tmp_path, stub_token_signing
    ):
        old = issue_token(
            home=tmp_path,
            subject="operator:aabbccdd00112233",
            capabilities=["skchat.send"],
            ttl_hours=24,
            sign=True,
        )

        plan = scan_canonical_rewrite(tmp_path)
        assert len(plan.tokens) == 1
        assert plan.tokens[0].old_subject == "operator:aabbccdd00112233"
        assert plan.tokens[0].new_subject == "device:aabbccdd00112233"

        report = apply_canonical_rewrite(plan)

        assert len(report.tokens_reissued) == 1
        assert report.tokens_revoked == [old.payload.token_id]
        assert is_revoked(tmp_path, old.payload.token_id)

        tokens = list_tokens(tmp_path)
        new_tokens = [t for t in tokens if t.payload.subject == "device:aabbccdd00112233"]
        assert len(new_tokens) == 1
        new_token = new_tokens[0]
        assert new_token.payload.token_id != old.payload.token_id
        assert new_token.payload.capabilities == old.payload.capabilities
        assert new_token.signature  # freshly signed, not a stale copy
        assert new_token.payload.metadata["migrated_from_token_id"] == old.payload.token_id
        assert new_token.payload.metadata["migrated_from_subject"] == "operator:aabbccdd00112233"

    def test_reissued_token_preserves_original_expiry_verbatim(self, tmp_path, stub_token_signing):
        old = issue_token(
            home=tmp_path,
            subject="operator:aabbccdd00112233",
            capabilities=["skchat.send"],
            ttl_hours=48,
            sign=True,
        )

        plan = scan_canonical_rewrite(tmp_path)
        apply_canonical_rewrite(plan)

        new_token = next(
            t for t in list_tokens(tmp_path) if t.payload.subject == "device:aabbccdd00112233"
        )
        assert new_token.payload.expires_at == old.payload.expires_at

    def test_revoked_noncanonical_token_is_left_alone(self, tmp_path, stub_token_signing):
        from capauth.tokens import revoke_token

        old = issue_token(
            home=tmp_path,
            subject="operator:aabbccdd00112233",
            capabilities=["skchat.send"],
            sign=True,
        )
        revoke_token(tmp_path, old.payload.token_id)

        plan = scan_canonical_rewrite(tmp_path)

        assert not plan.tokens
        assert len(plan.token_skips) == 1
        assert plan.token_skips[0].reason.startswith("already revoked")

        report = apply_canonical_rewrite(plan)
        assert not report.tokens_reissued
        # The revoked token's own subject is untouched.
        stored = next(
            t for t in list_tokens(tmp_path) if t.payload.token_id == old.payload.token_id
        )
        assert stored.payload.subject == "operator:aabbccdd00112233"

    def test_expired_noncanonical_token_is_left_alone(
        self, tmp_path, stub_token_signing, monkeypatch
    ):
        old = issue_token(
            home=tmp_path,
            subject="operator:aabbccdd00112233",
            capabilities=["skchat.send"],
            ttl_hours=1,
            sign=True,
        )
        # Force expiry without sleeping: rewrite the stored payload's
        # expires_at into the past.
        token_dir = tmp_path / "security" / "tokens"
        token_file = token_dir / f"{old.payload.token_id[:16]}.json"
        data = json.loads(token_file.read_text())
        data["payload"]["expires_at"] = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        ).isoformat()
        token_file.write_text(json.dumps(data))

        plan = scan_canonical_rewrite(tmp_path)

        assert not plan.tokens
        assert len(plan.token_skips) == 1
        assert "expired" in plan.token_skips[0].reason

    def test_canonical_token_is_not_reissued(self, tmp_path, stub_token_signing):
        issue_token(
            home=tmp_path,
            subject="device:aabbccdd00112233",
            capabilities=["skchat.send"],
            sign=True,
        )
        plan = scan_canonical_rewrite(tmp_path)
        assert not plan.tokens
        assert not plan.token_skips


# --------------------------------------------------------------------------- #
# authz dual-read (the "correlate by exact subject" correctness constraint)
# --------------------------------------------------------------------------- #
class TestSubjectTokensDualRead:
    def test_legacy_query_matches_a_canonical_stored_token(self, tmp_path, stub_token_signing):
        issue_token(
            home=tmp_path,
            subject="device:aabbccdd00112233",
            capabilities=["skchat.send"],
            sign=True,
        )
        found = _subject_tokens("operator:aabbccdd00112233", tmp_path)
        assert len(found) == 1
        assert found[0].payload.subject == "device:aabbccdd00112233"

    def test_canonical_query_still_matches_exact_canonical_token(
        self, tmp_path, stub_token_signing
    ):
        issue_token(
            home=tmp_path,
            subject="device:aabbccdd00112233",
            capabilities=["skchat.send"],
            sign=True,
        )
        found = _subject_tokens("device:aabbccdd00112233", tmp_path)
        assert len(found) == 1

    def test_unrelated_subject_does_not_match(self, tmp_path, stub_token_signing):
        issue_token(
            home=tmp_path,
            subject="device:aabbccdd00112233",
            capabilities=["skchat.send"],
            sign=True,
        )
        assert _subject_tokens("device:aaaaaaaaaaaaaaaa", tmp_path) == []
