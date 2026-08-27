"""Acceptance tests for fleet-scoped node and service signer policy."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from capauth.scoped_signers import ScopedSignerPolicyError, load_scoped_signer_policy

NODES = {f"chiap0{number}" for number in range(1, 8)}
HEX = "0123456789ABCDEF"


def _fingerprint(index: int) -> str:
    return (HEX[index % len(HEX)] * 40)[:40]


def _identity(
    identity_id: str,
    fingerprint: str,
    kind: str,
    node_id: str | None,
    *,
    service_id: str | None = None,
    status: str = "active",
    failover_to: list[str] | None = None,
    successor_id: str | None = None,
) -> dict:
    purposes = ["legal.decision.sign"]
    audiences = ["sklegal"]
    return {
        "identity_id": identity_id,
        "fingerprint": fingerprint,
        "kind": kind,
        "node_id": node_id,
        "service_id": service_id,
        "status": status,
        "purposes": purposes,
        "audiences": audiences,
        "secret_ref": f"/var/lib/capauth/signers/{identity_id.replace(':', '-')}/private.asc",
        "enrollment": {
            "proof_sha256": hashlib.sha256(identity_id.encode()).hexdigest(),
            "approved_by": "human:casey",
            "approved_at": "2026-08-27T00:00:00Z",
        },
        "failover_to": failover_to or [],
        "attribution_label": identity_id,
        "offline_only": False,
        "revoked_at": None,
        "revocation_reason": None,
        "successor_id": successor_id,
    }


def _policy() -> dict:
    identities = []
    trusted = []
    for index, node in enumerate(sorted(NODES), start=1):
        identity_id = f"node:{node}"
        fingerprint = _fingerprint(index)
        identities.append(
            _identity(
                identity_id,
                fingerprint,
                "node",
                node,
                failover_to=[f"service:{node}:sklegal"],
            )
        )
        service_id = f"service:{node}:sklegal"
        service_fingerprint = _fingerprint(index + 7)
        identities.append(
            _identity(service_id, service_fingerprint, "service", node, service_id="sklegal")
        )
        for issuer_id, fp, kind in (
            (identity_id, fingerprint, "node"),
            (service_id, service_fingerprint, "service"),
        ):
            trusted.append(
                {
                    "issuer_id": issuer_id,
                    "fingerprint": fp,
                    "purposes": ["legal.decision.sign"],
                    "audiences": ["sklegal"],
                    "principal_kinds": [kind],
                    "integration": "sklegal:trusted-issuers-v1",
                    "trust_revision": "revision-17",
                }
            )

    identities.append(
        {
            "identity_id": "human:casey",
            "fingerprint": "F" * 40,
            "kind": "human",
            "node_id": None,
            "service_id": None,
            "status": "active",
            "purposes": [],
            "audiences": [],
            "secret_ref": None,
            "enrollment": {
                "proof_sha256": "a" * 64,
                "approved_by": "human:casey",
                "approved_at": "2026-08-27T00:00:00Z",
            },
            "failover_to": [],
            "attribution_label": "Casey offline root",
            "offline_only": True,
            "revoked_at": None,
            "revocation_reason": None,
            "successor_id": None,
        }
    )
    return {
        "version": 1,
        "expected_nodes": sorted(NODES),
        "synced_roots": ["/home/casey/.skcapstone", "/srv/syncthing"],
        "identities": identities,
        "trusted_issuers": trusted,
    }


def _load(tmp_path: Path, data: dict):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
    return load_scoped_signer_policy(path)


def test_seven_nodes_have_distinct_node_and_service_attribution(tmp_path):
    policy, digest = _load(tmp_path, _policy())

    assert policy.expected_nodes == NODES
    assert len(policy.identities) == 15
    assert len({identity.fingerprint for identity in policy.identities}) == 15
    assert len(digest) == 64


def test_exact_purpose_audience_and_sklegal_trust_are_required(tmp_path):
    policy, _ = _load(tmp_path, _policy())

    assert policy.permits("service:chiap01:sklegal", "legal.decision.sign", "sklegal")
    assert not policy.permits("service:chiap01:sklegal", "token.issue", "sklegal")
    assert not policy.permits("service:chiap01:sklegal", "legal.decision.sign", "other")


def test_casey_key_is_offline_local_only_and_never_a_failover(tmp_path):
    policy, _ = _load(tmp_path, _policy())
    casey = next(identity for identity in policy.identities if identity.identity_id == "human:casey")

    assert casey.offline_only
    assert casey.secret_ref is None
    assert all("human:casey" not in identity.failover_to for identity in policy.identities)
    assert not policy.permits("human:casey", "legal.decision.sign", "sklegal")


def test_no_private_sync_rejects_secret_locator_below_synced_root(tmp_path):
    data = _policy()
    data["identities"][0]["secret_ref"] = "/srv/syncthing/private.asc"

    with pytest.raises(ScopedSignerPolicyError, match="inside a synced root"):
        _load(tmp_path, data)


@pytest.mark.parametrize("field", ["private_key", "passphrase", "secret_key"])
def test_policy_rejects_embedded_private_material(tmp_path, field):
    data = _policy()
    data["identities"][0][field] = "must-not-be-present"

    with pytest.raises(ScopedSignerPolicyError, match="private material field"):
        _load(tmp_path, data)


def test_revocation_denies_even_with_stale_trust_entry(tmp_path):
    data = _policy()
    signer = next(
        item for item in data["identities"] if item["identity_id"] == "service:chiap01:sklegal"
    )
    signer.update(
        status="revoked",
        revoked_at="2026-08-27T01:00:00Z",
        revocation_reason="incident-42",
    )
    node = next(item for item in data["identities"] if item["identity_id"] == "node:chiap01")
    node["failover_to"] = []
    policy, _ = _load(tmp_path, data)

    assert not policy.permits("service:chiap01:sklegal", "legal.decision.sign", "sklegal")


def test_rotation_requires_known_nonrevoked_successor_with_covering_scope(tmp_path):
    data = _policy()
    signer = next(
        item for item in data["identities"] if item["identity_id"] == "service:chiap01:sklegal"
    )
    signer.update(status="draining", successor_id="missing:successor")

    with pytest.raises(ScopedSignerPolicyError, match="unknown signer"):
        _load(tmp_path, data)


def test_missing_node_or_trusted_issuer_fails_closed(tmp_path):
    missing_node = _policy()
    missing_node["identities"] = [
        item for item in missing_node["identities"] if item["identity_id"] != "node:chiap07"
    ]
    with pytest.raises(ScopedSignerPolicyError, match="every expected node"):
        _load(tmp_path, missing_node)

    missing_trust = _policy()
    missing_trust["trusted_issuers"] = missing_trust["trusted_issuers"][1:]
    with pytest.raises(ScopedSignerPolicyError, match="no exact SKLegal trusted-issuer"):
        _load(tmp_path, missing_trust)
