# Identity estate discovery and retirement

`capauth doctor custody` validates one configured identity. `capauth doctor
estate` validates the wider machine estate: canonical and legacy CapAuth roots,
SKCapstone agent/named-identity roots, alternate user homes, GnuPG keyrings, and
Syncthing folders which contain those roots.

The workflow is read-only. It never removes a key and never emits private key or
passphrase bytes. An optional evidence file contains paths, primary
fingerprints, manifest digest, classifications, and results.

Retired quarantine records may declare an exact `members` list. The estate
doctor verifies the encrypted `.tar.gpg` envelope and hash by default. A
bounded decrypt check may be requested with `doctor estate --passphrase-file`
using a mode-0600 passphrase file. Passphrase bytes, decrypted contents, and
GnuPG stderr are never emitted.

## Authoritative manifest

Keep `estate.json` in the CapAuth home or pass it explicitly with `--manifest`.
Version 1 distinguishes human, service, and node identities, records lifecycle
state, constrains active private-key placement, and links retired fingerprints
to verified encrypted quarantine:

```json
{
  "version": 1,
  "identities": [
    {
      "fingerprint": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "status": "active",
      "identity_type": "human",
      "label": "operator",
      "allowed_secret_roots": [
        "/home/operator/.skcapstone/identities/operator/capauth"
      ]
    },
    {
      "fingerprint": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
      "status": "retired",
      "identity_type": "service",
      "label": "former service signer",
      "quarantine": {
        "archive": "/custody/capauth/retired-service.tar.gpg",
        "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "verified_at": "2026-08-21T00:00:00Z",
        "verified_by": "operator"
      }
    }
  ]
}
```

Fingerprints must be full 40- or 64-hex OpenPGP primary fingerprints.
`identity_type` is `human`, `service`, or `node`; `status` is `active` or
`retired`. Paths may be absolute or relative to the manifest.

For retired identities, `archive` must exist and end in `.gpg`, and its current
SHA-256 must match the manifest. `verified_at` and `verified_by` are operator
attestations that the encrypted archive was decrypt-tested and its expected
members/fingerprints were checked. The hash check does not replace that
decryptability test.

## Audit

Run against the current user:

```bash
capauth doctor estate \
  --manifest ~/.skcapstone/capauth/estate.json \
  --evidence /var/tmp/capauth-estate-evidence.json
```

Name every alternate home. This prevents a different login home from escaping
the inventory:

```bash
capauth doctor estate \
  --manifest /path/to/estate.json \
  --user-home /home/operator \
  --user-home /home/alternate
```

Use repeatable `--root` for identities outside the known layouts and
`--syncthing-config` for nonstandard Syncthing configuration paths. GnuPG
keyring inspection is on by default; `--no-gpg` exists for hermetic tests.

The command exits nonzero for:

- physical legacy and canonical trees which diverge;
- private keys outside their declared custody roots;
- unmanifested private keys;
- any discovered retired key copy;
- Syncthing conflict copies;
- missing private-key or root-revocation ignore rules at the actual Syncthing
  folder root;
- absent, non-encrypted, or hash-mismatched quarantine evidence.

An unmanifested public key and multiple copies of the same active secret key
warn. Public keys classified as active and correctly placed active private keys
pass.

## Retirement gate

1. Record the fingerprint as `retired`; do not delete anything.
2. Stream the complete material into an encrypted `.gpg` quarantine archive.
3. Decrypt-test the archive in a temporary location and verify expected
   fingerprints/members.
4. Record the archive SHA-256 and the operator attestation in the manifest.
5. Run `capauth doctor estate --evidence ...`. The quarantine check must be
   `OK`; discovered retired copies will still be `FAIL`.
6. Under an approved change, remove only the exact reported copies and GnuPG
   primary fingerprints.
7. Rerun the audit. Retired-copy findings must be gone while quarantine remains
   `OK`. Attach the evidence file and manifest digest to the change record.

This two-run pattern makes removal contingent on verified, encrypted,
recoverable custody and produces evidence without automating destructive key
deletion.

## Syncthing boundary

`capauth sync` now writes required `.stignore` rules before registering a
folder and fails closed if it cannot do so. Running it against an already
configured identity root also repairs missing required exclusions. At minimum,
the folder root must contain:

```text
**/private.*
**/root-revocation.asc
```

The setup command also excludes common passphrase, environment, SQLite, and
backup paths. Treat synced state as public distribution, never custody.
