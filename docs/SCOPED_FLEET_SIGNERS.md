# Scoped fleet signer migration

## Decision

Replace the shared C8D Jarvis signer on each of the seven application nodes
with one node identity and separate service identities for signing workloads.
The policy is represented by `capauth.scoped_signers.ScopedSignerPolicy`.
Policy files contain fingerprints, scopes, trust, lifecycle metadata, and local
secret locators only. They must never contain private keys or passphrases.

Casey's human identity is the offline recovery and enrollment authority. Its
private key remains local and offline. It is never installed on a fleet node,
listed as a failover target, accepted as an automated SKLegal issuer, or placed
under a Syncthing root.

## Identity and authorization contract

Each identity has a unique ID, OpenPGP primary fingerprint, kind, attribution
label, lifecycle state, and enrollment evidence. Node identities bind to one
node. Service identities bind to one node and service. A fleet identity may sign
only when all of these independently match:

1. the identity is active;
2. the requested purpose is explicitly listed;
3. the requested audience is explicitly listed;
4. SKLegal has an exact trusted-issuer row matching issuer ID, fingerprint,
   purpose, audience, principal kind, integration contract, and trust revision.

Unknown, pending, draining, revoked, untrusted, wrong-purpose, and
wrong-audience cases deny. Audit records should include identity ID,
fingerprint, node ID, service ID, purpose, audience, trust revision, request ID,
and decision, but no credential bytes.

## Enrollment

1. On the target node, create the node and service keys in a root-owned local
   custody directory outside every synchronized root. Do not export secret keys.
2. Export public keys and create a proof of possession over an enrollment
   challenge containing identity ID, fingerprint, node ID, service ID, purposes,
   audiences, nonce, and expiry.
3. On the offline workstation, Casey verifies the node through a separately
   authenticated channel, checks the proof, and signs the public enrollment
   statement. Only the public statement returns to the fleet.
4. Add exact SKLegal trusted-issuer rows as pending. Verify fingerprint and
   scopes from the signed statement, then atomically activate identity and trust.
5. Exercise positive exact-scope and negative wrong-purpose, wrong-audience,
   wrong-node, missing-trust, and private-sync tests before traffic eligibility.

Enrollment approval and runtime signing are separate duties. Enrollment does
not implicitly grant a purpose or audience.

## Failover

Failover is explicit by identity ID. A failover target must be a non-human,
non-revoked identity whose purposes and audiences cover the source. The
consumer still verifies the target's exact SKLegal trust row, so a link cannot
create trust. Prefer another service identity on the same node for process
failover and a pre-enrolled identity on an approved peer node for node loss.
Every failover produces target attribution. Never copy the failed identity's
private key and never use Casey as automatic failover.

## Rotation

1. Enroll a distinct successor fingerprint while the predecessor remains active.
2. Add pending SKLegal trust for the successor and run acceptance checks.
3. Mark predecessor `draining` with `successor_id`; draining identities cannot
   begin new signing work.
4. Activate successor trust and route new work to it.
5. After bounded in-flight work expires, revoke predecessor and remove its trust
   row. Retain public revocation and attribution records.
6. Under an approved change, quarantine or destroy predecessor private material
   according to the estate retirement procedure. Never synchronize it.

Rollback before revocation routes to the predecessor. After revocation, rollback
means enrolling another fingerprint, never unrevoke or restore the old key.

## Incident recovery

For suspected compromise, immediately mark the identity revoked, publish its
revocation, remove SKLegal trust, and deny cached trust revisions. Preserve
public attribution and audit evidence. Isolate local private material without
copying it to evidence storage. Activate an already enrolled failover identity
only if its own custody and trust are healthy. Otherwise fail closed while a new
identity is enrolled through the offline ceremony.

For node loss, rebuild from public policy and backups that exclude all private
signing material. Generate new keys on the replacement node. A disk or VM image
containing a prior signer must not establish continuity. Restore trust only
through fresh enrollment.

For loss of the offline Casey key, automated fleet identities continue within
their existing scopes, but enrollment and trust changes stop. Recovery requires
the separately governed human root recovery ceremony. Fleet keys must not be
promoted into human authority.

## Acceptance and evidence

Run hermetically before rollout:

```bash
pytest -q tests/test_scoped_signers.py
```

Required checks are:

- seven expected nodes each have a distinct active node fingerprint;
- services have distinct fingerprints and attributable node/service IDs;
- exact purpose, audience, identity kind, fingerprint, and SKLegal trust are
  jointly required;
- Casey is offline-only and cannot appear in automated scope or failover;
- revoked and draining identities cannot sign new work;
- failover and rotation references are known, non-human, non-revoked, and
  scope-covering;
- every local `secret_ref` is absolute and outside declared synchronized roots;
- policy parsing rejects embedded private-key, secret-key, and passphrase fields;
- a missing node or trusted-issuer row fails closed.

Fleet rollout additionally requires a read-only filesystem scan on every node
showing no private key or passphrase beneath any Syncthing folder, unique public
fingerprints at each runtime, exact SKLegal trust revisions, and negative signing
probes. Publish only sanitized reports and their SHA-256 hashes. Do not publish
private material, passphrases, or decrypted key listings.
