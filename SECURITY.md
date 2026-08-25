# Security Policy — capauth

`capauth` is **cryptographic identity infrastructure**: it generates, holds, signs
with, and verifies PGP key material, and it is the canonical agent-identity resolver
the rest of SKWorld trusts. Read the **honest-claim posture** and the **threat
model** before relying on it or reporting an issue.

> ⚠️ **Experimental · pre-1.0 · NOT independently security-audited.** No third-party
> security audit, fuzzing, or formal review has been performed. capauth binds vetted
> OpenPGP libraries (PGPy / GnuPG / Sequoia `sq`); the original code is the identity
> wiring, the resolver, the DID generators, and the verification service. **Review it
> yourself before production use.**

---

## Honest claims (what capauth does and does NOT promise)

Per the sk-standards
[CRYPTOGRAPHY_STANDARD](https://github.com/smilinTux/sk-standards), every claim is
scoped to **surface + FIPS/RFC number + hybrid-vs-classical**.

- ✅ **Sovereign, offline-verifiable identity.** A signed challenge proves the holder
  of a PGP private key with **no auth server and no phone-home**; anyone with the
  public key verifies it.
- ✅ **Privacy-tiered DID.** `did:key` / `did:web` mesh / `did:web` public never embed
  the private key, never embed Tailscale `100.x` IPs, and respect the tier-3 publish
  gate (enforced + tested in `did.py`).
- ✅ **Canonical resolver.** One `resolve_agent_identity()` so a cloned/impersonated
  agent fails signature verification instead of going undetected.
- ✅ **PQC signing is available and proven** — the Sequoia backend issues and verifies
  **ML-DSA-87 + Ed448** (FIPS 204) / **ML-KEM-1024 + X448** (FIPS 203) composite v6
  keys end-to-end. Migration is **additive and reversible**.
- ❌ **The live root is classical today.** The live sovereign root, agent signing,
  DID public key, challenge-response, and key-wrap are Ed25519 / RSA-4096 (RFC 8032 /
  4880) and therefore **Shor-breakable** once a CRQC exists. This is **not**
  "quantum-resistant" yet on those surfaces — do not claim it.
- ❌ **Never** "quantum-proof," "quantum-safe," "unbreakable," or "CNSA 2.0 compliant."
  Say **"quantum-resistant" / "post-quantum"** and cite the FIPS number + the surface.
- ❌ **Not a KEM / not transport security.** capauth authenticates; it does not
  establish bulk session secrets and does **not** defend Harvest-Now-Decrypt-Later
  (that is `sk_pqc` / TLS). Because it is a **signature** layer, signatures are not
  retroactively breakable — identity migration is real but **deferrable**.
- ❌ **Not** an authorization server and **not** a secret store for other services.

---

## Threat model

### In scope

- **Identity forgery / impersonation.** Authentication is a detached PGP signature
  over a fresh random nonce; a forger without the private key cannot produce a valid
  `ChallengeResponse`. A cloned agent fails verification.
- **Private-key exposure via DID/profile.** DID generators read **only**
  `public_key_armor`; the private key is never serialized into a document, profile
  export, or registry entry (invariant enforced + tested).
- **Metadata leakage in published identity.** Tier-2/3 documents strip Tailscale
  `100.x` IPs, `memory`/`journal`/detailed `soul` fields; tier-3 respects
  `publish_to_skworld: false`.
- **False crypto labels.** A v6 PQC root must not be mislabelled as RSA (fixed —
  honest v6/64-hex representation).

### Out of scope (you MUST handle these elsewhere)

- **Harvest-Now-Decrypt-Later on bulk content.** capauth is signature/identity only.
  Use a hybrid KEM (`sk_pqc`) + TLS for confidentiality at rest / in flight.
- **A live post-quantum root.** Until the gated root-rotation ceremony, the live root
  is classical. The proven Sequoia PQC backend is **available**, not yet the default.
- **Private-key storage / passphrase custody.** Caller / gpg-agent / skvault owns
  this; capauth prompts and never persists the passphrase.
- **Side channels in the bound OpenPGP libraries.** Constant-time / correctness
  guarantees come from PGPy / GnuPG / Sequoia; capauth does not re-audit them.
- **The verification service's transport.** Run it behind TLS (CF tunnel / tailnet);
  the PGP proof is the auth, the transport is the operator's responsibility.

### Trust roots / dependencies

| Surface | Library | Assurance basis |
|---|---|---|
| Default PGP sign/verify | PGPy (pure-Python) | RFC 4880 / 9580 |
| System-keyring / token PGP | python-gnupg → `gpg2` | RFC 4880; OS keyring |
| PQC signing root (proven) | Sequoia `sq` CLI (PQC build) | FIPS 204 (ML-DSA-87+Ed448) / FIPS 203 (ML-KEM-1024+X448), RFC 9580 v6, draft-ietf-openpgp-pqc-17 |
| Symmetric / hash | AES-256, SHA-256, S2K | quantum-acceptable (Grover-only) |

GnuPG is **signing-disqualified** for PQC (its PQC support is ML-KEM encryption
only); only the Sequoia backend can host a PQC **signing** root. capauth binds these
libraries — it does **not** hand-roll OpenPGP, lattice, or curve primitives. The
hybrid key-wrap target combines as `HKDF(X25519_ss ‖ MLKEM768_ss)` —
concatenate-then-KDF, **never XOR, never pure-PQ**.

---

## Capability-ceiling migration

The capability-ceiling registry is separate from the fqid grammar. The grammar
still has exactly five entity classes. A service fqid may receive either the
`service` ceiling or the narrower-purpose `connector` ceiling. A generic service
can never dispatch an email, filing, calendar action, or service action. A
connector can hold an explicit grant for those effects, but it still cannot hold
the wildcard, issue tokens, or sign identities.

Unclassified subjects fail closed before CapAuth reads a capability token. The
following temporary compatibility assignment is the complete inventory verified
on 2026-08-25 in the local shared CapAuth store:

| Existing subject | Temporary ceiling | Removal instant | Migration tool |
|---|---|---|---|
| `device:ad80d077a047babf29eec97af454fdbc3b1c37d9` | `edge-device` | `2026-09-01T00:00:00Z` | `capauth.identity_class.assign_identity_class()` |

Before the removal instant, the operator must persist that same assignment in
each deployment-specific CapAuth data directory:

```python
from pathlib import Path

from capauth.identity_class import IdentityClassName, assign_identity_class

assign_identity_class(
    "device:ad80d077a047babf29eec97af454fdbc3b1c37d9",
    IdentityClassName.EDGE_DEVICE,
    base_dir=Path("/absolute/path/to/the/active/capauth/data"),
)
```

This code change does not run that mutation. Inventory each deployment data
directory before installation. Classify every verified live subject explicitly,
then confirm that no subject remains outside the ceiling registry. New records
must receive an explicit ceiling immediately. The compatibility entry accepts no
other subject, performs no inferred rewrite, and stops resolving at the recorded
instant. After that instant, an unclassified subject is denied.

---

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | ✅ current |
| < 0.2.0 | ❌ pre-release |

Until 1.0, only the latest published `0.x` line receives security fixes.

---

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

- Report privately via **GitHub Security Advisories** ("Report a vulnerability" on the
  Security tab of [`smilinTux/capauth`](https://github.com/smilinTux/capauth)), or
- email the maintainers (smilinTux / SKWorld) at the address on the GitHub org.

Please include: affected version, Python version, backend in use (PGPy / GnuPG /
Sequoia), and a minimal reproduction. We aim to acknowledge within **72 hours** and
to ship a fix or mitigation within **90 days**, coordinating a disclosure date.
Credit is given unless you ask otherwise.

### What we especially want to hear about

- Any path where the **private key** reaches a DID document, profile export, registry
  entry, or log.
- A challenge-response that verifies a signature the prover did **not** produce
  (forgery / nonce reuse / replay).
- A DID/profile that leaks a Tailscale `100.x` IP or a gated tier-3 identity.
- A resolver path that returns the wrong agent's identity or an `@capauth.local`
  placeholder in production.
- A crypto-label overclaim — e.g. a classical surface described as
  "quantum-resistant," or a v6 root mislabelled.

---

**License:** GPL-3.0-or-later. **Standards:** RFC 4880 / 9580 (OpenPGP); RFC 7748 /
8032 (X25519 / Ed25519); FIPS 203/204/205 (ML-KEM / ML-DSA / SLH-DSA);
draft-ietf-openpgp-pqc-17; W3C DID-core; NIST CSWP 39 (crypto-agility).
