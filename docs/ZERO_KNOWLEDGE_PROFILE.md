# CapAuth Zero-Knowledge Profile

**Version:** 1.0.0 | **Date:** 2026-02-28 | **Status:** Implemented

> **Core invariant:** The CapAuth Verification Service stores ONLY your PGP
> fingerprint and public key. Every other claim — name, email, avatar, groups —
> lives on YOUR device, is signed by YOUR key, and is verified-then-discarded
> by the server. Nothing is persisted. There is no user database. There is no
> profile management. There is nothing to breach.

---

## Table of Contents

1. [Problem Statement](#problem-statement)
2. [Design Principles](#design-principles)
3. [Protocol Specification](#protocol-specification)
4. [Signed Claims Bundle](#signed-claims-bundle)
5. [Server-Side Storage Model](#server-side-storage-model)
6. [Data Flow](#data-flow)
7. [Authentik Stage Integration](#authentik-stage-integration)
8. [GDPR Compliance](#gdpr-compliance)
9. [Threat Model](#threat-model)
10. [Implementation Reference](#implementation-reference)

---

## Problem Statement

Every conventional authentication system requires the server to store user
profiles. The server becomes a honeypot: breach the server, steal everyone's
identity, email, group memberships.

CapAuth inverts this. The server is a **verifier and claims relay**, not a
store. It confirms that a signature is valid, then passes the client's claims
through to the application token. The claims are never written to any database.

---

## Design Principles

### 1. Fingerprint-Only Identity Anchor

The server stores one 40-character string per user:

```
9B3AB00F411B064646879B92D10E637B4F8367DA
```

This is the user's PGP fingerprint — their sovereign, self-sovereign identity.
Nothing else. No name. No email. No UUID assigned by the server.

### 2. Client-Asserted Claims

All profile information is **asserted by the client** at login time:

```json
{
  "name": "Chef Jonathan",
  "email": "chef@skworld.io",
  "groups": ["admins", "sovereign-stack"]
}
```

The client signs these claims cryptographically. The server verifies the
signature but does not store the claims.

### 3. Claims Are Ephemeral

Claims live only in:
- The user's local `~/.capauth/profile.yml`
- The OIDC token (duration-limited, typically 1 hour)

When the token expires, the claims are gone from the server's perspective.
The next login re-asserts them from the client's profile.

### 4. Server Changes Nothing

The server does not:
- Store names, emails, or group memberships
- Write to any user profile database
- Require "profile management" flows
- Have a "user account" concept beyond the fingerprint row

### 5. Privacy by Architecture

User changes their display name locally → every service sees the new name next
login. No profile update API. No sync delay. No data consistency problem. The
source of truth is the client's device.

---

## Protocol Specification

### Phase 1 — Challenge

The client requests authentication from a service.

**Request:**
```
POST /capauth/v1/challenge
{
  "fingerprint": "<40-char-uppercase-hex>",
  "client_nonce": "<base64-16-random-bytes>"
}
```

**Response:**
```json
{
  "nonce": "<uuid-v4>",
  "client_nonce": "<echo-of-client-nonce>",
  "timestamp": "<ISO-8601-UTC>",
  "expires": "<ISO-8601-UTC-plus-60s>",
  "service": "<service-id>",
  "server_signature": "<ASCII-armored-detach-sig>"
}
```

The `server_signature` signs the canonical nonce payload (see below). Clients
SHOULD verify this signature if they have the server's public key, to ensure
they are talking to the expected service.

**Canonical nonce payload (what the server signs):**
```
CAPAUTH_NONCE_V1
nonce=<uuid>
client_nonce=<base64>
timestamp=<ISO-8601>
service=<service-id>
expires=<ISO-8601>
```

### Phase 2 — Verify (with ZK Claims Bundle)

The client signs both the nonce and a claims bundle, then submits both.

**Request:**
```
POST /capauth/v1/verify
{
  "fingerprint": "<40-char-uppercase-hex>",
  "nonce": "<uuid from challenge>",
  "public_key_armor": "<ASCII-armored PGP public key>",
  "nonce_signature": "<ASCII-armored detach-sig over nonce payload>",
  "claims": {
    "name": "Chef Jonathan",
    "email": "chef@skworld.io",
    "groups": ["admins"]
  },
  "claims_signature": "<ASCII-armored detach-sig over claims payload>"
}
```

**Claims signature payload (what the client signs):**
```
CAPAUTH_CLAIMS_V1
fingerprint=<40-char-fp>
nonce=<uuid>
claims={"email":"chef@skworld.io","groups":["admins"],"name":"Chef Jonathan"}
```

Claims are JSON-encoded with sorted keys and no whitespace to ensure identical
serialization regardless of platform. The nonce binds the claims to this
specific authentication event — a replayed claims bundle is useless.

**Response (success):**
```json
{
  "status": "ok",
  "fingerprint": "<fingerprint>",
  "enrolled": true,
  "claims": {
    "sub": "<fingerprint>",
    "capauth_fingerprint": "<fingerprint>",
    "amr": ["pgp"],
    "name": "Chef Jonathan",
    "preferred_username": "Chef Jonathan",
    "email": "chef@skworld.io",
    "email_verified": false,
    "groups": ["admins"]
  }
}
```

The `claims` in the response are the OIDC-mapped claims — ready to embed in a
JWT. They are computed on-the-fly and not written to any database.

---

## Signed Claims Bundle

The claims bundle is the mechanism that makes ZK profiles work. It:

1. Carries the client's self-asserted profile data
2. Is bound to a specific nonce (single-use, 60-second TTL)
3. Is signed with the client's PGP private key
4. Is verified server-side against the enrolled public key
5. Is **never stored** — consumed to produce the OIDC token, then discarded

### Bundle Structure (client-side, before signing)

```python
# What the client signs (canonical_claims_payload in verifier.py):
claims_compact = json.dumps(claims, sort_keys=True, separators=(",", ":"))
payload = "\n".join([
    "CAPAUTH_CLAIMS_V1",
    f"fingerprint={fingerprint}",
    f"nonce={nonce}",
    f"claims={claims_compact}",
]).encode("utf-8")
```

### Security Properties

| Property | Mechanism |
|----------|-----------|
| Authenticity | Signature verified against enrolled public key |
| Freshness | Nonce is single-use with 60s TTL |
| Binding | Fingerprint in payload ties claims to specific identity |
| Replay protection | Nonce is consumed (deleted) on use |
| Tampering detection | Any byte change invalidates the signature |
| Forward secrecy | Claims expire with the OIDC token; no server-side record |

---

## Server-Side Storage Model

### What Is Stored (KeyStore, SQLite)

```sql
CREATE TABLE enrolled_keys (
    fingerprint       TEXT PRIMARY KEY,   -- 40-char PGP fingerprint
    public_key_armor  TEXT NOT NULL,       -- ASCII-armored public key
    enrolled_at       TEXT NOT NULL,       -- ISO 8601 enrollment timestamp
    last_auth         TEXT,                -- Last successful auth timestamp
    approved          INTEGER DEFAULT 1,   -- Admin approval flag
    linked_to         TEXT                 -- Primary FP for multi-device
);
```

**Total PII stored per user:** `0 bytes`

The public key and fingerprint are not considered PII under GDPR (they are
cryptographic identifiers, not personal data per se, though opinions vary by
jurisdiction). Name, email, group memberships, and avatar URLs are **not stored**.

### What Is NOT Stored

| Data | Where It Lives |
|------|----------------|
| Name | `~/.capauth/profile.yml` on client device |
| Email | `~/.capauth/profile.yml` on client device |
| Groups | `~/.capauth/profile.yml` on client device |
| Avatar URL | `~/.capauth/profile.yml` on client device |
| Soul blueprint | `~/.capauth/profile.yml` on client device |
| Agent type | `~/.capauth/profile.yml` on client device |

---

## Data Flow

```
┌──────────────────────────────────────────────────────────────────┐
│  CLIENT DEVICE                                                    │
│                                                                   │
│  ~/.capauth/profile.yml                                           │
│  ├── name: "Chef Jonathan"                                        │
│  ├── email: "chef@skworld.io"                                     │
│  ├── groups: [admins]                                             │
│  └── service_profiles: {...}                                      │
│                                                                   │
│  PGP Private Key (NEVER leaves device)                            │
│  └── Signs: nonce payload + claims bundle                         │
└────────────────────────────┬─────────────────────────────────────┘
                             │
                             │  POST /capauth/v1/verify
                             │  {fingerprint, nonce, nonce_sig,
                             │   claims: {name, email, groups},
                             │   claims_sig}
                             │
┌────────────────────────────▼─────────────────────────────────────┐
│  CAPAUTH VERIFICATION SERVICE                                     │
│                                                                   │
│  1. Load public_key from enrolled_keys[fingerprint]               │
│  2. Verify nonce_sig over canonical nonce payload    ✓            │
│  3. Verify claims_sig over canonical claims payload  ✓            │
│  4. Consume nonce (delete from nonce store)                       │
│  5. Map claims → OIDC claims (map_claims())                       │
│  6. Return OIDC claims                                            │
│                                                                   │
│  NOTHING WRITTEN: claims are processed in-memory only            │
│  update_last_auth(fingerprint)  ← only DB write                  │
└────────────────────────────┬─────────────────────────────────────┘
                             │
                             │  {status: ok, claims: {sub, name,
                             │   email, groups, amr: [pgp]}}
                             │
┌────────────────────────────▼─────────────────────────────────────┐
│  APPLICATION / AUTHENTIK                                          │
│                                                                   │
│  Embeds claims in OIDC token (JWT, 1-hour expiry)                │
│  Creates local session from token claims                          │
│  MAY store claims in its own user table (application's choice)   │
└──────────────────────────────────────────────────────────────────┘
```

---

## Authentik Stage Integration

The `CapAuthStage` in `authentik/stage.py` implements the ZK principle for
Authentik's authentication flow:

### User Object Invariant

```python
# From stage.py — what gets written to the Authentik user model:
user.username = preferred_username  # from claims (ephemeral display, not stored as PII)
user.name = display_name            # from claims (display only, overwritten each login)
# user.email is NOT set on the Authentik user — email is claims-only
```

The Authentik `User` object is keyed on `username`, which is derived from the
fingerprint as `capauth-{FP[:8].upper()}` when no name is claimed. This ensures
the user record is stable and fingerprint-derived, not name-derived.

**The user record that does get created in Authentik contains:**
- `username`: `capauth-{fingerprint[:8]}` (fingerprint-derived, stable)
- `name`: claimed display name (overwritten each login, not the identity anchor)
- No email in the Authentik user model — only in the OIDC token claims

### Claims Flow Through the Stage

```python
# stage.py — build_challenge() / verify_auth_response()
claims = response.data.get("claims", {})          # from client
oidc_claims = map_claims(fingerprint, claims)      # translate to OIDC
context[PLAN_CONTEXT_PENDING_USER] = user          # user keyed on fingerprint
context["capauth_claims"] = oidc_claims            # ephemeral, in-flow only
```

The `capauth_claims` context key lives only for the duration of the Authentik
flow. It is consumed by the claims mapper stage and embedded in the OIDC token.
It is not written to any Authentik database field.

---

## GDPR Compliance

### Right to Erasure (Article 17)

To fully erase a user from a CapAuth-integrated system:

```bash
# Revoke from CapAuth service
curl -X POST http://capauth:8420/capauth/v1/keys/revoke \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"fingerprint": "9B3AB00F..."}'

# That's it. One row deleted.
# No user profile table to clean up.
# No email address to hunt down.
# No avatar URLs to purge.
```

**What this erases:** The fingerprint row + public key (~700 bytes).

**What this does NOT erase:** Claims in existing unexpired OIDC tokens. This is
an inherent property of stateless tokens and is standard GDPR practice (tokens
have bounded lifetime).

### Right to Access (Article 15)

A user can see everything the server stores about them:

```bash
curl http://capauth:8420/capauth/v1/keys/me \
  -H "Authorization: Bearer $CAPAUTH_TOKEN"
# Returns: {fingerprint, enrolled_at, last_auth}
# That is literally all we have.
```

### Data Minimization (Article 5(1)(c))

We collect the minimum data technically necessary:
- Fingerprint: required to identify the key for verification
- Public key: required to verify signatures
- Enrollment timestamp: required for audit trail
- Last auth timestamp: required for rate limiting and security monitoring

All other data (name, email, groups) is explicitly excluded from storage.

---

## Threat Model

### What an Attacker Gets from Breaching the KeyStore

```
fingerprints: [
  "9B3AB00F411B064646879B92D10E637B4F8367DA",
  "AABBCCDDEEFF00112233445566778899AABBCCDD",
  ...
]
public_keys: [
  "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...",
  ...
]
```

**Impact:** None for authentication (public keys are public). Zero PII. An
attacker learns that certain PGP fingerprints have accounts, which is
equivalent to a list of usernames — already public information.

### What an Attacker CANNOT Get

- Names (not stored)
- Email addresses (not stored)
- Group memberships (not stored)
- Any data that would enable identity-based phishing

### Nonce Replay Attack

**Threat:** Attacker intercepts a verify request and replays it.

**Defense:** Nonces are single-use. Each nonce is deleted from the nonce store
when consumed. A replayed verify request will fail with `nonce not found`.
TTL is 60 seconds — even a fresh nonce expires before it can be misused in
most attack scenarios.

### Claims Tampering Attack

**Threat:** Attacker intercepts a verify request and replaces `"groups": ["users"]`
with `"groups": ["admins"]`.

**Defense:** The claims are signed. Any modification invalidates the signature.
The server verifies the signature before processing claims.

### Key Compromise

**Threat:** Attacker steals the client's PGP private key.

**Defense:** Standard key revocation. The compromised key can be revoked by
the admin via the `/capauth/v1/keys/revoke` endpoint. New authentication
requires the private key, so a revoked key cannot generate new sessions.

---

## Implementation Reference

### Core Files

| File | Purpose |
|------|---------|
| `capauth/src/capauth/authentik/verifier.py` | Canonical payload builders + signature verification |
| `capauth/src/capauth/authentik/claims_mapper.py` | Maps client claims → OIDC claims |
| `capauth/src/capauth/authentik/stage.py` | Authentik stage — ZK flow orchestrator |
| `capauth/src/capauth/service/app.py` | FastAPI service — standalone verifier |
| `capauth/src/capauth/service/keystore.py` | SQLite key store — fingerprint-only schema |
| `capauth/src/capauth/profile.py` | Client profile management |

### Canonical Payload Functions

```python
# verifier.py
def canonical_nonce_payload(nonce, client_nonce_echo, timestamp, service, expires) -> bytes
def canonical_claims_payload(fingerprint, nonce, claims) -> bytes
```

### Adding a New Claim Type

1. Add the claim to `_KNOWN_CLAIMS` in `claims_mapper.py`
2. Map it in `map_claims()` under the appropriate scope
3. Update the scope table in `SCOPE_CLAIMS`
4. Document it in `CLAIMS.md`
5. Update `profile.yml` examples

**Invariant to preserve:** New claims MUST come from the client. Never derive
a claim from server-side lookup. The server is a relay, not an oracle.

---

## Quick Reference

### Server stores per user
```
fingerprint  →  9B3AB00F411B064646879B92D10E637B4F8367DA   (40 chars)
public_key   →  -----BEGIN PGP PUBLIC KEY BLOCK-----...    (~3 KB)
enrolled_at  →  2026-02-24T13:00:00Z                        (20 chars)
last_auth    →  2026-02-28T09:15:32Z                        (20 chars)
```

### Client stores per user
```
~/.capauth/identity/private.asc  →  PGP private key (STAYS HERE)
~/.capauth/identity/public.asc   →  PGP public key
~/.capauth/profile.yml           →  name, email, groups, service profiles
```

### GDPR deletion
```bash
# Delete ONE row → user completely erased from CapAuth
skcapstone coord claim <revoke-task> --agent mcp-builder
capauth-service revoke --fingerprint 9B3AB00F...
```

---

*CapAuth: your identity is a key, not a database row.*

*#staycuriousANDkeepsmilin*
