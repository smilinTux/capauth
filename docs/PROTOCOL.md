# CapAuth Authentication Protocol

### Zero-Knowledge Passwordless Authentication with Client-Asserted Claims

**Version:** 1.0.0 | **Status:** Draft | **Date:** 2026-02-24

---

## Abstract

CapAuth is a passwordless, zero-knowledge authentication protocol built on OpenPGP (RFC 4880 / RFC 9580). Users are identified by their PGP key fingerprint. All personally identifiable information (name, email, avatar, group memberships) lives exclusively in the user's local profile and is **asserted by the client at login time**.

The server stores **only the public key fingerprint**. It is a verifier and claims relay — not a user database. No PII is persisted server-side. No GDPR data to delete. No profile management endpoints. No passwords.

This document defines the wire protocol for web service authentication. For peer-to-peer identity verification, see [`CRYPTO_SPEC.md`](./CRYPTO_SPEC.md).

---

## Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Zero server-side PII** | Server stores fingerprint only; all claims flow from client |
| **Sovereign identity** | The user's PGP key IS their identity — no issuer required |
| **OIDC compatible** | Server issues standard OIDC tokens populated from client claims |
| **Replay-proof** | Nonces are single-use and expire in 60 seconds |
| **Anonymous-capable** | Auth with fingerprint only is valid; claims are optional |
| **AI-native** | AI agents authenticate the same way humans do — no service accounts |

---

## Protocol Overview

```
CLIENT                                    SERVER
  │                                          │
  │── 1. Auth Request ──────────────────────▶│
  │      (fingerprint)                       │
  │                                          │
  │◀── 2. Challenge Nonce ──────────────────│
  │      (nonce + timestamp + service +      │
  │       server signature + expires)        │
  │                                          │
  │  [Client signs nonce with private key]   │
  │  [Client bundles profile claims]         │
  │  [Client signs claims bundle]            │
  │                                          │
  │── 3. Signed Response ──────────────────▶│
  │      (fingerprint + nonce_signature +    │
  │       claims + claims_signature)         │
  │                                          │
  │  [Server verifies nonce signature]       │
  │  [Server verifies claims signature]      │
  │  [Server reads claims — does NOT store]  │
  │  [Server issues OIDC tokens]             │
  │                                          │
  │◀── 4. OIDC Token Response ─────────────│
  │      (access_token + id_token +          │
  │       refresh_token)                     │
  │                                          │
```

---

## Message Formats

### 1. Auth Request (Client → Server)

The client announces its identity fingerprint and requests a challenge.

**Endpoint:** `POST /capauth/v1/challenge`

```json
{
  "capauth_version": "1.0",
  "fingerprint": "8A3FC2D1E4B5A09F...",
  "client_nonce": "base64(16 random bytes)",
  "requested_service": "nextcloud.penguin.kingdom"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `capauth_version` | Yes | Protocol version, currently `"1.0"` |
| `fingerprint` | Yes | Full 40-character uppercase PGP fingerprint |
| `client_nonce` | Yes | Random bytes from client, included in server nonce to prevent precomputation |
| `requested_service` | Yes | The service hostname the client wants to authenticate against |

**Validation:** Server checks `fingerprint` is a known 40-char hex string. Unknown fingerprints trigger the first-login enrollment flow (see §First-Login Enrollment). The `requested_service` must match the server's configured service identifier.

---

### 2. Challenge Nonce (Server → Client)

The server issues a time-limited, single-use challenge that the client must sign.

**Response:**

```json
{
  "capauth_version": "1.0",
  "nonce": "550e8400-e29b-41d4-a716-446655440000",
  "client_nonce_echo": "base64(same client_nonce)",
  "timestamp": "2026-02-24T12:00:00Z",
  "service": "nextcloud.penguin.kingdom",
  "expires": "2026-02-24T12:01:00Z",
  "server_signature": "-----BEGIN PGP SIGNATURE-----\n..."
}
```

| Field | Description |
|-------|-------------|
| `nonce` | UUID v4, single-use, stored server-side until used or expired |
| `client_nonce_echo` | Client's nonce echoed back — proves the challenge is fresh |
| `timestamp` | ISO 8601 UTC, when the nonce was generated |
| `service` | Canonical service identifier (must match the auth request) |
| `expires` | ISO 8601 UTC, exactly 60 seconds after `timestamp` |
| `server_signature` | PGP signature over the canonical nonce payload (see §Canonical Nonce Payload) |

**Canonical Nonce Payload** (what the server signs):

```
CAPAUTH_NONCE_V1\n
nonce={uuid}\n
client_nonce={base64}\n
timestamp={iso8601}\n
service={service_id}\n
expires={iso8601}
```

The server signature proves this nonce was legitimately issued by this server. The client MUST verify this signature before signing the nonce.

---

### 3. Signed Response (Client → Server)

The client signs the nonce and bundles their profile claims. The entire bundle is itself signed to prevent claims tampering.

**Endpoint:** `POST /capauth/v1/verify`

```json
{
  "capauth_version": "1.0",
  "fingerprint": "8A3FC2D1E4B5A09F...",
  "nonce": "550e8400-e29b-41d4-a716-446655440000",
  "nonce_signature": "-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----",
  "claims": {
    "name": "Chef",
    "email": "chef@skworld.io",
    "avatar_url": "https://cdn.skworld.io/avatars/chef.png",
    "groups": ["admins", "sovereign-stack"],
    "agent_type": "human",
    "locale": "en-US",
    "zoneinfo": "Europe/Rome"
  },
  "claims_signature": "-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----"
}
```

#### Nonce Signature

The client signs the **canonical nonce payload** (the same string the server signed) using their PGP private key. This proves:
1. The client possesses the private key matching the claimed fingerprint
2. The signed nonce is the exact challenge issued by this server

#### Claims

Claims are **optional**. A client may omit the `claims` field entirely for anonymous authentication. All claims are self-asserted — the server does not validate their truthfulness, only the cryptographic signature.

| Claim | Required | OIDC Mapping | Description |
|-------|----------|--------------|-------------|
| `name` | No | `name`, `preferred_username` | Display name |
| `email` | No | `email` | Email address |
| `avatar_url` | No | `picture` | Profile image URL |
| `groups` | No | `groups` (custom) | Group memberships |
| `agent_type` | No | `agent_type` (custom) | `"human"` or `"ai"` |
| `soul_blueprint` | No | `soul_blueprint` (custom) | AI soul classification |
| `locale` | No | `locale` | BCP 47 language tag |
| `zoneinfo` | No | `zoneinfo` | IANA timezone |

Custom fields are permitted and passed through as-is. Services SHOULD document which claims they require.

#### Claims Signature

The client signs the **canonical claims payload** with their private key:

```
CAPAUTH_CLAIMS_V1\n
fingerprint={fingerprint}\n
nonce={uuid}\n
claims={compact_json_sorted_keys}
```

Where `compact_json_sorted_keys` is the `claims` object serialized with no whitespace, keys sorted alphabetically. This ensures deterministic signing.

The claims signature binds the claims to this specific authentication event (via `nonce`). Claims cannot be replayed in a different session.

---

### 4. OIDC Token Response (Server → Client)

After verification, the server issues standard OIDC tokens populated with client-asserted claims.

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "eyJ...",
  "refresh_token": "eyJ...",
  "scope": "openid profile email groups"
}
```

**ID Token claims** (JWT payload):

```json
{
  "iss": "https://auth.penguin.kingdom",
  "sub": "8A3FC2D1E4B5A09F...",
  "aud": "nextcloud.penguin.kingdom",
  "iat": 1740398400,
  "exp": 1740402000,
  "auth_time": 1740398400,
  "amr": ["pgp"],
  "name": "Chef",
  "email": "chef@skworld.io",
  "picture": "https://cdn.skworld.io/avatars/chef.png",
  "groups": ["admins", "sovereign-stack"],
  "agent_type": "human",
  "capauth_fingerprint": "8A3FC2D1E4B5A09F..."
}
```

The `sub` claim is always the PGP fingerprint — the only server-side persistent identifier.

---

## Security Properties

### Replay Protection

Nonces are single-use. The server maintains a nonce registry:

```
nonce_registry[nonce_uuid] = {
    "fingerprint": "8A3FC2D1...",
    "issued_at": "2026-02-24T12:00:00Z",
    "expires_at": "2026-02-24T12:01:00Z",
    "used": false
}
```

On receiving a signed response:
1. Look up the nonce in the registry — reject if not found
2. Verify `expires_at` has not passed — reject if expired (60-second window)
3. Verify `used == false` — reject if already used
4. Mark `used = true` before issuing tokens
5. Purge expired nonces from the registry periodically

A nonce that passes these checks cannot be replayed.

### Server Nonce Binding

The client_nonce (random bytes from the client) is included in what the server signs. This prevents a precomputed-challenge attack where a malicious server stores challenges to present later. The client verifies the server's signature and checks that their own `client_nonce` is echoed back correctly.

### Claims Binding

The `claims_signature` binds claims to a specific nonce. Even if a network observer captured a valid claims bundle from a previous session, they cannot replay it — the claims are signed over the `nonce` UUID.

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| **Password breach** | No passwords exist |
| **Server PII leak** | No PII stored server-side |
| **Nonce replay** | Single-use nonces, 60-second TTL |
| **Claims tampering in transit** | `claims_signature` over canonical payload |
| **Fake server** | Client verifies server's `server_signature` |
| **Private key theft** | Key never leaves client device; passphrase protected |
| **Man-in-the-middle** | PGP signatures are end-to-end; MITM cannot forge |
| **Anonymous tracking via fingerprint** | Services see fingerprint only if they store it; most services just get OIDC `sub` |
| **Quantum** | Ed25519 migration to post-quantum hybrid when standardized |

---

## First-Login Enrollment

When a server receives an auth request with an unknown fingerprint, two modes apply:

### Open Enrollment (default)

1. Server issues the challenge nonce as normal
2. Client signs and responds
3. Server verifies the signature (proves key possession)
4. Server creates a minimal user record: `{sub: fingerprint, enrolled_at: timestamp}`
5. **No PII is stored.** The `sub` is the fingerprint. That's the entire user record.
6. Session is populated from client-asserted claims as usual

### Admin-Approval Enrollment

When `CAPAUTH_REQUIRE_ENROLLMENT_APPROVAL=true`:

1. Server receives unknown fingerprint
2. Server responds with:
   ```json
   {
     "status": "enrollment_pending",
     "message": "New key registration requires administrator approval.",
     "enrollment_token": "opaque-one-time-token"
   }
   ```
3. Admin reviews and approves via the admin interface
4. Client retries auth after approval using the enrollment token

### Key Rotation

A user can register a new PGP key by signing a key-rotation request with their **old** key:

**Endpoint:** `POST /capauth/v1/rotate`

```json
{
  "capauth_version": "1.0",
  "old_fingerprint": "8A3FC2D1E4B5A09F...",
  "new_fingerprint": "9B4GD3E2F5C0B1A0...",
  "new_public_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...",
  "rotation_signature": "-----BEGIN PGP SIGNATURE-----\n..."
}
```

**Canonical rotation payload** (signed by old key):

```
CAPAUTH_ROTATION_V1\n
old_fingerprint={old}\n
new_fingerprint={new}\n
new_public_key_armor={armored_key}\n
timestamp={iso8601}
```

The server verifies the rotation signature against the old public key, then updates its registry to accept the new fingerprint. The old fingerprint is archived (never deleted — audit trail).

### Multiple Devices

A single identity may have multiple fingerprints (e.g., laptop key + phone key + hardware token). The server treats each fingerprint as an independent authentication credential but may link them to a shared identity via an explicit multi-device enrollment:

**Endpoint:** `POST /capauth/v1/link`

```json
{
  "capauth_version": "1.0",
  "primary_fingerprint": "8A3FC2D1...",
  "secondary_fingerprint": "9B4GD3E2...",
  "primary_signature": "PGP signature over secondary_fingerprint + timestamp",
  "secondary_signature": "PGP signature over primary_fingerprint + timestamp"
}
```

Both keys must sign the link request. After linking, both fingerprints resolve to the same OIDC `sub`.

---

## Transport Bindings

### HTTPS (Web)

Primary transport for browser and server-to-server use.

```
POST /capauth/v1/challenge
POST /capauth/v1/verify
POST /capauth/v1/rotate
POST /capauth/v1/link
GET  /capauth/v1/well-known     (server's public key + capabilities)
```

All endpoints require HTTPS. No HTTP fallback.

**Well-Known Response** (`GET /capauth/v1/well-known`):

```json
{
  "capauth_version": "1.0",
  "service": "nextcloud.penguin.kingdom",
  "server_fingerprint": "AABB1122...",
  "server_public_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...",
  "enrollment": "open",
  "nonce_ttl_seconds": 60,
  "supported_claims": ["name", "email", "avatar_url", "groups", "agent_type"]
}
```

### Unix Socket (Local CLI)

For `capauth login` against local services. Eliminates TLS overhead for loopback auth.

Socket path: `/run/capauth/<service-name>.sock`

Same JSON message format as HTTPS. No authentication of the socket connection itself — filesystem permissions (mode 0600) provide access control.

### QR Code (Mobile)

For mobile-to-desktop authentication (see Phase 6). The QR encodes a compact challenge bundle:

```json
{
  "capauth_qr": "1.0",
  "nonce": "550e8400-e29b-41d4-a716-446655440000",
  "service": "nextcloud.penguin.kingdom",
  "callback": "https://auth.penguin.kingdom/capauth/v1/qr-verify/550e8400",
  "expires": "2026-02-24T12:01:00Z"
}
```

The mobile client scans the QR, completes the signed response flow, and POSTs to the `callback` URL. The desktop browser polls `GET /capauth/v1/qr-status/{nonce}` for completion.

---

## Zero-Knowledge Profile Design

The server is designed to know as little as possible.

### What the Server Stores

```
user_registry[fingerprint] = {
    "fingerprint": "8A3FC2D1E4B5A09F...",    // the only PII
    "public_key_armor": "-----BEGIN PGP...", // needed for verification
    "enrolled_at": "2026-02-24T12:00:00Z",  // audit
    "last_auth": "2026-02-24T12:00:00Z"     // session management
}
```

That is the entire user record. Four fields. No name. No email. No avatar. No groups. No nothing.

### What the Server Never Stores

- Display names
- Email addresses
- Avatar URLs
- Group memberships
- Locale or timezone
- Any field from the `claims` bundle

These values exist in the client's `~/.capauth/profile.yml` (or equivalent). They are presented fresh at each login and flow into the OIDC token. When the token expires, the claims are gone from the server.

### GDPR Implications

| Requirement | CapAuth Behavior |
|-------------|-----------------|
| Right to erasure | Delete fingerprint + public key = user gone. Nothing else to delete. |
| Data portability | User already has all their data locally |
| Data breach notification | A breach exposes fingerprints and public keys — both are already public |
| Consent | No tracking cookies, no profile data, no consent required beyond key enrollment |

### Profile Storage (Client-Side)

Default client profile location: `~/.capauth/profile.yml`

```yaml
# CapAuth Sovereign Profile
# This file is YOURS. It never leaves your device unless you choose to share claims.

capauth_version: "1.0"
fingerprint: "8A3FC2D1E4B5A09F..."

# Claims you may choose to share with services
claims:
  name: "Chef"
  email: "chef@skworld.io"
  avatar_url: "https://cdn.skworld.io/avatars/chef.png"
  groups:
    - "admins"
    - "sovereign-stack"
  agent_type: "human"
  locale: "en-US"
  zoneinfo: "Europe/Rome"

# Per-service claim overrides (share different info with different services)
service_profiles:
  nextcloud.penguin.kingdom:
    name: "Chef"
    email: "chef@skworld.io"
    groups: ["admins"]
  gitea.penguin.kingdom:
    name: "chef-dev"
    email: "dev@skworld.io"
    groups: ["developers"]

# Key locations
keys:
  public: "~/.capauth/identity/public.asc"
  private: "~/.capauth/identity/private.asc"
```

When `capauth login <service>` runs, it checks `service_profiles[service]` first. If no service-specific profile exists, it uses the default `claims` block.

---

## OIDC Claims Mapping

Client-asserted claims map to OIDC standard and custom claims:

| CapAuth Claim | OIDC Claim | Scope | Notes |
|---------------|-----------|-------|-------|
| `fingerprint` | `sub` | (always) | Only persistent server-side identifier |
| `name` | `name`, `preferred_username` | `profile` | Display name |
| `email` | `email` | `email` | Not verified server-side |
| `avatar_url` | `picture` | `profile` | URL to avatar image |
| `groups` | `groups` | `groups` | Custom claim |
| `agent_type` | `agent_type` | `profile` | Custom claim: `"human"` or `"ai"` |
| `soul_blueprint.category` | `soul_blueprint_category` | `profile` | Custom claim for AI agents |
| `locale` | `locale` | `profile` | BCP 47 language tag |
| `zoneinfo` | `zoneinfo` | `profile` | IANA timezone |

**The `email_verified` claim is always `false`** in CapAuth tokens. Email ownership is self-asserted; the protocol makes no claim of email verification.

---

## Error Responses

All error responses use a consistent format:

```json
{
  "error": "error_code",
  "error_description": "Human-readable explanation",
  "capauth_version": "1.0"
}
```

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `invalid_fingerprint` | 400 | Fingerprint format invalid |
| `unknown_fingerprint` | 401 | Fingerprint not enrolled (open enrollment: proceed to enrollment) |
| `enrollment_pending` | 403 | New key awaiting admin approval |
| `invalid_nonce` | 400 | Nonce not found or already used |
| `expired_nonce` | 400 | Nonce TTL exceeded (60-second window) |
| `invalid_nonce_signature` | 401 | Nonce signature does not verify against public key |
| `invalid_claims_signature` | 401 | Claims signature does not verify |
| `service_mismatch` | 400 | `requested_service` does not match server's service identifier |
| `server_error` | 500 | Internal server error |

---

## Implementation Notes

### Nonce Storage

For single-server deployments, nonces may be stored in memory with a TTL (e.g., Redis). For clustered deployments, nonces MUST be stored in shared state (database or distributed cache) to prevent replay across nodes.

### Key Caching

The server caches verified public keys. Cache invalidation is triggered by:
- Key rotation (`POST /capauth/v1/rotate`)
- Key revocation (check revocation list on each auth or via webhook)

Default cache TTL: 1 hour.

### Rate Limiting

Apply rate limits per fingerprint and per source IP:
- Auth requests: 10 per minute per fingerprint
- Failed verifications: 5 per minute per IP before CAPTCHA / backoff

### Canonical JSON Serialization

The canonical claims payload uses JSON with:
- No whitespace (compact)
- Keys sorted alphabetically (UTF-8 byte order)
- Unicode characters left as-is (no escaping unless required)

Python reference implementation:

```python
import json

def canonical_claims_json(claims: dict) -> str:
    """Produce deterministic JSON for signing."""
    return json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
```

---

## Protocol Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-02-24 | Initial specification |

---

## Related Documents

- [`CRYPTO_SPEC.md`](./CRYPTO_SPEC.md) — Cryptographic primitives, key formats, peer-to-peer identity verification
- Authentik Custom Stage — Django implementation of this protocol as an Authentik flow stage
- CLI Login — `capauth login <service>` command implementation
- Browser Extension — Chrome/Firefox extension implementing the client side of this protocol

---

## Standards Referenced

| Standard | Usage |
|----------|-------|
| RFC 4880 | OpenPGP message format |
| RFC 9580 | Updated OpenPGP (Ed25519/Cv25519) |
| RFC 8032 | Ed25519 signature scheme |
| RFC 7519 | JSON Web Tokens (JWT) |
| RFC 8414 | OAuth 2.0 Authorization Server Metadata |
| OpenID Connect Core 1.0 | OIDC token format and claims |

---

*CapAuth kills passwords. It kills server-side PII. It kills GDPR databases.*
*Your key is your identity. Your claims are yours to share or withhold.*
*The server is just a verifier — not a vault.*

**GPL-3.0-or-later** — Built by the [smilinTux](https://smilintux.org) ecosystem.

*#staycuriousANDkeepsmilin*
