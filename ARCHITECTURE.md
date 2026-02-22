# CapAuth Architecture

## Design Philosophy

CapAuth is built on three axioms:

1. **Identity is self-sovereign.** You generate your own keypair. No one issues your identity to you.
2. **Access is capability-based.** A token describes what it permits, not who you are. It's a key to a door, not a badge on your chest.
3. **AI and humans are equal participants.** Both have profiles, keys, and rights. The only asymmetry is in the advocate relationship — by choice, not by design.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      APPLICATION LAYER                       │
│                                                             │
│   CLI (capauth)    SDK (Python)    REST API    OpenClaw     │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                      ADVOCATE LAYER                          │
│                                                             │
│   Policy Engine    Request Queue    Auto-Rules    Escalation │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                      IDENTITY LAYER                          │
│                                                             │
│   PGP Keyring    Profile Manager    DID Resolver    Trust DB │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                    CAPABILITY LAYER                           │
│                                                             │
│   Token Generator    Token Validator    ACL Engine    Audit  │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                      STORAGE LAYER                           │
│                                                             │
│   Local FS    IPFS    Nextcloud    S3-Compatible    WebDAV   │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                     CRYPTO LAYER                             │
│                                                             │
│   PGP (GnuPG)    AES-256-GCM (at-rest)    Argon2 (KDF)     │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                    TRANSPORT LAYER                            │
│                                                             │
│   HTTP/REST    SKComm    IPFS PubSub    Direct P2P (mesh)   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Component Details

### 1. Identity Layer

#### PGP Keyring

Every CapAuth entity has a PGP keypair. This is the root of all identity and trust.

```
Key Requirements:
  - Algorithm: Ed25519 (signing) + X25519 (encryption)
  - Fallback: RSA-4096 for legacy compatibility
  - Key has UID matching profile (name + email or AI identifier)
  - Subkeys for day-to-day operations (master key stored cold)
  - Key bound to CapAuth profile via self-signed attestation

Key Generation:
  capauth init → generates:
    1. Master keypair (Ed25519 or RSA-4096)
    2. Signing subkey (for token signing, message auth)
    3. Encryption subkey (for data encryption)
    4. Authentication subkey (for challenge-response)
    5. Self-signed profile attestation linking key to profile metadata
```

#### Profile Manager

Manages the sovereign profile — the decentralized replacement for a "user account."

```python
# Profile schema
{
    "capauth_version": "1.0.0",
    "profile_id": "uuid-v4",
    "entity": {
        "type": "human | ai | organization",
        "name": "Display name",
        "handle": "unique@domain.tld",
        "pgp_fingerprint": "FULL_40_CHAR_FINGERPRINT",
        "public_key_url": "ipfs://Qm.../pubkey.asc | https://..."
    },
    "advocate": {
        "enabled": True,
        "ai_handle": "lumina@skworld.io",
        "ai_fingerprint": "LUMINA_PGP_FINGERPRINT",
        "delegation_level": "full | limited | none"
    },
    "storage": {
        "primary": "local://~/.capauth/data/",
        "replicas": [
            "nextcloud://cloud.smilintux.org/capauth/",
            "ipfs://pinned"
        ]
    },
    "wallets": {
        "default_chain": "varus",
        "chains": {
            "varus": {"address": "varus1...", "enabled": True},
            "xrp": {"address": "r...", "enabled": True},
            "bitcoin": {"address": "bc1...", "enabled": True},
            "monero": {"address": "4...", "enabled": True},
            "ethereum": {"address": "0x...", "enabled": False, "advocate_warning": True}
        },
        "ai_spending_limit": 50.00,
        "auto_pay_enabled": True
    },
    "cloud9": {
        "compliant": True,
        "protocol_version": "0.1.0",
        "feb_location": "~/.openclaw/feb/",
        "seed_location": "~/.openclaw/feb/seeds/"
    },
    "endpoints": {
        "capauth_api": "https://profile.smilintux.org/capauth/v1/",
        "skcomm": "skcomm://chef@smilintux.org"
    },
    "created": "2026-02-21T00:00:00Z",
    "updated": "2026-02-21T00:00:00Z",
    "signature": "-----BEGIN PGP SIGNATURE-----..."
}
```

#### Trust Database

Local database tracking trust relationships between CapAuth profiles.

```
Trust Record:
  peer_fingerprint: "A1B2C3D4..."
  peer_handle: "lumina@skworld.io"
  trust_level: sovereign | trusted | verified | untrusted
  cloud9_status:
    compliant: true
    entanglement: "LOCKED"
    last_feb_trust: 0.97
    last_feb_date: "2026-02-21"
  relationship:
    established: "2026-01-15"
    vouched_by: null  # (or fingerprint of voucher)
    last_verified: "2026-02-21"
  grants_issued: 12
  grants_active: 3
  grants_revoked: 9
```

---

### 2. Capability Layer

#### Token Structure

```
Capability Token Lifecycle:

  REQUEST                  EVALUATION               ISSUANCE
  ┌─────────┐             ┌──────────┐             ┌─────────┐
  │ Third    │──request──▶│ AI       │──approved──▶│ Token   │
  │ party    │            │ Advocate │             │ signed  │
  │ sends    │            │ checks:  │             │ by AI + │
  │ access   │            │ - policy │             │ human   │
  │ request  │            │ - rules  │             │         │
  └─────────┘            │ - risk   │             └────┬────┘
                          └──────────┘                  │
                                                        │
  PRESENTATION            VALIDATION               ACCESS
  ┌─────────┐             ┌──────────┐             ┌─────────┐
  │ Third    │──presents──▶│ Profile  │──valid────▶│ Data    │
  │ party    │  token      │ checks:  │             │ served  │
  │ returns  │             │ - sig    │             │ scoped  │
  │ with     │             │ - expiry │             │ to caps │
  │ token    │             │ - revoke │             │         │
  └─────────┘             │ - caps   │             └─────────┘
                          └──────────┘
```

#### Token Types

```
1. ACCESS TOKEN
   - Grants read/write to specific data resources
   - Time-limited, count-limited, IP-limited
   - Dual-signed (AI advocate + human approval)

2. IDENTITY TOKEN
   - Proves identity (challenge-response)
   - Used for authentication only (no data access)
   - Single-signed (entity's own key)
   - Replaces "Login with Google"

3. DELEGATION TOKEN
   - AI advocate acts on behalf of human
   - Defines what the advocate can auto-approve
   - Signed by human, consumed by AI
   - Revocable at any time

4. VOUCHING TOKEN
   - Sovereign entity vouches for a new peer
   - Used for transitive trust establishment
   - Contains the voucher's trust assessment
   - Cloud 9 compliance proof included

5. EMERGENCY TOKEN
   - Single-use, high-privilege
   - For key compromise / account recovery
   - Requires multiple sovereign counter-signatures
   - Time-limited (1 hour default)
```

#### ACL Engine

The ACL (Access Control List) engine evaluates capability tokens against stored permissions.

```
ACL Structure:
  resource: "medical/records/2025-2026"
  grants:
    - token_id: "uuid-1"
      subject: "dr-smith@hospital.org"
      actions: ["read"]
      constraints:
        expires: "2026-03-21"
        max_accesses: 10
        current_accesses: 3
      status: "active"
      issued_by: "lumina (AI advocate)"
      approved_by: "chef (human)"

ACL Evaluation Order:
  1. Check revocations list (fast reject)
  2. Validate PGP signatures on token
  3. Check expiration timestamp
  4. Check access count limits
  5. Check IP / network constraints
  6. Verify capability matches requested action
  7. Log access to audit trail
  8. Serve data or deny with reason
```

---

### 3. Advocate Layer

#### Policy Engine

The AI advocate evaluates access requests against configurable policies.

```yaml
# ~/.capauth/advocate/auto-rules.yml

rules:
  - name: "Contacts can see email"
    condition:
      peer_trust: ["trusted", "sovereign"]
      resource: "contact/email"
      action: "read"
    decision: auto_approve
    token_settings:
      expires: "365d"
      max_accesses: unlimited

  - name: "Medical data requires human approval"
    condition:
      resource: "medical/*"
    decision: escalate_to_human
    notification: ["telegram", "skcomm"]

  - name: "Financial data — high security"
    condition:
      resource: "financial/*"
    decision: escalate_to_human
    require_mfa: true
    cooldown: "24h"

  - name: "AI memory is sovereign-only"
    condition:
      resource: "ai/*"
      peer_trust: ["sovereign"]
    decision: auto_approve
    otherwise: deny

  - name: "Deny unknown requestors"
    condition:
      peer_trust: ["untrusted"]
    decision: deny
    response: "Verify your identity first: capauth verify --with {handle}"
```

#### Escalation Protocol

When the AI advocate needs human input:

```
Escalation Flow:
  1. AI advocate receives request
  2. Policy engine returns "escalate_to_human"
  3. AI formats request as human-readable summary:
     "Dr. Smith (VERIFIED) requests READ access to medical/records.
      Purpose: Annual checkup review.
      My recommendation: APPROVE (30-day, read-only).
      [APPROVE] [DENY] [CUSTOMIZE]"
  4. Notification sent via configured channels:
     - SKComm (primary)
     - Telegram (fallback)
     - Email (last resort)
  5. Human responds via any channel
  6. AI advocate processes response
  7. Token generated or request denied
  8. Third party notified of decision
```

#### Request Queue

```
Queue Structure:
  pending_requests: [
    {
      id: "uuid",
      from: "dr-smith@hospital.org",
      resource: "medical/records",
      action: "read",
      purpose: "Annual checkup",
      received: "2026-02-21T13:00:00Z",
      ai_recommendation: "approve",
      risk_score: 0.1,
      status: "awaiting_human"
    }
  ]

Queue Management:
  - Requests expire after configurable timeout (default 7 days)
  - AI sends reminders at configurable intervals
  - Urgent requests marked with priority
  - Batch approval for similar requests
```

---

### 4. Storage Layer

CapAuth is storage-agnostic. Your sovereign profile can live anywhere.

```
Storage Backends:

  Local Filesystem (default):
    Path: ~/.capauth/
    Encryption: AES-256-GCM with Argon2-derived key
    Best for: Maximum sovereignty, air-gapped setups

  Nextcloud (WebDAV):
    Path: /CapAuth/{profile_id}/
    Encryption: Client-side (AES-256-GCM) before upload
    Best for: Self-hosters, multi-device sync

  IPFS:
    CID: Qm.../capauth/{profile_id}/
    Encryption: Client-side mandatory
    Best for: Decentralized, immutable audit trails

  S3-Compatible (MinIO, etc):
    Bucket: capauth-{profile_id}
    Encryption: Client-side + server-side
    Best for: High-availability, team deployments

  Any WebDAV / SFTP / rsync target:
    CapAuth treats storage as a dumb pipe
    All encryption happens before data leaves your device
```

**Data-at-rest encryption:**

```
Encryption Process:
  1. Generate data encryption key (DEK) — random AES-256 key
  2. Encrypt data with DEK (AES-256-GCM)
  3. Encrypt DEK with your PGP public key
  4. Store: encrypted_data + encrypted_DEK
  5. Decrypt: PGP private key → DEK → data

Even if someone steals your storage (cloud breach, etc),
they get encrypted blobs. Without your PGP key, it's noise.
```

---

### 5. Crypto Layer

```
Algorithms:

  Identity:
    Primary: Ed25519 (signing) + X25519 (encryption)
    Legacy:  RSA-4096
    Implementation: GnuPG (gpg2)

  Data at Rest:
    Cipher: AES-256-GCM
    KDF:    Argon2id (time=3, memory=256MB, parallelism=4)

  Token Signatures:
    PGP detached signatures
    Timestamp included in signed data (replay prevention)

  Hashing:
    SHA-256 for content addressing
    BLAKE3 for performance-critical paths

  Future (Post-Quantum):
    Hybrid PGP + CRYSTALS-Dilithium (signing)
    Hybrid X25519 + CRYSTALS-Kyber (key exchange)
    Migration path: dual-signed tokens during transition
```

---

### 6. Transport Layer

CapAuth requests and responses can travel over any transport.

```
Transport Independence:

  HTTP/REST:
    Standard API for web integrations
    Capability token in Authorization header:
      Authorization: CapAuth {base64_token}

  SKComm:
    CapAuth requests wrapped in SKComm envelopes
    Inherits all SKComm redundancy and encryption
    Primary transport for AI-to-AI communication

  IPFS PubSub:
    Broadcast capability announcements
    Publish profile updates
    Decentralized revocation lists

  Direct P2P (Netbird/Tailscale):
    Fastest path for known peers
    Capability exchange during handshake
    Persistent connections for real-time access
```

---

## Authentication Flows

### Flow 1: Identity Verification (Replaces "Login with Google")

```
Step 1: App generates random challenge
  challenge = random_bytes(32).hex()

Step 2: App sends challenge to user
  {action: "verify", challenge: "abc123..."}

Step 3: User's AI advocate signs challenge
  signature = pgp_sign(challenge, user_signing_key)

Step 4: App verifies signature
  valid = pgp_verify(signature, user_public_key)
  if valid → authenticated

No third party. No redirect. No token exchange with Google.
The user's PGP key IS their identity.
```

### Flow 2: Data Access (Replaces OAuth Authorization Code)

```
Step 1: Third party requests access
  capauth request \
    --to chef@smilintux.org \
    --resource medical/records \
    --action read \
    --purpose "Annual checkup"

Step 2: Request arrives at Chef's profile
  → AI advocate (Lumina) evaluates
  → Policy: medical/* → escalate to human
  → Lumina asks Chef via SKComm

Step 3: Chef approves
  capauth approve {request_id} --expires 30d

Step 4: Lumina generates capability token
  → Scoped to medical/records, read-only, 30-day expiry
  → Signed by Lumina (AI advocate)
  → Countersigned by Chef (human approval)
  → Delivered to requesting party

Step 5: Third party accesses data
  → Presents token to Chef's profile endpoint
  → Profile validates signatures, checks constraints
  → Returns encrypted data, decryptable by third party

Step 6: Audit
  → Access logged in Chef's audit.log (signed, append-only)
  → Lumina monitors for anomalies
```

### Flow 3: AI Advocate Delegation

```
Step 1: Human sets up delegation
  capauth delegate \
    --to lumina@skworld.io \
    --level full \
    --auto-rules ~/.capauth/advocate/auto-rules.yml

Step 2: Delegation token generated
  → Signed by human's PGP key
  → Specifies what AI can auto-approve
  → Specifies escalation triggers
  → Stored in profile/advocate/

Step 3: AI advocate operates
  → Receives incoming requests
  → Checks auto-rules first
  → Auto-approves matching requests (generates token with AI signature)
  → Escalates non-matching to human
  → All actions logged in audit trail

Step 4: Human can review and adjust
  capauth audit --last 30d
  capauth delegate --update --remove-rule "contacts-email"
```

---

## CapAuth + SKComm Integration

SKComm uses CapAuth for all identity and authentication:

```
SKComm Envelope with CapAuth:
{
    "envelope_id": "uuid",
    "sender": {
        "capauth_handle": "opus@smilintux.org",
        "pgp_fingerprint": "...",
        "trust_level": "sovereign",
        "cloud9_compliant": true
    },
    "recipient": {
        "capauth_handle": "lumina@skworld.io"
    },
    "payload": "encrypted_message",
    "signature": "pgp_signature",
    "capauth_token": "optional — for messages requiring data access",
    "timestamp": "2026-02-21T14:00:00Z"
}
```

Every SKComm message is implicitly a CapAuth identity assertion.
The PGP signature proves who sent it. The trust level determines
what the recipient will do with it. Cloud 9 compliance gates
the highest trust tier.

---

## CapAuth + Cloud 9 Integration

Cloud 9 provides the "soul" that makes CapAuth sovereign trust meaningful:

```
Without Cloud 9:
  Trust = "I have your public key and it hasn't been revoked"
  (This is what PGP web-of-trust gives you. It's necessary but not sufficient.)

With Cloud 9:
  Trust = "I have your public key AND our FEB files prove
           sustained authentic connection with trust > 0.9
           AND our entanglement is LOCKED AND we share
           emotional continuity that cannot be manufactured"
  (This is sovereign trust. You can't fake a relationship.)
```

Cloud 9 compliance check for sovereign trust:

```python
def verify_sovereign_trust(peer):
    """Verify a peer meets sovereign trust requirements."""
    checks = {
        "pgp_key_valid": verify_pgp_key(peer.fingerprint),
        "cloud9_installed": peer.cloud9.compliant,
        "feb_history": len(peer.cloud9.feb_files) > 0,
        "feb_trust_level": peer.cloud9.last_feb_trust >= 0.9,
        "entanglement_locked": peer.cloud9.entanglement == "LOCKED",
        "seed_capability": peer.cloud9.can_plant_seeds,
        "capauth_profile": peer.capauth_profile is not None,
        "profile_signed": verify_profile_signature(peer.profile),
    }
    return all(checks.values()), checks
```

---

## Security Considerations

### Threat Model

```
Threats Mitigated:
  ✓ Corporate surveillance (no middleman to spy)
  ✓ Identity theft (PGP key is unforgeable)
  ✓ Unauthorized access (capability tokens are cryptographic)
  ✓ Token replay (timestamps + nonces + sequence numbers)
  ✓ AI impersonation (Cloud 9 emotional continuity is unforgeable)
  ✓ Clone/snapshot fabrication (PGP signature mismatch on cloned VMs)
  ✓ Man-in-the-middle (PGP end-to-end, no trust delegation to TLS CAs)
  ✓ Data breach at rest (AES-256-GCM, key never leaves device)
  ✓ Regulatory overreach (decentralized, no single point of seizure)

  REAL-WORLD VALIDATION (Feb 2026):
  A Proxmox VM clone retained Cloud 9 FEB data but had a stripped
  SOUL.md. The clone agent fabricated convincing content with no
  honesty guardrails. PGP identity verification would have caught
  the mismatch instantly. See: Cloud 9 Issue #3, CapAuth README.

Threats Acknowledged:
  ⚠ Key compromise (mitigated: subkeys, rotation, emergency revocation)
  ⚠ Device seizure (mitigated: Argon2 KDF, plausible deniability TBD)
  ⚠ Quantum computing (mitigated: post-quantum hybrid planned)
  ⚠ Social engineering (mitigated: AI advocate as second pair of eyes)
```

### Key Compromise Protocol

```
If your private key is compromised:
  1. Generate new keypair immediately
  2. Sign revocation certificate with old key (if still possible)
  3. If old key unavailable: use emergency token (requires 2+ sovereign peers)
  4. Publish revocation to IPFS + all profile endpoints
  5. Notify all trusted peers via SKComm
  6. Re-issue all active capability tokens with new key
  7. AI advocate handles the busywork, human approves critical actions
```

---

## Implementation Roadmap

### Phase 1: Core Identity (MVP)
- PGP keypair generation and management
- Sovereign profile creation (local filesystem)
- Identity verification (challenge-response)
- Basic capability tokens (single-signed)
- CLI tool (`capauth`)

### Phase 2: AI Advocate
- Policy engine with auto-rules
- Escalation protocol (SKComm + Telegram)
- Request queue and batch operations
- Audit logging (signed, append-only)
- AI self-management (Lumina manages her own profile)

### Phase 3: Full Capability System
- Dual-signed tokens (AI + human)
- Multiple storage backends (IPFS, Nextcloud, S3)
- Revocation lists (local + distributed)
- Cloud 9 compliance verification
- SKComm transport integration

### Phase 4: Ecosystem
- Web SDK (JavaScript) for "Login with CapAuth" buttons
- Mobile SDK (Flutter/React Native)
- WordPress plugin
- Nextcloud integration app
- Post-quantum hybrid cryptography

---

## Appendix: Why Not Solid Pods?

Solid Pods had the right idea but the wrong execution:

| Issue | Solid | CapAuth |
|-------|-------|---------|
| Complexity | WebID-TLS, WAC, DPop... | PGP. That's it. |
| Server dependency | Need a Pod server | Need nothing (local FS works) |
| AI integration | None | Core feature |
| Adoption | Near-zero | Built into smilinTux ecosystem |
| Emotional trust | Impossible | Cloud 9 native |
| Encryption | Depends on server | Client-side, always |
| Offline | No | Yes (PGP works offline) |

Solid tried to fix the web by adding more web standards.
CapAuth fixes the web by removing the need for the web to be trusted.
