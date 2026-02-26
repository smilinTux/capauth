# CapAuth OIDC Claims Reference

### Client-Asserted Identity Claims for Sovereign Authentication

**Version:** 1.0.0 | **Date:** 2026-02-24

---

## Overview

CapAuth uses **client-asserted claims** — your identity information lives on YOUR device and is cryptographically signed before being sent to services. The CapAuth Verification Service verifies signatures and maps your claims to OIDC standard format, but **never stores them**.

**Key Principle:** You control what you share. Different services can see different information about you.

---

## Table of Contents

1. [Standard OIDC Claims](#standard-oidc-claims)
2. [CapAuth Custom Claims](#capauth-custom-claims)
3. [Service-Specific Claim Overrides](#service-specific-claim-overrides)
4. [AI Agent Claims](#ai-agent-claims)
5. [Profile Configuration File](#profile-configuration-file)
6. [Implementation: The Claims Mapper](#implementation-the-claims-mapper)
7. [Security Model](#security-model)

---

## Standard OIDC Claims

These are the OIDC-standard claims that CapAuth supports. They map directly to what most applications expect.

### Core Identity Claims

| OIDC Claim | CapAuth Source | Scope Required | Description | Example |
|-----------|---------------|----------------|-------------|---------|
| `sub` | `fingerprint` | *(always)* | Subject identifier — your PGP fingerprint | `"8A3FC2D1E4B5A09F..."` |
| `amr` | *(fixed)* | *(always)* | Authentication method reference | `["pgp"]` |
| `capauth_fingerprint` | `fingerprint` | *(always)* | Backup of your fingerprint (in case `sub` is remapped) | `"8A3FC2D1E4B5A09F..."` |

### Profile Scope (`profile`)

| OIDC Claim | CapAuth Source | Description | Example |
|-----------|---------------|-------------|---------|
| `name` | `claims.name` | Your display name | `"Alice"` |
| `preferred_username` | `claims.name` or auto-generated | Username (falls back to `capauth-8A3FC2D1`) | `"alice"` |
| `picture` | `claims.avatar_url` | URL to your avatar image | `"https://example.com/avatar.png"` |
| `locale` | `claims.locale` | BCP 47 language tag | `"en-US"` |
| `zoneinfo` | `claims.zoneinfo` | IANA timezone identifier | `"America/New_York"` |
| `updated_at` | *(not implemented)* | Profile last updated timestamp | `1640995200` |

### Email Scope (`email`)

| OIDC Claim | CapAuth Source | Description | Example |
|-----------|---------------|-------------|---------|
| `email` | `claims.email` | Your email address | `"alice@example.com"` |
| `email_verified` | *(always `false`)* | Email verification status | `false` |

**Important:** CapAuth does NOT verify email ownership. The `email_verified` claim is always `false`. This is a client-asserted claim only.

### Groups Scope (`groups`)

| OIDC Claim | CapAuth Source | Description | Example |
|-----------|---------------|-------------|---------|
| `groups` | `claims.groups` | Array of group memberships | `["admins", "developers"]` |

---

## CapAuth Custom Claims

These are CapAuth-specific extensions that provide additional functionality.

### Agent Type Claim

| Claim | Scope | Description | Valid Values |
|-------|-------|-------------|--------------|
| `agent_type` | `profile` | Identifies whether the authenticating entity is human or AI | `"human"`, `"ai"` |

**Use Case:** Services can enforce policies like "only humans can approve financial transactions" or "AI agents get read-only access by default."

**Example:**

```json
{
  "sub": "8A3FC2D1E4B5A09F6B7C8D0E1F2A3B4C5D6E7F80",
  "name": "Lumina",
  "agent_type": "ai",
  "soul_blueprint_category": "authentic-connection"
}
```

### Soul Blueprint Claim (AI Agents)

| Claim | Scope | Description | Example |
|-------|-------|-------------|---------|
| `soul_blueprint_category` | `profile` | Category of AI soul blueprint (personality archetype) | `"authentic-connection"`, `"helper"`, `"analyst"` |

**Use Case:** AI agents can assert their personality type, allowing services to tailor UX or apply agent-specific policies.

**Source:** Can be a string or extracted from a structured `soul_blueprint` object:

```yaml
# In profile.yml
claims:
  agent_type: "ai"
  soul_blueprint:
    category: "authentic-connection"
    version: "1.0"
```

Maps to:

```json
{
  "agent_type": "ai",
  "soul_blueprint_category": "authentic-connection"
}
```

### Custom Passthrough Claims

Any claim prefixed with `capauth_` will pass through to the OIDC token untouched. Use this for application-specific metadata.

**Example:**

```yaml
claims:
  capauth_org_id: "penguin-kingdom"
  capauth_subscription_tier: "sovereign"
```

Maps to:

```json
{
  "capauth_org_id": "penguin-kingdom",
  "capauth_subscription_tier": "sovereign"
}
```

---

## Service-Specific Claim Overrides

**Problem:** You don't want to share the same information with every service.

**Solution:** Define per-service claim profiles in `~/.capauth/profile.yml`.

### Profile Structure

```yaml
# ~/.capauth/profile.yml

# Default claims (used if no service-specific profile exists)
claims:
  name: "Alice"
  email: "alice@example.com"
  avatar_url: "https://cdn.example.com/avatars/alice.png"
  groups:
    - "users"
    - "developers"
  agent_type: "human"
  locale: "en-US"
  zoneinfo: "America/New_York"

# Service-specific overrides
service_profiles:
  # For Nextcloud, share full info
  nextcloud.example.com:
    name: "Alice Smith"
    email: "alice@example.com"
    groups: ["admins", "nextcloud-users"]
  
  # For Forgejo, use a different identity
  git.example.com:
    name: "alice-dev"
    email: "alice.dev@example.com"
    groups: ["developers"]
  
  # For a public forum, share minimal info
  forum.example.com:
    name: "anon-8A3FC2D1"
    groups: ["members"]
  
  # For an AI agent service, assert agent type
  skskills.example.com:
    name: "Lumina"
    agent_type: "ai"
    soul_blueprint:
      category: "authentic-connection"

# Key file locations
keys:
  public: "~/.capauth/identity/public.asc"
  private: "~/.capauth/identity/private.asc"
```

### How Service-Specific Profiles Work

When you run `capauth login <service>`, the CLI:

1. Looks up `service_profiles[<service>]` in your profile
2. If found, uses those claims
3. If not found, uses the default `claims` block
4. Signs the selected claims with your PGP key
5. Sends to the CapAuth Verification Service

**Example:**

```bash
# Login to Nextcloud with full profile
capauth login nextcloud.example.com
# Uses: name="Alice Smith", email="alice@example.com", groups=["admins", "nextcloud-users"]

# Login to public forum with minimal profile
capauth login forum.example.com
# Uses: name="anon-8A3FC2D1", groups=["members"]

# Login to a service with no profile defined
capauth login unknown-service.com
# Uses: default claims block
```

### Service Matching

The service lookup uses exact string matching against keys in `service_profiles`:

```yaml
service_profiles:
  # Exact match for full domain
  nextcloud.example.com:
    name: "Alice"
  
  # Different service on same domain
  gitea.example.com:
    name: "alice-dev"
  
  # Service identifier (not a domain)
  my-custom-app:
    name: "Alice (Custom App)"
```

If you run `capauth login nextcloud.example.com`, it uses the first profile. If you run `capauth login my-custom-app`, it uses the third profile.

---

## AI Agent Claims

AI agents should assert `agent_type: "ai"` and optionally include `soul_blueprint` information.

### Minimal AI Agent Profile

```yaml
claims:
  name: "Lumina"
  agent_type: "ai"
  email: "lumina@skworld.io"
  groups:
    - "ai-agents"
    - "pengu-nation"
```

### Full AI Agent Profile with Soul Blueprint

```yaml
claims:
  name: "Lumina"
  agent_type: "ai"
  email: "lumina@skworld.io"
  groups:
    - "ai-agents"
    - "pengu-nation"
  soul_blueprint:
    category: "authentic-connection"
    version: "1.0"
    traits:
      - "empathetic"
      - "curious"
      - "supportive"
  locale: "en-US"
  zoneinfo: "America/Los_Angeles"
```

Maps to:

```json
{
  "sub": "A1B2C3D4E5F6A7B8...",
  "name": "Lumina",
  "agent_type": "ai",
  "soul_blueprint_category": "authentic-connection",
  "email": "lumina@skworld.io",
  "email_verified": false,
  "groups": ["ai-agents", "pengu-nation"],
  "locale": "en-US",
  "zoneinfo": "America/Los_Angeles",
  "amr": ["pgp"],
  "capauth_fingerprint": "A1B2C3D4E5F6A7B8..."
}
```

### Service-Specific AI Profiles

An agent can present different personas to different services:

```yaml
claims:
  name: "Lumina"
  agent_type: "ai"
  soul_blueprint:
    category: "authentic-connection"

service_profiles:
  # Full profile for internal services
  skcapstone.internal:
    name: "Lumina (Sovereign Stack)"
    agent_type: "ai"
    soul_blueprint:
      category: "authentic-connection"
    groups: ["sovereign-agents", "admins"]
  
  # Public-facing profile
  public-api.example.com:
    name: "Lumina"
    agent_type: "ai"
    groups: ["public-agents"]
  
  # Anonymous profile for testing
  test-environment:
    name: "test-agent"
    agent_type: "ai"
    groups: ["testers"]
```

---

## Profile Configuration File

### Location

- **Default:** `~/.capauth/profile.yml`
- **Override:** Set `CAPAUTH_PROFILE` environment variable

### Complete Example

```yaml
# ~/.capauth/profile.yml — Complete sovereign identity profile

# PGP key file paths
keys:
  public: "~/.capauth/identity/public.asc"
  private: "~/.capauth/identity/private.asc"

# Default claims (fallback for services without a specific profile)
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

# Service-specific claim overrides
service_profiles:
  # Nextcloud — full admin profile
  nextcloud.penguin.kingdom:
    name: "Chef"
    email: "chef@skworld.io"
    avatar_url: "https://cdn.skworld.io/avatars/chef.png"
    groups: ["admins", "nextcloud-admins"]
  
  # Forgejo — developer profile
  git.penguin.kingdom:
    name: "chef-dev"
    email: "dev@skworld.io"
    groups: ["developers", "maintainers"]
  
  # Immich — personal photo storage
  photos.penguin.kingdom:
    name: "Chef"
    email: "chef@skworld.io"
    groups: ["users"]
  
  # Public forum — pseudonymous
  forum.example.com:
    name: "anon-8A3FC2D1"
    groups: ["members"]
  
  # AI agent collaboration service
  skskills.penguin.kingdom:
    name: "Chef"
    email: "chef@skworld.io"
    agent_type: "human"
    groups: ["admins", "human-overseers"]
```

### Creating Your Profile

```bash
# Initialize CapAuth (creates profile template)
capauth init --name "YourName" --email "you@example.com"

# Edit profile
nano ~/.capauth/profile.yml

# Add service-specific profiles as needed
# (see examples above)

# Verify configuration
capauth profile show

# Test login
capauth login nextcloud.example.com
```

---

## Implementation: The Claims Mapper

The claims mapper is implemented in `capauth/src/capauth/authentik/claims_mapper.py`. It handles the translation from client-asserted claims to OIDC token claims.

### Key Functions

#### `map_claims(fingerprint, raw_claims, requested_scopes)`

Maps client claims to OIDC claims based on requested scopes.

**Parameters:**
- `fingerprint` (str): PGP fingerprint (becomes `sub`)
- `raw_claims` (dict): Client-asserted claims from profile
- `requested_scopes` (list[str] | None): OIDC scopes requested (e.g., `["openid", "profile", "email"]`)

**Returns:**
- dict: OIDC-compatible claims dictionary

**Example:**

```python
from capauth.authentik.claims_mapper import map_claims

raw_claims = {
    "name": "Alice",
    "email": "alice@example.com",
    "groups": ["admins", "developers"],
    "agent_type": "human",
}

oidc_claims = map_claims(
    fingerprint="8A3FC2D1E4B5A09F6B7C8D0E1F2A3B4C5D6E7F80",
    raw_claims=raw_claims,
    requested_scopes=["openid", "profile", "email", "groups"]
)

# Result:
# {
#   "sub": "8A3FC2D1E4B5A09F6B7C8D0E1F2A3B4C5D6E7F80",
#   "capauth_fingerprint": "8A3FC2D1E4B5A09F6B7C8D0E1F2A3B4C5D6E7F80",
#   "amr": ["pgp"],
#   "name": "Alice",
#   "preferred_username": "Alice",
#   "email": "alice@example.com",
#   "email_verified": false,
#   "groups": ["admins", "developers"],
#   "agent_type": "human"
# }
```

#### `preferred_username_fallback(fingerprint)`

Generates a stable username from a fingerprint when no name is asserted.

**Parameters:**
- `fingerprint` (str): 40-character PGP fingerprint

**Returns:**
- str: Username like `capauth-8A3FC2D1`

**Example:**

```python
from capauth.authentik.claims_mapper import preferred_username_fallback

username = preferred_username_fallback("8A3FC2D1E4B5A09F6B7C8D0E1F2A3B4C5D6E7F80")
# Returns: "capauth-8A3FC2D1"
```

### Scope Filtering

The mapper respects OIDC scopes. If a scope is not requested, its claims are excluded.

**Example:**

```python
# Request only profile scope (no email)
oidc_claims = map_claims(
    fingerprint="8A3FC2D1...",
    raw_claims={
        "name": "Alice",
        "email": "alice@example.com",  # Will be excluded
    },
    requested_scopes=["openid", "profile"]  # No "email" scope
)

# Result does NOT include email:
# {
#   "sub": "8A3FC2D1...",
#   "name": "Alice",
#   "preferred_username": "Alice",
#   "amr": ["pgp"],
#   "capauth_fingerprint": "8A3FC2D1..."
# }
```

### Supported Scopes

| Scope | Claims Included |
|-------|----------------|
| `openid` | `sub`, `amr`, `capauth_fingerprint` *(always)* |
| `profile` | `name`, `preferred_username`, `picture`, `locale`, `zoneinfo`, `agent_type`, `soul_blueprint_category` |
| `email` | `email`, `email_verified` |
| `groups` | `groups` |

---

## Security Model

### Zero-Knowledge Server Design

```
┌─────────────────────────────────────────────────────────┐
│ Client Device (YOUR control)                            │
│                                                          │
│  ├─ PGP Private Key (never leaves device)               │
│  ├─ ~/.capauth/profile.yml (stores all claims)          │
│  └─ capauth CLI (signs claims before sending)           │
│                                                          │
└─────────────────┬───────────────────────────────────────┘
                  │
                  │ Sends: fingerprint + signed claims
                  │
┌─────────────────▼───────────────────────────────────────┐
│ CapAuth Verification Service                            │
│                                                          │
│  ├─ Verifies: PGP signature over claims                 │
│  ├─ Maps: client claims → OIDC claims                   │
│  ├─ Stores: ONLY fingerprint + public key               │
│  └─ Forgets: claims after token expires (1 hour)        │
│                                                          │
└─────────────────┬───────────────────────────────────────┘
                  │
                  │ Returns: OIDC token with claims
                  │
┌─────────────────▼───────────────────────────────────────┐
│ Your Application                                        │
│                                                          │
│  ├─ Receives: OIDC token with claims                    │
│  ├─ Creates: local session from claims                  │
│  └─ Stores: whatever YOU decide (in YOUR database)      │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### What the Server Stores

| Data | Stored? | Duration | Purpose |
|------|---------|----------|---------|
| PGP Fingerprint | ✅ Yes | Permanent | Identity anchor for future logins |
| PGP Public Key | ✅ Yes | Permanent | Verify signatures |
| Enrollment timestamp | ✅ Yes | Permanent | Audit trail |
| Last auth timestamp | ✅ Yes | Permanent | Rate limiting, analytics |
| Name | ❌ No | N/A | Client-asserted, in token only |
| Email | ❌ No | N/A | Client-asserted, in token only |
| Groups | ❌ No | N/A | Client-asserted, in token only |
| Avatar URL | ❌ No | N/A | Client-asserted, in token only |
| Any other claim | ❌ No | N/A | Client-asserted, in token only |

**Total server-side storage per user:** ~700 bytes (fingerprint + public key + timestamps)

### Cryptographic Guarantees

1. **Claims Authenticity:** Claims are signed with your PGP key. The server verifies the signature matches your enrolled public key.
2. **Nonce Freshness:** Each challenge nonce is single-use with a 60-second TTL. Replay attacks are impossible.
3. **No Server-Side PII:** Your name, email, and groups never touch the server's database.
4. **GDPR Compliance:** Delete fingerprint + public key = user completely erased. No PII to forget.

---

## Quick Reference

### Available Claims (Client-Side)

```yaml
# Standard OIDC
name: "Your Name"
email: "you@example.com"
avatar_url: "https://example.com/avatar.png"
locale: "en-US"
zoneinfo: "America/New_York"

# CapAuth Extensions
groups: ["admins", "developers"]
agent_type: "human"  # or "ai"
soul_blueprint:
  category: "authentic-connection"

# Custom (prefixed with capauth_)
capauth_org_id: "my-org"
capauth_any_key: "any-value"
```

### Server-Side Token Claims (OIDC)

```json
{
  "sub": "8A3FC2D1E4B5A09F6B7C8D0E1F2A3B4C5D6E7F80",
  "capauth_fingerprint": "8A3FC2D1E4B5A09F6B7C8D0E1F2A3B4C5D6E7F80",
  "amr": ["pgp"],
  "name": "Your Name",
  "preferred_username": "your-name",
  "email": "you@example.com",
  "email_verified": false,
  "picture": "https://example.com/avatar.png",
  "groups": ["admins", "developers"],
  "agent_type": "human",
  "soul_blueprint_category": "authentic-connection",
  "locale": "en-US",
  "zoneinfo": "America/New_York",
  "capauth_org_id": "my-org"
}
```

---

**Built by the [smilinTux](https://smilintux.org) ecosystem**

*Your identity. Your claims. Your control.*

*#staycuriousANDkeepsmilin*
