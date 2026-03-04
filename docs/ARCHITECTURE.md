# CapAuth Architecture

## Identity Architecture

```mermaid
graph TB
    subgraph "CapAuth Identity"
        Profile[Profile YAML] --> |loads| Generator[DIDDocumentGenerator]
        PubKey[Public Key - PGP] --> Generator
        Soul[Soul YAML] --> |optional| Generator

        Generator --> T1[Tier 1: did:key]
        Generator --> T2[Tier 2: did:web mesh]
        Generator --> T3[Tier 3: did:web public]
    end

    subgraph "Key Management"
        GPG[GPG Keyring] --> PubKey
        GPG --> PrivKey[Private Key]
        PrivKey --> Sign[Sign Messages]
        PubKey --> Verify[Verify Signatures]
        PubKey --> Encrypt[Encrypt to Peer]
    end

    subgraph "DID Publishing"
        T1 --> |~/.skcapstone/did/key.json| Local[Local Storage]
        T2 --> |~/.skcomm/well-known/did.json| Tailscale[Tailscale Serve]
        T3 --> |publish-did.sh| CF[Cloudflare KV]
        CF --> |did:web:ws.weblink.skworld.io| Public[Public Resolution]
    end

    subgraph "Authentication"
        Validator[CapAuth Validator] --> |Bearer token| API[FastAPI Endpoints]
        PrivKey --> |sign challenge| Validator
    end
```

## DID Resolution Flow

```mermaid
sequenceDiagram
    participant P as Peer
    participant R as DID Registry
    participant CF as Cloudflare KV
    participant TS as Tailscale Mesh

    Note over P: Public Resolution
    P->>R: GET /agents/opus/.well-known/did.json
    R->>CF: KV lookup "opus"
    CF-->>R: Tier 3 DID Document
    R-->>P: did:web:ws.weblink.skworld.io:agents:opus

    Note over P: Mesh Resolution
    P->>TS: GET hostname.tailnet/.well-known/did.json
    TS-->>P: Tier 2 DID Document (full endpoints)
```

## DID Tier Details

### Tier 1 — did:key (Zero Infrastructure)

- Self-contained: the DID identifier encodes the public key directly
- No DNS, no servers, no hosting required
- Stored locally at `~/.skcapstone/did/key.json`
- Falls back from Tier 2 when no Tailscale hostname is configured

### Tier 2 — did:web mesh (Tailscale-Private)

- Served via Tailscale Serve at `~/.skcomm/well-known/did.json`
- References Tailscale magic-DNS hostname only — never raw `100.x.x.x` IPs
- Includes full service endpoints:
  - `SKCommMessaging` — `/api/v1/profile`
  - `CapAuthVerification` — `/api/v1/did/verify`
  - `AgentProfile` — `/api/v1/profile/identity`
- Includes optional `skworld:agentCard` with capabilities and entity type

### Tier 3 — did:web public (skworld.io)

- Published to Cloudflare KV via `scripts/publish-did.sh`
- Resolved as `did:web:ws.weblink.skworld.io:agents:<slug>`
- Minimal by design: public key JWK + name + entity_type + org only
- No service endpoints, no Tailscale hostnames, no capabilities
- Opt-out: set `publish_to_skworld: false` in `~/.capauth/config.yaml`

## Source Module Map

| Module | Responsibility |
|--------|---------------|
| `did.py` | `DIDDocumentGenerator`, `DIDTier`, `DIDContext`; all three tier generators |
| `identity.py` | PGP challenge-response: `create_challenge`, `respond_to_challenge`, `verify_challenge` |
| `cli.py` | Click CLI — `init`, `profile`, `verify`, `login`, `mesh`, `pma`, `register`, `setup` |
| `profile.py` | Sovereign profile init, load, export; `DEFAULT_CAPAUTH_DIR` |
| `models.py` | Pydantic models: `SovereignProfile`, `ChallengeRequest`, `ChallengeResponse` |
| `crypto/` | Pluggable backends: `pgpy_backend.py` (default), `gnupg_backend.py` |
| `pma.py` | PMA membership — Fiducia Communitatis request/approve/verify/revoke |
| `registry.py` | `RegistryEntry`, sovereign org registry |
| `mesh.py` | `PeerMesh` — P2P peer discovery and verification |
| `discovery/` | Discovery backends: `file_discovery.py`, `mdns.py` |
| `login.py` | `do_login()` — full CapAuth bearer token auth flow |
| `service/` | FastAPI service (`app.py`), `server.py`, `keystore.py` |
| `authentik/` | Authentik custom stage — OIDC bridge, claims mapper, nonce store |
