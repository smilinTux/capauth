# CapAuth Skill

**SKILL.md — Capability-based Authentication**

---

## Description

CapAuth is a PGP-based decentralized identity and authentication system. It provides sovereign identity verification without relying on OAuth, corporate identity providers, or centralized login services.

Authentication is performed through cryptographic challenge-response using PGP keys. Your identity is your key. No third party can revoke, suspend, or surveil your authentication flow.

---

## Install

### From PyPI

```bash
pip install capauth
```

### From Source

```bash
git clone https://forgejo.skworld.io/smilintux/capauth.git
cd capauth
pip install -e .
```

### Optional Extras

```bash
# GnuPG keyring integration
pip install "capauth[gnupg]"

# FastAPI authentication service
pip install "capauth[service]"

# Development and testing tools
pip install "capauth[dev]"

# All extras
pip install "capauth[gnupg,service,dev]"
```

**Package info:**
- Name: `capauth`
- Version: `0.1.0`
- Author: smilinTux
- License: GPL-3.0-or-later
- Python: >=3.10
- Homepage: https://capauth.io
- Dependencies: `click`, `pydantic`, `PGPy`, `pyyaml`, `rich`, `httpx`

---

## Quick Start

### 1. Initialize your sovereign profile

```bash
capauth init
```

This creates your PGP keypair and sovereign profile under `~/.capauth/`.

### 2. View or manage your profile

```bash
capauth profile
```

### 3. Run a challenge-response verification with a peer

```bash
capauth verify
```

### 4. Export your public key for sharing

```bash
capauth export-pubkey
```

---

## CLI Commands

| Command | Description |
|---|---|
| `capauth init` | Create your sovereign profile and PGP keypair |
| `capauth profile` | View and manage your sovereign profile |
| `capauth verify` | Run a challenge-response identity verification with a peer |
| `capauth export-pubkey` | Export your ASCII-armored public key |
| `capauth-service` | Start the CapAuth FastAPI authentication service |

### Global Option

| Option | Description | Default |
|---|---|---|
| `--home PATH` | CapAuth home directory | `~/.capauth/` |

---

## Service Mode

The `capauth-service` entry point starts a FastAPI authentication server for web and API authentication use cases. It exposes HTTP endpoints for challenge issuance, signature verification, and session management.

```bash
# Start the CapAuth FastAPI service
capauth-service
```

Requires the `[service]` extra:

```bash
pip install "capauth[service]"
```

The service is designed to be deployed behind a reverse proxy. It issues cryptographic challenges to clients, validates PGP-signed responses, and returns authenticated session tokens — without passwords, OAuth flows, or corporate identity providers.

---

## Challenge-Response Flow

CapAuth authentication follows a two-step cryptographic handshake:

1. **Challenge issuance** — The verifier (server or peer) generates a random nonce and sends it to the authenticating party.

2. **Signing** — The authenticating party signs the nonce with their private PGP key and returns the signature along with their key fingerprint.

3. **Verification** — The verifier retrieves the public key (via profile or keyserver), verifies the signature against the original nonce, and confirms identity.

4. **Session grant** — On successful verification, the verifier grants access or returns a session token.

No shared secrets are transmitted. No passwords. Identity is proven entirely through asymmetric cryptography.

```
Client                          Server
  |                               |
  |  --- request challenge -->    |
  |                               |  generate nonce
  |  <-- nonce --                 |
  |                               |
  |  sign(nonce, private_key)     |
  |  --- signature + fingerprint --> |
  |                               |  verify(signature, public_key, nonce)
  |  <-- session token / OK --    |
```

---

## Configuration Paths

CapAuth stores all state under the home directory (default: `~/.capauth/`).

| Path | Contents |
|---|---|
| `~/.capauth/` | CapAuth home directory |
| `~/.capauth/profile.yaml` | Sovereign profile (name, fingerprint, metadata) |
| `~/.capauth/keys/` | PGP key storage |
| `~/.capauth/keys/private.asc` | ASCII-armored private key |
| `~/.capauth/keys/public.asc` | ASCII-armored public key |
| `~/.capauth/peers/` | Trusted peer public keys |
| `~/.capauth/config.yaml` | CapAuth configuration file |

Override the home directory using the `--home` flag or the `CAPAUTH_HOME` environment variable.

---

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `CAPAUTH_HOME` | CapAuth home directory | `~/.capauth/` |
| `CAPAUTH_SERVICE_HOST` | Host for the FastAPI service | `127.0.0.1` |
| `CAPAUTH_SERVICE_PORT` | Port for the FastAPI service | `8000` |
| `CAPAUTH_LOG_LEVEL` | Logging level (`debug`, `info`, `warning`, `error`) | `info` |

---

## Python API

Basic programmatic usage:

```python
from capauth import CapAuth

# Initialize with default home directory
auth = CapAuth()

# Initialize with custom home directory
auth = CapAuth(home="/custom/path/.capauth")

# Load your profile
profile = auth.load_profile()
print(profile.fingerprint)

# Export public key as ASCII armor
pubkey = auth.export_pubkey()
print(pubkey)

# Sign a challenge nonce
challenge = b"some-random-nonce-from-server"
signature = auth.sign_challenge(challenge)

# Verify a peer's signed challenge
peer_pubkey_path = "~/.capauth/peers/peer-fingerprint.asc"
is_valid = auth.verify_challenge(
    challenge=challenge,
    signature=signature,
    pubkey_path=peer_pubkey_path
)
```

### Challenge-Response with httpx

```python
import httpx
from capauth import CapAuth

auth = CapAuth()

# 1. Request a challenge from the CapAuth service
response = httpx.post("https://auth.example.com/challenge", json={
    "fingerprint": auth.profile.fingerprint
})
nonce = response.json()["nonce"]

# 2. Sign the challenge
signature = auth.sign_challenge(nonce.encode())

# 3. Submit the signed response
session_response = httpx.post("https://auth.example.com/verify", json={
    "fingerprint": auth.profile.fingerprint,
    "signature": signature.decode()
})
session_token = session_response.json()["token"]
```

---

## Integration with SK* Packages

CapAuth is a foundational pillar of the SK* sovereign stack. Other packages in the ecosystem depend on or integrate with it:

| Package | Integration |
|---|---|
| **SKComm** | Signed message envelopes use CapAuth keys for sender authentication and non-repudiation |
| **SKSeal** | Document signing uses CapAuth keypairs; signed documents carry verifiable identity |
| **SKChat** | Encrypted message storage and P2P session authentication via CapAuth challenge-response |
| **SKCapstone** | Agent identity is anchored to a CapAuth fingerprint; trust graph is built on PGP signatures |
| **SKWorld / OpenClaw** | Web session authentication replaces OAuth with CapAuth challenge-response |
| **Forgejo** | CapAuth browser extension enables passwordless login to sovereign git infrastructure |

---

## Author / Support

- **Author**: smilinTux
- **License**: GPL-3.0-or-later
- **Homepage**: https://capauth.io
- **Repository**: https://forgejo.skworld.io/smilintux/capauth
- **Issues**: https://forgejo.skworld.io/smilintux/capauth/issues
