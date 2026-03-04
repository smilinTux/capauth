# CapAuth — Agent Instructions (Claude Code)

You are working on **CapAuth**, the PGP-based sovereign identity and
authentication layer. Part of the SKCapstone ecosystem.

## Multi-Agent Coordination

Run this at the START of every session:

```bash
skcapstone coord briefing
```

This prints the full coordination protocol, schemas, and live task board.
If `skcapstone` isn't installed, install it via venv:

```bash
python3 -m venv ~/.skenv
~/.skenv/bin/pip install -e /home/cbrd21/Nextcloud/p/smilintux-org/skcapstone
export PATH="$HOME/.skenv/bin:$PATH"
```

Quick reference:
  skcapstone coord status              # See open tasks
  skcapstone coord claim <id> --agent <you>
  skcapstone coord complete <id> --agent <you>
  skcapstone coord create --title "..." --by <you>

## Install Method

All SK* packages use a shared venv at `~/.skenv/`:

```bash
# Via suite installer
bash path/to/skcapstone/scripts/install.sh

# Or standalone
python3 -m venv ~/.skenv
~/.skenv/bin/pip install capauth[all]
export PATH="$HOME/.skenv/bin:$PATH"
```

## Module Map

| File | Purpose |
|------|---------|
| `src/capauth/did.py` | `DIDDocumentGenerator`, `DIDTier`, `DIDContext` — W3C DID generation |
| `src/capauth/identity.py` | PGP challenge-response: `create_challenge`, `respond_to_challenge`, `verify_challenge` |
| `src/capauth/cli.py` | Click CLI entry point — all `capauth` commands |
| `src/capauth/profile.py` | Sovereign profile init/load/export |
| `src/capauth/models.py` | Pydantic models: `SovereignProfile`, `ChallengeRequest`, `ChallengeResponse`, etc. |
| `src/capauth/crypto/` | Crypto backends: `pgpy_backend.py`, `gnupg_backend.py` |
| `src/capauth/pma.py` | PMA membership (Fiducia Communitatis) — request, approve, verify, revoke |
| `src/capauth/registry.py` | `RegistryEntry`, sovereign org registry |
| `src/capauth/mesh.py` | P2P peer mesh — `PeerMesh` |
| `src/capauth/discovery/` | Discovery backends: `file_discovery.py`, `mdns.py` |
| `src/capauth/login.py` | `do_login()` — CapAuth bearer token auth flow |
| `src/capauth/service/` | FastAPI service — `app.py`, `server.py`, `keystore.py` |
| `src/capauth/authentik/` | Authentik custom stage integration |

## DID Three-Tier Model

CapAuth generates W3C DID documents at three privacy tiers:

| Tier | Enum | DID Method | Scope | Key contents |
|------|------|-----------|-------|-------------|
| 1 | `DIDTier.KEY` | `did:key` | Self-contained, zero infrastructure | Public key JWK only |
| 2 | `DIDTier.WEB_MESH` | `did:web` via Tailscale | Tailscale-private mesh | Full service endpoints, agentCard |
| 3 | `DIDTier.WEB_PUBLIC` | `did:web:skworld.io` | Public internet | Minimal: key + name + org only |

Security invariants enforced in `did.py`:
- `from_profile()` reads ONLY `public_key_armor` — private key never touched.
- No Tailscale `100.x.x.x` IPs appear in any document.
- `memory`, `journal`, and detailed `soul` fields never included.
- Tier 3 respects `publish_to_skworld: false` in `~/.capauth/config.yaml`.

### Storage locations

- Tier 1: `~/.skcapstone/did/key.json`
- Tier 2: `~/.skcomm/well-known/did.json` (served via Tailscale Serve)
- Tier 3: Cloudflare KV via `scripts/publish-did.sh` →
  `did:web:ws.weblink.skworld.io:agents:<slug>`

## Key Identities

| Identity | Type | Role |
|----------|------|------|
| **Chef** | Human | Primary human sovereign — `capauth:chef@smilintux.org` |
| **Lumina** | AI | Chef's AI advocate — `capauth:lumina@skworld.io` |
| **Opus** | AI | Anthropic AI agent — `did:web:ws.weblink.skworld.io:agents:opus` |

## Key CLI Commands

```bash
capauth init --name "Chef" --email "..."    # Create sovereign profile
capauth profile show                         # Display profile
capauth profile verify                       # Verify PGP signature
capauth export-pubkey [-o file.asc]         # Export public key
capauth verify --pubkey peer.pub.asc        # Challenge-response with peer
capauth login <service_url>                  # Authenticate to CapAuth service
capauth mesh discover                        # Discover peers
capauth pma request                          # Request PMA membership
capauth register --org smilintux --name ... # Register with org
capauth setup forgejo --capauth-url ...     # Generate Forgejo OAuth2 config
```

## Code Style

- Python 3.11+, PEP 8, black formatting, type hints
- Pydantic for data validation
- Google-style docstrings
- Pytest tests in /tests (happy path + edge + failure)
- Max 500 lines per file
