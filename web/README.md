# CapAuth Authentik frontend stage

This directory contains the **`ak-stage-capauth`** Lit web component for Authentik’s flow executor. It is intended to be copied into Authentik’s web frontend and built with it.

## Contract (backend)

- Challenge fields: `need_fingerprint`, `fingerprint`, `nonce`, `client_nonce_echo`, `timestamp`, `service`, `expires`, `server_signature`, `presentation`, `qr_payload`, `component`.
- Step 1: When `need_fingerprint` is true, show fingerprint input; on submit send `{ fingerprint }`.
- Step 2: When `need_fingerprint` is false, show nonce/QR; on submit send `{ fingerprint, nonce, nonce_signature, claims?, claims_signature?, public_key? }`.

## Integration into Authentik (2025.12.x)

1. Clone Authentik and check out the version you use (e.g. `version/2025.12.3`).
2. Copy this directory into Authentik’s flow stages:
   ```bash
   cp -r /path/to/capauth/web/stages/capauth /path/to/authentik/web/src/flow/stages/
   ```
3. Register the stage in the flow entrypoint:
   - Edit `web/src/flow/index.entrypoint.ts` and add:
   ```ts
   import "#flow/stages/capauth/CapAuthStage";
   ```
4. Rebuild Authentik’s web assets and use the resulting build with your custom Authentik image that has the capauth backend installed.

See [AUTHENTIK_CUSTOM_STAGE.md](../docs/AUTHENTIK_CUSTOM_STAGE.md) for full installation (backend + frontend).
