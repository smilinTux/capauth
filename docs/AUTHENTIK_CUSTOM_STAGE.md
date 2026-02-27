# Authentik Custom Stage — Native PGP Challenge-Response

This document describes how to run the **CapAuth custom stage** inside Authentik so users see a PGP challenge (fingerprint + nonce/QR) instead of a password box — the native passwordless experience.

## What’s Implemented

- **Backend (this repo)**
  - `CapAuthStage` model extending `authentik.flows.models.Stage` with `service_id`, `require_enrollment_approval`, `nonce_ttl_seconds`.
  - `CapAuthChallenge` / `CapAuthChallengeResponse` for the flow executor (Challenge/ChallengeResponse contract).
  - `CapAuthStageView` (ChallengeStageView): GET returns either “need fingerprint” or full nonce challenge; POST accepts fingerprint-only (returns new challenge with nonce) or full signed response (verifies and completes).
  - `CapAuthStageSerializer` and `CapAuthStageViewSet` in `capauth/authentik/api.py` for admin/API.
  - Challenge logic and key registry live in `stage.py`, `nonce_store.py`, `verifier.py`, `claims_mapper.py`.

- **Frontend (this repo)**
  - A Lit-based **web component** `ak-stage-capauth` is provided under `capauth/web/stages/capauth/` (see [web/README.md](../web/README.md)). Copy it into Authentik’s web build and register it in the flow entrypoint. Authentik’s flow executor expects this component to:
    1. Renders the challenge: either a fingerprint input (when `need_fingerprint` is true) or the nonce/QR/copyable string (when `need_fingerprint` is false).
    2. On “Continue” with only fingerprint: POSTs `{ fingerprint }`; backend responds with a new challenge (nonce, etc.); component re-renders and shows nonce/QR.
    3. After the user signs in the CapAuth client (CLI/extension/mobile), POSTs the full signed response `{ fingerprint, nonce, nonce_signature, claims?, claims_signature?, public_key? }`; backend verifies and advances the flow.

  The component name is fixed in the backend as `component = "ak-stage-capauth"` (challenge and response).

## Installation Path (Authentik 2025.12.x)

To use this stage inside a real Authentik instance you must:

### 1. Install the capauth package inside Authentik

The Authentik image already provides Django and the `authentik` package. Install capauth from source into that environment.

**Option A — Custom Authentik image (recommended for production):**

```dockerfile
# Dockerfile.authentik-capauth
FROM ghcr.io/goauthentik/server:2025.12.3
USER root
COPY . /app/capauth
RUN pip install --no-cache-dir -e /app/capauth
USER authentik
```

Build and use this image instead of the stock Authentik image so that the `capauth` package and its Django app are available.

**Option B — Bind-mount and install at runtime:**

Mount the capauth source into the container and run `pip install -e /path/to/capauth` inside the running Authentik container (or in an init script). Less ideal for production.

### 2. Register the Django app and URL routes

Authentik loads settings from environment and YAML. You must add the capauth app and the stage API routes.

- **INSTALLED_APPS:** Add `capauth.apps.CapauthConfig` to Authentik’s `INSTALLED_APPS`. How you do this depends on your deployment:
  - **Environment:** If Authentik supports appending to `INSTALLED_APPS` via env (e.g. `AUTHENTIK_APPS_EXTRA=capauth.apps.CapauthConfig`), use that.
  - **Custom settings file:** If you use a custom Django settings module or patch, append `"capauth.apps.CapauthConfig"` to `INSTALLED_APPS`.

  The capauth package provides:
  - `capauth.apps.CapauthConfig` — Django AppConfig (label `capauth`).
  - `capauth.models` — Imports `CapAuthStage` and `CapAuthKeyRegistry` when Django is available so they are discovered as part of the `capauth` app.

- **URLs:** Include the CapAuth stage API in Authentik’s root URLconf so the ViewSet is reachable at `api/v3/stages/capauth/`. In Authentik’s main `urls.py` (or equivalent), add:
  - `path("api/v3/stages/capauth/", include("capauth.authentik.urls"))`

  This allows creating and editing CapAuth stages via the API. The flow executor uses the stage’s `view` and `component` properties; it does not require a separate URL for execution.

### 3. Run migrations

Inside the Authentik environment (same container or venv):

```bash
python manage.py migrate capauth
```

This creates the `capauth_capauthstage` and `capauth_capauthkeyregistry` tables. The initial migration depends on `authentik_flows.0001_squashed_0007_auto_20200703_2059` (Stage model).

### 4. Frontend — `ak-stage-capauth` web component

Authentik’s flow executor renders the challenge in the browser and expects a **Lit-based web component** with the tag `ak-stage-capauth` (the `component` field in the challenge is `"ak-stage-capauth"`). You must build and register this component in Authentik’s frontend build.

- **Contract:** The component receives the challenge object (e.g. `need_fingerprint`, `fingerprint`, `nonce`, `qr_payload`, `presentation`, etc.) and must submit the response by calling the flow executor’s submit API with either:
  - `{ fingerprint }` (step 1), or
  - `{ fingerprint, nonce, nonce_signature, claims?, claims_signature?, public_key? }` (step 2).

- **Where to add it:** Copy `capauth/web/stages/capauth/` into Authentik’s repo at `web/src/flow/stages/capauth/`, add `import "#flow/stages/capauth/CapAuthStage";` to `web/src/flow/index.entrypoint.ts`, and rebuild the frontend. See [web/README.md](../web/README.md) for the exact steps.

- **Minimal behaviour:**
  1. If `need_fingerprint` is true: show a text input for the 40-char fingerprint and a “Continue” button; on submit, POST `{ fingerprint }`.
  2. If `need_fingerprint` is false: show the nonce (and optionally `qr_payload` as QR, or copyable text); provide a way for the user to signal “I have signed” (e.g. “Continue” that POSTs the full signed response). In practice the signed response is filled by a CapAuth client (CLI/extension/mobile) or the user pastes it; the component must send that payload to the flow executor.

The `ak-stage-capauth` Lit component is provided at `capauth/web/stages/capauth/CapAuthStage.ts` (305 lines). It implements both the fingerprint input step and the nonce/signed-response step with QR support. Copy it into Authentik’s web build and register it to complete the integration.

### 5. Create a stage and bind to a flow

- In Authentik admin (or via API): create a **CapAuth Stage** instance (set `service_id`, `require_enrollment_approval`, `nonce_ttl_seconds` as needed).
- Edit your Authentication or Authorization flow and add the CapAuth stage in the desired position (e.g. first stage instead of Identification/Password).

### 6. Environment

Set where Authentik runs (same as for the standalone CapAuth service):

- `CAPAUTH_SERVICE_ID` — Hostname/identifier clients use in auth requests (e.g. `sso.skstack01.douno.it`).
- `CAPAUTH_SERVER_KEY_ARMOR` — (Optional) Server’s ASCII-armored PGP key for signing challenge nonces.
- `CAPAUTH_SERVER_KEY_PASSPHRASE` — (Optional) Passphrase for the server key.
- `CAPAUTH_REQUIRE_APPROVAL` — Set to `true` if new keys require admin approval before first login.

Authentik must be able to use the same cache backend (e.g. Redis) for the nonce store; the capauth stage uses Django’s cache framework (`django.core.cache`) for nonce storage.

## Flow Summary

1. User hits the flow; executor loads CapAuth stage and calls GET.
2. If no `?fingerprint=...` in the request, backend returns a challenge with `need_fingerprint: true`. Frontend shows fingerprint input.
3. User enters fingerprint and submits; frontend POSTs `{ fingerprint }`. Backend issues nonce, stores it in plan context, returns a new challenge with `need_fingerprint: false` and nonce/QR/copyable string. Frontend shows that.
4. User signs the nonce in the CapAuth client; frontend POSTs full signed response. Backend verifies, enrolls key if new, sets `PLAN_CONTEXT_PENDING_USER` and related context, calls `stage_ok()`.

## Summary checklist

| Step | Item |
|------|------|
| 1 | Install capauth in Authentik environment (custom image or pip install -e) |
| 2 | Add `capauth.apps.CapauthConfig` to INSTALLED_APPS |
| 3 | Add `path("api/v3/stages/capauth/", include("capauth.authentik.urls"))` to Authentik URLconf |
| 4 | Run `python manage.py migrate capauth` |
| 5 | Build and register `ak-stage-capauth` in Authentik’s web frontend |
| 6 | Create CapAuth Stage in admin and add it to your flow |
| 7 | Set CAPAUTH_* environment variables and ensure cache (e.g. Redis) is used for nonces |

## References

- Authentik flow executor: `authentik.flows.stage.ChallengeStageView`, `authentik.flows.challenge.Challenge` / `ChallengeResponse`.
- Authentik stages: `authentik.flows.models.Stage` (base), `authentik.stages.dummy` for a minimal example.
- CapAuth deployment: `AUTHENTIK_FORGEJO_DEPLOYMENT.md`.
