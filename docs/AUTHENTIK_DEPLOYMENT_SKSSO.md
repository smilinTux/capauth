# CapAuth Authentik stage — sksso-prod deployment outline

Exact steps to deploy the CapAuth custom stage on **sksso-prod** (Authentik 2025.12.3, flow `skstack01-application-authorization` UUID `97730dbd-b5fc-4171-8dce-4de5273c1db2`).

## Prerequisites

- CapAuth backend and frontend stage source in this repo (`capauth/`, `capauth/web/stages/capauth/`).
- Authentik 2025.12.3 (e.g. `ghcr.io/goauthentik/server:2025.12.3`).
- API access: `docker run --rm --network sksso-prod curlimages/curl:latest curl -s -H "Authorization: Bearer <token>" http://server:9000/api/v3/...`

---

## 1. Custom Authentik image with capauth

- **Dockerfile** (e.g. in this repo or your infra):
  ```dockerfile
  FROM ghcr.io/goauthentik/server:2025.12.3
  USER root
  COPY . /app/capauth
  RUN pip install --no-cache-dir -e /app/capauth
  USER authentik
  ```
- Build and push your image; use it for the Authentik server service in sksso-prod instead of the stock image.

---

## 2. Django: INSTALLED_APPS and URLconf

Authentik does not always expose `INSTALLED_APPS` via env. Options:

- **If you use a custom settings file or patch:**  
  Append `"capauth.apps.CapauthConfig"` to `INSTALLED_APPS` and add to the root URLconf:
  ```python
  path("api/v3/stages/capauth/", include("capauth.authentik.urls"))
  ```
- **If Authentik supports extra apps via env:**  
  Set e.g. `AUTHENTIK_APPS_EXTRA=capauth.apps.CapauthConfig` and ensure the URL include is applied (may require a custom image that patches `urls.py` or equivalent).

In practice, a **custom image** that patches Authentik’s settings/urls (e.g. in an entrypoint or a small Django patch) is the reliable way to add both the app and the URL.

---

## 3. Migrations

Inside the Authentik container (or same environment):

```bash
python manage.py migrate capauth
```

Creates `capauth_capauthstage` and `capauth_capauthkeyregistry`.

---

## 4. Frontend: register `ak-stage-capauth`

- Clone Authentik and check out `version/2025.12.3`.
- Copy stage into Authentik’s web tree:
  ```bash
  cp -r /path/to/capauth/web/stages/capauth /path/to/authentik/web/src/flow/stages/
  ```
- In `web/src/flow/index.entrypoint.ts` add:
  ```ts
  import "#flow/stages/capauth/CapAuthStage";
  ```
- Rebuild Authentik’s web assets (e.g. `npm run build` in `web/`).
- Serve the built frontend from your custom Authentik setup (e.g. bake the build into the custom image or mount it).

---

## 5. Create CapAuth stage and add to flow

- **Create stage** (Authentik admin or API):
  - POST or create “CapAuth Stage” with desired `service_id` (e.g. `sso.skstack01.douno.it`), `require_enrollment_approval`, `nonce_ttl_seconds`.
  - Note the stage UUID/pk.
- **Bind to flow:**  
  Edit flow `97730dbd-b5fc-4171-8dce-4de5273c1db2` (skstack01-application-authorization) and add the CapAuth stage in the desired position (e.g. first stage instead of Identification/Password).

Via API (example):

```bash
# List stages
curl -s -H "Authorization: Bearer <token>" "http://server:9000/api/v3/stages/capauth/"

# Get flow
curl -s -H "Authorization: Bearer <token>" "http://server:9000/api/v3/flows/instances/97730dbd-b5fc-4171-8dce-4de5273c1db2/"

# Update flow stages (depends on Authentik’s flow/stage binding API)
```

Use the admin UI “Flows” → “skstack01-application-authorization” → add CapAuth stage to the diagram.

---

## 6. Environment and cache

- Set on the Authentik server (sksso-prod):
  - `CAPAUTH_SERVICE_ID` — e.g. `sso.skstack01.douno.it`
  - `CAPAUTH_SERVER_KEY_ARMOR` — (optional) server PGP key for signing nonces
  - `CAPAUTH_SERVER_KEY_PASSPHRASE` — (optional)
  - `CAPAUTH_REQUIRE_APPROVAL` — `true` if new keys need admin approval
- **Cache:** CapAuth nonce store uses Django’s cache. Configure a shared backend (e.g. Redis) so that the Authentik server uses the same cache for nonce storage. See Django `CACHES` and Authentik’s cache configuration for your deployment.

---

## Checklist

| Step | Action |
|------|--------|
| 1 | Build custom Authentik image with `pip install -e /app/capauth` |
| 2 | Add `capauth.apps.CapauthConfig` to INSTALLED_APPS and `path("api/v3/stages/capauth/", include("capauth.authentik.urls"))` to URLconf |
| 3 | Run `python manage.py migrate capauth` |
| 4 | Copy `capauth/web/stages/capauth` into Authentik web, add import, rebuild frontend |
| 5 | Create CapAuth Stage in admin, add it to flow `97730dbd-b5fc-4171-8dce-4de5273c1db2` |
| 6 | Set CAPAUTH_* env and shared cache (e.g. Redis) |

See [AUTHENTIK_CUSTOM_STAGE.md](AUTHENTIK_CUSTOM_STAGE.md) for full installation and contract details.
