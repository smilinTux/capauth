# CapAuth as an OIDC/OAuth2 Identity Provider

**Status:** Browser authorization-code boundary hardened by card `62417b25`.
**Implements:** Track 2 (Option C2) of `docs/AUTHENTIK_STRATEGY_DECISION.md`

This turns the standalone CapAuth service into its **own OIDC Authorization
Code + PKCE Identity Provider**. The PGP login UI lives on CapAuth's own page
(fully ours), and **stock** Authentik federates to it via its first-class
OAuth/OIDC **Source** support — **no Authentik bundle patching, no custom
Authentik image**. This sidesteps the unfixable problem that Authentik has no
supported way to add a custom flow-stage web component (founder confirmed,
issue #1541).

```
   ┌─────────┐   user clicks "Sign in with CapAuth"   ┌──────────────────────┐
   │ Browser │ ─────────────────────────────────────► │ stock Authentik      │
   └─────────┘                                         │ (OAuth/OIDC Source)  │
        ▲                                              └─────────┬────────────┘
        │  redirect to CapAuth /oidc/authorize                  │ federates identity
        │                                                       ▼
        │   PGP login page (challenge → sign → verify)   ┌──────────────────────┐
        └──────────────────────────────────────────────►│ CapAuth OIDC IdP     │
            code → token (RS256 ID token) → userinfo     │ (this service)       │
                                                         └──────────────────────┘
```

Everything below is served by the existing CapAuth FastAPI service
(`capauth-service`). The new code lives in `src/capauth/service/oidc/`.

---

## 1. Endpoints

All under the issuer base URL. Canonical discovery is at
`/oidc/.well-known/openid-configuration`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/oidc/.well-known/openid-configuration` | Discovery document (issuer, endpoints, supported scopes/response_types/grant_types/PKCE methods). |
| GET | `/oidc/jwks.json` | JWKS — the **RSA public key** (`RS256`) used to sign ID tokens. This is the IdP's token-signing key, **separate** from any user's PGP key. |
| GET | `/oidc/authorize` | Validates `client_id` / `redirect_uri` / `scope` / `state` / PKCE, then renders the **PGP login page**. |
| POST | `/oidc/complete` | Called by the login page after the user signs. Runs the real PGP verify (reuses `verify_auth_response`), mints an auth code bound to the verified fingerprint + PKCE challenge, and returns the redirect URL with `code` + `state`. |
| POST | `/oidc/token` | `authorization_code` grant + PKCE verify → signed **ID token** (JWT, RS256: `sub`=PGP fingerprint, `iss`, `aud`=client_id, `nonce`, `amr:["pgp"]`, plus `email`/`name`/`groups` from the claims mapper) + `access_token`. |
| GET | `/oidc/userinfo` | `Authorization: Bearer <access_token>` → the verified claims. |
| POST | `/oidc/logout`, `/oidc/revoke` | Revoke the presented current bearer access token. |

There is also a root alias `GET /.well-known/oidc-idp-configuration` (same
content) so generic clients that only know the issuer can autodiscover without
colliding with the **legacy** consumer-facing `/.well-known/openid-configuration`
document the service already serves.

### The PGP login flow on `/oidc/authorize`

The login page reuses the existing, proven endpoints and the canonical
`CAPAUTH_NONCE_V1` payload contract — so the **same** signing client works (CLI
`capauth sign`, browser extension, Nextcloud app):

1. User enters their 40-char PGP fingerprint.
2. Page calls `POST /capauth/v1/challenge` → gets a nonce.
3. User signs the canonical nonce payload with their PGP key and pastes the
   signature (the extension/CLI fill it automatically).
4. Page calls `POST /oidc/complete` → CapAuth runs the real
   `verify_auth_response` (nonce consume + replay protection + PGP signature
   check + claims signature check + OIDC claims mapping). On success the browser
   is redirected back to the client's `redirect_uri` with `code` + `state`.

---

## 2. Configuring a client

### 2.1 RSA signing key

Auto-generated and persisted on first start at
`<capauth_home>/service/oidc_signing_key.pem` (override with
`CAPAUTH_OIDC_SIGNING_KEY_PATH`). The `kid` is derived from the key, stable
across restarts. **Keep this file**; rotating it invalidates issued tokens until
clients refetch JWKS.

### 2.2 Issuer URL

Set `CAPAUTH_OIDC_ISSUER` to the public base URL of the service (e.g.
`https://capauth.skworld.io`). If unset it falls back to `CAPAUTH_BASE_URL`, then
`https://<CAPAUTH_SERVICE_ID>`. The issuer MUST be the exact origin clients use.

### 2.3 Static client registry

Clients are declared up front (no dynamic registration in the spike). Provide
either:

- `CAPAUTH_OIDC_CLIENTS_FILE` — path to a JSON file, or
- `CAPAUTH_OIDC_CLIENTS_JSON` — the JSON array inline.

See `src/capauth/service/oidc/clients.example.json`:

```json
[
  {
    "client_id": "authentik",
    "client_secret": "CHANGE-ME-to-a-long-random-secret",
    "redirect_uris": ["https://authentik.example.com/source/oauth/callback/capauth/"],
    "name": "Authentik",
    "scopes": ["openid", "profile", "email", "groups"]
  }
]
```

- `redirect_uris` is matched **exactly** (no wildcards).
- `client_secret` is mandatory. The token endpoint rejects public or
  unconfigured clients even when PKCE is present.

### 2.4 Other env knobs

| Env | Default | Meaning |
|---|---|---|
| `CAPAUTH_OIDC_ISSUER` | `CAPAUTH_BASE_URL` | Issuer / public origin. |
| `CAPAUTH_OIDC_SIGNING_KEY_PATH` | `<home>/service/oidc_signing_key.pem` | RSA signing key PEM. |
| `CAPAUTH_OIDC_STATE_DB` | `<home>/service/oidc_state.db` | Durable one-use request, code, rate-limit, token currentness, and revocation state. |
| `CAPAUTH_OIDC_CLIENTS_FILE` / `_JSON` | — | Static client registry. |
| `CAPAUTH_OIDC_ID_TOKEN_TTL` | `300` | ID token lifetime in seconds, bounded to 1 through 300. |
| `CAPAUTH_OIDC_ACCESS_TOKEN_TTL` | `300` | Access token lifetime in seconds, bounded to 1 through 300. |

### 2.5 Run it

```bash
export CAPAUTH_OIDC_ISSUER="https://capauth.example.com"
export CAPAUTH_OIDC_CLIENTS_FILE="/etc/capauth/oidc-clients.json"
capauth-service --port 8420
# discovery:  https://capauth.example.com/oidc/.well-known/openid-configuration
# jwks:       https://capauth.example.com/oidc/jwks.json
```

---

## 3. Registering CapAuth as an OAuth/OIDC Source in **stock** Authentik

No custom image. Use the official `ghcr.io/goauthentik/server` image.

### 3.1 Add the client to CapAuth

Add an entry to your CapAuth client registry for Authentik:

```json
{
  "client_id": "authentik",
  "client_secret": "<long-random-secret>",
  "redirect_uris": ["https://<authentik-host>/source/oauth/callback/capauth/"],
  "name": "Authentik",
  "scopes": ["openid", "profile", "email", "groups"]
}
```

> The redirect URI Authentik uses for an OAuth source is
> `https://<authentik-host>/source/oauth/callback/<source-slug>/`. If you name
> the source slug `capauth`, the URI is the one above. Confirm the exact value
> on the source's detail page after you create it (Authentik shows the callback
> URL) and make sure it matches `redirect_uris` **exactly**.

### 3.2 Create the Source in Authentik

Authentik Admin → **Directory → Federation & Social login** (a.k.a. **Sources**)
→ **Create** → **OAuth Source**, then:

| Field | Value |
|---|---|
| **Name** | `CapAuth` |
| **Slug** | `capauth` (this becomes the callback URL segment) |
| **Provider type** | **OpenID Connect** (generic) |
| **Consumer key (client ID)** | `authentik` (the `client_id` you registered in CapAuth) |
| **Consumer secret (client secret)** | the `client_secret` you registered |
| **Scopes** | `openid profile email groups` |
| **OIDC Well-known URL** | `https://<capauth-host>/oidc/.well-known/openid-configuration` |

Using the **OIDC Well-known URL** lets Authentik autodiscover the
authorization/token/userinfo/JWKS endpoints. (If you prefer manual entry, fill
Authorization URL = `…/oidc/authorize`, Access token URL = `…/oidc/token`,
Profile/Userinfo URL = `…/oidc/userinfo`, JWKS URL = `…/oidc/jwks.json`.)

Save. Authentik fetches the JWKS and will verify CapAuth's RS256 ID tokens.

### 3.3 Wire the Source into a login flow

- Authentik shows the new Source as a login option automatically on the default
  login flow (a **Source** button), OR
- Bind it explicitly: edit your `default-authentication-flow` and ensure the
  **Identification stage** has **Sources** enabled (it lists enabled sources as
  login buttons). Optionally add a **Source stage** for a source-first flow.

### 3.4 Map the identity (optional but recommended)

- The ID token `sub` is the **PGP fingerprint** — that is the stable external
  user id Authentik links on.
- Add **Source property mappings** if you want CapAuth claims to populate
  Authentik user fields (e.g. `email` → email, `name` → name, `groups` →
  groups). Authentik's generic OIDC source reads standard claims by default.

### 3.5 Test E2E

1. Open Authentik's login page → click **CapAuth**.
2. Authentik redirects to `…/oidc/authorize` → CapAuth's PGP login page renders.
3. Enter fingerprint, sign the nonce (CLI/extension), submit.
4. CapAuth redirects back to Authentik's callback with `code`+`state`; Authentik
   exchanges the code at `/oidc/token`, verifies the RS256 ID token against
   `/oidc/jwks.json`, reads `/oidc/userinfo`, and creates/links the user.
5. Authentik now fans SSO out to every downstream app it fronts.

---

## 4. Security boundary and remaining work

The browser flow requires an exact HTTPS issuer, registered redirect, scope,
state, nonce, confidential client, and RFC 7636 S256 challenge. Login requests
and codes are durable and one-use across restart. Only an explicitly enrolled
and approved fingerprint can complete login. ID and access tokens are bounded
to five minutes. UserInfo checks durable token currentness, the registered
client and scope, and enrollment approval on every request. Rate-limit,
enrollment, signing, configuration, and state outages deny without being
collapsed into an authentication denial.

- **Refresh tokens.** The browser authorization-code boundary intentionally
  issues no refresh token. Refresh-family work belongs to its separately gated
  contract.
- **Dynamic client registration.** Clients are static config only (no
  `/register`, no admin CRUD).
- **Signing-key rotation / multi-key JWKS.** Single key, single `kid`. No
  overlap window for rotation; JWKS publishes exactly one key.
- **Scope-filtered claims.** All mapped claims are included; per-scope claim
  filtering (`map_claims(requested_scopes=…)`) is not yet applied at the token
  endpoint.
- **PGP login page polish** (QR/extension auto-fill hooks exist in other flows;
  this page is minimal server-rendered HTML).

---

## 5. Code map

| File | Purpose |
|---|---|
| `src/capauth/service/oidc/signing_key.py` | RSA signing key (load/generate/persist), JWK/JWKS export, stable `kid`. |
| `src/capauth/service/oidc/clients.py` | Static `ClientRegistry` / `OIDCClient` (env- or file-driven). |
| `src/capauth/service/oidc/store.py` | `AuthCodeStore` (login requests + auth codes) and `verify_pkce`. |
| `src/capauth/service/oidc/provider.py` | The FastAPI router: discovery, JWKS, authorize (PGP login page), complete, token, userinfo. Reuses `capauth.authentik.{stage,verifier,nonce_store,claims_mapper}`. |
| `src/capauth/service/app.py` | Mounts the router at `/oidc` + root discovery alias. |
| `tests/test_oidc_idp.py` | Unit tests (discovery/JWKS/PKCE/code flow, PGP mocked). |
| `tests/test_oidc_idp_e2e.py` | E2E with a real generated PGP key (no crypto mocked). |

## Passkey (WebAuthn) front-door — convenience tier

A passkey is an **additive, phishing-resistant authenticator bound to an
existing PGP fingerprint — not a new identity.** The sovereign PGP key stays the
root of trust; the passkey is easy-mode.

- **Register (PGP-gated):** `POST /oidc/passkey/register/begin` verifies a PGP
  signature for the fingerprint, then returns WebAuthn creation options + a
  binding ticket; `POST /oidc/passkey/register/complete` stores the credential.
  A passkey can only be created for a key you can sign with. Enrollment page:
  `GET /oidc/passkey/enroll`.
- **Login:** `POST /oidc/passkey/login/begin` (with the OIDC `request_id`) →
  `POST /oidc/passkey/login/complete` verifies the assertion, requires the
  resolved fingerprint to be an approved CapAuth identity, and mints the SAME
  authorization code/identity (`sub` = fingerprint) with **`amr=["webauthn"]`**
  (vs `["pgp"]`) so relying parties can tell the tier. A "🔑 Sign in with a
  passkey" button sits on `/oidc/authorize`; browser helpers at `/oidc/passkey.js`.
- **Store:** `oidc/passkey.py` `PasskeyStore` — persisted credentials (keyed by
  credential id → fingerprint + public key + sign count), in-memory ceremony
  challenges. RP id/origin derive from the issuer. Dep: `webauthn` (capauth[service]).
- **Verified:** full register→login ceremony in Python (soft-webauthn) AND live
  in a browser with a virtual authenticator → a passkey login minted an OIDC code.
