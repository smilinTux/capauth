# Decision Document: Long-Term Strategy for the CapAuth ↔ Authentik Integration

**Status:** DECIDED — Chef approved Option B (two-track strategy, §5) on 2026-10-23,
as part of the full Authentik 2026.8.5 upgrade (framework release v2.26.17).
Decision relayed verbatim through the coordinator: "patch now, and b for capauth."
Scope: this applies to the full 2026.8.5 migration, not the 2026-10-23 tactical
same-line security patch (nor to 2025.12.6, NAM to 2026.2.7), which keeps both
images on their current major line and does not touch the fork or the Source
integration. See "2026-10-23 cutover plan" at the end of this document.
**Date:** 2026-06-22 (proposed) / 2026-10-23 (decided)
**Author:** Opus (research + recommendation); decision recorded by Lumina per Chef/coordinator
**Scope:** How to maintain the CapAuth PGP passwordless login *inside* Authentik
long-term — upstream PR, fork/custom image, redistributable package, or drop
Authentik in favor of native per-app plugins.

> TL;DR recommendation: **Stop investing in the forked custom image as the
> primary path. Adopt a two-track strategy: (1) make native per-app CapAuth
> plugins the default sovereign login (Nextcloud is already done and works in a
> real browser); (2) keep Authentik integration alive in a *backend-only,
> non-web-patching* form — a custom Django app layered on the stock image with
> NO web-bundle rebuild — and use Authentik's *existing* WebAuthn/passkey or an
> OIDC-source bridge for the browser UI rather than shipping our own Lit
> component.** Only pursue an upstream PR if we first reframe CapAuth as a
> *Source* (external IdP) rather than a built-in *Stage*. See §5.

---

## 1. What our changes actually are, and why they are fragile

### 1.1 The two artifacts

| Artifact | What it is | Where |
|---|---|---|
| **CapAuth backend stage** | A Django app: `CapAuthStage` model + `CapAuthStageView` (flow-executor `ChallengeStageView`), DRF serializer/viewset, `nonce_store`, `verifier`, `claims_mapper`, plus a `CapAuthKeyRegistry` model that *is* the entire user DB (one row per PGP fingerprint). | `src/capauth/authentik/` |
| **CapAuth web component** | A Lit web component `ak-stage-capauth` (`BaseStage` subclass) that renders the fingerprint→nonce→signed-response UI in the flow executor. | `web/stages/capauth/CapAuthStage.ts` |

These are stitched into Authentik by **`Dockerfile.authentik-capauth`** (cap12 =
current), which:

1. Clones `goauthentik/authentik` at `version/2026.5.3`, `npm ci`s the exact
   pinned deps, copies our component into `web/src/flow/stages/capauth/`,
   **appends an `import` to the internal `src/flow/index.entrypoint.ts`**, and
   runs `npm run build` to recompile Authentik's whole web bundle.
2. Installs the `capauth` Python package + PGPy into the stock server image's
   detected venv site-packages, and **vendors an `imghdr` shim** (PGPy 0.6.0
   `import imghdr`; stdlib-removed in py3.13 per PEP 594; AK 2026.5.x runs
   py3.14).
3. Registers the Django app by dropping `/data/user_settings.py` that puts
   `capauth` into `TENANT_APPS`, and bakes a blueprint creating the stage + flow.

### 1.2 Why it is fragile (the cost of forking — observed, not theoretical)

Every one of these has already bitten us on `.13`:

- **The web bundle must be recompiled from source on every version bump.** There
  is no extension point: `src/flow/index.entrypoint.ts` and the stage-dispatch
  registry are *internal* files. We edit Authentik's own source to register a
  component.
- **The from-source web build is currently broken and shipped DISABLED.** `npm
  run build` hits an esbuild code-splitting bug — a shared chunk defines Lit's
  `createRef` but doesn't re-export it across the chunk boundary → runtime SPA
  throws `does not provide an export named 'createRef'` → blank spinner, SPA
  never boots. Identical under `npm ci` *and* `npm install`, so it is the
  from-source build itself, not version drift. **Net effect: cap9–cap12 ship the
  stock frontend, so the `ak-stage-capauth` component is ABSENT — the PGP login
  form does not render in a browser.** PGP login is only proven via the
  flow-executor API. (Our own blueprint comment says: "For in-browser PGP today,
  use the native nextcloud `capauth` plugin instead.")
- **Python-minor drift across releases.** The venv Python moved 3.13 → 3.14; we
  detect site-packages at build time and vendor an `imghdr` shim because a
  transitive dep (PGPy) relies on a removed stdlib module.
- **Internal flow-state assumptions broke us twice.** `plan.context` in-place
  mutations don't persist across Django session writes (two-step nonce loss);
  `HttpChallengeResponse(...)` requires an explicit `.is_valid()` before `.data`.
  These are undocumented internals that can change between releases.
- **Migration timing.** A custom system-migration ran `ak migrate capauth` too
  early on a fresh DB (`relation authentik_version_history does not exist`); we
  had to fall back to standard `python -m lifecycle.migrate`.

**Bottom line:** the *backend* stage is reasonably robust (it rides documented-ish
flow-executor contracts). The *frontend* is the structural liability: there is no
supported way to add a flow-stage web component without rebuilding Authentik's
bundle, and that rebuild is currently broken. The fork's headline feature
(in-browser PGP login) does not actually ship today.

---

## 2. Authentik's actual extension capabilities for custom stages

### 2.1 There is no plugin system. This is by design and stated by the founder.

The clearest source is **issue [#1541 "Custom plugin support"](https://github.com/goauthentik/authentik/issues/1541)** (closed). The
maintainer/founder **BeryJu** responded directly (verified via GitHub API):

> "A more general answer; in theory it's possible. You can just add a django
> application; **there would have to be some changes made to allow dynamic
> hooking into all the places without having to modify the core.**
> Currently, my opinion is that **any custom applications either make sense to
> merge upstream, or shouldn't be django applications and instead use the API.**"

This is the governing position. It tells us three things:

1. **Custom Django apps are not a supported public extension path.** They "work"
   only because Django + `user_settings.py` lets you bolt one on — but the core
   would need changes for clean dynamic hooking, and those changes don't exist.
   Our `TENANT_APPS` injection is a **hack**, not a sanctioned mechanism.
2. **The sanctioned answers are: merge upstream, or use the API** (i.e. integrate
   from outside via OIDC/SCIM/the REST API rather than living inside the process).
3. There is **no runtime/sideloaded stage loading** roadmap.

### 2.2 No runtime frontend stage registration exists

Authentik's web frontend is a **single compiled bundle** built with esbuild +
wireit across npm workspaces (`@goauthentik/web`, `@goauthentik/core`,
`@goauthentik/web-sfe`), using Lit web components. Stages are dispatched from a
compile-time registry in the flow interface. There is **no documented mechanism
to register a flow-stage web component at runtime or sideload one**; confirmed by
the docs (no plugin/extension API in
[Contributing](https://docs.goauthentik.io/developer-docs/contributing/) or the
[developer docs](https://docs.goauthentik.io/developer-docs/)) and by the
frontend architecture (see the [Web Frontend System](https://deepwiki.com/goauthentik/authentik/2-web-frontend-system)
overview). To add a stage component you **must** modify and rebuild the bundle —
exactly what we do, and exactly what breaks.

### 2.3 What Authentik *does* support as extension points

- **Blueprints** ([docs](https://docs.goauthentik.io/customize/blueprints/)):
  declarative YAML to create/configure stages, flows, providers, brands. This is
  configuration-as-code, **not** a way to add *new stage types* — it can only
  instantiate stage classes that already exist in the running image. (We use it
  correctly to wire the flow once the class is baked in.)
- **The REST API / Terraform**: manage all objects externally. The sanctioned
  "use the API" path.
- **Sources** ([docs](https://docs.goauthentik.io/users-sources/sources/)):
  Authentik can *consume* external identity from OAuth/OIDC/SAML/LDAP/SCIM
  sources. **This is the supported way to plug in a foreign IdP** — and it is the
  one extension point that fits CapAuth without touching Authentik's bundle (see
  §4 Option C and §5).
- **Expression policies / property mappings**: Python snippets evaluated at
  runtime — useful for claims logic, but cannot render a custom login UI or
  implement a challenge/response stage.
- **`AUTHENTIK_*` env + `user_settings.py`**: configuration override hook. It
  loads custom settings (and can append to `TENANT_APPS`), but that is settings
  injection, not a stage-plugin API — and per BeryJu it is not a supported way to
  ship a custom Django app.

**Conclusion for §2:** Authentik has **rich configuration extensibility (blueprints,
API, Terraform) and a supported way to federate external IdPs (Sources), but NO
plugin mechanism for custom flow STAGES, and specifically no way to add a stage
WEB COMPONENT without rebuilding the core bundle.** Our fork exists precisely
because the thing we need doesn't exist.

---

## 3. Would the CapAuth PGP stage be accepted upstream?

### 3.1 Contribution model

Authentik takes community PRs (code/docs/features) per
[Contributing](https://docs.goauthentik.io/developer-docs/contributing/):
feature-branch PRs, black/Ruff linting, tests expected, status checks must pass.
New built-in stages have historically landed as first-party PRs (e.g. the
WebAuthn/passkey stages). There is no documented CLA in the contributing guide,
but the project is commercially backed (Authentik Security, Inc.) with an
open-core model, so a CLA may be requested in practice.

### 3.2 Precedent and scope fit

- **Passwordless precedent exists and is strong.** Authentik already ships
  WebAuthn/FIDO2/Passkeys ([docs](https://docs.goauthentik.io/add-secure-apps/flows-stages/stages/authenticator_webauthn/))
  with active investment (WebAuthn L3 `hints` added in
  [2026.5](https://docs.goauthentik.io/releases/2026.5/)). So "passwordless
  challenge/response crypto login" is squarely in-scope conceptually.
- **But PGP-as-a-login-factor is niche relative to their direction.** The market
  and the maintainers are converging on **passkeys/WebAuthn** (their MFA blog
  argues phishing-resistant FIDO2 is the future:
  [link](https://goauthentik.io/blog/2025-03-05-mfa-in-authentik/)). A
  PGP-fingerprint primary-login stage — where the fingerprint *is* the user and
  the user table is a key registry — is a sovereign-identity philosophy that does
  not match Authentik's user model (real `User` objects, brands, enterprise RBAC).
- **The custom-stage appetite is unproven.** The open feature request for
  generic custom stages ([#17726](https://github.com/goauthentik/authentik/issues/17726))
  sits at `status/reviewing` with no maintainer commitment, and the plugin
  request ([#1541](https://github.com/goauthentik/authentik/issues/1541)) was
  closed pointing people to "upstream or API."

### 3.3 Assessment

**Low-to-moderate probability of acceptance as a built-in *Stage*; higher as a
*Source*.** A PGP-challenge *Stage* asks the maintainers to adopt and maintain a
crypto path (PGPy, nonce store, a parallel key-registry user model) that
duplicates the role of their passkey work and carries an unusual identity model.
Realistically that gets "interesting, but use the API / make it a Source."
Reframing CapAuth as an **OIDC/OAuth Source** (CapAuth service is the IdP,
Authentik consumes it) needs **zero** new built-in stage and uses an extension
point they actively support — that is far more upstream-friendly *and* removes our
web-patching problem entirely. (See §5.)

---

## 4. Options and tradeoffs

### Option A — Upstream PR to Authentik core (the stage)

| | |
|---|---|
| **What** | Submit `CapAuthStage` + web component as a built-in stage PR. |
| **Maintenance** | Low *if merged* (they carry it). High *until* merged (rebase against a fast-moving codebase) and merge is uncertain. |
| **Version fragility** | Eliminated if merged (it's in-tree). |
| **Who can use it** | Everyone, out of the box — best reach. |
| **Time cost** | High + unbounded: shape to their conventions, tests, review cycles, likely a CLA, likely rejection or "make it a Source." |
| **SKWorld fit** | Good if accepted (sovereign PGP login becomes mainstream IdP capability). Poor expected value given §3 acceptance odds. |
| **Verdict** | Don't lead with this for the *Stage*. Viable only if reframed as a *Source* (Option C/§5). |

### Option B — Maintain the custom image fork (current state)

| | |
|---|---|
| **What** | Keep `Dockerfile.authentik-capauth`, rebuild + re-patch per version. |
| **Maintenance** | **High and recurring.** Re-patch internal files, fight the esbuild `createRef` bug, re-`npm ci`, re-verify the component renders, re-handle py-minor/imghdr drift, re-test flow internals — every bump. |
| **Version fragility** | **Worst of all options.** Breaks on web-bundle internals each release; the web build is *currently broken*, so the headline feature (browser PGP form) doesn't ship today. |
| **Who can use it** | Only us (and anyone who pulls our ghcr image and trusts it). |
| **Time cost** | Recurring engineer-days per Authentik release, indefinitely. |
| **SKWorld fit** | Centralized SSO is attractive, but a fork that breaks on every bump and can't render its own UI is a liability, not an asset. |
| **Verdict** | Not sustainable as the primary path. At most keep a **backend-only** variant (no web rebuild) for API/headless use. |

### Option C — Redistributable Authentik integration (no core fork)

Two sub-flavors, both avoiding the web-bundle patch:

**C1 — Backend-only custom Django app, stock frontend.** Ship the `capauth`
Django app as a layer on the *unmodified* official image (the cap9+ reality
already does this), wire it via blueprint, and **don't** ship a web component.
The stage works via the flow-executor API / headless / CLI / extension clients,
not the browser form.

**C2 — CapAuth as an OIDC/OAuth *Source* (recommended sub-flavor).** Run the
existing standalone CapAuth service (`ghcr.io/smilintux/capauth`) as the IdP;
register it in Authentik as an **OAuth/OIDC Source**. The browser does PGP login
*on CapAuth's own page* (which we fully control — no Authentik bundle), then
Authentik federates the identity in. Authentik then fans out SSO to all
downstream apps.

| | C1 (backend Django app) | C2 (OIDC Source) |
|---|---|---|
| **Maintenance** | Medium: app rides flow-executor contracts; no web rebuild. | **Low:** OIDC is a stable, versioned standard; Authentik's Source support is first-class. |
| **Version fragility** | Low-medium: only backend internals, no esbuild. | **Lowest:** OIDC contract is decoupled from Authentik internals. |
| **Browser PGP UI** | ✗ (no component → stock UI can't render PGP). | ✓ (on CapAuth's own login page). |
| **Who can use it** | Anyone running our image layer. | **Anyone running stock Authentik** + our CapAuth service. No custom Authentik image at all. |
| **Time cost** | Low ongoing; medium to build a clean redistributable. | Medium one-time to build the OIDC IdP endpoints in the CapAuth service; then near-zero. |
| **SKWorld fit** | OK as a headless/API capability. | **Excellent:** centralized SSO from one PGP login, sovereign service we own, no fork. |

### Option D — Drop Authentik; native per-app CapAuth plugins

| | |
|---|---|
| **What** | Each app gets a native CapAuth plugin using *that app's* supported extension API. **Nextcloud is done and proven.** |
| **Evidence** | `src/capauth/integrations/nextcloud/` is a complete, idiomatic Nextcloud app: real `IUserBackend` (`lib/User/Backend.php`), `AlternativeLogin/CapAuthLogin.php` ("Sign in with CapAuth" button), challenge/verifier/provisioning/group-sync services, DB migration, nonce-prune background job, registered via `appinfo/info.xml`. It is **passwordless PRIMARY login in a real browser** — the thing the Authentik fork can't currently do. |
| **Maintenance** | Per-app, but each uses *supported* extension points (stable, documented), so far less fragile than patching Authentik's bundle. Cost scales with number of apps. |
| **Version fragility** | Low per app (app APIs are stable contracts). |
| **Who can use it** | Anyone running that app — and it's publishable to the app's marketplace (Nextcloud app store), real reach. |
| **Time cost** | One plugin per target app (Forgejo scaffold exists; others TBD). No central SSO — N integrations for N apps. |
| **SKWorld fit** | **Excellent for sovereignty** (no central dependency, each app fully owned), **weak for scale** (no single login → many apps; re-implement per ecosystem). |

---

## 5. Recommendation

**Adopt a two-track strategy. Retire the web-patching fork as the primary path.**

### Track 1 (now): native per-app plugins are the default sovereign login — Option D

Nextcloud already delivers what the Authentik fork promised: **passwordless PGP
PRIMARY login that renders in a real browser**, via Nextcloud's *supported*
extension points. Make this the canonical CapAuth login experience for our
highest-value apps. It is sovereign, marketplace-publishable, and not fragile.
Prioritize the next 1–2 apps by actual need (Forgejo scaffold already exists).

### Track 2 (next): centralized SSO via CapAuth-as-OIDC-Source — Option C2

For the "one PGP login → many apps" value that only an IdP gives, **do not** keep
fighting Authentik's bundle. Instead:

1. Add OIDC/OAuth2 *provider* endpoints to the standalone CapAuth service
   (authorize/token/userinfo/jwks) so it is a real IdP. The PGP challenge UI
   lives on **CapAuth's own page** — fully ours, zero Authentik web patching.
2. Register CapAuth in **stock** Authentik as an **OAuth/OIDC Source**. Authentik
   then fans SSO out to every downstream app it fronts.
3. This uses an extension point Authentik *actively supports*, runs on the
   **official unmodified image**, and is decoupled from Authentik internals via
   the stable OIDC standard — eliminating the version-bump treadmill.

### What to do with the existing fork: downgrade, don't delete

- **Stop shipping the web-builder stage.** It's already disabled; make that
  permanent. Do not invest more in the esbuild `createRef` fix — there is no
  supported home for a custom stage component, so even a fixed build re-breaks
  next release.
- **Keep the backend Django app (Option C1) only as a headless/API capability**
  if a concrete need exists (CLI/extension/agent flows that hit the flow-executor
  API directly). Otherwise archive it once C2 lands.
- Tag the last fork image clearly as "backend/API-only; no browser PGP form; see
  AUTHENTIK_STRATEGY_DECISION.md."

### Only pursue upstream (Option A) in this specific shape

If we ever want it mainstream, propose CapAuth to Authentik **as a Source / IdP
integration**, not as a built-in challenge *Stage*. That matches BeryJu's stated
"upstream or use the API" position, needs no new web component, and is far more
likely to be accepted. A PGP *Stage* PR is low-EV and should not be our first move.

### Why this is right

- It **removes the only structurally unfixable problem** (no runtime stage-component
  loading → mandatory bundle rebuild → currently broken).
- It **keeps both strategic values**: sovereignty + working browser login (Track 1,
  proven) and centralized SSO from one PGP login (Track 2, on stock Authentik).
- It moves us onto **supported extension points everywhere** (Nextcloud app API;
  Authentik Sources/OIDC) instead of patching internals — slashing
  version-bump fragility.
- It is **honest about what ships today**: the fork's headline feature doesn't
  render in a browser; Nextcloud's does.

---

## 6. Concrete next steps

1. **Decision sign-off (Chef):** approve the two-track strategy; mark the
   web-patching fork as deprecated-for-browser-use.
2. **Track 1:** publish/polish the Nextcloud CapAuth app (it's complete); pick
   the next target app (Forgejo scaffold → finish, or another high-use app).
3. **Track 2 (spike):** add OIDC provider endpoints to the standalone CapAuth
   service; stand up stock Authentik with CapAuth registered as an OAuth/OIDC
   **Source**; prove PGP-login→Authentik-session→downstream-app SSO E2E on `.13`.
   This replaces the cap-image deploy.
4. **Fork housekeeping:** freeze `Dockerfile.authentik-capauth` at backend-only;
   add the "no browser PGP form" banner to `docs/authentik-capauth.md` and the
   blueprint header; stop chasing the esbuild `createRef` bug.
5. **Upstream (optional, later):** open a discussion proposing CapAuth as a
   *Source* integration, not a built-in stage, if/when Track 2 is solid.

---

## Sources

- BeryJu (authentik founder) on custom plugins — "merge upstream, or use the API":
  <https://github.com/goauthentik/authentik/issues/1541> (verified via GitHub API)
- Custom stages feature request (open, `status/reviewing`, no maintainer commitment):
  <https://github.com/goauthentik/authentik/issues/17726>
- Contributing to authentik (no plugin/extension API documented):
  <https://docs.goauthentik.io/developer-docs/contributing/>
- Developer documentation overview: <https://docs.goauthentik.io/developer-docs/>
- Web Frontend System (single compiled esbuild/Lit/npm-workspaces bundle; no runtime stage loading):
  <https://deepwiki.com/goauthentik/authentik/2-web-frontend-system>
- Stages overview (stages are core building blocks; created via admin/API/Terraform from existing types):
  <https://docs.goauthentik.io/add-secure-apps/flows-stages/stages/>
- Blueprints (declarative config of existing objects, not new stage types):
  <https://docs.goauthentik.io/customize/blueprints/>
- Sources (supported way to federate external IdPs — the C2 path):
  <https://docs.goauthentik.io/users-sources/sources/>
- WebAuthn / FIDO2 / Passkeys stage (existing passwordless precedent + direction):
  <https://docs.goauthentik.io/add-secure-apps/flows-stages/stages/authenticator_webauthn/>
- MFA direction blog (phishing-resistant FIDO2/passkeys as the priority):
  <https://goauthentik.io/blog/2025-03-05-mfa-in-authentik/>
- Release 2026.5 (WebAuthn L3 hints — ongoing passkey investment):
  <https://docs.goauthentik.io/releases/2026.5/>
- Flows/stages/policies explainer: <https://goauthentik.io/blog/2024-08-27-flows-stages-and-policies/>

### Internal evidence (this repo)
- Fork mechanics + disabled web build + reasons: `Dockerfile.authentik-capauth`
- Backend stage + flow-state/migration learnings: `src/capauth/authentik/stage.py`
- Web component (the un-loadable piece): `web/stages/capauth/CapAuthStage.ts`
- Blueprint admitting "use the native nextcloud plugin for in-browser PGP":
  `src/capauth/authentik/blueprints/capauth-pgp-login.yaml`
- Working native browser login (Option D proof):
  `src/capauth/integrations/nextcloud/` (`lib/User/Backend.php`,
  `lib/AlternativeLogin/CapAuthLogin.php`)
- Deploy history / E2E-API-only proof: `HANDOFF-capauth-authentik-2026-06-17.md`


---

## 2026-10-23 cutover plan (nor, as part of the 2026.8.5 upgrade, v2.26.17)

Chef's decision is Option B / Track 2 (CapAuth as an OIDC/OAuth Source on stock
Authentik). This section records the concrete cutover plan for **nor**, the only
estate still running the `Dockerfile.authentik-capauth` fork. NAM is unaffected
(always ran stock Authentik, never had the fork).

### What changes

- nor's `sksso-prod_server`/`_worker` move from the custom image
  (`skgit.skstack01.douno.it/skadmin/authentik-capauth:*`) to the **stock**
  `ghcr.io/goauthentik/server:2026.8.5` image, the same image NAM runs.
- The sksso role's `sksso.CAPAUTH_ENABLED: true` path (documented in
  `v1/ansible/optional/sksso/README.md`, "CapAuth login (optional)") replaces
  the baked-in stage: the standalone `capauth` service becomes an Authentik
  **OAuth Source**, with its own login flow, instead of a flow stage compiled
  into Authentik's bundle. This is already-shipped, already-tested code (commit
  `ecc8e50`, "per-client require_nonce so stock Authentik's OAuth source can
  log in"), not new engineering.
- The existing CapAuth flow/stage objects baked in by the fork's blueprint (see
  `AUTHENTIK_DEPLOYMENT_SKSSO.md`, flow `97730dbd-b5fc-4171-8dce-4de5273c1db2`)
  are superseded by `tasks/capauth_provision.yml`'s `CAPAUTH_FLOW_SLUG`
  (default `capauth-authentication`) and OAuth source objects. They are NOT
  touched automatically; retiring the old objects is a manual admin-UI cleanup
  step after the new flow is proven (see "Rollback" in the README's CapAuth
  section for the exact unbind order, run in reverse as an adopt order).
- Enrolled users move from the fork's `CapAuthKeyRegistry` (one row per PGP
  fingerprint, no linked Authentik user) to `sksso.CAPAUTH_USERS`
  (fingerprint maps to an existing Authentik user). Every current nor CapAuth
  user must be re-enrolled against an actual Authentik user account before
  cutover, or their login breaks. This is the one step with real user-facing
  migration risk and needs its own checklist before the lab run.

### Order of operations (lab first, skstack06, before any nor change)

1. Deploy the sksso role on skstack06 at nor's exact current state: stock
   2025.12.6 (post-tactical-patch) is NOT the fork, so model the fork explicitly
   by building `authentik-capauth:2025.12.6` there too, so the lab reproduces
   nor's real pre-cutover shape, not a simplified stand-in.
2. Seed representative data: a handful of users and groups, at least one OIDC
   provider, the embedded outpost plus a forward-auth proxy provider, and
   enough CapAuth-fork enrollments to exercise the migration.
3. Enable `sksso.CAPAUTH_ENABLED: true` alongside the still-running fork, bring
   up the `capauth` service and OAuth source, and prove login through the new
   path end to end (challenge and verify, OAuth source login, SSO fan-out)
   while the old path still works too (parallel-run, not cutover yet).
4. Only once the new path is proven: swap `sksso.IMAGE`/`authentik_version` to
   stock `2026.8.5`, set `CAPAUTH_ENABLED: true` for real, remove the fork
   image reference, and re-verify every login path (password, OIDC apps,
   forward-auth, the new CapAuth OAuth source) plus the rollback (restore the
   pre-cutover dump, confirm the fork image still boots against it).
5. The full upgrade path for nor to reach 2026.8.5 still applies underneath
   this (2025.12.6 to 2026.2.7 to 2026.5.7 to 2026.8.5); the CapAuth cutover
   happens at the LAST hop, once nor is already on stock Authentik, not
   before, since doing it earlier would mean rebuilding the fork against an
   intermediate version for no reason.

### Fork retirement (after the lab proof and after nor is cut over)

- Freeze `Dockerfile.authentik-capauth` and
  `scripts/build_authentik_capauth_image.sh`: add a banner pointing at this
  decision and `CAPAUTH_ENABLED`, do not delete (historical reference and the
  one documented rollback path if the Source integration needs to be backed
  out urgently).
- Archive the `release/authentik-capauth-cap10`, `cap11`, `cap12` branches (do
  not force-delete; they are the build history for the fork, useful if anyone
  needs to reconstruct exactly what nor ran).
- Update `docs/authentik-capauth.md` with a top banner: "superseded by
  CAPAUTH_ENABLED, see AUTHENTIK_STRATEGY_DECISION.md".
