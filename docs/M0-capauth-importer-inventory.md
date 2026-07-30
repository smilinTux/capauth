# M0: capauth Importer Inventory (blast-radius map)

**Status:** FROZEN (M0 deliverable, card R0.1).
**Date:** 2026-07-30.
**Companion:** `docs/M0-capauth-api-v1.md` (the API v1 contract freeze).
**Purpose:** enumerate everything that imports or depends on capauth today, across
the SKWorld repos, so the M1-M3 extraction can shim every caller safely. A missed
caller is worse than noise; this map errs toward completeness.

Repos swept (ripgrep over each absolute path):
`capauth`, `skcapstone`, `skchat`, `skchat-app` (Dart), `skcomms`, `skmemory`,
`skgateway` (Node), `skos`, `skharness`. Note: `~/clawd/skcapstone-repos/skos`
does NOT exist on disk (the skos platform code the roadmap references is elsewhere
or not yet a sibling repo); it contributes zero capauth importers here.

---

## 0. Headline numbers

- **4 Python repos import capauth at runtime:** `skcapstone`, `skchat`, `skcomms`,
  `skmemory`. `skgateway` (Node) reimplements the protocol in JS; `skharness`
  gates via an injected fail-closed seam with no capauth import; `skchat-app`
  (Dart) delegates all capauth-authoritative signing to the local SKComms daemon
  over HTTP and imports nothing.
- **Most-coupled repo:** `skcapstone` (identity resolver + crypto + profile + did +
  the trust/tokens modules that MOVE into capauth + the MCP tool wrappers). Second:
  `skchat` (identity resolver in 8+ modules, plus the pairing and authz surfaces
  the folds replace).
- **Two undeclared-but-importing consumers:** `skchat` and `skmemory` import
  capauth but do NOT declare it in packaging. Fix before the M1 venv upgrade.
- **Zero cross-repo importers of the modules that MOVE** (`skcapstone.trust_graph`,
  `skcapstone.trust_calibration`, `skcapstone.tokens`): every caller is
  skcapstone-internal, so M1 is a low-risk mechanical move behind shims.
- **capauth's OIDC / Authentik / login / bunker service surface has zero
  downstream Python importers:** consumed only via the `capauth` /
  `capauth-service` CLI and HTTP, never as a Python API.

### Dependency-declaration status

| Repo | Declares capauth? | Evidence |
|---|---|---|
| capauth | is the package | `pyproject.toml` `name = "capauth"`; scripts `capauth`, `capauth-service` |
| skcomms | YES (pinned) | `pyproject.toml:55,108` `"capauth>=0.1.0"`; `constraints.txt:28` `capauth==0.2.3` |
| skcapstone | YES | `pyproject.toml:53,84` `"capauth>=0.1.0"` |
| **skchat** | **NO (imports, does not declare)** | not in `skchat/pyproject.toml`; imports in 8+ src modules |
| **skmemory** | **NO (imports, does not declare)** | not in `pyproject.toml`/`requirements.txt`; imports in `context_loader.py:480` |
| skgateway | N/A (Node) | `package.json` keyword only; JS reimpl `src/identity/capauth.mjs` |
| skharness | NO (seam only) | injected `verify_caller`, fail-closed placeholder; no import |
| skchat-app | N/A (Dart) | no dep; capauth signing delegated to SKComms daemon |

---

## 1. IDENTITY domain callers (`resolve_agent_identity` / `AgentIdentity` / `capauth.agent_identity` / `resolve_capauth_home` / `capauth_uri` / `fqid`)

This is the largest coupling surface. All CURRENT (section 1 of the API doc);
FROZEN, so these callers are NOT touched by M1-M3 except where noted.

### skcapstone
- `src/skcapstone/fleet/store.py:47,49` `from capauth import resolve_agent_identity` -> `.capauth_uri`
- `src/skcapstone/fleet/signing.py:67` `from capauth import resolve_capauth_home`; `:91,140` `from capauth.crypto import get_backend`
- `src/skcapstone/cli/identity_cmd.py:204,206` resolver + `.fqid` (`_MANAGED_FIELDS` incl. fqid at `:38`)
- `src/skcapstone/doctor.py:971,998,1000` resolver + `.capauth_uri` (the `identity:*` doctor checks)
- `src/skcapstone/operator_link.py:112,113,165` `capauth.crypto`, `capauth.profile`, `resolve_capauth_home`
- `src/skcapstone/pillars/identity.py:124,146,147,173` `capauth.profile`, `capauth.models`, `capauth.keys`
- `src/skcapstone/onboard.py:1513,1514,1609` `capauth.profile`, `capauth.sync`
- `src/skcapstone/consciousness_loop.py:2240`, `sync_engine.py:347`, `sync/vault.py:406,467,507`, `discovery.py:118` `capauth.crypto` / `capauth.profile`
- `src/skcapstone/whoami.py:240` `import capauth` (importability probe)
- `src/skcapstone/mcp_tools/did_tools.py:219,285,345,443` `capauth.did`
- `src/skcapstone/mcp_tools/capauth_tools.py:60,71,136,165` `import capauth`, `capauth.profile`, `capauth.did`, `capauth.tokens` (note `:165` is the tokens MOVE surface, see section 4)
- Tests: `tests/test_cross_package.py:112,413,428`, `tests/test_identity_migrate.py:30`, `tests/test_doctor.py:669,686`

### skchat (resolver in 8+ modules)
- `src/skchat/identity_bridge.py:75,77,133,135,138` resolver (the SEAM-7 delegate)
- `src/skchat/spaces/federation/assertion.py:36,37,39,50` `from capauth import resolve_agent_identity` + `capauth.crypto`
- `src/skchat/p2p_calls.py:34,36`, `federation_status.py:59,61`, `call_routes.py:49,51`,
  `agent_profile.py:102,104,111,115,129`, `conf/fed_client.py:61,63`, `pq_invites.py:309,311`
- `scripts/preflight_glossa_live.py:75,76` `capauth.crypto`, `capauth.crypto.base`
- Tests: `tests/test_identity_bridge.py:135` (+ patches `capauth.agent_identity.resolve_agent_identity`)

### skcomms
- `src/skcomms/identity.py:46,52,56,58,69` resolver + builds `capauth:<name>@skworld.io`
- `src/skcomms/realm.py:61,63` resolver -> `.fqid`
- `src/skcomms/did_router.py:116,133,172,215,287` `capauth.did`
- `src/skcomms/capauth_validator.py:118,119` `capauth.crypto.pgpy_backend._assert_key_usable`, `capauth.exceptions`
- Tests: `tests/test_identity_realm.py:104,106,159,161`

### skmemory
- `skmemory/skmemory/context_loader.py:478-484,634` `from capauth import resolve_agent_identity` (graceful/optional), `.fqid`

### skgateway (Node, NOT a Python importer)
- `src/identity/capauth.mjs:67-139` hardcoded agent registry with `capauth_uri`
  values for lumina/jarvis/opus/artisan/herald/sentinel/architect/scholar/steward/coder.
  Reimplements the resolver in JS; will need its own update if the URI shape ever
  changes, but is NOT a Python import.

### skchat-app (Dart)
- Uses `fqid` as the peer key throughout (`lib/services/skcomms_client.dart:162`,
  `lib/core/chat_text.dart:118`, `lib/features/conversation/conversation_provider.dart:265`,
  `conf/conf_screen.dart:27,40,55`, `call_shared/in_call_panels.dart:35`,
  `post_quantum_badge.dart:17`) and strips the `capauth:` prefix
  (`lib/services/agent_model_service.dart:121,124`). Consumes capauth identity, does
  not import the package.

**Flag:** none of these touch a TARGET-not-yet-implemented surface. Identity is
fully shipped. This whole group stays put.

---

## 2. PAIRING domain callers (the M2 fold surface)

Spec-confirmed: pairing bootstrap mostly does NOT consult capauth today. These are
the call sites the M2 fold converts to `capauth.pairing` delegates (API doc
section 2). Flagged TARGET because the module they will delegate to does not exist
yet.

### skchat
- `src/skchat/pairing_gate.py` (`PairingGate` at `:27`, `open_window` `:50`,
  `check` `:65`, `consume` `:80`) - **NO capauth import today.** TARGET: delegates
  window state to `capauth.pairing.open_window`.
- `src/skchat/guest_accept.py` (`trust_operator` `:511`, `is_operator_trusted`
  `:542`, `list_trusted_operators` `:546`, operator attestation `:135-150`,
  `ConsumedNonces` SQLite `trusted_operators` store) - **NO capauth import today.**
  TARGET: delegates to `enroll_device(mode=...)` / `list_devices`; the SQLite store
  demotes to a read cache.
- `src/skchat/join_routes.py` - **NO capauth import** (prose only at `:3,9,62,135`).
  TARGET: accept path records a `tofu` enrollment.
- `src/skchat/pq_invites.py:309,311` - **imports capauth** but only optionally, to
  read its own fqid (`resolve_agent_identity`, wrapped try/except at `:314-315`).
  TARGET: a redeemed invite records the enrollment through capauth.

### skcomms
- `src/skcomms/pairing.py` - **NO capauth import**; reads `~/.capauth/...public.asc`
  by PATH at `:90,92,104,151`. TARGET: folds onto the same kernel (card R2.3).
- `src/skcomms/public_pairing.py` - **NO capauth reference at all.** TARGET: same
  fold wave.

### skharness (future front door)
- skcode-hostd `/pair/*` routes (card R2.4) will proxy onto `capauth.pairing`. Not
  present yet; the P0 verifier `auth.py::require_bearer` deliberately denies all
  tokens until real pairing lands.

**Flag:** entire section is TARGET-adjacent. None of these break at M0/M1; they
convert during M2 behind `SKCHAT_PAIRING_KERNEL=off|shadow|on` with fixture replay.

---

## 3. AUTHZ domain callers (the M3 fold surface)

Spec-confirmed: skchat authz is self-contained. These are the M3 PEP fold sites
(API doc section 3). Flagged TARGET.

### skchat
- `src/skchat/dataplane_auth.py`: `dataplane_auth_enabled()` `:39` (reads
  `SKCHAT_DATAPLANE_AUTH`), `CapAuthValidator.validate` `:64`,
  `_verify_capauth_credential` `:75` (lazy-imports capauth INDIRECTLY via
  `skchat.spaces.federation.assertion`, which imports capauth - so the capauth
  dependency is transitive), `enforce_dataplane_auth` `:143`.
- Wired into routes: `src/skchat/daemon_proxy.py:32,738,912`
  (`Depends(require_dataplane_auth)` on send + inbox); `src/skchat/webui.py:39,51-63,1138`
  (middleware gate + dep).
- Tests: `tests/test_dataplane_auth.py`, `test_gate_middleware.py:93,109-134`,
  `test_dataplane_accepts_operator_session.py`.

### skcomms (a SEPARATE, real validator - not the M3 fold, but capauth-coupled)
- `src/skcomms/capauth_validator.py:181` `CapAuthValidator` (same class name,
  different module) imports `capauth.crypto.pgpy_backend` + `capauth.exceptions`.
  Wired at `api.py:30,149,2483`, `signaling.py:35,267-284`, `profile_router.py:23,33`,
  `did_router.py:45-47`, `transports/webrtc.py:752-754`. This one is CURRENT and
  stays; note the name collision with skchat's validator when reasoning about the
  fold.

**Flag:** skchat `dataplane_auth` is the TARGET PEP; it depends on capauth only
transitively today. M3 makes the dependency explicit via `capauth.authz.decide`,
gated by `SKCHAT_AUTHZ_PDP=off|shadow|enforce`.

---

## 4. TRUST + TOKENS modules that MOVE into capauth (M1)

The modules `skcapstone.trust_graph`, `skcapstone.trust_calibration`,
`skcapstone.tokens` move into `capauth.trust` / `capauth.tokens` (API doc sections
4 and 5). **Every caller is skcapstone-INTERNAL (relative imports). Zero cross-repo
importers.** This is the key low-risk finding for M1.

### skcapstone.tokens importers (all internal)
- `src/skcapstone/api.py:525,1911`, `daemon.py:2321`,
  `_cli_monolith.py:1433,1479,1533,1572,1598`, `cli/token.py:36,84,135,174,201`
- Already-capauth-path reference: `src/skcapstone/mcp_tools/capauth_tools.py:165`
  `from capauth.tokens import verify_token` (latently broken until M1 lands the
  module; verify after R1.1).
- Tests: `tests/test_tokens.py:11`, `test_cross_package.py:35`, `test_integration.py:28`,
  `test_trust_graph.py:16`

### skcapstone.trust_graph importers (all internal)
- `src/skcapstone/shell.py:266-267`, `dashboard.py:436,447`,
  `_cli_monolith.py:1755-1756`, `cli/trust.py:131-132`,
  `mcp_tools/trust_tools.py:104-105`, `mcp_server.py:3779-3780`
- Tests: `tests/test_trust_graph.py:17`, `tests/test_dashboard_trust.py:68`

### skcapstone.trust_calibration importers (all internal)
- `src/skcapstone/shell.py:287`, `_cli_monolith.py:1787`, `cli/trust.py:146`,
  `pillars/trust.py:336`, `mcp_tools/trust_tools.py:64`, `mcp_server.py:3715`
- Test: `tests/test_trust_calibration.py:10`

### MCP tool wrappers exposing trust_* / capauth_* (route through the shims after M1)
- `mcp_server.py`: `trust_calibrate` `:573`, `trust_graph` `:624`, `trust_rehydrate`
  `:2337`, `trust_status` `:2348`, `trust_febs` `:2357`, `capauth_secret_get` `:2234`,
  `capauth_status` `:2494`, `capauth_verify` `:2503`; handlers `:3713,3777,5151,5175-5191,5250,5257`
- `mcp_tools/trust_tools.py:13,41,62,102,118-119`,
  `mcp_tools/cloud9_tools.py:17,28,37,48,73,98,116-118`,
  `mcp_tools/capauth_tools.py:21,30,55,104,165,189-190`,
  `mcp_tools/skstacks_tools.py:22,168,288` (`capauth_secret_get`)

**Flag:** the MCP wrappers are the thing that must keep working byte-identically
through the M1 shims. `capauth_tools.py:165` already points at the capauth path.

---

## 5. CLI / subprocess invocations of the `capauth` binary

**No repo shells out to the `capauth` binary via subprocess/os.system/Popen.** All
`capauth <cmd>` occurrences are documentation strings, user-facing "run this"
hints, or a scheduled-job command STRING that is asserted but not executed.

- capauth (own): `src/capauth/integration.py:144` `"command": "capauth profile verify"`
  (job stub, asserted in `tests/test_integration.py:126`); usage examples in
  `cli.py`, `profile.py`, `login.py`, `custody.py`, `sync.py`, `did.py:470`,
  `service/oidc/provider.py:180`, `integrations/forgejo/oidc_provider.py:92`;
  `scripts/capauth-restore.sh:256` `capauth profile verify`.
- skcapstone: `onboard.py:1621,1896`, `doctor.py:834,878,1111` (hint strings, not exec).
- skchat: `scripts/bootstrap-node.sh:149` (prose "do NOT run capauth init");
  `scripts/preflight_glossa_live.py` (uses injected backends, not the CLI).
- No systemd unit and no yaml runtime path invokes `capauth`.

**Implication:** the CLI surface (`capauth init|profile|verify|export-pubkey|
register|login|mesh|pma|sign|sync`, `cli.py:51-1387`) has no programmatic callers
to shim; it is a human/ceremony surface.

---

## 6. capauth.service / OIDC / Authentik / login / bunker consumers

**Zero external Python importers.** No sibling repo imports `capauth.service`,
`capauth.login`, `do_login`, the OIDC provider/router, the Authentik stage, or the
bunker signer. All references live inside capauth's own `src/` and `tests/`. The
only external mention is deployment topology prose
(`skchat/deploy/skstack01-stack.yml:17` "Cloudflare -> Authentik -> Traefik").

**Implication:** capauth's whole service/IdP surface can be refactored internally
without breaking any import in the ecosystem. It is a CLI + HTTP contract only.

---

## 7. skchat-app (Dart) capauth touchpoints (no import, daemon-mediated)

The app signs NO manifest and holds NO capauth signing key. All
capauth-authoritative signing is delegated to the local SKComms daemon over HTTP.

- `lib/features/skos/access_token_signer.dart:11-21,38-53,61,65` - asks the daemon
  to mint the capauth `SignedEnvelope` via `POST /api/v1/access/token` (the app's
  RSA signature can never be a byte-compatible OpenPGP packet, so the private key
  never leaves the daemon).
- `lib/services/pgp_capauth_signer.dart:9-28` `PgpCapAuthSigner implements
  SovereignSigner` - app-local RSA signer for ADVISORY message signatures only.
- Operator token (pasted): `lib/services/operator_token.dart` +
  `call_api_client.dart:75-83`, `guest_group_service.dart:357-364` (reads
  `SKCHAT_GUEST_OPERATOR_TOKEN`).
- Operator session (bearer): `lib/services/operator_session_service.dart` +
  `skcomms_client.dart:39-104,762-763` (attaches `Authorization: Bearer <session>`).
  This is the code card R4.2 extends for audience-token minting.
- capauth fingerprint as soul identity: `lib/models/conversation.dart:5,19,60`,
  `core/theme/sovereign_colors.dart:36`, `services/peer_trust_store.dart:7,114`,
  `livekit_call_service.dart:146`.
- There is NO `skworld.module.json` / `.sig` in the app yet (card R1.10 adds it).
  The Dart `ModuleManifest` (`lib/core/modules/module_manifest.dart`) is the UI
  module-spine model, NOT a capauth-signed manifest, and does no signing/verifying.

---

## 8. Domain coupling summary (where the extraction risk concentrates)

| Domain | Repos coupled | Caller count (approx) | Move/fold risk |
|---|---|---|---|
| identity | skcapstone, skchat, skcomms, skmemory, (skgateway JS, skchat-app Dart consume) | 40+ Python call sites | LOW: frozen, unchanged by M1-M3 |
| trust | skcapstone only (internal) | ~13 internal + MCP wrappers | LOW: zero cross-repo callers, mechanical move behind shim (M1) |
| tokens | skcapstone only (internal) + 1 forward ref | ~11 internal + `capauth_tools.py:165` | LOW-MED: latent broken ref until M1 |
| pairing | skchat (4 files), skcomms (2 files) | ~6 files, live guest traffic | MED-HIGH: live flows, shadow-gated fold (M2) |
| authz | skchat (dataplane_auth + routes), skcomms (separate validator) | ~2 modules, LIVE in prod since 07-20 | MED-HIGH: live enforcement, shadow-gated PEP (M3) |
| audience-mint | skchat-app (daemon-mediated), extends operator_session | new surface | MED: net-new, gated behind R4.2 |

The safe order the roadmap already picked (M1 trust/tokens first, then M2 pairing,
then M3 authz) is exactly the low-to-high coupling order this map confirms: the
mechanical internal moves go first, the live-traffic folds go last behind shadow
flags.
